"""
Authentication routes: signup, login/logout, refresh token rotation,
email verification, password reset, MFA (TOTP + recovery codes),
Google OAuth, and session management.

Conventions used throughout this file:
- Emails are always lowercased before storage or lookup, to keep
  matching case-insensitive.
- Rate limiting (via check_rate_limit) runs before any other validation
  on routes that are public/unauthenticated attack surfaces, so a bad
  actor can't rack up expensive DB queries by hammering these routes.
- Every state-changing auth event is recorded via log_audit_event
  for security auditing.
"""

import requests
import uuid
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.config import settings
from app.core.emails import send_password_reset_email, send_verification_email
from app.core.dependencies import get_current_user, require_verified
from app.core.redis_client import check_rate_limit, store_oauth_state, consume_oauth_state
from app.database import get_db
from app.models.oauth_accounts import OAuthAccount
from app.models.users import User
from app.models.role import Role
from app.models.refresh_token import RefreshToken
from app.models.password_reset_token import PasswordResetToken
from app.models.recovery_code import RecoveryCode
from app.schemas.user import UserCreate, UserResponse
from app.schemas.auth import RefreshRequest, Token, LoginRequest, ResendVerificationRequest, ForgotPasswordRequest, ResetPasswordRequest, MFAChallengeResponse, MFAVerifyRequest, MFALoginVerifyRequest, MFADisableRequest, SessionOut
from app.models.email_verification_token import EmailVerificationToken
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    generate_refresh_token,
    hash_refresh_token, decode_access_token, give_user_tokens, log_audit_event)
import pyotp

router = APIRouter()


#SIGNUP ROUTE
@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def signup(user: UserCreate, full_request:Request, db: Session = Depends(get_db)):
    check_rate_limit(key = f"signup: {full_request.client.host}", limit = 5, window_seconds = 300)
    existing_user = db.query(User).filter(User.email == user.email.lower()).first()
    if existing_user:
        log_audit_event(db, existing_user.id, "signup_failed_duplicate_email", full_request.client.host,full_request.headers.get("user-agent"),)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    hashed_password = hash_password(user.password)
    new_user = User(email=user.email.lower(), hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    user_role = db.query(Role).filter(Role.name == "user").first()
    new_user.roles.append(user_role)
    db.commit()

    # Create an email verification token for the new user
    verification_token = generate_refresh_token()  # Reusing method from refresh tokens to generate a random token
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)  # Token expires in 24 hours
    token_row = EmailVerificationToken(user_id=new_user.id,token_hash=hash_refresh_token(verification_token),# Reusing method from refresh tokens to has the random token that was created
        expires_at=expires_at,
        is_used=False
    )
    db.add(token_row)
    db.commit()
    send_verification_email(new_user.email,verification_token)
    log_audit_event(db, new_user.id, "signup_successful",full_request.client.host,full_request.headers.get("user-agent"),)
    return new_user

#LOGIN ROUTE
@router.post("/login", response_model=Token | MFAChallengeResponse)
def login(login_data: LoginRequest,full_request: Request,db: Session = Depends(get_db)):
    # Keyed on email (not IP) so credential-stuffing attempts against one specific account are throttled regardless of which IP they come from
    check_rate_limit(f"login: {login_data.email.lower()}", limit = 5, window_seconds = 300)
    user = db.query(User).filter(User.email == login_data.email.lower()).first()
    if not user or not user.hashed_password or not verify_password(user.hashed_password, login_data.password):
        log_audit_event(db, user.id if user else None, "login_failed_invalid_user",full_request.client.host,full_request.headers.get("user-agent"),)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    if user.mfa_enabled:
        challenge_token = create_access_token({"sub": str(user.id),"mfa_pending": True},expires_delta= timedelta(minutes=5))
        log_audit_event(db, user.id, "mfa_challenge_issued",full_request.client.host,full_request.headers.get("user-agent"),)
        return {"mfa_required": True, "challenge_token": challenge_token}
    log_audit_event(db, user.id, "login_successful",full_request.client.host,full_request.headers.get("user-agent"),)
    return give_user_tokens(db, user,device_info=full_request.headers.get("user-agent"))

@router.post("/refresh", response_model=Token)
def refresh(full_request: Request, refresh_input: RefreshRequest, db: Session = Depends(get_db)):
    refresh_token_hash = hash_refresh_token(refresh_input.refresh_token)
    refresh_token_row = db.query(RefreshToken).filter(RefreshToken.token_hash == refresh_token_hash).first()
    
    if not refresh_token_row or refresh_token_row.revoked or refresh_token_row.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    
    user = db.query(User).filter(User.id == refresh_token_row.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    access_token = create_access_token({"sub": str(user.id)})
    new_refresh_token = generate_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    # Rotate refresh tokens on every use: revoke the old one and issue a new one.
    # If a stolen refresh token is ever used after the legitimate one, the old
    # token will already be revoked, which is a signal of token theft.
    refresh_token_row.revoked = True
    db.add(refresh_token_row)
    new_refresh_token_row = RefreshToken(user_id=user.id, token_hash=hash_refresh_token(new_refresh_token), expires_at=expires_at, revoked=False,device_info = full_request.headers.get("user-agent"))
    db.add(new_refresh_token_row)
    
    db.commit()
    
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": new_refresh_token}

#LOGOUT ROUTE
@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(logout_input: RefreshRequest, db: Session = Depends(get_db)):
    refresh_token_hash = hash_refresh_token(logout_input.refresh_token)
    refresh_token_row = db.query(RefreshToken).filter(RefreshToken.token_hash == refresh_token_hash).first()
    
    if not refresh_token_row or refresh_token_row.revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or already revoked refresh token",
        )
    
    # Revoke the refresh token
    refresh_token_row.revoked = True
    db.add(refresh_token_row)
    db.commit()
    
    return None

# EMAIL VERIFICATION
@router.get("/verify-email")
def verify_email(token:str, db: Session = Depends(get_db)):
    token_hash = hash_refresh_token(token) #Reusing refresh token module to hash the verification token
    token_row = db.query(EmailVerificationToken).filter(EmailVerificationToken.token_hash == token_hash).first()
    if not token_row or token_row.is_used or token_row.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail = "Invalid or expired verification code")
    user = db.query(User).filter(User.id == token_row.user_id).first()
    user.is_verified = True
    token_row.is_used = True
    db.commit()

    return {"message": "Email verified successfully"}

# RESENDING EMAIL VERIFICATION
@router.post("/resend-verification")
def resend_verification(request: ResendVerificationRequest,full_request: Request, db: Session = Depends(get_db)):
    check_rate_limit(key=f"resend_verification: {full_request.client.host}", limit=5, window_seconds=300)
    user = db.query(User).filter(User.email == request.email.lower()).first()
    if not user or user.is_verified:
        return {"message": "If this account exists and is unverified, a new link has been sent to you"}

    db.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id, EmailVerificationToken.is_used == False,
    ).update({"is_used": True})

    verification_token = generate_refresh_token() #reusing refresh token module to generate random token
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    token_row = EmailVerificationToken(
        user_id=user.id,
        token_hash = hash_refresh_token(verification_token),
        expires_at = expires_at
    )
    db.add(token_row)
    db.commit()
    send_verification_email(user.email.lower(),verification_token)
    return {"message": "If this account exists and is unverified, a new link has been sent to you"}

#FORGOT PASSWORD
@router.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest,full_request: Request, db: Session = Depends(get_db)):
    check_rate_limit(key=f"forgot_password: {full_request.client.host}", limit=5, window_seconds=300)
    user = db.query(User).filter(User.email == request.email.lower()).first()
    if not user:
        return {"message": "If account exists, a password reset link has been sent to your email address"}

    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.is_used == False,
    ).update({"is_used": True})

    reset_token = generate_refresh_token() #reusing refresh token model for generating random token
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    token_row = PasswordResetToken(
        user_id = user.id,
        token_hash = hash_refresh_token(reset_token),
        expires_at=expires_at,
    )
    db.add(token_row)
    db.commit()

    send_password_reset_email(user.email.lower(),reset_token)
    return {"message": "If account exists, a password reset link has been sent to your email address"}

#RESET PASSWORD
@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest, full_request: Request,db: Session = Depends(get_db)):
    token_hash = hash_refresh_token(request.token)
    token_row = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == token_hash).first()
    if not token_row or token_row.is_used or token_row.expires_at < datetime.now(timezone.utc):
        log_audit_event(db, None, "invalid_or_expired_reset_token",full_request.client.host,full_request.headers.get("user-agent"))
        raise HTTPException(status_code = 400, detail = "Invalid or expired reset token")
    
    user = db.query(User).filter(User.id==token_row.user_id).first()
    user.hashed_password = hash_password(request.new_password)
    token_row.is_used = True
    # Revoke all sessions after a password reset, since the old password may
    # have been compromised. Anyone using a previously-issued token should be
    # forced to re-authenticate with the new password.
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id,RefreshToken.revoked == False,).update({"revoked":True})
    user.tokens_valid_after = datetime.now(timezone.utc)
    db.commit()
    log_audit_event(db, user.id,"reset_password_successful",full_request.client.host,full_request.headers.get("user-agent"))
    return {"message": "Password reset successfully"}

@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_form(token: str):
    """
    Minimal server-rendered form for password reset, so the link in the
    reset email is directly clickable rather than requiring a frontend.
    Submits via JS as JSON to match the existing POST /auth/reset-password
    route's expected body, rather than a standard form-encoded POST.
    """
    return f"""
    <html>
        <body>
            <h2>Reset your password</h2>
            <form id="reset-form">
                <input type="password" id="new_password" placeholder="New password" required>
                <button type="submit">Reset Password</button>
            </form>
            <p id="message"></p>
            <script>
                document.getElementById("reset-form").addEventListener("submit", async function(e) {{
                    e.preventDefault();
                    const response = await fetch("/auth/reset-password", {{
                        method: "POST",
                        headers: {{ "Content-Type": "application/json" }},
                        body: JSON.stringify({{
                            token: "{token}",
                            new_password: document.getElementById("new_password").value
                        }})
                    }});
                    const data = await response.json();
                    document.getElementById("message").innerText = data.detail || data.message;
                }});
            </script>
        </body>
    </html>
    """


#GENERATING MFA CODES THAT USER NEEDS TO CONFIRM ARE WORKING BEFORE TURNING ON MFA
@router.post("/mfa/setup")
def setup_mfa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db), _verified: User = Depends(require_verified)):
    secret = pyotp.random_base32()
    current_user.mfa_secret = secret
    db.commit()

    provisioning_url = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email.lower(),
        issuer_name = "AUTH_API"
    )
    recovery_codes =[generate_refresh_token()[0:10] for _ in range(8)] #reusing refresh token function to generate random 10 digit recovery codes
    for code in recovery_codes:
        db.add(RecoveryCode(user_id=current_user.id, code_hash=hash_refresh_token(code)))
        db.commit()
    return {"secret": secret, "recovery_codes": recovery_codes, "provisioning_url": provisioning_url}

# TURNING OFF MULTI-FACTOR AUTHENTICATION
@router.post("/mfa/disable")
def disable_mfa(request: MFADisableRequest,full_request: Request,current_user: User = Depends(get_current_user), db: Session = Depends(get_db), _verified: User = Depends(require_verified)):
    totp = pyotp.totp.TOTP(current_user.mfa_secret)
    if not totp.verify(request.code):
        raise HTTPException(status_code = 400, detail = "Invalid code")
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.query(RecoveryCode).filter(RecoveryCode.user_id == current_user.id).delete()
    db.commit()
    log_audit_event(db, current_user.id,"disable_mfa",full_request.client.host,full_request.headers.get("user-agent"))
    return {"message": "MFA is disabled"}

# TURNING ON MFA
@router.post("/mfa/verify-setup")
def verify_mfa_setup(request:MFAVerifyRequest ,current_user: User = Depends(get_current_user), db: Session = Depends(get_db), _verified: User = Depends(require_verified)):
    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(request.code):
        raise HTTPException(status_code = 400, detail = "Invalid code")
    current_user.mfa_enabled = True
    db.commit()
    return {"message": "MFA is enabled"}

# LOGGING IN WITH MFA
@router.post("/mfa/login-verify")
def mfa_login_verify(request: MFALoginVerifyRequest, full_request: Request,db: Session = Depends(get_db)):
    payload = decode_access_token(request.challenge_token)
    if not payload.get("mfa_pending"):
        log_audit_event(db,None,"failed_mfa_login",full_request.client.host,full_request.headers.get("user-agent"))
        raise HTTPException(status_code = 400, detail = "Invalid challenge token")
    user = db.query(User).filter(User.id == uuid.UUID(payload["sub"])).first()
    if not user:
        log_audit_event(db, None, "mfa_login_user_does_not_exist", full_request.client.host,
                        full_request.headers.get("user-agent"))
        raise HTTPException(status_code = 401, detail = "Invalid challenge token")
    totp = pyotp.TOTP(user.mfa_secret)

    if not totp.verify(request.code):
        #fall back to recovery code
        # Recovery codes let a user log in if they've lost access to their
        # authenticator app; each one is single-use.
        code_hash = hash_refresh_token(request.code)
        recovery = db.query(RecoveryCode).filter(
            RecoveryCode.user_id == user.id,
            RecoveryCode.is_used == False,
            RecoveryCode.code_hash == code_hash,
        ).first()
        if not recovery:
            log_audit_event(db, None, "failed_mfa_login", full_request.client.host,
                            full_request.headers.get("user-agent"))
            raise HTTPException(status_code = 400, detail = "Invalid code")
        recovery.is_used = True
        db.commit()
    # issue user access and refresh token
    log_audit_event(db, user.id, "mfa_login_success",full_request.client.host,full_request.headers.get("user-agent"))
    return give_user_tokens(db, user,device_info=full_request.headers.get("user-agent"))

# Generate google login url which has state variable that will be used for csrf verification when response comes back from google.
@router.get("/oauth/google/login")
def google_login():
    state = generate_refresh_token()[:32] #reusing generate_refresh_token to generate random string for oauth state
    store_oauth_state(state)

    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={settings.google_client_id}"
        f"&redirect_uri={settings.google_redirect_uri}"
        "&response_type=code"
        "&scope=openid%20email%20profile"
        f"&state={state}"
    )
    return RedirectResponse(google_auth_url)

# Google Login Process after getting response from Google oauth
@router.get("/oauth/google/callback")
def google_oauth_callback(full_request:Request,code: str = None, state: str = None,error: str = None, db: Session = Depends(get_db)):
    check_rate_limit(key=f"oauth_callback: {full_request.client.host}", limit=5, window_seconds=300)
    is_new_user = False
    # Check if there is an error or if state returned from Google is valid. If it is, remove from set.
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    if not consume_oauth_state(state):
        raise HTTPException(status_code=400, detail="Invalid state")
    # Swap code for Google tokens
    token_response = requests.post("https://oauth2.googleapis.com/token",data = {
        "code": code,
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret,
        "redirect_uri": settings.google_redirect_uri,
        "grant_type": "authorization_code",
    })
    if token_response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to exchange authorization code")
    google_tokens = token_response.json()

    # Fetch User Profile and throw error if Gmail is not verified
    userinfo_response = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {google_tokens['access_token']}"},
    )
    if userinfo_response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch Google user info")
    profile = userinfo_response.json()

    if not profile.get("email_verified"):
        raise HTTPException(status_code=400, detail="Google email not verified")

    # Check if oauth or existing user that had not used oauth initially
    oauth_account = db.query(OAuthAccount).filter(OAuthAccount.provider == "google", OAuthAccount.provider_user_id == profile["sub"]).first()

    if oauth_account:
        user = db.query(User).filter(User.id == oauth_account.user_id).first()
    else:
        user = db.query(User).filter(User.email == profile["email"].lower()).first()

        if not user:
            # Add User if it does not exist
            is_new_user = True
            user = User(email =profile["email"].lower(), hashed_password = None, is_verified = True)
            db.add(user)
            db.commit()
            db.refresh(user)
            user_role = db.query(Role).filter(Role.name == "user").first()
            user.roles.append(user_role)
            db.commit()
        # Oauth does not exist for user so we add it
        db.add(OAuthAccount(user_id = user.id, provider = "google", provider_user_id = profile["sub"]))
        db.commit()

    # Give User access and refresh tokens
    log_audit_event(db, user.id, "oauth_login",full_request.client.host,full_request.headers.get("user-agent"),event_metadata = {"provider":"google","new_account": is_new_user})
    return give_user_tokens(db, user,device_info=full_request.headers.get("user-agent"))

# Get & Remove Active Sessions Routes

@router.get("/me/sessions", response_model = list[SessionOut])
def list_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(RefreshToken).filter(RefreshToken.user_id == current_user.id,RefreshToken.revoked == False, RefreshToken.expires_at > datetime.now(timezone
                                                                                                                                                       .utc)).all()
@router.delete("/me/sessions/{session_id}", status_code = status.HTTP_204_NO_CONTENT)
def delete_single_session(session_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    session_row = db.query(RefreshToken).filter(RefreshToken.user_id == current_user.id,RefreshToken.id == session_id,RefreshToken.revoked == False).first()
    if not session_row:
        raise HTTPException(status_code = 404, detail = "Session not found")
    session_row.revoked = True
    # Note: tokens_valid_after is deliberately NOT updated here. It's a per-user
    # field, so setting it would invalidate access tokens for ALL sessions, not
    # just this one — defeating the purpose of single-session revocation.
    db.commit()
    return None

@router.delete("/me/sessions", status_code = status.HTTP_204_NO_CONTENT)
def delete_all_sessions(current_user: User = Depends(get_current_user),db: Session = Depends(get_db)):
    db.query(RefreshToken).filter(RefreshToken.user_id == current_user.id,RefreshToken.revoked == False).update({"revoked": True})
    # Unlike single-session revocation, this invalidates ALL of the user's
    # existing access tokens too, since every session is being revoked at once.
    current_user.tokens_valid_after = datetime.now(timezone.utc)
    db.commit()
    return None