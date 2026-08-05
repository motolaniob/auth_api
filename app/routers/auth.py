import profile
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.config import settings
from app.core.emails import send_password_reset_email, send_verification_email
from app.core.dependencies import get_current_user, require_verified, give_user_tokens
from app.database import get_db
from app.models.oauth_accounts import OAuthAccount
from app.models.users import User
from app.models.role import Role
from app.models.refresh_token import RefreshToken
from app.models.password_reset_token import PasswordResetToken
from app.models.recovery_code import RecoveryCode
from app.schemas.user import UserCreate, UserResponse
from app.schemas.auth import RefreshRequest, Token, LoginRequest, ResendVerificationRequest, ForgotPasswordRequest, ResetPasswordRequest, MFAChallengeResponse, MFAVerifyRequest, MFALoginVerifyRequest, MFADisableRequest
from app.models.email_verification_token import EmailVerificationToken
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    generate_refresh_token,
    hash_refresh_token, decode_access_token)
import pyotp

router = APIRouter()
oauth_states : set[str] = set()

#SIGNUP ROUTE
@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    hashed_password = hash_password(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
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
    return new_user

#LOGIN ROUTE
@router.post("/login", response_model=Token | MFAChallengeResponse)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not user.hashed_password or not verify_password(user.hashed_password, login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    if user.mfa_enabled:
        challenge_token = create_access_token({"sub": str(user.id),"mfa_pending": True},expires_delta= timedelta(minutes=5))
        return {"mfa_required": True, "challenge_token": challenge_token}
    return give_user_tokens(db, user)
    """access_token = create_access_token({"sub": str(user.id), "roles": [role.name for role in user.roles]})
    refresh_token = generate_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    refresh_token_row = RefreshToken(user_id = user.id, token_hash = hash_refresh_token(refresh_token), expires_at = expires_at, revoked = False)
    db.add(refresh_token_row)
    db.commit()
    db.refresh(refresh_token_row)
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}"""

@router.post("/refresh", response_model=Token)
def refresh(refresh_input: RefreshRequest, db: Session = Depends(get_db)):
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
    
    # Revoke the old refresh token
    refresh_token_row.revoked = True
    db.add(refresh_token_row)
    
    # Store the new refresh token
    new_refresh_token_row = RefreshToken(user_id=user.id, token_hash=hash_refresh_token(new_refresh_token), expires_at=expires_at, revoked=False)
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
def resend_verification(request: ResendVerificationRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
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
    send_verification_email(user.email,verification_token)
    return {"message": "If this account exists and is unverified, a new link has been sent to you"}

#FORGOT PASSWORD
@router.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
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

    send_password_reset_email(user.email,reset_token)
    return {"message": "If account exists, a password reset link has been sent to your email address"}

#RESET PASSWORD
@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    token_hash = hash_refresh_token(request.token)
    token_row = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == token_hash).first()
    if not token_row or token_row.is_used or token_row.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code = 400, detail = "Invalid or expired reset token")
    
    user = db.query(User).filter(User.id==token_row.user_id).first()
    user.hashed_password = hash_password(request.new_password)
    token_row.is_used = True
    #After old password is reset, revoke all refresh tokens. 
    db.query(RefreshToken).filter(RefreshToken.user_id == user.id,RefreshToken.revoked == False,).update({"revoked":True})
    db.commit()
    return {"message": "Password reset successfully"}

#GENERATING MFA CODES THAT USER NEEDS TO CONFIRM ARE WORKING BEFORE TURNING ON MFA
@router.post("/mfa/setup")
def setup_mfa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db), _verified: User = Depends(require_verified)):
    secret = pyotp.random_base32()
    current_user.mfa_secret = secret
    db.commit()

    provisioning_url = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name = "AUTH_API"
    )
    recovery_codes =[generate_refresh_token()[0:10] for _ in range(8)] #reusing refresh token function to generate random 10 digit recovery codes
    for code in recovery_codes:
        db.add(RecoveryCode(user_id=current_user.id, code_hash=hash_refresh_token(code)))
        db.commit()
    return {"secret": secret, "recovery_codes": recovery_codes, "provisioning_url": provisioning_url}

# TURNING OFF MULTI FACTOR AUTHENTICATION
@router.post("/mfa/disable")
def disable_mfa(request: MFADisableRequest,current_user: User = Depends(get_current_user), db: Session = Depends(get_db), _verified: User = Depends(require_verified)):
    totp = pyotp.totp.TOTP(current_user.mfa_secret)
    if not totp.verify(request.code):
        raise HTTPException(status_code = 400, detail = "Invalid code")
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.query(RecoveryCode).filter(RecoveryCode.user_id == current_user.id).delete()
    db.commit()
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
def mfa_login_verify(request: MFALoginVerifyRequest, db: Session = Depends(get_db)):
    payload = decode_access_token(request.challenge_token)
    if not payload.get("mfa_pending"):
        raise HTTPException(status_code = 400, detail = "Invalid challenge token")
    user = db.query(User).filter(User.id == uuid.UUID(payload["sub"])).first()
    if not user:
        raise HTTPException(status_code = 401, detail = "Invalid challenge token")
    totp = pyotp.TOTP(user.mfa_secret)

    if not totp.verify(request.code):
        #fall back to recovery code
        code_hash = hash_refresh_token(request.code)
        recovery = db.query(RecoveryCode).filter(
            RecoveryCode.user_id == user.id,
            RecoveryCode.is_used == False,
            RecoveryCode.code_hash == code_hash,
        ).first()
        if not recovery:
            raise HTTPException(status_code = 400, detail = "Invalid code")
        recovery.is_used = True
        db.commit()
    # issue user access and refresh token
    return give_user_tokens(db, user)
    """access_token = create_access_token({"sub": str(user.id), "roles": [role.name for role in user.roles]})
    refresh_token = generate_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    refresh_token_row = RefreshToken(user_id=user.id, token_hash=hash_refresh_token(refresh_token),expires_at=expires_at, revoked=False)
    db.add(refresh_token_row)
    db.commit()
    db.refresh(refresh_token_row)
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}"""



# Generate google login url which has state variable that will be used for csrf verification when response comes back from google.
@router.get("/oauth/google/login")
def google_login():
    state = generate_refresh_token()[:32] #reusing generate_refresh_token to generate random string for oauth state
    oauth_states.add(state) #Temporary implementation, add the state to list of states in set

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
def google_oauth_callback(code: str = None, state: str = None, db: Session = Depends(get_db)):
    # Check if there is an error or if state returned from google is valid. If it is, remove from set.
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    if state not in oauth_states:
        raise HTTPException(status_code=400, detail="Invalid state")
    oauth_states.remove(state)

    # Swap code for Google tokens
    token_response = requests.post("https://oauth2.googleapis.com/token",data = {
        "code": code,
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret,
        "redirect_uri": settings.google_redirect_uri,
        "grant_type": "authorization_code",
    })
    google_tokens = token_response.json()

    # Fetch User Profile and throw error if Gmail is not verified
    userinfo_response = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {google_tokens['access_token']}"},
    )
    profile = userinfo_response.json()

    if not profile.get("email_verified"):
        raise HTTPException(status_code=400, detail="Google email not verified")

    # Check if oauth or existing user that had not used oauth initially
    oauth_account = db.query(OAuthAccount).filter(OAuthAccount.provider == "google", OAuthAccount.provider_user_id == profile["sub"]).first()

    if oauth_account:
        user = db.query(User).filter(User.id == oauth_account.user_id).first()
    else:
        user = db.query(User).filter(User.email == profile["email"]).first()

        if not user:
            # Add User if it does not exist
            user = User(email =profile["email"], hashed_password = None, is_verified = True)
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
    return give_user_tokens(db, user)

    """access_token = create_access_token({"sub": str(user.id), "roles": [role.name for role in user.roles]})
    refresh_token = generate_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    refresh_token_row = RefreshToken(user_id=user.id, token_hash=hash_refresh_token(refresh_token),expires_at=expires_at, revoked=False)
    db.add(refresh_token_row)
    db.commit()
    db.refresh(refresh_token_row)
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}"""
