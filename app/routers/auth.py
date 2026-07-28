from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.users import User
from app.models.role import Role
from app.models.refresh_token import RefreshToken
from app.models.password_reset_token import PasswordResetToken
from app.schemas.user import UserCreate, UserResponse
from app.schemas.auth import RefreshRequest, Token, LoginRequest, ResendVerificationRequest, ForgotPasswordRequest, ResetPasswordRequest
from app.models.email_verification_token import EmailVerificationToken
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    generate_refresh_token,
    hash_refresh_token)

router = APIRouter()

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
    #TO DO: Replace with real email service (see README)
    print(f"Verification link: http://localhost:8000/auth/verify-email?token={verification_token}")
    return new_user

@router.post("/login", response_model=Token)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not user.hashed_password or not verify_password(user.hashed_password, login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    access_token = create_access_token({"sub": str(user.id), "roles": [role.name for role in user.roles]})
    refresh_token = generate_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    refresh_token_row = RefreshToken(user_id = user.id, token_hash = hash_refresh_token(refresh_token), expires_at = expires_at, revoked = False)
    db.add(refresh_token_row)
    db.commit()
    db.refresh(refresh_token_row)
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

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
    print(f"Verification link: http://localhost:8000/auth/verify-email?token={verification_token}")#TO DO: Wire up to real email sender
    return {"message": "If this account exists and is unverified, a new link has been sent to you"}

@router.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        return {"message": "If account exists, a password reset link has been sent to your email address"}

    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.is_used == False,
    ).update({"is_used": True})

    reset_token = generate_refresh_token #reusing refresh token model for generating random token
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    token_row = PasswordResetToken(
        user_id = user.id,
        token_hash = hash_refresh_token(reset_token),
        expires_at=expires_at,
    )
    db.add(token_row)
    db.commit()

    #TO DO: Hook up to real email  service
    print(f"Password reset link: http://localhost:8000/reset-password?token={reset_token}")

    return {"message": "If account exists, a password reset link has been sent to your email address"}

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