from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.users import User
from app.models.refresh_token import RefreshToken
from app.schemas.user import UserCreate, UserResponse
from app.schemas.auth import RefreshRequest, Token, LoginRequest
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
    
    return new_user

@router.post("/login", response_model=Token)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not user.hashed_password or not verify_password(user.hashed_password, login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    access_token = create_access_token({"sub": str(user.id)})
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