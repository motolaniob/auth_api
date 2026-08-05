from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose.exceptions import JWTError, ExpiredSignatureError
from datetime import datetime, timezone, timedelta
from app.database import get_db
from app.models.users import User
from app.models.refresh_token import RefreshToken
from app.core.security import decode_access_token, create_access_token, hash_refresh_token, generate_refresh_token
import uuid   

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User: 

    credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},)

    try: payload = decode_access_token(token)
    except (ExpiredSignatureError, JWTError):
        raise credentials_exception

    user_id = payload.get("sub")
    if user_id is None:
        raise credentials_exception

    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if user is None:
        raise credentials_exception
    
    return user

def require_role(required_role: str):
    def role_checker(current_user: User = Depends(get_current_user), payload: dict = Depends(get_token_payload)) -> User:
        token_roles = payload.get("roles", [])
        if required_role not in token_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action."
            )
        return current_user
    return role_checker

def require_verified(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_verified:
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail="Please verify your email to access this feature"
        )
    return current_user

def get_token_payload(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = decode_access_token(token)
        return payload
    except (ExpiredSignatureError, JWTError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def give_user_tokens(db: Session, user : User) -> dict:
    access_token = create_access_token({"sub": str(user.id), "roles": [role.name for role in user.roles]})
    refresh_token = generate_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    refresh_token_row = RefreshToken(user_id=user.id, token_hash=hash_refresh_token(refresh_token),expires_at=expires_at, revoked=False)
    db.add(refresh_token_row)
    db.commit()
    db.refresh(refresh_token_row)
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}