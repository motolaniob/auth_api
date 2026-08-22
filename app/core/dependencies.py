"""
FastAPI dependencies for authentication and authorization: extracting and
validating the current user from a JWT, and role/verification-based access
control for protected routes.
"""

from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose.exceptions import JWTError, ExpiredSignatureError
from datetime import datetime, timezone, timedelta
from app.database import get_db
from app.models import User
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
    iat = payload.get("iat")
    # Tokens issued before tokens_valid_after are rejected even if not expired —
    # this is how logout-all-sessions, password reset, and role changes take
    # effect immediately instead of waiting for natural token expiry.
    if user.tokens_valid_after and (iat is None or iat < user.tokens_valid_after):
        raise credentials_exception
    return user

def require_role(required_role: str):
    """
       Checks roles embedded in the JWT itself, not a fresh DB query — faster,
       but means a role change won't take effect until the user's token is
       reissued. This is mitigated by tokens_valid_after being bumped on role
       change (see admin.py's update_user_roles), which forces reauthentication.
    """
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

