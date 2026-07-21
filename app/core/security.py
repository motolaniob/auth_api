from datetime import timedelta, timezone, datetime
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from pathlib import Path
from jose import jwt
from app.config import settings

private_key = Path(settings.keys_directory / "private_key.pem").read_text()
public_key = Path(settings.keys_directory / "public_key.pem").read_text()
ph = PasswordHasher()

def hash_password(password: str) -> str:
    """Hash a password using Argon2."""
    return ph.hash(password)

def verify_password(hashed_password: str, password: str) -> bool:
    """Verify a password against its hash."""
    try:
        return ph.verify(hashed_password, password)
    except VerifyMismatchError:
        return False

def create_access_token(payload: dict, expires_delta: timedelta = None) -> str:
    """Create a JWT access token."""
    # Implementation for creating a JWT access token using the private key
    to_encode = payload.copy()
    expiry = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expiry, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, private_key, algorithm="RS256")

def decode_access_token(token: str) -> dict:
    """Decode a JWT access token."""
    return jwt.decode(token, public_key, algorithms=["RS256"])

 
