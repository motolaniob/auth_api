"""
Core security primitives shared across the auth system: password hashing
(Argon2), JWT access tokens (RS256, asymmetric so only this service can
issue tokens but any service with the public key can verify them),
refresh token generation/hashing, breach-checking via Have I Been Pwned,
and audit logging.

Refresh tokens are stored hashed (never raw) in the database, mirroring
how passwords are handled — if the database were ever compromised, stored
refresh tokens couldn't be used directly to authenticate as a user.
"""

from datetime import timedelta, timezone, datetime
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from pathlib import Path
from jose import jwt
from app.config import settings
import hashlib
import requests
import secrets
from sqlalchemy.orm import Session
from app.models.users import User
from app.models.refresh_token import RefreshToken
from app.models.audit_logs import AuditLog

private_key = Path(settings.keys_directory / "private_key.pem").read_text()
public_key = Path(settings.keys_directory / "public_key.pem").read_text()
# RS256 (asymmetric) instead of HS256: only this service holds the private
# key needed to issue tokens, but any other service can verify tokens using
# just the public key, without being able to forge new ones.
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

 
def check_password_breach(password: str) -> int:
    """Check if a password has been breached using the Have I Been Pwned API."""
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    
    if response.status_code != 200:
        # Fails closed: if HIBP is unreachable, signup/password-reset should
        # error out rather than silently skip the breach check.
        raise Exception("Error checking password breach status.")
    
    for line in response.text.splitlines():
        hash_suffix, count = line.split(':')
        if suffix == hash_suffix:
            return int(count)
    return 0

def generate_refresh_token() -> str:
    """
        Generates a cryptographically secure random URL-safe string.
        Despite the name, this is reused throughout the codebase anywhere a
        random token is needed — email verification, password reset, OAuth
        state, and recovery codes — not just refresh tokens.
    """
    return secrets.token_urlsafe(64)

def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def revoke_all_refresh_tokens(user_id: str, db: Session):
    """
        Marks all of a user's refresh tokens as revoked. Does NOT touch
        tokens_valid_after — callers that also need to invalidate already-issued
        access tokens (not just refresh tokens) must set that separately.
        Used by: reset_password, delete_all_sessions, update_user_roles.
    """
    db.query(RefreshToken).filter(RefreshToken.user_id == user_id).update({"revoked": True})
    db.commit()

def give_user_tokens(db: Session, user : User, device_info: str) -> dict:
    access_token = create_access_token({"sub": str(user.id), "roles": [role.name for role in user.roles]})
    refresh_token = generate_refresh_token()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    refresh_token_row = RefreshToken(user_id=user.id, token_hash=hash_refresh_token(refresh_token),expires_at=expires_at, revoked=False, device_info=device_info)
    db.add(refresh_token_row)
    db.commit()
    db.refresh(refresh_token_row)
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

def log_audit_event(db: Session, user_id, event_type: str, ip_address: str = None, user_agent: str = None ,event_metadata: dict = None):
    db.add(AuditLog(user_id=user_id, event_type=event_type, ip_address=ip_address, user_agent=user_agent, event_metadata=event_metadata))
    db.commit()