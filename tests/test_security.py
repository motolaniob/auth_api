from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from datetime import timedelta
from jose.exceptions import ExpiredSignatureError
import pytest

def test_hash_password_produces_different_hash_than_input():
    password = "mysecretpassword123"
    hashed = hash_password(password)
    assert hashed != password

def test_verify_password_succeeds_with_correct_password():
    password = "mysecretpassword123"
    hashed = hash_password(password)
    assert verify_password(hashed, password) is True

def test_verify_password_fails_with_wrong_password():
    hashed = hash_password("correctpassword")
    assert verify_password(hashed, "wrongpassword") is False

def test_access_token_round_trip():
    token = create_access_token({"sub": "user-123"})
    decoded = decode_access_token(token)
    assert decoded["sub"] == "user-123"
    assert "exp" in decoded
    assert "iat" in decoded

def test_expired_token_raises():
    token = create_access_token({"sub": "user-123"}, expires_delta=timedelta(seconds=-1))
    with pytest.raises(ExpiredSignatureError):
        decode_access_token(token)