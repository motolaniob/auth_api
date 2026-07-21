from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    check_password_breach

)
from datetime import timedelta
from jose.exceptions import ExpiredSignatureError
import pytest
import hashlib
from unittest.mock import patch, Mock


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

def test_access_token_contains_expected_claims():
    payload = {"sub": "user-123", "role": "admin"}
    token = create_access_token(payload)
    decoded = decode_access_token(token)
    assert decoded["sub"] == "user-123"
    assert decoded["role"] == "admin"

def test_password_found_in_breach_list():
    password = "testpassword123"
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = f"{suffix}:42\nSOMEOTHERHASH:7\n"

    with patch("app.core.security.requests.get", return_value=mock_response) as mock_get:
        count = check_password_breach(password)
        assert count == 42
        mock_get.assert_called_once_with(f"https://api.pwnedpasswords.com/range/{prefix}")

def test_password_not_found_in_breach_list():
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "AAAAA:5\nBBBBB:2\n"

    with patch("app.core.security.requests.get", return_value=mock_response):
        count = check_password_breach("some-safe-password")
        assert count == 0

def test_api_error_raises_exception():
    mock_response = Mock()
    mock_response.status_code = 500

    with patch("app.core.security.requests.get", return_value=mock_response):
        with pytest.raises(Exception):
            check_password_breach("anypassword")