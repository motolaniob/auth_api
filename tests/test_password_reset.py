from app.models.password_reset_token import PasswordResetToken
from app.models.users import User

def _signup(client, email, password):
    return client.post("/auth/signup", json={"email": email, "password": password})

def test_forgot_password_generic_response_for_unknown_email(client, captured_verification_email):
    response = client.post("/auth/forgot-password", json={"email": "ghost@example.com"})
    assert response.status_code == 200

def test_forgot_password_creates_token_for_real_user(client, db_session, captured_verification_email, captured_reset_email):
    _signup(client, "resetme@example.com", "Xk9$mQ2vL8pT4wZ1")
    client.post("/auth/forgot-password", json={"email": "resetme@example.com"})
    user = db_session.query(User).filter(User.email == "resetme@example.com").first()
    token_row = db_session.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).first()
    assert token_row is not None

def test_reset_password_full_flow(client, captured_verification_email, captured_reset_email):
    _signup(client, "fullflow@example.com", "OldPassw0rd!9zK")
    client.post("/auth/forgot-password", json={"email": "fullflow@example.com"})
    token = captured_reset_email["token"]

    reset_response = client.post("/auth/reset-password", json={"token": token, "new_password": "NewPassw0rd!7qR"})
    assert reset_response.status_code == 200

    old_login = client.post("/auth/login", json={"email": "fullflow@example.com", "password": "OldPassw0rd!9zK"})
    assert old_login.status_code == 401

    new_login = client.post("/auth/login", json={"email": "fullflow@example.com", "password": "NewPassw0rd!7qR"})
    assert new_login.status_code == 200

def test_reset_password_rejects_reused_token(client, captured_verification_email, captured_reset_email):
    _signup(client, "reusereset@example.com", "OldPassw0rd!9zK")
    client.post("/auth/forgot-password", json={"email": "reusereset@example.com"})
    token = captured_reset_email["token"]

    client.post("/auth/reset-password", json={"token": token, "new_password": "NewPassw0rd!7qR"})
    response = client.post("/auth/reset-password", json={"token": token, "new_password": "AnotherPassw0rd!"})
    assert response.status_code == 400

def test_reset_password_revokes_existing_refresh_tokens(client, captured_verification_email, captured_reset_email):
    _signup(client, "revoke@example.com", "OldPassw0rd!9zK")
    login_response = client.post("/auth/login", json={"email": "revoke@example.com", "password": "OldPassw0rd!9zK"})
    old_refresh_token = login_response.json()["refresh_token"]

    client.post("/auth/forgot-password", json={"email": "revoke@example.com"})
    token = captured_reset_email["token"]
    client.post("/auth/reset-password", json={"token": token, "new_password": "NewPassw0rd!7qR"})

    refresh_attempt = client.post("/auth/refresh", json={"refresh_token": old_refresh_token})
    assert refresh_attempt.status_code == 401