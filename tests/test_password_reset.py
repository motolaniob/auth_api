from app.models.password_reset_token import PasswordResetToken
from app.models.users import User

def _signup(client, email, password):
    return client.post("/auth/signup", json={"email": email, "password": password})

def test_forgot_password_generic_response_for_unknown_email(client):
    response = client.post("/auth/forgot-password", json={"email": "ghost@example.com"})
    assert response.status_code == 200
    assert "message" in response.json()

def test_forgot_password_creates_token_for_real_user(client, db_session):
    _signup(client, "resetme@example.com", "Xk9$mQ2vL8pT4wZ1")
    client.post("/auth/forgot-password", json={"email": "resetme@example.com"})
    user = db_session.query(User).filter(User.email == "resetme@example.com").first()
    token_row = db_session.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).first()
    assert token_row is not None

def test_reset_password_full_flow(client, capsys): 
    _signup(client, "fullflow@example.com", "OldPassw0rd!9zK")
    capsys.readouterr()  # discard the signup verification-email print
    client.post("/auth/forgot-password", json={"email": "fullflow@example.com"})
    captured = capsys.readouterr()
    token = captured.out.split("token=")[1].split()[0].strip()

    reset_response = client.post("/auth/reset-password", json={"token": token, "new_password": "NewPassw0rd!7qR"})
    assert reset_response.status_code == 200

    old_login = client.post("/auth/login", json={"email": "fullflow@example.com", "password": "OldPassw0rd!9zK"})
    assert old_login.status_code == 401

    new_login = client.post("/auth/login", json={"email": "fullflow@example.com", "password": "NewPassw0rd!7qR"})
    assert new_login.status_code == 200

def test_reset_password_rejects_reused_token(client, capsys):
    _signup(client, "reusereset@example.com", "OldPassw0rd!9zK")
    capsys.readouterr()  # discard the signup verification-email print
    client.post("/auth/forgot-password", json={"email": "reusereset@example.com"})
    captured = capsys.readouterr()
    token = captured.out.split("token=")[1].split()[0].strip()
    client.post("/auth/reset-password", json={"token": token, "new_password": "NewPassw0rd!7qR"})
    response = client.post("/auth/reset-password", json={"token": token, "new_password": "AnotherPassw0rd!"})
    assert response.status_code == 400

def test_reset_password_revokes_existing_refresh_tokens(client, capsys):
    _signup(client, "revoke@example.com", "OldPassw0rd!9zK")
    capsys.readouterr()  # discard the signup verification-email print
    login_response = client.post("/auth/login", json={"email": "revoke@example.com", "password": "OldPassw0rd!9zK"})
    old_refresh_token = login_response.json()["refresh_token"]
    client.post("/auth/forgot-password", json={"email": "revoke@example.com"})
    captured = capsys.readouterr()  
    token = captured.out.split("token=")[1].split()[0].strip()
    client.post("/auth/reset-password", json={"token": token, "new_password": "NewPassw0rd!7qR"})

    refresh_attempt = client.post("/auth/refresh", json={"refresh_token": old_refresh_token})
    assert refresh_attempt.status_code == 401