from app.models.email_verification_token import EmailVerificationToken
from app.models.users import User

def test_signup_creates_unverified_user_and_token(client, db_session):
    client.post("/auth/signup", json={"email": "verify@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    user = db_session.query(User).filter(User.email == "verify@example.com").first()
    assert user.is_verified is False
    token_row = db_session.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id).first()
    assert token_row is not None
    assert token_row.is_used is False

def test_unverified_user_can_still_login(client):
    client.post("/auth/signup", json={"email": "loginunverified@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    response = client.post("/auth/login", json={"email": "loginunverified@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    assert response.status_code == 200

def test_verify_email_with_valid_token(client, db_session, capsys):
    client.post("/auth/signup", json={"email": "verifyflow@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    captured = capsys.readouterr()
    token = captured.out.split("token=")[1].split()[0].strip()

    response = client.get(f"/auth/verify-email?token={token}")
    assert response.status_code == 200

    user = db_session.query(User).filter(User.email == "verifyflow@example.com").first()
    assert user.is_verified is True

def test_verify_email_rejects_reused_token(client, capsys):
    client.post("/auth/signup", json={"email": "reuse@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    captured = capsys.readouterr()
    token = captured.out.split("token=")[1].split()[0].strip()

    client.get(f"/auth/verify-email?token={token}")
    response = client.get(f"/auth/verify-email?token={token}")
    assert response.status_code == 400

def test_verify_email_rejects_garbage_token(client):
    response = client.get("/auth/verify-email?token=not-a-real-token")
    assert response.status_code == 400

def test_resend_verification_generic_response(client):
    r1 = client.post("/auth/resend-verification", json={"email": "doesnotexist@example.com"})
    client.post("/auth/signup", json={"email": "resend@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    r2 = client.post("/auth/resend-verification", json={"email": "resend@example.com"})
    assert r1.json()["message"] == r2.json()["message"]