from app.models.users import User
from app.models.audit_logs import AuditLog
from unittest.mock import patch


def test_audit_log_generated_on_signup(client,db_session):
    email = "audit@signup.com"
    client.post("/auth/signup", json={"email":email, "password": "Xk9$mQ2vL8pT4wZ1"})
    user = db_session.query(User).filter(User.email == email).first()
    audit = db_session.query(AuditLog).filter(AuditLog.user_id==user.id, AuditLog.event_type == "signup_successful").first()
    assert audit is not None

def test_audit_log_generated_on_log_in(client,db_session):
    email = "audit@signup.com"
    client.post("/auth/signup", json={"email": email, "password": "Xk9$mQ2vL8pT4wZ1"})
    client.post("/auth/login", json={"email": email, "password": "Xk9$mQ2vL8pT4wZ1"})
    user = db_session.query(User).filter(User.email == email).first()
    audit = db_session.query(AuditLog).filter(AuditLog.user_id==user.id, AuditLog.event_type == "login_successful").first()
    assert audit is not None

def test_audit_log_generated_on_login_failure(client,db_session):
    client.post("/auth/login", json={"email": "invaliduser@login.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    audit = db_session.query(AuditLog).filter(AuditLog.event_type == "login_failed_invalid_user").first()
    assert audit is not None

def test_audit_log_generated_on_oauth_login(client, db_session, mock_google_oauth,mock_consume_oauth_states):
    email = "new_user_oauth@example.com"
    sub = "google-new-111"
    mock_google_oauth(email=email, sub=sub)
    client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    user = db_session.query(User).filter(User.email == email).first()
    audit = db_session.query(AuditLog).filter(AuditLog.user_id == user.id,AuditLog.event_type == "oauth_login").first()
    assert audit is not None
    assert audit.event_metadata == {"provider": "google", "new_account": True}

def test_audit_log_created_on_password_reset(client,db_session):
    email = "audit@reset.com"
    client.post("/auth/signup", json={"email": email, "password": "Xk9$mQ2vL8pT4wZ1"})
    with patch("app.routers.auth.generate_refresh_token", return_value="fixed-token"):
        client.post("/auth/forgot-password", json={"email": email})
    client.post("/auth/reset-password", json={"token": "fixed-token", "new_password": "NewPass$9E4850"})
    user = db_session.query(User).filter(User.email == email).first()
    audit = db_session.query(AuditLog).filter(AuditLog.user_id == user.id, AuditLog.event_type == "reset_password_successful").first()
    assert audit is not None
