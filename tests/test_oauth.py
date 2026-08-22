from app.models.users import User
from app.models.oauth_accounts import OAuthAccount
from urllib.parse import urlparse, parse_qs


def test_new_google_oauth_user_logs_in(client, db_session, mock_google_oauth,mock_consume_oauth_states):
    email = "new_user_oauth@example.com"
    sub = "google-new-111"
    mock_google_oauth(email= email, sub = sub)
    response = client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    assert response.status_code == 200
    user = db_session.query(User).filter(User.email == email).first()
    assert user is not None
    oauth_user = db_session.query(OAuthAccount).filter(OAuthAccount.user_id == user.id).first()
    assert oauth_user is not None

def test_unverified_user_logs_in(client, db_session,mock_google_oauth,mock_consume_oauth_states):
    mock_google_oauth(email_verified = False)
    response = client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    assert response.status_code == 400

def test_returning_oauth_user_logs_in(client, db_session,mock_google_oauth,mock_consume_oauth_states):
    email = "returning_oauth_user@example.com"
    sub = "google-existing-456"
    user = User(email = email)
    db_session.add(user)
    db_session.commit()
    user = db_session.query(User).filter(User.email == email).first()
    user_id = user.id
    db_session.add(OAuthAccount(user_id=user_id,provider = "google", provider_user_id = sub))
    db_session.commit()
    mock_google_oauth(email=email,sub=sub)
    response = client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    assert response.status_code == 200
    user = db_session.query(User).filter(User.email == email).all()
    assert len(user) == 1
    assert user[0].id == user_id
    oauth_user = db_session.query(OAuthAccount).filter(OAuthAccount.user_id == user_id).all()
    assert len(oauth_user) == 1

def test_returning_non_oauth_user_logs_in(client, db_session,mock_google_oauth,mock_consume_oauth_states):
    email = "returning_user@example.com"
    sub = "google-first_time_oauth-456"
    user = User(email = email)
    db_session.add(user)
    db_session.commit()
    user = db_session.query(User).filter(User.email == email).first()
    user_id = user.id
    mock_google_oauth(email=email,sub=sub)
    response = client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    assert response.status_code == 200
    user = db_session.query(User).filter(User.email == email).all()
    assert len(user) == 1
    assert user[0].id == user_id
    oauth_user = db_session.query(OAuthAccount).filter(OAuthAccount.user_id == user_id).all()
    assert len(oauth_user) == 1

def test_invalid_state_rejected(client, db_session,mock_google_oauth):
    mock_google_oauth()
    response = client.get("/auth/oauth/google/callback?code=test-code?state=invalid-state")
    assert response.status_code == 400

def test_reused_state_rejected(client, db_session,mock_google_oauth):
    response = client.get("/auth/oauth/google/login", follow_redirects=False)
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    mock_google_oauth()
    response = client.get(f"/auth/oauth/google/callback?code=test-code&state={state}")
    assert response.status_code == 200
    response = client.get(f"/auth/oauth/google/callback?code=test-code&state={state}")
    assert response.status_code == 400

def test_google_token_exchange_failure(client, db_session,mock_consume_oauth_states,mock_google_token_exchange_failure):
    response = client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    assert response.status_code == 400