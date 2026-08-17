from app.models import User
from app.models.users import User
from app.models.oauth_accounts import OAuthAccount
from tests.conftest import mock_google_oauth, mock_consume_oauth_states


def test_new_google_oauth_user_logs_in(client, db_session, mock_google_oauth,mock_consume_oauth_states):
    email = "new_user_oauth@example.com"
    sub = "google-new-111"
    mock_google_oauth(email= email, sub = sub)
    mock_consume_oauth_states()
    response = client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    assert response.status_code == 200
    user = db_session.query(User).filter(User.email == email).first()
    assert user is not None
    oauth_user = db_session.query(OAuthAccount).filter(OAuthAccount.user_id == user.id).first()
    assert oauth_user is not None

def test_unverified_user_logs_in(client, db_session,mock_google_oauth,mock_consume_oauth_states):
    mock_google_oauth(email_verified = False)
    mock_consume_oauth_states()
    response = client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    assert response.status_code == 400

def test_returning_oauth_user_logs_in(client, db_session,mock_google_oauth,mock_consume_oauth_states):
    email = "returning_oauth_user"
    db_session.add(OAuthAccount(email = email))
    db_session.add(User(email = email))
    db_session.commit()
    mock_google_oauth(email=email)
    response = client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    assert response.status_code == 200
    user = db_session.query(User).filter(User.email == email).all()
    assert len(user) == 1
    oauth_user = db_session.query(OAuthAccount).filter(OAuthAccount.email == email).all()
    assert len(oauth_user) == 1

