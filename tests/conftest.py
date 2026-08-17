import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from app.database import Base, get_db
from app.config import settings
from app.main import app
from app.models.role import Role
from unittest.mock import patch
from app.core.redis_client import redis_client


main_db = settings.database_url
temp_engine = create_engine(main_db)
with temp_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
    db_name = "auth_db_test"
    exists = conn.execute(
        text("SELECT 1 FROM pg_database WHERE datname = :name"),{"name":db_name},).scalar()
    if not exists:
        conn.execute(text(f'CREATE DATABASE "{db_name}"'))

engine = create_engine(settings.test_database_url)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(autouse=True)
def flush_redis():
    redis_client.flushdb()
    yield
    redis_client.flushdb()

@pytest.fixture(scope = "function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    # Seed roles for RBAC tests
    session.add_all([Role(name="user", description="Standard user"), Role(name="admin", description="Administrator")])
    session.commit()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope = "function")
def client(db_session):
    def override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()

@pytest.fixture(autouse=True)
def mock_hibp_check():
    with patch("app.schemas.user.check_password_breach", return_value=0):
        yield

@pytest.fixture(autouse=True)
def captured_verification_email():
    sent = {}
    def fake_send(email, verification_token):
        sent["email"] = email
        sent["token"] = verification_token
    with patch("app.routers.auth.send_verification_email", side_effect=fake_send):
        yield sent

@pytest.fixture(autouse=True)
def captured_reset_email():
    sent = {}
    def fake_send(email, reset_token):
        sent["email"] = email
        sent["token"] = reset_token
    with patch("app.routers.auth.send_password_reset_email", side_effect=fake_send):
        yield sent

@pytest.fixture()
def mock_google_oauth():
    with patch("app.routers.auth.requests.post") as mock_post, patch("app.routers.auth.requests.get") as mock_get:
        def _configure(email = "test@example.com",sub = "google-123", email_verified = True):
            mock_post.return_value.json.return_value = {"access_token": "fake_access_token"}
            mock_get.return_value.json.return_value = {"email": email, "sub": sub, "email_verified": email_verified}
            return mock_post, mock_get
        yield _configure

@pytest.fixture()
def mock_consume_oauth_states():
    with patch("app.routers.auth.consume_oauth_state", return_value = True) as mock:
        yield mock