import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from app.database import Base, get_db
from app.config import settings
from app.main import app
from app.models.role import Role
from unittest.mock import patch
engine = create_engine(settings.test_database_url)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

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
    """Prevent every test from hitting the real HIBP API — always report 'not breached'."""
    with patch("app.core.security.check_password_breach", return_value=0):
        yield

@pytest.fixture(autouse=True)
def mock_hibp_check():
    with patch("app.schemas.user.check_password_breach", return_value=0):
        yield