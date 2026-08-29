from app.models.users import User
from app.models.role import Role

def _signup_and_login(client, email="refresh@example.com", password="supersecretpassword123"):
    client.post("/auth/signup", json={"email": email, "password": password})
    return client.post("/auth/login", json={"email": email, "password": password}).json()

def test_refresh_rotates_token(client):
    tokens = _signup_and_login(client)
    response = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 200
    new_tokens = response.json()
    assert new_tokens["refresh_token"] != tokens["refresh_token"]

def test_old_refresh_token_rejected_after_rotation(client):
    tokens = _signup_and_login(client)
    client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    # reuse the now-revoked original token
    response = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 401

def test_logout_revokes_refresh_token(client):
    tokens = _signup_and_login(client)
    logout_response = client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert logout_response.status_code == 204
    refresh_response = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh_response.status_code == 401

def test_refresh_token_preserves_roles(client, db_session):
    # Sign up and promote to admin so we can hit a role-gated route
    signup_response = client.post("/auth/signup", json={"email": "refreshroles@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    user = db_session.query(User).filter(User.email == "refreshroles@example.com").first()
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    user.roles.append(admin_role)
    db_session.commit()

    login_response = client.post("/auth/login", json={"email": "refreshroles@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    refresh_token = login_response.json()["refresh_token"]

    refresh_response = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_response.status_code == 200
    new_access_token = refresh_response.json()["access_token"]

    # Use the NEW access token against an admin-only route
    admin_response = client.get("/admin/users", headers={"Authorization": f"Bearer {new_access_token}"})
    assert admin_response.status_code == 200