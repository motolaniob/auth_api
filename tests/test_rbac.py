from app.models.users import User
from app.models.role import Role

def test_non_admin_blocked_from_admin_route(client):
    client.post("/auth/signup", json={"email": "regular@example.com", "password": "supersecretpassword123"})
    tokens = client.post("/auth/login", json={"email": "regular@example.com", "password": "supersecretpassword123"}).json()
    response = client.get("/admin/users", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert response.status_code == 403

def test_admin_can_access_admin_route(client, db_session):
    client.post("/auth/signup", json={"email": "admin@example.com", "password": "supersecretpassword123"})
    user = db_session.query(User).filter(User.email == "admin@example.com").first()
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    user.roles.append(admin_role)
    db_session.commit()

    tokens = client.post("/auth/login", json={"email": "admin@example.com", "password": "supersecretpassword123"}).json()
    response = client.get("/admin/users", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert response.status_code == 200