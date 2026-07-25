def test_users_me_requires_token(client):
    response = client.get("/users/me")
    assert response.status_code == 401

def test_users_me_with_valid_token(client):
    client.post("/auth/signup", json={"email": "me@example.com", "password": "supersecretpassword123"})
    tokens = client.post("/auth/login", json={"email": "me@example.com", "password": "supersecretpassword123"}).json()
    response = client.get("/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert response.status_code == 200
    assert response.json()["email"] == "me@example.com"

def test_users_me_with_garbage_token(client):
    response = client.get("/users/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401