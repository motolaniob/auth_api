def test_signup_creates_user(client):
    response = client.post("/auth/signup", json={"email": "test@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    print("RESPONSE BODY:", response.json())
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "hashed_password" not in data  # never leaked

def test_signup_duplicate_email_fails(client):
    client.post("/auth/signup", json={"email": "dup@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    response = client.post("/auth/signup", json={"email": "dup@example.com", "password": "anotherpassword123"})
    assert response.status_code == 400

def test_login_success_returns_tokens(client):
    client.post("/auth/signup", json={"email": "login@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    response = client.post("/auth/login", json={"email": "login@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

def test_login_wrong_password_fails(client):
    client.post("/auth/signup", json={"email": "wrongpw@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    response = client.post("/auth/login", json={"email": "wrongpw@example.com", "password": "wrongpassword"})
    assert response.status_code == 401

def test_login_nonexistent_email_gives_same_error_as_wrong_password(client):
    r1 = client.post("/auth/login", json={"email": "ghost@example.com", "password": "whatever12345"})
    client.post("/auth/signup", json={"email": "real@example.com", "password": "correctpassword123"})
    r2 = client.post("/auth/login", json={"email": "real@example.com", "password": "wrongpassword"})
    assert r1.status_code == r2.status_code == 401
    assert r1.json()["detail"] == r2.json()["detail"]  # proves no enumeration leak