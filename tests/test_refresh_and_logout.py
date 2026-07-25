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