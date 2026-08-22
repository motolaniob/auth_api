def test_sign_up_is_rate_limited(client):
    email = "ratelimit@signup.com"
    for _ in range(5):
        client.post("/auth/signup", json={"email": email, "password": "Xk9$mQ2vL8pT4wZ1"})
    response = client.post("/auth/signup", json={"email": email, "password": "Xk9$mQ2vL8pT4wZ1"})
    assert response.status_code == 429

def test_login_is_rate_limited(client):
    client.post("/auth/signup", json={"email": "login@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    for _ in range(5):
        client.post("/auth/login", json={"email": "login@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    response = client.post("/auth/login", json={"email": "login@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    assert response.status_code == 429

def test_resend_verification_is_rate_limited(client):
    for _ in range(5):
        client.post("/auth/resend-verification", json={"email": "doesnotexist@example.com"})
    response = client.post("/auth/resend-verification", json={"email": "doesnotexist@example.com"})
    assert response.status_code == 429

def test_oauth_callback_is_rate_limited(client, db_session, mock_google_oauth,mock_consume_oauth_states):
    email = "new_user_oauth@example.com"
    sub = "google-new-111"
    mock_google_oauth(email=email, sub=sub)
    for _ in range(5):
        client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    response = client.get("/auth/oauth/google/callback?code=test-code&state=valid-state")
    assert response.status_code == 429

def test_forgot_password_is_rate_limited(client):
    client.post("/auth/signup", json={"email": "resetme@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    for _ in range(5):
        client.post("/auth/forgot-password", json={"email": "forgotpassword@ratelimit.com"})
    response = client.post("/auth/forgot-password", json={"email": "forgotpassword@ratelimit.com"})
    assert response.status_code == 429