import pyotp
from app.models.users import User
from app.models.role import Role

def _signup_login(client, db_session,email="mfa@example.com", password="Xk9$mQ2vL8pT4wZ1"):
    client.post("/auth/signup", json={"email": email, "password": password})
    user = db_session.query(User).filter(User.email == email).first()
    user.is_verified = True
    db_session.commit()
    login = client.post("/auth/login", json={"email": email, "password": password}).json()
    return login["access_token"]

def test_mfa_setup_returns_secret_and_recovery_codes(client, db_session):
    access_token = _signup_login(client, db_session)
    response = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {access_token}"})
    print(response.json())
    assert response.status_code == 200
    data = response.json()
    assert "secret" in data
    assert len(data["recovery_codes"]) == 8

def test_verify_setup_enables_mfa(client, db_session):
    access_token = _signup_login(client,db_session, email="verifysetup@example.com")
    setup = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {access_token}"}).json()

    valid_code = pyotp.TOTP(setup["secret"]).now()
    response = client.post(
        "/auth/mfa/verify-setup",
        json={"code": valid_code},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200

    user = db_session.query(User).filter(User.email == "verifysetup@example.com").first()
    assert user.mfa_enabled is True

def test_login_with_mfa_enabled_returns_challenge(client,db_session):
    access_token = _signup_login(client,db_session, email="challenge@example.com")
    setup = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {access_token}"}).json()
    valid_code = pyotp.TOTP(setup["secret"]).now()
    client.post("/auth/mfa/verify-setup", json={"code": valid_code}, headers={"Authorization": f"Bearer {access_token}"})

    login_response = client.post("/auth/login", json={"email": "challenge@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    data = login_response.json()
    assert data["mfa_required"] is True
    assert "challenge_token" in data
    assert "access_token" not in data

def test_mfa_login_verify_with_correct_totp(client,db_session):
    access_token = _signup_login(client,db_session, email="loginverify@example.com")
    setup = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {access_token}"}).json()
    valid_code = pyotp.TOTP(setup["secret"]).now()
    client.post("/auth/mfa/verify-setup", json={"code": valid_code}, headers={"Authorization": f"Bearer {access_token}"})

    login_response = client.post("/auth/login", json={"email": "loginverify@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    challenge_token = login_response.json()["challenge_token"]

    second_code = pyotp.TOTP(setup["secret"]).now()
    verify_response = client.post("/auth/mfa/login-verify", json={"challenge_token": challenge_token, "code": second_code})
    assert verify_response.status_code == 200
    assert "access_token" in verify_response.json()

def test_mfa_login_verify_with_wrong_code_fails(client,db_session):
    access_token = _signup_login(client, db_session,email="wrongcode@example.com")
    setup = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {access_token}"}).json()
    valid_code = pyotp.TOTP(setup["secret"]).now()
    client.post("/auth/mfa/verify-setup", json={"code": valid_code}, headers={"Authorization": f"Bearer {access_token}"})

    login_response = client.post("/auth/login", json={"email": "wrongcode@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    challenge_token = login_response.json()["challenge_token"]

    response = client.post("/auth/mfa/login-verify", json={"challenge_token": challenge_token, "code": "000000"})
    assert response.status_code == 400

def test_recovery_code_works_as_fallback_and_is_single_use(client,db_session):
    access_token = _signup_login(client, db_session,email="recovery@example.com")
    setup = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {access_token}"}).json()
    valid_code = pyotp.TOTP(setup["secret"]).now()
    client.post("/auth/mfa/verify-setup", json={"code": valid_code}, headers={"Authorization": f"Bearer {access_token}"})
    recovery_code = setup["recovery_codes"][0]

    login_response = client.post("/auth/login", json={"email": "recovery@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    challenge_token = login_response.json()["challenge_token"]

    response = client.post("/auth/mfa/login-verify", json={"challenge_token": challenge_token, "code": recovery_code})
    assert response.status_code == 200

    # try the same recovery code again on a fresh login attempt
    login_response2 = client.post("/auth/login", json={"email": "recovery@example.com", "password": "Xk9$mQ2vL8pT4wZ1"})
    challenge_token2 = login_response2.json()["challenge_token"]
    reuse_response = client.post("/auth/mfa/login-verify", json={"challenge_token": challenge_token2, "code": recovery_code})
    assert reuse_response.status_code == 400

def test_disable_mfa_requires_valid_code(client, db_session):
    access_token = _signup_login(client,db_session, email="disable@example.com")
    setup = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {access_token}"}).json()
    valid_code = pyotp.TOTP(setup["secret"]).now()
    client.post("/auth/mfa/verify-setup", json={"code": valid_code}, headers={"Authorization": f"Bearer {access_token}"})

    fresh_code = pyotp.TOTP(setup["secret"]).now()
    response = client.post("/auth/mfa/disable", json={"code": fresh_code}, headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200

    user = db_session.query(User).filter(User.email == "disable@example.com").first()
    assert user.mfa_enabled is False

def test_admin_can_force_disable_mfa(client, db_session):
    # target user with MFA enabled
    target_token = _signup_login(client,db_session, email="target@example.com")
    setup = client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {target_token}"}).json()
    valid_code = pyotp.TOTP(setup["secret"]).now()
    client.post("/auth/mfa/verify-setup", json={"code": valid_code}, headers={"Authorization": f"Bearer {target_token}"})

    target_user = db_session.query(User).filter(User.email == "target@example.com").first()

    # promote a separate user to admin
    admin_token_raw = _signup_login(client,db_session, email="admin@example.com")
    admin_user = db_session.query(User).filter(User.email == "admin@example.com").first()
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    admin_user.roles.append(admin_role)
    db_session.commit()
    admin_login = client.post("/auth/login", json={"email": "admin@example.com", "password": "Xk9$mQ2vL8pT4wZ1"}).json()
    admin_access_token = admin_login["access_token"]

    response = client.post(
        f"/admin/users/{target_user.id}/mfa/disable",
        headers={"Authorization": f"Bearer {admin_access_token}"},
    )
    assert response.status_code == 200
    db_session.refresh(target_user)
    assert target_user.mfa_enabled is False