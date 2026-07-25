# Auth API

A standalone, full-featured authentication API — built to be plugged into any application instead of building auth from scratch. 

## Stack
- **FastAPI** — REST framework
- **PostgreSQL** — primary datastore (via SQLAlchemy + Alembic migrations)
- **Redis** — planned for rate limiting and audit logging (not yet wired in)
- **Docker Compose** — Postgres + Redis running locally
- **Argon2** — password hashing
- **JWT (RS256)** — access tokens
- **pytest** — testing

## Features implemented so far

### Authentication
- `POST /auth/signup` — create an account (email + password)
  - Password requires a minimum length (NIST 800-63B guidance — no forced character-class rules)
  - Checked against the Have I Been Pwned breach database via k-anonymity (only a partial hash prefix is ever sent externally)
  - Password stored as an Argon2 hash — never in plaintext
- `POST /auth/login` — authenticate, receive an access token + refresh token
  - Returns an identical, generic error for both "no such account" and "wrong password," to prevent attackers from enumerating registered emails
- `POST /auth/refresh` — exchange a valid refresh token for a new access + refresh token pair
  - Refresh tokens rotate on every use — the old one is immediately revoked
- `POST /auth/logout` — revoke a refresh token, ending that session's ability to silently renew

### Authorization (RBAC)
- Users are assigned a role (`user` by default) at signup via a proper many-to-many `User`↔`Role` relationship
- Roles are embedded directly in the JWT payload
- `GET /admin/users` — admin-only, lists all users
- `PATCH /admin/users/{user_id}/roles` — admin-only, changes a user's roles and forces re-authentication by revoking their existing refresh tokens

### Route protection
- `GET /users/me` — returns the authenticated user's profile; requires a valid bearer access token

## Design decisions worth knowing

- **UUID primary keys**, not auto-incrementing integers — avoids ID enumeration attacks
- **Access tokens are stateless JWTs signed with RS256** — the private key signs, the public key verifies, allowing other services to validate tokens without holding the signing secret
- **Refresh tokens are opaque random strings, stored server-side only as a hash** — never as plaintext, so a database leak alone doesn't expose usable tokens
- **Roles are embedded in the access token** rather than looked up fresh on every request. This is faster (no extra DB query per request) but means a role change doesn't take effect until the user's current access token expires (≤15 min) or they re-authenticate. Changing a user's roles via the admin endpoint mitigates this by revoking their refresh tokens, forcing a fresh login that picks up the new roles — but the *current* access token remains valid for its remaining lifetime. A Redis-backed token blacklist (planned) would close this gap for instant revocation.
- **Generic, identical error messages** across all authentication failure paths (login, token validation) — deliberately avoids leaking *why* an attempt failed.

## Known limitations (by design, for now)
- Logout/role changes don't instantly invalidate an already-issued access token — only refresh tokens are revoked immediately. See above.
- No rate limiting yet on auth endpoints (planned, Redis-backed).
- No email verification or password reset flow yet.
- No MFA or OAuth social login yet.

## Project status
Core auth (signup, login, refresh rotation, logout, route protection, RBAC) is complete and manually verified end-to-end, including direct database inspection. Automated test coverage for the full endpoint surface (Steps 3–6) is in progress.

 