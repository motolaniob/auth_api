# auth_api

A full-featured authentication API built as a portfolio project, demonstrating production-style auth patterns: JWT with asymmetric signing, refresh token rotation, RBAC, email verification, password reset, and (in progress) TOTP-based MFA.

## Tech Stack

- **FastAPI** — API framework
- **PostgreSQL** — primary datastore
- **Redis** — planned for rate limiting and JWT blacklist (see Roadmap)
- **Docker Compose** — local development environment
- **argon2-cffi** — password hashing
- **pydantic-settings** — configuration management

## Features

### Implemented

- **Signup & Login** — Argon2 password hashing, breach-checking against Have I Been Pwned (HIBP) at signup, JWT (RS256) issuance on login
- **Refresh Token Rotation** — `/auth/refresh` and `/auth/logout`, with revocation support and hashed storage of refresh tokens
- **Protected Routes** — `get_current_user` dependency validates JWTs and exposes the authenticated user to route handlers (e.g. `GET /users/me`)
- **Role-Based Access Control (RBAC)** — roles embedded directly in the JWT payload (rather than a fresh DB lookup per request); includes `revoke_all_refresh_tokens` and an admin `update_user_roles` endpoint to limit staleness after a role change
- **Email Verification** — partial-access model: unverified users can still log in, but a `require_verified` dependency gates specific sensitive routes rather than blocking all access
- **Password Reset** — `forgot-password` / `reset-password` flow; resetting a password revokes all existing refresh tokens for that user

### In Progress

- **MFA (TOTP)** — time-based one-time password support via an authenticator app:
  - Enrollment endpoint generates a TOTP secret and provisioning URI/QR code
  - Confirm-enrollment endpoint validates a code before enabling MFA
  - Login flow issues an intermediate "MFA pending" token when MFA is enabled, exchanged for full access/refresh tokens after a valid TOTP code
  - Disable-MFA requires re-verification (TOTP code or password), not a bare toggle
  - Optional: hashed, one-time recovery codes generated at enrollment

## Roadmap

Remaining steps from the original 12-step project plan:

- [ ] **MFA / TOTP** (in progress — see above)
- [ ] **OAuth** — third-party login support
- [ ] **Redis-backed rate limiting**
- [ ] **Session management**
- [ ] **Audit logging**
- [ ] **Redis-backed JWT blacklist** — tracks a `jti` claim per token so that logout, role changes, and password resets can invalidate the current access token instantly, rather than waiting out its ~15-minute expiry (a current limitation, since roles/verification status live in the JWT payload itself)

## Design Notes

- **UUID primary keys** throughout
- **Tokens are stored hashed**, never in plaintext
- **`event_metadata`** column naming (instead of `metadata`) to avoid conflicts with SQLAlchemy's reserved attribute
- **`hashed_password` is nullable** to support OAuth-only users once OAuth is added
- Password hashing uses **argon2-cffi** over passlib (unmaintained) or raw bcrypt

## Testing

Test suite (`pytest`) covers signup/login, refresh/logout, protected routes, and RBAC, with an isolated test database, role-seeding fixtures, and an autouse HIBP mock in `conftest.py`. Tests for email verification and password reset are in progress.

## Local Development

Local environment runs via Docker Compose (Postgres + Redis), with credentials managed through a `.env` file and loaded via a `pydantic-settings` `Settings` class in `app/config.py`.

```bash
docker-compose up -d
# API available at http://localhost:8000/docs
```

## Status

Actively developed as of July 2026. Steps 1–8 of the original project plan are complete; MFA (Step 9) is the current focus, followed by OAuth, rate limiting, session management, audit logging, and the JWT blacklist.