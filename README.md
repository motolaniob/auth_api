# Auth API

A full-featured authentication API built with FastAPI, PostgreSQL, and Redis. Built as a portfolio project to demonstrate production-grade authentication patterns: JWT with asymmetric signing, refresh token rotation, MFA, OAuth, rate limiting, audit logging, and session management.

## Features

- **Signup / Login / Logout** with Argon2 password hashing
- **JWT access tokens** (RS256, asymmetric signing) with short-lived expiry
- **Refresh token rotation** — tokens are opaque, hashed at rest, and rotated on every use; reuse of a revoked token signals possible theft
- **Email verification** via [Resend](https://resend.com), with a partial-access model (unverified users can log in, but sensitive routes require verification)
- **Password reset** via emailed link, with a minimal server-rendered confirmation form
- **Multi-factor authentication (TOTP)** with single-use recovery codes for account recovery
- **Google OAuth login**, with automatic account linking by verified email
- **Role-based access control** (admin/user roles embedded in the JWT)
- **Session management** — list and revoke individual sessions or all sessions at once
- **Rate limiting** (Redis-backed) on all public, unauthenticated endpoints
- **Audit logging** of security-relevant events (logins, password resets, role changes, MFA changes, OAuth logins)
- **Have I Been Pwned** integration to reject breached passwords at signup

## Tech Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL (via SQLAlchemy ORM)
- **Cache / Rate limiting / Ephemeral state**: Redis
- **Password hashing**: Argon2 (`argon2-cffi`)
- **JWT**: RS256 (asymmetric — see [Security Notes](#security-notes))
- **Email delivery**: Resend
- **Testing**: pytest, with a fully isolated test database and mocked external services (Google OAuth, email sending, HIBP)
- **Containerization**: Docker & Docker Compose

## Getting Started

### Prerequisites

- Docker and Docker Compose
- A [Resend](https://resend.com) API key (for sending verification/reset emails)
- A [Google OAuth Client ID and Secret](https://console.cloud.google.com/apis/credentials) (for Google login)
- An RSA key pair for JWT signing (see below)

### 1. Clone the repo

```bash
git clone https://github.com/motolaniob/auth_api.git
cd auth_api
```

### 2. Generate JWT signing keys

The API signs access tokens with RS256, which requires an RSA private/public key pair:

```bash
mkdir -p keys
openssl genrsa -out keys/private_key.pem 2048
openssl rsa -in keys/private_key.pem -pubout -out keys/public_key.pem
```

These files are gitignored — never commit them.

### 3. Configure environment variables

Copy the example env file and fill in your own values:

```bash
cp .env.example .env
```

See [`.env.example`](.env.example) for the full list of required variables (database credentials, Redis URL, Resend API key, Google OAuth credentials, key directory path, and base app URL).

### 4. Run with Docker Compose

```bash
docker compose up --build
```

This starts three services: the API, PostgreSQL, and Redis. On first boot, the app automatically seeds the base `admin` and `user` roles (idempotent — safe to run repeatedly).

The API will be available at `http://localhost:8000`. Interactive API docs (Swagger UI) are at `http://localhost:8000/docs`.

### 5. Run tests

```bash
pytest
```

Tests run against a fully isolated test database (`auth_db_test`), created automatically if it doesn't exist. External services (Google OAuth, Resend, Have I Been Pwned) are mocked — no real API calls are made during testing.

## API Overview

All routes are prefixed by their router tag.

### Auth (`/auth`)

| Method | Path | Description |
|---|---|---|
| POST | `/signup` | Create a new account |
| POST | `/login` | Log in with email/password (returns tokens, or an MFA challenge) |
| POST | `/refresh` | Exchange a refresh token for a new token pair |
| POST | `/logout` | Revoke a single refresh token |
| GET | `/verify-email` | Verify an email address via emailed token |
| POST | `/resend-verification` | Resend the verification email |
| POST | `/forgot-password` | Request a password reset email |
| GET | `/reset-password` | Server-rendered password reset form |
| POST | `/reset-password` | Submit a new password with a valid reset token |
| POST | `/mfa/setup` | Begin MFA setup (returns secret, QR provisioning URL, recovery codes) |
| POST | `/mfa/verify-setup` | Confirm MFA setup with a valid TOTP code |
| POST | `/mfa/disable` | Disable MFA (requires a valid TOTP code) |
| POST | `/mfa/login-verify` | Complete login when MFA is required |
| GET | `/oauth/google/login` | Start Google OAuth flow |
| GET | `/oauth/google/callback` | Google OAuth callback (handled automatically by Google's redirect) |
| GET | `/me/sessions` | List active sessions |
| DELETE | `/me/sessions/{session_id}` | Revoke a single session |
| DELETE | `/me/sessions` | Revoke all sessions ("log out everywhere") |

### Users (`/users`)

| Method | Path | Description |
|---|---|---|
| GET | `/me` | Get the current authenticated user |

### Admin (`/admin`) — requires the `admin` role

| Method | Path | Description |
|---|---|---|
| GET | `/users` | List all users |
| PATCH | `/users/{user_id}/roles` | Update a user's roles |
| POST | `/users/{user_id}/mfa/disable` | Disable a user's MFA (account recovery) |

Full request/response schemas are available in the interactive docs at `/docs`.

## Security Notes

- **Passwords** are hashed with Argon2 and checked against the Have I Been Pwned breach database at signup.
- **Refresh tokens** are never stored in plaintext — only a SHA-256 hash is persisted. They're rotated on every use, so reuse of an already-rotated token is a signal of theft.
- **Access tokens** use RS256 (asymmetric signing): only this service holds the private key needed to issue tokens, while any service with the public key can verify them without being able to forge new ones.
- **`tokens_valid_after`** is a per-user timestamp checked on every request, allowing instant invalidation of all previously issued access tokens (used on password reset and role changes) without needing a token blacklist.
- **Rate limiting** is applied to every public, unauthenticated endpoint to mitigate credential stuffing and abuse.
- **OAuth CSRF protection**: the Google OAuth flow uses a short-lived, single-use state token stored in Redis to prevent CSRF attacks against the callback.

## Project Structure

```
app/
├── core/
│   ├── security.py       # Password hashing, JWT, token generation, audit logging
│   ├── redis_client.py   # Rate limiting, OAuth state storage
│   ├── emails.py         # Transactional email sending
│   └── dependencies.py   # Auth/authorization FastAPI dependencies
├── models/                # SQLAlchemy models
├── schemas/               # Pydantic request/response schemas
├── routers/
│   ├── auth.py            # Authentication routes
│   ├── users.py           # User self-service routes
│   └── admin.py           # Admin-only routes
├── config.py              # Environment-based settings
├── database.py            # SQLAlchemy engine/session setup
└── main.py                # App entry point, router wiring, startup seeding
tests/                      # pytest test suite
```

## License

This project is available for reference and educational purposes.