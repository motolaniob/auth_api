# Auth API

I built this to learn how production-grade authentication works. It's a full auth service built with FastAPI, PostgreSQL, and Redis, covering the stuff most tutorials skip: asymmetric JWT signing, refresh token rotation, MFA, OAuth, rate limiting, audit logging, session management.

## What it does

- Signup / login / logout with Argon2 password hashing
- JWT access tokens (RS256, asymmetric signing), short-lived
- Refresh token rotation. Tokens are opaque, hashed at rest, rotated on every use. Reusing a revoked token is treated as a signal of theft
- Email verification via Resend, with a partial-access model. Unverified users can still log in, but sensitive routes require verification
- Password reset via emailed link, with a minimal server-rendered form so it works without a separate frontend
- MFA (TOTP) with single-use recovery codes for account recovery
- Google OAuth login, with automatic account linking by verified email
- Role-based access control (admin/user roles embedded in the JWT)
- Session management. List and revoke individual sessions or everything at once
- Rate limiting (Redis-backed) on every public, unauthenticated endpoint
- Audit logging on security-relevant events: logins, password resets, role changes, MFA changes, OAuth logins
- Have I Been Pwned check to reject breached passwords at signup

## Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL via SQLAlchemy
- **Redis**: rate limiting, OAuth state, ephemeral stuff
- **Password hashing**: Argon2 (argon2-cffi)
- **JWT**: RS256, see the security notes below for why
- **Email**: Resend
- **Testing**: pytest, fully isolated test database, external services (Google OAuth, email, HIBP) mocked
- **Containers**: Docker & Docker Compose

## Running it

### You'll need

- Docker and Docker Compose
- A Resend API key
- A Google OAuth Client ID and Secret
- An RSA key pair for JWT signing

### 1. Clone it

```bash
git clone https://github.com/motolaniob/auth_api.git
cd auth_api
```

### 2. Generate the JWT signing keys

RS256 needs an RSA key pair:

```bash
mkdir -p keys
openssl genrsa -out keys/private_key.pem 2048
openssl rsa -in keys/private_key.pem -pubout -out keys/public_key.pem
```

These are gitignored, don't commit them.

### 3. Set up your env vars

```bash
cp .env.example .env
```

Then fill it in. See `.env.example` for the full list, database credentials, Redis URL, Resend key, Google OAuth credentials, key directory path, base app URL.

### 4. Run it

```bash
docker compose up --build
```

This spins up the API, Postgres, and Redis. On first boot, the app seeds the base admin/user roles automatically (idempotent, safe to run again).

API's at `http://localhost:8000`, docs at `http://localhost:8000/docs`.

### 5. Run the tests

```bash
pytest
```

Tests run against their own isolated database (`auth_db_test`), created automatically. External services are all mocked, nothing real gets called during a test run.

## Routes

Prefixed by their router.

### Auth (`/auth`)

| Method | Path | What it does                                        |
|---|---|-----------------------------------------------------|
| POST | `/signup` | Create an account                                   |
| POST | `/login` | Log in (returns tokens, or an MFA challenge)        |
| POST | `/refresh` | Exchange a refresh token for a new pair             |
| POST | `/logout` | Revoke one refresh token                            |
| GET | `/verify-email` | Verify email via the token on the verification email |
| POST | `/resend-verification` | Resend the verification email                       |
| POST | `/forgot-password` | Request a password reset email                      |
| GET | `/reset-password` | Server-rendered password reset form                 |
| POST | `/reset-password` | Actually set the new password                       |
| POST | `/mfa/setup` | Start MFA setup (secret, QR URL, recovery codes)    |
| POST | `/mfa/verify-setup` | Confirm setup with a TOTP code                      |
| POST | `/mfa/disable` | Turn MFA off (needs a valid TOTP code)              |
| POST | `/mfa/login-verify` | Finish login when MFA is required                   |
| GET | `/oauth/google/login` | Kicks off Google OAuth                              |
| GET | `/oauth/google/callback` | Google's redirect lands here                        |
| GET | `/me/sessions` | List active sessions                                |
| DELETE | `/me/sessions/{session_id}` | Revoke one session                                  |
| DELETE | `/me/sessions` | Revoke everything, log out everywhere               |

### Users (`/users`)

| Method | Path | What it does |
|---|---|---|
| GET | `/me` | Get the current user |

### Admin (`/admin`), requires the admin role

| Method | Path | What it does |
|---|---|---|
| GET | `/users` | List every user |
| PATCH | `/users/{user_id}/roles` | Change a user's roles |
| POST | `/users/{user_id}/mfa/disable` | Disable a user's MFA for them |

Full schemas are in the interactive docs at `/docs`.

## Security Notes

- **Passwords** are hashed with Argon2 and checked against Have I Been Pwned at signup.
- **Refresh tokens** are never stored as plaintext, only a SHA-256 hash. They rotate on every use, so if a stolen token ever gets reused after the legitimate one already rotated it, that's a clear signal something's wrong.
- **Access tokens** use RS256 on purpose. Only this service holds the private key to issue tokens, but anything with the public key can verify them without being able to forge new ones.
- **`tokens_valid_after`** is a per-user timestamp I check on every request. It lets me instantly invalidate every access token a user has out there (used on password reset and role changes) without needing to maintain a token blacklist.
- **Rate limiting** sits on every public endpoint to slow down credential stuffing and abuse.
- **OAuth CSRF protection**: the Google flow uses a short-lived, single-use state token in Redis so the callback can't be forged.

## Layout

```
app/
├── core/
│   ├── security.py       # hashing, JWT, token generation, audit logging
│   ├── redis_client.py   # rate limiting, OAuth state
│   ├── emails.py         # transactional email
│   └── dependencies.py   # auth/authorization dependencies
├── models/                # SQLAlchemy models
├── schemas/               # Pydantic schemas
├── routers/
│   ├── auth.py
│   ├── users.py
│   └── admin.py
├── config.py
├── database.py
└── main.py                # entry point, router wiring, startup seeding
tests/
```

## License

Available for reference and educational purposes.