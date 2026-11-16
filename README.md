# Auth API

A reusable authentication and authorization API built with **Python, FastAPI, PostgreSQL, and Redis**.

I built this project to explore how production-oriented authentication systems work, with a focus on security, maintainability, and practical backend engineering.

It implements authentication, authorization, token management, MFA, OAuth, session management, rate limiting, and security audit logging.

## Features

### Authentication and account management
- User registration and login.
- Argon2 password hashing.
- JWT access tokens using RS256 asymmetric signing.
- Refresh-token rotation with hashed token storage.
- Access-token invalidation using per-user token validity timestamps.
- Email verification with partial-access support.
- Password reset via email.
- Password breach detection using Have I Been Pwned.

### Multi-factor authentication
- TOTP-based MFA.
- QR-code provisioning.
- Single-use recovery codes.
- MFA setup, verification, and disablement.
- MFA challenge tokens during login.

### OAuth
- Google OAuth 2.0 authentication.
- OAuth CSRF protection using short-lived, single-use Redis state tokens.
- Account linking using verified email addresses.

### Authorization and session management
- Role-based access control (RBAC).
- Admin and user roles.
- Individual session listing and revocation.
- Global session revocation.
- Security-related audit logging.

### API protection
- Redis-backed rate limiting.
- Protected routes using authentication dependencies.
- Email verification requirements for sensitive operations.
- Password hashing and token hashing.
- Access-token invalidation following security-sensitive account changes.

## Technology stack

| Technology | Purpose |
|---|---|
| Python | Backend language |
| FastAPI | REST API framework |
| PostgreSQL | Relational database |
| SQLAlchemy | ORM and database access |
| Redis | Rate limiting and temporary OAuth state |
| Pydantic | Request validation and serialization |
| Argon2 | Password hashing |
| JWT / RS256 | Access-token authentication |
| Resend | Transactional email delivery |
| Google OAuth 2.0 | Third-party authentication |
| pytest | Automated testing |
| Docker | Application containerization |

## Architecture

The application follows a modular structure, separating API routes, business logic, database models, schemas, and shared security functionality.

```text
Client
  |
  v
FastAPI Application
  |
  +---- Authentication Router
  |       |
  |       +---- Registration / Login
  |       +---- JWT / Refresh Tokens
  |       +---- MFA
  |       +---- Google OAuth
  |       +---- Password Reset
  |
  +---- Users Router
  |       |
  |       +---- User Profile
  |
  +---- Admin Router
  |       |
  |       +---- User Management
  |       +---- Role Management
  |
  +---- Core Services
  |       |
  |       +---- Security Utilities
  |       +---- Email Services
  |       +---- Redis Services
  |
  +---- PostgreSQL
  |
  +---- Redis
```

### Project structure

```text
auth_api/
|
+-- app/
|   |
|   +-- core/
|   |   +-- security.py
|   |   +-- redis_client.py
|   |   +-- emails.py
|   |   +-- dependencies.py
|   |
|   +-- models/
|   |   +-- SQLAlchemy database models
|   |
|   +-- schemas/
|   |   +-- Pydantic schemas
|   |
|   +-- routers/
|   |   +-- auth.py
|   |   +-- users.py
|   |   +-- admin.py
|   |
|   +-- config.py
|   +-- database.py
|   +-- main.py
|
+-- tests/
|
+-- keys/
|
+-- docker-compose.yml
+-- Dockerfile
+-- .env.example
+-- README.md
```

## Getting started

### Prerequisites

- Docker and Docker Compose.
- Python (for running tests locally).
- A Resend API key.
- Google OAuth Client ID and Client Secret.
- OpenSSL for generating RSA keys.

### 1. Clone the repository

```bash
git clone https://github.com/motolaniob/auth_api.git

cd auth_api
```

### 2. Generate RSA signing keys

The API uses RS256 for JWT signing, requiring a private and public RSA key pair.

```bash
mkdir -p keys

openssl genrsa -out keys/private_key.pem 2048

openssl rsa \
  -in keys/private_key.pem \
  -pubout \
  -out keys/public_key.pem
```

The private and public keys are excluded from version control. Never commit private signing keys.

### 3. Configure environment variables

Create your environment file:

```bash
cp .env.example .env
```

Configure the following variables:

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection URL |
| `TEST_DATABASE_URL` | Test database connection URL |
| `POSTGRES_USER` | PostgreSQL username |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `POSTGRES_DB` | PostgreSQL database name |
| `REDIS_URL` | Redis connection URL |
| `DEBUG_MODE` | Application debug configuration |
| `APP_BASE_URL` | Base application URL |
| `KEYS_DIRECTORY` | Directory containing RSA signing keys |
| `RESEND_API_KEY` | Resend API key |
| `RESEND_EMAIL_ADDRESS` | Sender email address |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | Google OAuth callback URL |

For local development, the default callback URL is:

```text
http://localhost:8000/auth/oauth/google/callback
```

Make sure the same callback URL is configured in your Google Cloud OAuth client.

Never commit your actual `.env` file or production credentials.

### 4. Start the application

```bash
docker compose up --build
```

Docker Compose starts the API, PostgreSQL, and Redis services.

The application seeds the default admin and user roles during startup when they are missing.

Once running:

- API: http://localhost:8000
- Interactive Swagger documentation: http://localhost:8000/docs
- ReDoc documentation: http://localhost:8000/redoc
- Health check: http://localhost:8000/health

## API endpoints

All endpoints are grouped by router prefix.

### Authentication (`/auth`)

| Method | Endpoint | Description |
|---|---|---|
| POST | `/signup` | Register a new user |
| POST | `/login` | Authenticate a user |
| POST | `/refresh` | Rotate refresh tokens |
| POST | `/logout` | Revoke a refresh token |
| GET | `/verify-email` | Verify email address |
| POST | `/resend-verification` | Resend verification email |
| POST | `/forgot-password` | Request password reset |
| GET | `/reset-password` | Display password reset form |
| POST | `/reset-password` | Set a new password |
| POST | `/mfa/setup` | Initiate MFA setup |
| POST | `/mfa/verify-setup` | Verify MFA configuration |
| POST | `/mfa/disable` | Disable MFA |
| POST | `/mfa/login-verify` | Complete MFA login |

### Google OAuth (`/auth`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/oauth/google/login` | Initiate Google OAuth |
| GET | `/oauth/google/callback` | Handle Google OAuth callback |

### User endpoints (`/users`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/me` | Retrieve authenticated user profile |

### Session management (`/auth`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/me/sessions` | List active sessions |
| DELETE | `/me/sessions/{session_id}` | Revoke an individual session |
| DELETE | `/me/sessions` | Revoke all sessions |

### Admin endpoints (`/admin`)

These endpoints require administrator authorization.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/users` | List users |
| PATCH | `/users/{user_id}/roles` | Update user roles |
| POST | `/users/{user_id}/mfa/disable` | Disable MFA for a user |

For request schemas, response formats, and interactive API exploration, visit `/docs`.

## Security considerations

### Password security
Passwords are hashed using Argon2 rather than stored in plaintext.

New passwords are also checked against the Have I Been Pwned password database using its range-based API.

### JWT authentication
The API uses RS256 asymmetric signing.

The private key is used to issue tokens, while the public key is used for verification.

### Refresh-token security
Refresh tokens are opaque values stored as SHA-256 hashes rather than plaintext.

Tokens are rotated when refreshed, and revoked or expired refresh tokens are rejected.

### MFA
MFA uses time-based one-time passwords (TOTP), with single-use recovery codes for account recovery.

MFA challenge tokens are restricted to the MFA verification flow and cannot be used as normal authenticated access tokens.

### Access-token invalidation
A per-user `tokens_valid_after` timestamp allows previously issued access tokens to be invalidated following sensitive account operations, including password resets and role changes.

### OAuth protection
Google OAuth uses short-lived, single-use state tokens stored in Redis to protect against cross-site request forgery.

### Rate limiting
Redis-backed rate limiting helps protect public endpoints against brute-force attempts and excessive requests.

## Running tests

The project uses pytest with an isolated test database.

External integrations, including Google OAuth, email delivery, and Have I Been Pwned, are mocked during testing.

Run the test suite:

```bash
pytest
```

Tests use the configured `TEST_DATABASE_URL` rather than the normal application database.

## Future improvements

Potential areas for further development include:

- Expanded security and integration test coverage.
- Improved observability and structured logging.
- Performance and concurrency testing.
- Further hardening of authentication and session-management workflows.
- Automated CI checks for linting, formatting, and test execution.

## License

Available for reference and educational purposes.
