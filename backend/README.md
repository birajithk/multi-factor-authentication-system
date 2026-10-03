# SecureByte Backend

Backend for the SecureByte MFA system: registration, password first factor, TOTP second factor, server-side sessions, and a protected demo resource.

## Stack

- Node.js 20+ (ES modules, `"type": "module"`)
- Express 5
- PostgreSQL 16 (`pg`)
- Argon2id password hashing (`argon2`)
- TOTP with `otplib` v13 (SHA-1, 6 digits, 30 s period, current step ± 1)
- AES-256-GCM encryption of stored TOTP secrets
- `cookie-parser` for HttpOnly session cookies

## 1. Install

```bash
cd backend
npm ci
```

## 2. Configure `.env`

```bash
cp .env.example .env
```

| Variable | Meaning |
|---|---|
| `PORT` | HTTP port. On macOS, port 5000 is taken by AirPlay Receiver, so use e.g. `5050` or turn AirPlay Receiver off. |
| `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD` | PostgreSQL connection. |
| `NODE_ENV` | `development` / `production`. |
| `TOTP_ENCRYPTION_KEY` | 32-byte key as **64 hex characters**. Generate with `openssl rand -hex 32`. |
| `AUTH_SOURCE_LIMIT`, `AUTH_SOURCE_WINDOW_SECONDS` | Per-source password submission budget (default 20 per 60 s). |
| `COOKIE_SECURE` | `true` (default) marks session cookies `Secure` (HTTPS only). Set `false` **only** for local development over plain HTTP, otherwise the browser/curl will not send the cookies back. |

`.env` is git-ignored. Never commit real passwords or keys.

## 3. Create the database and apply the schema

```bash
# As a PostgreSQL superuser (e.g. your macOS user with Homebrew Postgres)
psql -d postgres -c "CREATE ROLE securebyte_user LOGIN PASSWORD 'choose-a-password';"
psql -d postgres -c "CREATE DATABASE securebyte OWNER securebyte_user;"

# Apply the schema as the application user
psql -h localhost -U securebyte_user -d securebyte -f src/database/schema.sql
```

`schema.sql` is idempotent (`CREATE ... IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`). Re-run it after pulling schema changes; existing data is kept.

## 4. Start

```bash
npm run dev     # nodemon
npm start       # plain node
```

Check it is up:

```bash
curl http://localhost:5050/api/health
curl http://localhost:5050/api/health/db
```

## Authentication flow

```
register ──► ENROLLMENT cookie ──► /api/totp/enroll ──► /api/totp/enroll/verify ──► account ACTIVE
                                                                                    (no session; log in)

password ──► MFA_PENDING cookie ──► /api/auth/totp ──► full session cookie ──► /api/dashboard
```

- Password success **never** creates a full session.
- Enrollment success activates the account but does **not** log the user in.
- Only `POST /api/auth/totp` creates a full session.

### Session scopes and cookies

| Scope | Cookie | Stored in | Lifetime | Allows |
|---|---|---|---|---|
| `ENROLLMENT` | `securebyte_pending` | `pending_auth` | 5 min | TOTP enrollment only (account must be `ENROLLING`) |
| `MFA_PENDING` | `securebyte_pending` | `pending_auth` | 5 min | `POST /api/auth/totp` only (account must be `ACTIVE`) |
| Full session | `securebyte_session` | `sessions` | 30 min (absolute), revocable | Protected routes |

- Tokens are 32 random bytes (base64url). The database stores only their SHA-256 hash.
- Cookies are `HttpOnly; SameSite=Lax; Path=/` and `Secure` unless `COOKIE_SECURE=false`.
- `user_id` stays server-side. It is never taken from headers or request bodies.
- The guard reloads the session on every request and requires: not revoked, not expired, and account still `ACTIVE`.

### Second-factor limits

- 5 wrong codes on one pending transaction ends that transaction.
- 5 second-factor failures per account in a rolling 15 minutes returns `429` with `Retry-After`. This survives new password logins. Recovery-code failures must record into the same `second_factor_failure_events` table.
- Replay protection: a code is accepted only if its matched time-step is greater than `totp_credentials.last_accepted_step`.

### CSRF

Cookie-authenticated `POST` routes (marked below) reject any request whose `Content-Type` is not `application/json` (`415 UNSUPPORTED_CONTENT_TYPE`). Send `Content-Type: application/json` even when the body is empty (`{}`).

## Endpoints

| Method | Path | Required scope | JSON only | Description |
|---|---|---|---|---|
| GET | `/api/health` | none | | Service health |
| GET | `/api/health/db` | none | | Database health |
| POST | `/api/auth/register` | none | | Create an `ENROLLING` account; sets the `ENROLLMENT` cookie |
| POST | `/api/auth/password` | none | | Verify password; sets `MFA_PENDING` (ACTIVE) or `ENROLLMENT` (ENROLLING); nothing for `RECOVERY_REQUIRED` |
| POST | `/api/totp/enroll` | `ENROLLMENT` | yes | Start (or restart an unverified) enrollment; returns `setupKey` and `otpAuthUri` |
| POST | `/api/totp/enroll/verify` | `ENROLLMENT` | yes | Body `{ "token": "123456" }`; activates the account and ends the enrollment scope |
| POST | `/api/auth/totp` | `MFA_PENDING` | yes | Body `{ "token": "123456" }`; creates the full session |
| GET | `/api/dashboard` | full session | | Demo protected resource (returns username) |
| GET | `/api/session` | full session | | Current session info |
| POST | `/api/session/logout` | full session | yes | Revokes the session (`revoked_at`) and clears the cookie |

Errors use the shape:

```json
{ "success": false, "error": { "type": "AUTHENTICATION_REQUIRED", "message": "..." } }
```

### Example with curl

```bash
B=http://localhost:5050; J=jar.txt
curl -s -c $J -b $J -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"a-long-unique-passphrase"}' $B/api/auth/password
curl -s -c $J -b $J -H 'Content-Type: application/json' -d '{"token":"123456"}' $B/api/auth/totp
curl -s -c $J -b $J $B/api/dashboard
curl -s -c $J -b $J -H 'Content-Type: application/json' -d '{}' -X POST $B/api/session/logout
```

(With curl over plain HTTP, set `COOKIE_SECURE=false`.)

## Frontend notes

- The browser must send cookies: call the API from the same origin (e.g. a Vite dev-server proxy for `/api`) or use `fetch(url, { credentials: "include" })`.
- Never read or store session tokens in JavaScript; they are HttpOnly.

## Docs

- Root [CI/CD & DevOps guide](../README.md#cicd--devops): Docker Compose, GitHub Actions, local CI commands and test safety requirements.
- `npm run check`: validates backend JavaScript syntax and application imports.
- `npm run db:test:prepare` and `npm test`: apply the real schema and run HTTP integration tests against a dedicated PostgreSQL test database. Follow the root guide; tests truncate test tables and reject non-test configuration.

- `docs/password-authentication-test-evidence.md`: password module tests
- `docs/password-benchmark.md`: Argon2id benchmark
- `docs/auth-flow-integration-test-evidence.md`: end-to-end session/TOTP flow tests
