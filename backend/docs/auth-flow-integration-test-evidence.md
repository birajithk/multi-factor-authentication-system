# SecureByte Authentication Flow Integration Test Evidence

## Module

**Owner:** Khamshayan

**Responsibility:** Controller integration (registration/password → pending scopes → TOTP login → full session), server-side session service, and the protected-route guard.

**Branch:** `khamshayan/controller-integration`

**Build tested:** dcab264

**Test date:** 2026-09-25

---

## Test Environment

- Node.js: v20.20.2
- Express: 5.2.1
- cookie-parser: 1.4.7
- otplib: 13.5.0
- PostgreSQL: PostgreSQL 16.15 (Homebrew)
- Operating system: macOS 27.0
- Architecture: arm64
- CPU: Apple M5
- Logical CPUs: 10
- Local backend port: 5050 (port 5000 is taken by macOS AirPlay Receiver)
- `COOKIE_SECURE=false` for the plain-HTTP curl run (see COOKIE1 for the default)

---

## Test Method

- Real HTTP requests with `curl`, one cookie jar per simulated browser (`-b jar -c jar`).
- A fresh local PostgreSQL database with `src/database/schema.sql` applied.
- TOTP codes generated from the returned setup key using `generateTOTPCode` from `src/services/totp.service.js`.
- Wrong codes generated as random 6-digit values that `verifyTOTPCode` rejects for the current step ± 1.
- Database state checked with `psql` after each step.
- Where the replay rule requires a new code, the script waited for the next real 30-second time-step.
- Setup keys and raw tokens are not reproduced in this document.

Test accounts used the run suffix `1790277937` (for example `alice1790277937`).

**Overall result:** 92 scripted checks passed, 0 failed. Separate COOKIE1 and RACE1 runs also passed.

---

# Pre-Integration Finding

## TOTP1 - Codes Were Calculated for Unix Time 0

**Scenario:** Before integration, inspect the `otplib` v13 result for the existing `TOTP_CONFIG`.

### Procedure

1. Read `node_modules/@otplib/totp/dist/index.d.ts` (`VerifyResultValid`) and the `verify` implementation.
2. Generated a code with the existing `generateTOTPCode` and compared it with `otplib`'s code for Unix time 0 and for the real current time.

### Actual Result

- In v13, `epoch` is the **current time** used for generation and verification, not the RFC 6238 start time.
- `TOTP_CONFIG` set `epoch: 0`, so every code was the 1970 code and never changed (`same_as_time0: true`).
- A real authenticator's current code was rejected.
- `window: 1` is not a v13 option and was ignored.
- `verify` returns `{ valid, delta, epoch, timeStep }`, where `timeStep` is the exact matched step.

### Fix

Commit `996a34b`: `t0: 0, epochTolerance: 30`. After the fix, codes from steps −1, 0 and +1 verify, and −2/+2 are rejected. Replay checks now use the matched `timeStep`, for both login and enrollment.

### Result

**FIXED**

---

# Integration Test Results

## REG2 / ENR1 - Register → Enroll → No Dashboard → Must Log In

**Scenario:** A new user registers and enrolls the authenticator. Enrollment must not grant protected access.

### Procedure

1. `POST /api/auth/register` for `alice1790277937`.
2. `POST /api/totp/enroll` with only an `X-User-Id` header (no cookie).
3. `POST /api/totp/enroll` with the registration cookie jar.
4. `POST /api/totp/enroll/verify` with the current code.
5. `GET /api/dashboard` with the same jar, and with the old enrollment token sent as either cookie.
6. `POST /api/totp/enroll` again with the old cookie.

### Actual Result

- Registration: HTTP 201. The body keys are unchanged (`success, user, next_step`).
- `Set-Cookie: securebyte_pending=<43-char token>; Max-Age=300; Path=/; HttpOnly; SameSite=Lax`
- The database holds one `ENROLLMENT` row whose `token_hash` equals SHA-256(cookie). The raw token is not stored.
- `X-User-Id` only: HTTP 401 `AUTHENTICATION_REQUIRED`.
- Enroll with cookie: HTTP 201. The `otpauth` label is the username (`SecureByte:alice1790277937`), not the `user_id`.
- Enroll verify: HTTP 200, account `ACTIVE`, pending cookie cleared, enrollment row deleted.
- Sessions for the user after enrollment: **0**.
- Dashboard after enrollment: HTTP 401. Old enrollment token as either cookie: HTTP 401.
- Old enrollment cookie on `/api/totp/enroll`: HTTP 401.

### Result

**PASS**

---

## PWD1 / AUTH1 - Password Success Only → Dashboard 401

**Scenario:** A correct password for an ACTIVE account creates a pending MFA transaction, while protected access stays denied.

### Procedure

1. `POST /api/auth/password` for the ACTIVE account.
2. Inspected the response body, the `Set-Cookie` header and `pending_auth`.
3. `GET /api/dashboard` with the pending cookie, and with the pending token copied into `securebyte_session`.
4. `POST /api/totp/enroll` with the `MFA_PENDING` cookie.

### Actual Result

- HTTP 200 with a byte-identical body:
  `{"success":true,"result":"PASSWORD_VERIFIED","account_status":"ACTIVE","next_step":"TOTP_VERIFICATION"}`
- The body contains no `user_id` or token.
- `Set-Cookie: securebyte_pending=<43-char token>; Max-Age=300; Path=/; HttpOnly; SameSite=Lax`
- No `securebyte_session` cookie.
- `pending_auth` holds one row with scope `MFA_PENDING`, bound to the account's `user_id`, with a 300 s lifetime.
- `sessions` rows for the user: **0**.
- Dashboard with the pending cookie: HTTP 401. Pending token as session cookie: HTTP 401.
- `MFA_PENDING` cookie on enrollment: HTTP 401 (scopes are not interchangeable).

### Result

**PASS**

PWD1, listed as "Integration pending" in `password-authentication-test-evidence.md`, is now executed and passing.

---

## AUTH2 - Full Login: Password → TOTP → Dashboard 200

### Procedure

1. Waited for the next time-step, because enrollment had already accepted the current one.
2. `POST /api/auth/totp` with `Content-Type: text/plain`.
3. `POST /api/auth/totp` `{ "token": "<current code>" }` as JSON.
4. `GET /api/dashboard` and `GET /api/session`.

### Actual Result

- `text/plain`: HTTP 415 `UNSUPPORTED_CONTENT_TYPE` (CSRF defense).
- JSON: HTTP 200 `{"success":true,"result":"AUTHENTICATED","next_step":"DASHBOARD"}`
- `Set-Cookie: securebyte_session=<43-char token>; Max-Age=1800; Path=/; HttpOnly; SameSite=Lax`
- Pending cookie cleared (`Expires=Thu, 01 Jan 1970`) and pending row deleted.
- The `sessions` row stores only the SHA-256 hash, with a 1800 s lifetime.
- `last_accepted_step` equals the current step (59675932).
- Dashboard: HTTP 200 `{"success":true,"dashboard":{"username":"alice1790277937",...}}`
- Session info: HTTP 200 (username, status, created/expiry; no IDs or tokens).

### Result

**PASS**

---

## TOTP2 - Replay: Same Code Reused

### Procedure

1. New password login in a new jar (new `MFA_PENDING` transaction).
2. Submitted the exact code that had just completed AUTH2.

### Actual Result

- HTTP 401 `AUTHENTICATION_FAILED`, message `Invalid verification code.`
- No session cookie. The user still has exactly one session.
- `pending_auth.failed_attempts` = 1, and one `second_factor_failure_events` row.

### Result

**PASS**

---

## BIND1 - Another User's `user_id` in the TOTP Body

### Procedure

1. Registered and enrolled `bob1790277937`.
2. Alice logged in with her password (`MFA_PENDING` bound to Alice).
3. Submitted `{ token: <Bob's current code>, user_id: <Bob's id>, username: "bob…" }`.
4. Submitted `{ token: <Alice's current code>, user_id: <Bob's id>, username: "bob…" }`.
5. `GET /api/session`.

### Actual Result

- Bob's code with Bob's IDs: HTTP 401. Sessions for Bob: 0.
- Alice's code with Bob's IDs: HTTP 200, and the session belongs to **alice1790277937**.
- Sessions for Bob: still 0.

### Result

**PASS**

The account is taken only from the pending transaction. Body identifiers are ignored.

---

## TOTP3 - Five Wrong Codes → Blocked

### Procedure

1. Registered and enrolled `carol1790277937`, then logged in with her password.
2. Submitted five wrong codes.
3. Waited for a new step, then submitted the correct code in the same jar.
4. Logged in with the password again (new pending transaction) and submitted the correct code.

### Actual Result

- Wrong codes 1–5: HTTP 401 `Invalid verification code.` each.
- The 5th failure cleared the pending cookie and deleted the transaction. `second_factor_failure_events` = 5.
- Correct code in the same jar: HTTP 401 `AUTHENTICATION_REQUIRED`.
- New password login: HTTP 200. The password budget is separate.
- Correct code on the **new** transaction: HTTP 429 `TEMPORARILY_RESTRICTED`, `Retry-After: 871`, `retry_after_seconds: 871`.
- Sessions for Carol: 0.

### Result

**PASS**

The per-account budget survives a new pending transaction.

---

## LOGOUT1 - Logout → Old Cookie Gets 401

### Procedure

1. `POST /api/session/logout` with `Content-Type: text/plain`.
2. `POST /api/session/logout` with `{}` as JSON.
3. Replayed the saved old session cookie on `GET /api/dashboard`.
4. Checked Alice's other (BIND1) session.

### Actual Result

- `text/plain`: HTTP 415.
- JSON: HTTP 200 `{"success":true,"result":"LOGGED_OUT"}`, session cookie cleared.
- `sessions.revoked_at` is set.
- Old cookie: HTTP 401.
- Other session: HTTP 200 (logout revokes only the current session).

### Result

**PASS**

---

## PEND1 - Expired Pending Transaction → TOTP Rejected

### Procedure

1. Waited for a new time-step, then logged in with the password.
2. Set that transaction's `expires_at` to 1 second in the past.
3. Submitted a valid current code.

### Actual Result

- HTTP 401 `AUTHENTICATION_REQUIRED` (`Sign-in session is missing or expired. Sign in again.`)
- The expired row was deleted and no new session was created.

### Result

**PASS**

---

## GUARD1 - Additional Guard Checks

| Check | Expected | Actual |
|---|---|---|
| Full session with `expires_at` in the past | 401 | 401 |
| Same session restored to the future | 200 | 200 |
| Account set to `DISABLED` while the session is live | 401 | 401 |
| Malformed session cookie | 401 | 401 |

### Result

**PASS**

The account status is checked on every request.

---

## ENR2 - Interrupted Enrollment Resumes After Password Login

### Procedure

1. Registered `dave1790277937` and started enrollment, but did not verify.
2. Logged in with the password.
3. `POST /api/totp/enroll`, then verified with the new key.
4. Retried `/api/totp/enroll` with the original registration cookie.

### Actual Result

- Password: HTTP 200 with the unchanged `ENROLLING` / `AUTHENTICATOR_ENROLLMENT` body and an `ENROLLMENT` cookie.
- Restarted enrollment: HTTP 201 with a **new** setup key. The unverified credential was replaced.
- Verify: HTTP 200, account ACTIVE.
- Old registration cookie: HTTP 401.

### Result

**PASS**

---

## REC1 - RECOVERY_REQUIRED Creates No Pending Scope

### Actual Result

- Password: HTTP 200 with the unchanged `RECOVERY_REQUIRED` / `RECOVERY_CODE_VERIFICATION` body.
- No `Set-Cookie` and no `pending_auth` rows.

### Result

**PASS**

Recovery remains owned by the recovery module.

---

## TOKEN1 - Raw Tokens Never Stored

Every cookie value left in the test jars was searched for in `pending_auth.token_hash` and `sessions.token_hash`: **0 matches**. The earlier checks confirmed that each stored hash equals SHA-256(cookie).

### Result

**PASS**

---

## COOKIE1 - Secure Flag Default

A separate server instance was started with `COOKIE_SECURE=true`, and another with `COOKIE_SECURE` absent.

### Actual Result

Both instances returned:

`Set-Cookie: securebyte_pending=<token>; Max-Age=300; Path=/; ...; HttpOnly; Secure; SameSite=Lax`

### Result

**PASS**

---

## RACE1 - Concurrent Replay

Four password logins created four `MFA_PENDING` transactions for the same account. The same fresh code was then submitted on all four in parallel.

### Actual Result

- One HTTP 200 and three HTTP 401.
- Exactly **1** new session.

### Result

**PASS**

`SELECT ... FOR UPDATE` on the TOTP credential serializes the replay check.

---

# Security Event Metadata

TOTP login and logout build credential-free metadata with the same shape as the password module (`eventType`, `timestamp`, `outcome`, `correlationId`, `userId`):

- `TOTP_VERIFICATION_SUCCESS` / `SUCCESS`
- `TOTP_VERIFICATION_FAILURE` / `FAILURE`
- `TEMPORARY_RESTRICTION` / `BLOCKED` (second-factor budget exhausted)
- `LOGOUT` / `SUCCESS`

No code, setup key or token is included. The server console output during the whole run contained only the startup lines.

### Integration Status

`security-logger.service.js` is not on `main` yet, so the events are passed to an integration-point comment, the same approach as the password module.

---

# Current Completion Status

| Area | Status |
|---|---|
| TOTP time calculation (TOTP1) | FIXED |
| Register → enroll → no dashboard (REG2/ENR1) | PASS |
| PWD1 / AUTH1 password-only access denied | PASS |
| AUTH2 full login | PASS |
| TOTP replay (TOTP2) | PASS |
| Concurrent replay (RACE1) | PASS |
| Account binding (BIND1) | PASS |
| Five wrong codes / account budget (TOTP3) | PASS |
| Logout revocation (LOGOUT1) | PASS |
| Expired pending (PEND1) | PASS |
| Guard: expiry, DISABLED, malformed (GUARD1) | PASS |
| Interrupted enrollment resume (ENR2) | PASS |
| RECOVERY_REQUIRED no scope (REC1) | PASS |
| Hash-only token storage (TOKEN1) | PASS |
| Cookie flags incl. Secure default (COOKIE1) | PASS |
| CSRF content-type check | PASS |
| Security-event persistence | Integration pending (common logger) |

---

# Remaining Integration Dependencies

1. Connect the TOTP/logout event metadata to the common security logger once it is merged.
2. Recovery-code failures must record into `second_factor_failure_events`, using `second-factor-attempt.service.js`, so TOTP and recovery codes share one budget.
3. The frontend must send cookies (same-origin proxy or `credentials: "include"`) and send `Content-Type: application/json` on the cookie-authenticated POST routes.
