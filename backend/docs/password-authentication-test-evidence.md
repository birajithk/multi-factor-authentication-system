# SecureByte Registration and Password Authentication Test Evidence

## Module

**Owner:** Birajith K. - 230091H

**Responsibility:** Registration, password policy and storage, first-factor password verification, password guessing controls, source-rate limiting, and password-module security-event metadata.

**Branch:** `birajith/password-authentication`

**Build tested:** ed9c5b6

**Test date:** 2026-09-22

---

## Test Environment

- Node.js: v22.23.0
- Argon2 package: argon2@0.45.1
- PostgreSQL: PostgreSQL 16
- Operating system/kernel: Linux 7.0.0-28-generic
- Architecture: x86_64
- CPU: 11th Gen Intel(R) Core(TM) i9-11900H @ 2.50GHz
- Logical CPUs: 16
- Backend: Express
- Database: PostgreSQL
- Local backend port: 5000

---

# Source Test Results

## REG1 - Duplicate Username Registration

**Scenario:** Register the same username twice using different capitalization.

### Procedure

1. Registered `FinalReg1Test` through `POST /api/auth/register`.
2. Registration succeeded with HTTP 201.
3. Submitted another registration using `FINALREG1TEST`.
4. The second request returned HTTP 409 with `DUPLICATE_USERNAME`.
5. Queried PostgreSQL for the normalized username.

### Actual Result

- Initial registration: HTTP 201
- Stored username: `finalreg1test`
- Account status: `ENROLLING`
- Duplicate registration: HTTP 409
- Database account count: 1

### Result

**PASS**

Case-insensitive username uniqueness is enforced by the application and by a PostgreSQL unique index on `LOWER(username)`.

---

## PWD1 - Correct Password for Active Account

**Required result:** A correct password for an ACTIVE account creates a pending MFA transaction while protected application access remains denied.

### Current Module Evidence

The password module successfully verifies a correct password and returns only an internal `PASSWORD_VERIFIED` result. Password proof alone does not create a full session or protected access.

The HTTP endpoint returns only the current account state and the permitted next step.

### Integration Status

**NOT YET FULLY EXECUTED**

The final PWD1 acceptance test requires the real shared controller/session integration to create a server-side pending MFA transaction for an ACTIVE account. That integration is owned jointly with the controller/session modules.

This module does not claim PWD1 as passed until that real pending-MFA transaction is connected and tested.

---

## PWD2 - Incorrect Password

**Scenario:** Submit an incorrect password for an existing account.

### Procedure

1. Created a fresh test account.
2. Confirmed the account initially had zero password-failure records.
3. Submitted one incorrect password through `POST /api/auth/password`.
4. Queried the persistent password-failure state.

### Actual Result

- HTTP response: 401 Unauthorized
- Response type: `AUTHENTICATION_FAILED`
- Initial failure count: 0
- Failure count after request: 1

### Result

**PASS**

The wrong password is rejected and the persistent failure count increases.

---

## PWD3 - Fresh Password Salts

**Scenario:** Register two accounts with the same plaintext password.

### Procedure

1. Registered `FinalPwd3TestA`.
2. Registered `FinalPwd3TestB` using the exact same password.
3. Compared the encoded password hashes stored in PostgreSQL.

### Actual Result

- First registration: HTTP 201
- Second registration: HTTP 201
- Both values use Argon2id.
- PostgreSQL comparison returned `hashes_are_different = true`.

### Result

**PASS**

Identical plaintext passwords produce different encoded hashes because the Argon2 implementation generates a fresh random salt for each password.

---

## PWD4 - Password Retry Limit

**Scenario:** Exceed the account password failure budget and retry from new requests.

### Procedure

1. Created a fresh test account.
2. Submitted five incorrect passwords.
3. Each of the five requests returned HTTP 401.
4. Submitted the correct password after the fifth failure.
5. The request was rejected with HTTP 429.
6. Repeated the correct-password request using a different capitalization of the username.
7. The second request was also rejected with HTTP 429.
8. Queried PostgreSQL for failures in the current rolling window.

### Actual Result

- Attempts 1-5: HTTP 401 `AUTHENTICATION_FAILED`
- Correct-password attempt after limit: HTTP 429
- New request/case variant: HTTP 429
- Failure records in current 15-minute window: 5
- Retry state remained effective across separate requests and Node processes.

### Result

**PASS**

The five-failure account budget is maintained on the server and persists independently of browser state.

---

# Additional Password Policy Tests

## Minimum and Maximum Length

The following password lengths were tested through the real registration endpoint:

| Length | Expected | Actual |
|---:|---|---|
| 14 | Reject | Rejected with HTTP 400 |
| 15 | Accept | Accepted with HTTP 201 |
| 128 | Accept | Accepted with HTTP 201 |
| 129 | Reject | Rejected with HTTP 400 |

The accepted 128-character password was subsequently verified successfully through the password-authentication endpoint.

**Result: PASS**

The implementation enforces the 15-128 character policy without silent truncation.

---

## Weak/Common Password Blocklist

A password contained in the documented local SecLists blocklist was submitted during registration.

### Actual Result

The registration request returned HTTP 400 with a password validation error.

**Result: PASS**

Blocklist source documentation is stored in `src/data/README.md`.

---

## Username Normalization

The implementation treats username case variants as the same identifier.

Examples:

- `Birajith`
- `birajith`
- `BIRAJITH`

are normalized to the same lowercase username.

Database-level uniqueness is additionally enforced using a unique index on `LOWER(username)`.

**Result: PASS**

---

# First-Factor Failure Behaviour

## Unknown Account

An unknown username was submitted to the password endpoint.

### Actual Result

- HTTP 401
- `AUTHENTICATION_FAILED`
- Generic message: `Invalid username or password.`

The password module performs a dummy Argon2 verification for unknown identifiers instead of immediately returning through a cheap lookup-failure path.

**Result: PASS**

---

## Disabled Account

A controlled test account was changed to `DISABLED`, then its correct password was submitted.

### Actual Result

- HTTP 401
- `AUTHENTICATION_FAILED`
- Generic message: `Invalid username or password.`

The public result was identical to the wrong-password and unknown-account failure responses.

**Result: PASS**

---

# Source Address Rate Limit

The supplementary source-address budget was tested using the configured defaults:

- 20 authentication submissions
- Rolling 60-second window

### Procedure

Twenty-one authentication requests were sent from one source.

### Actual Result

- Requests 1-20 were permitted to reach authentication processing.
- Request 21 returned HTTP 429.
- PostgreSQL contained 20 accepted source submission events.
- The blocked request did not create an additional accepted event.

### Result

**PASS**

The source-address limit supplements the account password-failure budget.

---

# Rolling Window Test

Five password failures were generated for a controlled test account.

The controlled test timestamps were then moved to 16 minutes before the current time to simulate expiry from the configured rolling 15-minute window.

### Actual Result

- Recent failure count became 0.
- Correct password verification became permitted again.
- Expired failure records were removed during retry-state evaluation.

### Result

**PASS**

The account restriction is temporary and uses a rolling 15-minute window.

---

# Malformed Request Handling

Malformed JSON was submitted to the password-authentication endpoint.

### Actual Result

The server returned controlled HTTP 400 JSON:

- `VALIDATION_ERROR`
- `Request body contains invalid JSON.`

The response did not expose:

- an HTML stack trace,
- application filesystem paths,
- Node module paths,
- credential values.

### Result

**PASS**

---

# Security Event Metadata

The password module generates credential-free metadata for integration with the common security logger.

## Successful Password Verification

Generated metadata contained:

- event type: `PASSWORD_AUTHENTICATION_SUCCESS`
- outcome: `SUCCESS`
- UTC timestamp
- correlation ID
- known user ID

## Unknown Account Failure

Generated metadata contained:

- event type: `PASSWORD_AUTHENTICATION_FAILURE`
- outcome: `FAILURE`
- UTC timestamp
- correlation ID
- `userId: null`

The event metadata does not contain the entered password, password hash, session cookie, or other credential values.

The metadata is not returned to the browser.

### Integration Status

The metadata contract is implemented.

Persistent security-event logging remains dependent on the group's common logging module owned by the recovery/logging member.

---

# HTTP Response Credential Inspection

Successful and failed registration/password responses were inspected.

The responses do not expose:

- plaintext passwords,
- password hashes,
- salts,
- internal retry keys,
- security-event metadata,
- raw session identifiers.

Static source inspection also found no deliberate console logging of entered passwords or password hashes.

### Result

**PASS**

---

# Argon2id Configuration and Benchmark

The implementation uses:

- Argon2id
- 19 MiB memory
- 2 iterations
- parallelism 1
- fresh random salt for each password

Encoded parameter inspection produced:

```text
$argon2id$v=19$m=19456,p=1,t=2
```

Two measured benchmark runs are documented separately in `docs/password-benchmark.md`.

The observed mean of the two reported average hashing times was approximately 18.58 ms, and the observed mean of the two reported average verification times was approximately 18.51 ms.

### Result

**PASS**

The measurements describe the tested development hardware only and are not claimed as production response-time guarantees.

---

# Current Completion Status

| Area | Status |
|---|---|
| REG1 | PASS |
| PWD1 | Integration pending |
| PWD2 | PASS |
| PWD3 | PASS |
| PWD4 | PASS |
| 15-128 password boundaries | PASS |
| Local password blocklist | PASS |
| Case-insensitive usernames | PASS |
| Unknown-account generic failure | PASS |
| Disabled-account generic failure | PASS |
| Persistent account retry state | PASS |
| Rolling retry expiry | PASS |
| Source-address rate limit | PASS |
| Malformed JSON handling | PASS |
| Credential-free event metadata | PASS |
| Argon2id benchmark | PASS |

---

# Remaining Integration Dependencies

The following items cannot honestly be marked complete by this module alone:

1. For an ACTIVE account, successful password verification must create or authorize the real server-side pending MFA transaction used by the TOTP module.
2. Protected dashboard/API access must remain denied until the second factor succeeds through the shared protected-resource guard.
3. Password security-event metadata must be connected to the common persistent security logger.
4. Frontend registration/password screens must consume the real backend response categories and must not implement browser-side authorization.

These items will be verified during group integration.