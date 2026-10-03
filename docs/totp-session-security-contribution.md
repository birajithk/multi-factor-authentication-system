# TOTP Verification and Session Security Contribution

## Contributor

- **Student ID:** 230015G
- **Student Name:** Abishek F. A.
- **Project:** SecureByte Multi-Factor Authentication System
- **Contribution:** TOTP Verification and Session Security

---

## 1. Contribution Overview

This contribution implements the TOTP verification and session-security components of the SecureByte multi-factor authentication system.

The implementation ensures that successful password authentication alone does not grant access to protected application resources.

A user must successfully complete the required second-factor verification before a full authenticated session is created.

The contribution includes:

- TOTP authenticator enrollment
- TOTP verification
- encrypted TOTP-secret storage
- replay protection
- restricted MFA-pending authentication state
- server-side session management
- protected-resource authorization
- authentication retry controls
- logout and session revocation
- session expiration and extension handling
- security-event integration
- integration with authenticator recovery where required by the authentication state model

---

## 2. TOTP Configuration

The TOTP implementation uses the following parameters:

| Parameter | Configuration |
|---|---|
| Secret size | 160-bit randomly generated secret |
| Algorithm | HMAC-SHA-1 |
| Code length | 6 decimal digits |
| Time step | 30 seconds |
| Initial time | Unix epoch |
| Verification tolerance | Current, previous, and next time step |

The implementation uses the maintained `otplib` library rather than implementing the cryptographic algorithm manually.

---

## 3. Authenticator Enrollment

Authenticator enrollment occurs only within an authorized enrollment state.

The enrollment process is:

1. The server generates a new random TOTP secret.
2. The secret is encrypted before database storage.
3. A text setup key is returned during the setup process.
4. The user adds the setup key to an authenticator application.
5. The user submits the generated six-digit TOTP code.
6. The backend verifies the code.
7. Successful verification activates the authenticator credential.

Completing authenticator enrollment does not automatically create a full authenticated application session.

The user must subsequently perform the normal password and TOTP login flow.

---

## 4. TOTP Secret Protection

TOTP secrets are protected using AES-256-GCM authenticated encryption.

The database stores:

- encrypted secret
- nonce
- authentication tag
- key identifier

The encryption key is supplied through environment configuration and is not stored in the application database.

A fresh nonce is generated for each encryption operation.

Plaintext authenticator secrets and setup keys are not written to security logs.

---

## 5. MFA-Pending Authentication State

Successful password verification does not directly authenticate the user into the protected application.

Instead, the backend creates a restricted MFA-pending transaction.

The MFA-pending state:

- is stored server-side
- is associated with the verified account
- has a limited lifetime
- permits only the appropriate second-factor operations
- cannot access the protected dashboard

The account identity used during TOTP verification comes from the server-side pending transaction rather than from a user ID supplied by the frontend.

This prevents account switching between the password and TOTP verification stages.

---

## 6. TOTP Verification and Replay Protection

TOTP verification checks:

- pending authentication validity
- pending authentication expiry
- account state
- retry limits
- encrypted authenticator credential
- submitted TOTP code
- previously accepted TOTP time step

When a code is valid, the backend obtains the exact TOTP time step matched by the verification.

The matched time step must be newer than the credential's stored `last_accepted_step`.

A successful authentication transaction atomically:

1. validates the accepted TOTP time step
2. updates `last_accepted_step`
3. consumes the pending authentication transaction
4. creates the full authenticated session

This prevents an already accepted TOTP code from being successfully replayed.

Database locking and transactions also prevent concurrent requests from successfully consuming the same accepted TOTP state.

---

## 7. Authentication Retry Controls

The implementation applies restrictions to repeated authentication failures.

Controls include:

- per-pending-transaction TOTP failure limits
- rolling second-factor failure tracking
- shared TOTP/recovery second-factor failure restrictions
- temporary authentication restrictions
- supplementary source-address authentication limits

Retry state is maintained server-side rather than being controlled by the browser.

---

## 8. Full Session Security

A full authenticated session is created only after successful MFA verification.

Session identifiers are:

- cryptographically random
- sent to the browser using cookies
- stored in the database only as hashes
- tracked and validated server-side

The full-session cookie uses:

- `HttpOnly`
- `Secure`
- `SameSite=Lax`

Protected endpoints validate the session against server-side state on each request.

Validation checks include:

- valid session-token format
- matching session-token hash
- session not revoked
- session not expired
- account still in the `ACTIVE` state

Restricted enrollment, MFA-pending, and recovery-only credentials cannot be used as full authenticated sessions.

---

## 9. Protected Resource Authorization

The protected dashboard is guarded by server-side session middleware.

Direct access to the protected API without a valid full session is rejected.

Therefore:

```text
Password only
    -> MFA pending
    -> Dashboard denied

Password + valid TOTP
    -> Full session
    -> Dashboard allowed