# Accessway

**Downloaded source edition:** read [START-HERE.md](START-HERE.md) first. It explains local setup and how the local demo identity differs from hosted sign-in.

A working, private multi-factor authentication prototype designed for blind and low-vision users. It adds a separate server-enforced MFA gate to the identity provided by the private Sites dispatcher. ChatGPT sign-in identifies the account; it does not bypass either Accessway factor.

## Authentication design

1. Create an Accessway password (at least 15 characters).
2. Enroll either a WebAuthn passkey/security key or a time-based authenticator.
3. Verify possession before activating the account. Save the eight recovery codes shown once.
4. On subsequent sign-ins, verify the password and a registered second factor before entering the protected account view.

| Method | Factors | Accessible interaction |
| --- | --- | --- |
| Password + passkey/security key | Knowledge + possession; device user verification is also required | Device PIN/fingerprint or physical key; no transcription |
| Password + authenticator | Knowledge + possession | One real code input with whole-code paste/autofill; manual setup key or authenticator deep link |
| Password + recovery code | Knowledge + possession of a stored recovery secret | Paste one complete saved code; consumed once |

Spoken instructions are an optional presentation aid, **not** an authentication factor. Accessway does not collect voiceprints or biometric templates. The authenticator handles local user verification.

## Accessible interaction

- Semantic headings and landmarks, an initial skip link, and explicit labels.
- Keyboard-operable controls, visible focus, and focus moved to the heading after a step change or the alert after an error.
- One underlying OTP input; visual slots do not create six screen-reader fields. Password managers, autofill, and pasting are allowed.
- No image puzzles, QR-only enrollment, required audio, automatic form submission, or character-position password questions.
- High contrast and larger text options, responsive layouts, browser zoom compatibility, reduced-motion and forced-color rules.
- Persistent live region for status, alert semantics for errors, and optional speech that reads instructions rather than secrets.
- Time warnings and up to ten user-requested extensions. Extensions never refresh the five-minute recent-MFA requirement for adding a method.
- Only display preferences are stored in localStorage. Credentials and authorization state are not.

The implementation is informed by [W3C accessible authentication guidance](https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-minimum.html), particularly support for password managers, paste, and alternatives to transcription. It is not a WCAG conformance certification.

## Architecture

- **Interface:** React with Vinext; accessible Radix/Shadcn primitives for dialogs, switches, and the single-input OTP component.
- **API:** `app/api/auth/[...action]/route.ts`, invoking the runtime-independent service in `lib/auth-service.ts`.
- **Cryptography:** `lib/auth-crypto.ts`, Node crypto, OTPAuth, and SimpleWebAuthn.
- **Persistence:** Cloudflare D1, prepared statements, and transactional batches. Schema in `db/schema.ts`; versioned schema-only migrations in `drizzle/`.
- **Identity boundary:** trusted `oai-authenticated-user-id` and `oai-authenticated-user-email` headers from the private Sites dispatcher. Directly exposing this Worker without that trusted boundary would be unsafe. No anonymous/public account registration is implemented.

The API checks identity and session ownership on every request. `GET /api/auth/account` is a protected resource: it rejects password-only, expired, and other-user sessions. The UI is not an authorization boundary.

### Security controls

- Scrypt password hashing: N=32768, r=8, p=3, a random 16-byte salt, and a 32-byte hash. Passwords normalize to NFC; no arbitrary composition rules.
- AES-256-GCM authenticated encryption for authenticator seeds using a deployment secret and account-specific additional authenticated data. Random IV per ciphertext.
- Standard 6-digit SHA-1 TOTP, 30-second step, one-step clock-skew window. A database compare-and-swap on the last accepted counter prevents reuse across sessions.
- WebAuthn requires the configured origin, RP ID, a short-lived single-use challenge, user presence and user verification, valid signatures, and an account-owned stored credential. Counters are checked and persisted by SimpleWebAuthn verification.
- Eight random 96-bit recovery codes, stored only as account-scoped SHA-256 hashes. Atomic deletion prevents concurrent reuse.
- Opaque 256-bit tokens; only token hashes stored server-side. `__Host-` cookies have Secure, HttpOnly, SameSite=Lax, and Path=/. A new token is issued after password and MFA verification. Signing out invalidates the server session.
- Account-scoped persistent request/password/verification limits with Retry-After. Limits persist across new sessions.
- Strict configured-Origin checks on JSON POST requests, bounded request bodies, no-store API responses, and no logging of credential material.
- Initial enrollment, factors, recovery hashes, and the full session are committed as one batch. A unique enrollment record prevents two initial setups committing for the same identity.
- Adding a method requires a full session authenticated in the last five minutes. Session extensions preserve that authentication timestamp.

TOTP and recovery codes remain susceptible to phishing. Prefer the WebAuthn route for resistance to verifier impersonation. See [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) and the [SimpleWebAuthn server documentation](https://simplewebauthn.dev/docs/packages/server). This project does not claim NIST AAL certification.

### API map

| Endpoint under `/api/auth/` | Access and effect |
| --- | --- |
| `GET status` | Signed-in platform identity; returns non-secret setup/session state |
| `GET account` | Requires a full MFA session |
| `POST setup` / `password` | Creates/verifies a password; only issues an enrollment/partial session |
| `POST totp/setup` | Enrollment or recent full MFA; returns a new private seed and deep link |
| `POST totp/enroll` | Verifies the pending seed before binding it |
| `POST totp/verify` | Password session; validates and consumes one TOTP time step |
| `POST key/register/options` / `verify` | Enrollment or recent full MFA; validates and stores a public credential |
| `POST key/authenticate/options` / `verify` | Password session; challenge and signature verification |
| `POST recovery/verify` | Password session; consumes one saved recovery code |
| `POST extend` | Valid current session; extends within the fixed total limit |
| `POST logout` | Invalidates the current token and clears the cookie |

## Configuration and development

Use the repository's pinned pnpm installation. Run `pnpm test`, `pnpm typecheck`, and `pnpm build` for validation. Migrations are generated with `pnpm db:generate`. Production uses the logical `DB` binding in `.openai/hosting.json`.

Copy `.env.example` to `.env` for local values. Set `APP_ORIGIN` to the exact origin, without a trailing slash, and `MFA_ENCRYPTION_KEY` to a cryptographically random 32-byte base64url string. Production secrets are configured separately from source. Keep the encryption key stable and backed up; changing it without migrating ciphertext makes existing authenticator secrets unreadable. Never commit `.env` or secrets.

The service requires the trusted dispatcher identity headers even locally. The test harness injects test-only identities into an in-memory SQLite adapter; no development bypass exists in production source.

## Verification

`node tests/run.mjs` transpiles the actual service code into an ignored temporary directory and tests it against SQLite using the generated migrations. Ten tests cover:

- trusted identity, CSRF, input checks, and denial before MFA;
- possession-checked enrollment, token rotation, encryption and hashing;
- TOTP replay and time-step handling;
- concurrent recovery-code reuse;
- expiration and recent-verification requirements;
- ten time extensions without renewing recent-MFA age;
- verification and password throttling;
- signed software-authenticator WebAuthn registration and authentication, missing user verification, wrong origin, and reused challenges;
- ciphertext integrity and account binding.

Browser-based assistive-technology testing, physical passkey/security-key testing, and WebMCP validation were not run. WebMCP is feature-detected and exposes only accessibility preferences, never credential submission or authentication. Its absence does not affect sign-in.

## Prototype boundaries

- Private, account-linked deployment; not a general public identity provider.
- Before wider use, conduct an independent security review and testing with blind and low-vision participants using NVDA, JAWS, VoiceOver, TalkBack, braille displays, magnification, high contrast, and keyboard-only navigation.
- A small common-password blocklist is included, not a complete breached-password service.
- No password-reset, external identity proofing, operator recovery, notification delivery, authenticator replacement/removal, or security audit dashboard is implemented. Losing the password or every registered second factor and recovery code can make this prototype account inaccessible. Re-enrollment must never be a silent MFA bypass.
- Authenticator deep links and device prompts vary by operating system/browser. Manual setup remains available. Clipboard errors fall back to selectable text.
- Current session defaults are 15 minutes before MFA and 30 minutes after it. User-requested extensions allow at most eleven times the original duration; applications integrating this design should set lifetime policy for their own risk and accessibility requirements.
