# Accessway — start here

This ZIP contains the full editable source for the accessible MFA prototype: the interface, authentication service, database schema and migrations, cryptography helpers, and ten automated security tests.

## Run on your computer

1. Extract the ZIP and open the `accessway` folder in VS Code.
2. Install Node.js 24 (or Node.js 22.13 or newer) and pnpm 11.25.0. If pnpm is not installed, run `npm install --global pnpm@11.25.0` in your terminal.
3. In the terminal, inside the extracted `accessway` folder, run:

```sh
pnpm install --frozen-lockfile
pnpm setup:local
pnpm dev
```

4. Open **http://localhost:5173** in your browser. Use that exact address; `APP_ORIGIN` and the local identity helper depend on it.
5. On the initial account-loading message, click **Sign in with ChatGPT**. In local development this selects the bundled `seedy@sites.test` demo identity. It does not contact ChatGPT or ask for ChatGPT credentials.
6. Create your own Accessway password, then register an authenticator app or a compatible passkey/security key. Save the recovery codes. Sign out and sign in again to try both factors.

Keep the terminal open while using the app. Press Ctrl+C to stop it. On later visits, use `pnpm dev`; your local account persists.

`setup:local` creates a fresh local encryption key in `.env` and applies the SQL migrations to local storage. It preserves an existing `.env` and existing migrated database. It does not create a cloud database or use the hosted app's credentials. Node modules, accounts, database files, production secrets, and Git credentials are not included in this ZIP.

## What is real and what is simulated?

**Real:** password hashing and verification, TOTP enrollment/verification, WebAuthn verification, single-use recovery codes, server-side MFA gates, session expiry, and throttling.

**Simulated locally:** the initial platform identity. The bundled development-only helper supplies one shared demo identity on localhost. It is not an email verification service or public registration system. The password and second factor are still required to unlock the Accessway account.

The hosted version uses its trusted identity dispatcher instead. The export's hosting manifest contains logical database bindings but no link to the original live Site.

## GitHub Codespaces

You can put these files in a repository and work on them in Codespaces. The provided local identity helper intentionally accepts only localhost requests. To use that helper, connect the Codespace through desktop VS Code and forward port 5173 to localhost on your computer, then open `http://localhost:5173`.

Opening an `app.github.dev` forwarded URL directly is not supported by the bundled localhost identity helper. This archive does not provision a Codespace or a public authentication provider.

## Useful commands

```sh
pnpm test
pnpm typecheck
pnpm build
```

`pnpm test` exercises the actual authentication service against the included SQLite schema. It includes a software-authenticator WebAuthn test. Tests do not replace screen-reader user testing or physical-key/browser testing.

## Main files

| Location | Purpose |
| --- | --- |
| `app/auth-app.tsx` | Accessible interface and sign-in flow |
| `app/globals.css` | Responsive layout, high contrast, larger text, focus styling |
| `app/api/auth/[...action]/route.ts` | HTTP API entry point |
| `lib/auth-service.ts` | Server-side MFA, sessions, rate limits, recovery |
| `lib/auth-crypto.ts` | Password hashing, encrypted TOTP secrets, code helpers |
| `db/schema.ts` and `drizzle/` | Persistent schema and migrations |
| `tests/` | Ten automated security tests |
| `README.md` | Architecture, assumptions, limitations, and references |

## Troubleshooting

- **Account cannot load:** use the local sign-in link, ensure setup completed, and check the terminal for errors. Do not enter your real ChatGPT password into the local app.
- **Wrong origin / port busy:** keep port 5173 available and use `http://localhost:5173`. The export stops if that port is busy instead of silently changing it.
- **Passkey or clipboard unavailable:** browser support and secure-context rules vary. Use manual authenticator setup and whole-code paste as the alternate route. The app does not require a passkey.
- **Already-used authenticator code:** wait for the next code. Enrollment consumes its verification code too.
- **Too many attempts:** wait for the displayed cooldown. Restarting the server does not clear account-scoped limits.
- **Lost local test account:** after stopping the server, you may intentionally delete the local `.wrangler/state` folder and run `pnpm setup:local` to start an empty local database. This deletes all local test accounts. It is not an account-recovery feature and is never a production procedure.
- **Encryption key:** keep `.env` paired with the local database. Replacing its key makes saved authenticator seeds unreadable. Do not commit `.env` or database files.

Before public deployment, integrate a trusted identity boundary, configure the exact HTTPS origin and private secrets, and complete security and assistive-technology reviews. Do not expose the development server as a public identity service.

## Setup references

- [Cloudflare local environment variables](https://developers.cloudflare.com/workers/local-development/environment-variables/)
- [Cloudflare D1 migration commands](https://developers.cloudflare.com/workers/wrangler/commands/d1/)
