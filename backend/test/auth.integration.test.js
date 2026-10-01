import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { createHash, randomUUID } from "node:crypto";
import pool from "../src/config/database.js";
import { generateTOTPCode } from "../src/services/totp.service.js";
import { verifyPassword } from "../src/services/password.service.js";
import { assertTestEnvironment } from "./helpers/test-environment.js";

assertTestEnvironment();

const password = "CI only unique passphrase 2026!";
const hash = (value) => createHash("sha256").update(value).digest("hex");
let server;
let serverExit;
let baseUrl;

// This is an HTTP integration client, not a browser. It explicitly sends Secure
// cookies over loopback HTTP so their production flags can still be asserted.
// Browser HTTPS/SameSite enforcement requires a separate browser test suite.
function client() {
  const cookies = new Map();
  return {
    cookies,
    async request(path, { method = "GET", body, headers = {}, raw } = {}) {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers: {
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
          ...(cookies.size ? { Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; ") } : {}),
          ...headers,
        },
        body: raw ?? (body === undefined ? undefined : JSON.stringify(body)),
        signal: AbortSignal.timeout(5000),
      });
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(";", 1)[0];
        const index = pair.indexOf("=");
        const name = pair.slice(0, index);
        const value = pair.slice(index + 1);
        if (value) cookies.set(name, value);
        else cookies.delete(name);
      }
      return { status: response.status, body: await response.json(), headers: response.headers };
    },
  };
}

async function register(browser, username = `ci_${randomUUID().replaceAll("-", "")}`) {
  const response = await browser.request("/api/auth/register", {
    method: "POST", body: { username, password },
  });
  assert.equal(response.status, 201);
  return response;
}

async function loginPassword(browser, username, suppliedPassword = password) {
  return browser.request("/api/auth/password", {
    method: "POST", body: { username, password: suppliedPassword },
  });
}

function assertSecureCookie(headers, name) {
  const cookie = headers.getSetCookie().find((value) => value.startsWith(`${name}=`));
  assert.ok(cookie, "Expected authentication cookie");
  // Boolean assertions avoid dumping cookie tokens when an assertion fails.
  for (const flag of ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"]) {
    assert.ok(cookie.includes(flag), `Cookie must include ${flag}`);
  }
}

before(async () => {
  // Fail immediately when PostgreSQL or the real schema is unavailable.
  await pool.query("SELECT user_id FROM users LIMIT 0");
  const reservation = createServer();
  reservation.listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise((resolve, reject) => reservation.close((error) => error ? reject(error) : resolve()));
  baseUrl = `http://127.0.0.1:${port}`;
  // Exercise the actual production entrypoint, including startup imports and cleanup.
  server = spawn(process.execPath, ["src/server.js"], {
    env: { ...process.env, PORT: String(port) },
    stdio: ["ignore", "inherit", "inherit"],
  });
  serverExit = once(server, "exit");
  let spawnError;
  server.on("error", (error) => { spawnError = error; });
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (spawnError) throw spawnError;
    assert.equal(server.exitCode, null, "Backend exited during startup");
    try {
      const response = await fetch(`${baseUrl}/api/health`, { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch { /* Retry only connection readiness, never test assertions. */ }
    await delay(100);
  }
  throw new Error("Backend did not become ready within 15 seconds.");
}, { timeout: 20000 });

beforeEach(async () => {
  // Guarded above and intentionally destructive ONLY in a dedicated *_test database.
  // Reset source-rate events too, so independent tests retain the real rate limits.
  await pool.query(`TRUNCATE users, security_events, authentication_source_events,
    password_failure_events RESTART IDENTITY CASCADE`);
});

after(async () => {
  try {
    if (server && server.exitCode === null && server.signalCode === null) {
      server.kill("SIGTERM");
      const watchdog = setTimeout(() => server.kill("SIGKILL"), 5000);
      watchdog.unref();
      try { await serverExit; } finally { clearTimeout(watchdog); }
    }
  } finally {
    await pool.end();
  }
});

test("backend health endpoint responds from the real server", async () => {
  const response = await client().request("/api/health");
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { status: "ok", service: "SecureByte Backend" });
});

test("database health endpoint queries PostgreSQL", async () => {
  const response = await client().request("/api/health/db");
  assert.equal(response.status, 200);
  assert.equal(response.body.database, "connected");
  assert.ok(Number.isFinite(Date.parse(response.body.time)));
});

test("protected routes reject absent, malformed and forged session cookies", async () => {
  for (const cookie of ["", "securebyte_session=malformed", `securebyte_session=${"A".repeat(43)}`]) {
    for (const path of ["/api/dashboard", "/api/session"]) {
      const response = await client().request(path, { headers: { Cookie: cookie } });
      assert.equal(response.status, 401);
      assert.equal(response.body.error.type, "AUTHENTICATION_REQUIRED");
    }
  }
});

test("registration validation and malformed JSON fail with controlled errors", async () => {
  const browser = client();
  const weak = await browser.request("/api/auth/register", {
    method: "POST", body: { username: "ci_invalid", password: "short" },
  });
  assert.equal(weak.status, 400);
  assert.equal(weak.body.error.type, "VALIDATION_ERROR");
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM users")).rows[0].count, 0);
  const malformed = await browser.request("/api/auth/password", {
    method: "POST", headers: { "Content-Type": "application/json" }, raw: "{",
  });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body.error.type, "VALIDATION_ERROR");
  assert.ok(!JSON.stringify(malformed.body).includes("stack"));
});

test("REG1/PWD3: registration normalizes names, rejects duplicates and salts Argon2id hashes", async () => {
  const browser = client();
  const response = await register(browser, "CI_Registration");
  assert.equal(response.body.user.username, "ci_registration");
  assert.equal(response.body.user.account_status, "ENROLLING");
  assert.equal(response.body.next_step, "AUTHENTICATOR_ENROLLMENT");
  assertSecureCookie(response.headers, "securebyte_pending");
  assert.ok(!browser.cookies.has("securebyte_session"));
  const duplicate = await browser.request("/api/auth/register", {
    method: "POST", body: { username: "CI_REGISTRATION", password },
  });
  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.body.error.type, "DUPLICATE_USERNAME");
  await register(client(), "ci_second");
  const users = (await pool.query("SELECT password_hash FROM users ORDER BY username")).rows;
  assert.equal(users.length, 2);
  for (const user of users) {
    assert.ok(user.password_hash.startsWith("$argon2id$"));
    assert.ok(await verifyPassword(user.password_hash, password));
  }
  assert.ok(users[0].password_hash !== users[1].password_hash, "Fresh password salts are required");
  const pending = (await pool.query("SELECT token_hash, scope FROM pending_auth WHERE user_id = $1", [response.body.user.user_id])).rows;
  assert.equal(pending.length, 1);
  assert.equal(pending[0].scope, "ENROLLMENT");
  assert.ok(pending[0].token_hash === hash(browser.cookies.get("securebyte_pending")));
  assert.equal((await browser.request("/api/dashboard")).status, 401);
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM sessions")).rows[0].count, 0);
});

test("PWD2: wrong passwords, unknown users and disabled accounts share a generic failure", async () => {
  const response = await register(client());
  const username = response.body.user.username;
  const wrong = await loginPassword(client(), username, "Incorrect CI passphrase!");
  const unknown = await loginPassword(client(), "ci_unknown_account");
  await pool.query("UPDATE users SET account_status = 'DISABLED' WHERE username = $1", [username]);
  const disabled = await loginPassword(client(), username);
  for (const result of [wrong, unknown, disabled]) {
    assert.equal(result.status, 401);
    assert.equal(result.body.error.type, "AUTHENTICATION_FAILED");
    assert.equal(result.headers.getSetCookie().length, 0);
  }
  assert.deepEqual(wrong.body, unknown.body);
  assert.deepEqual(wrong.body, disabled.body);
  const failures = await pool.query("SELECT COUNT(*)::int AS count FROM password_failure_events");
  assert.equal(failures.rows[0].count, 3);
});

test("ENR2: password login can resume enrollment but cannot access the dashboard", async () => {
  const registered = await register(client());
  const browser = client();
  const response = await loginPassword(browser, registered.body.user.username);
  assert.equal(response.status, 200);
  assert.equal(response.body.result, "PASSWORD_VERIFIED");
  assert.equal(response.body.next_step, "AUTHENTICATOR_ENROLLMENT");
  assertSecureCookie(response.headers, "securebyte_pending");
  assert.equal((await browser.request("/api/dashboard")).status, 401);
  assert.equal((await browser.request("/api/totp/enroll", { method: "POST", body: {} })).status, 201);
});

test("PWD4: five password failures persist across requests and restrict a correct password", async () => {
  const response = await register(client());
  const username = response.body.user.username;
  for (let attempt = 0; attempt < 5; attempt++) {
    assert.equal((await loginPassword(client(), username, "Incorrect CI passphrase!")).status, 401);
  }
  for (const name of [username, username.toUpperCase()]) {
    const restricted = await loginPassword(client(), name);
    assert.equal(restricted.status, 429);
    assert.equal(restricted.body.error.type, "TEMPORARILY_RESTRICTED");
    assert.ok(Number(restricted.headers.get("retry-after")) > 0);
  }
});

test("REG2/AUTH1/AUTH2/TOTP2/GUARD1/LOGOUT1: real MFA, scoped sessions, replay and revocation", { timeout: 90000 }, async () => {
  const browser = client();
  const registered = await register(browser);
  const { user_id: userId, username } = registered.body.user;
  const enrollmentToken = browser.cookies.get("securebyte_pending");
  const enrolled = await browser.request("/api/totp/enroll", { method: "POST", body: {} });
  assert.equal(enrolled.status, 201);
  assert.ok(typeof enrolled.body.setupKey === "string");
  const credential = (await pool.query("SELECT * FROM totp_credentials WHERE user_id = $1", [userId])).rows[0];
  assert.ok(credential.encrypted_secret !== enrolled.body.setupKey, "TOTP secret must be encrypted");
  assert.equal(Buffer.from(credential.nonce, "base64").length, 12);
  assert.equal(Buffer.from(credential.auth_tag, "base64").length, 16);
  const verified = await browser.request("/api/totp/enroll/verify", {
    method: "POST", body: { token: await generateTOTPCode(enrolled.body.setupKey) },
  });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.user.account_status, "ACTIVE");
  assert.ok(!browser.cookies.has("securebyte_pending"));
  assert.ok(!browser.cookies.has("securebyte_session"));
  assert.equal((await browser.request("/api/dashboard")).status, 401);
  assert.equal((await browser.request("/api/dashboard", {
    headers: { Cookie: `securebyte_session=${enrollmentToken}` },
  })).status, 401);

  const firstFactor = await loginPassword(browser, username);
  assert.equal(firstFactor.status, 200);
  assert.equal(firstFactor.body.next_step, "TOTP_VERIFICATION");
  const pendingToken = browser.cookies.get("securebyte_pending");
  assert.ok(!browser.cookies.has("securebyte_session"));
  assert.equal((await browser.request("/api/dashboard")).status, 401);
  assert.equal((await browser.request("/api/dashboard", {
    headers: { Cookie: `securebyte_session=${pendingToken}` },
  })).status, 401);
  assert.equal((await browser.request("/api/totp/enroll", { method: "POST", body: {} })).status, 401);
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM sessions")).rows[0].count, 0);
  const plain = await browser.request("/api/auth/totp", {
    method: "POST", headers: { "Content-Type": "text/plain" }, raw: "{}",
  });
  assert.equal(plain.status, 415);

  // Enrollment consumed one real TOTP step. Wait for the next real step; never
  // reset last_accepted_step, mock the verifier, or change the application clock.
  const acceptedStep = Number((await pool.query("SELECT last_accepted_step FROM totp_credentials WHERE user_id = $1", [userId])).rows[0].last_accepted_step);
  const waitMs = Math.max(0, (acceptedStep + 1) * 30000 - Date.now() + 250);
  assert.ok(waitMs < 31000, "Unexpected TOTP clock drift");
  await delay(waitMs);
  const loginCode = await generateTOTPCode(enrolled.body.setupKey);
  const authenticated = await browser.request("/api/auth/totp", { method: "POST", body: { token: loginCode } });
  assert.equal(authenticated.status, 200);
  assert.equal(authenticated.body.result, "AUTHENTICATED");
  assertSecureCookie(authenticated.headers, "securebyte_session");
  assert.ok(!browser.cookies.has("securebyte_pending"));
  const sessionToken = browser.cookies.get("securebyte_session");
  const sessions = (await pool.query("SELECT token_hash FROM sessions WHERE user_id = $1", [userId])).rows;
  assert.equal(sessions.length, 1);
  assert.ok(sessions[0].token_hash === hash(sessionToken), "Store only the session token hash");
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM pending_auth WHERE user_id = $1", [userId])).rows[0].count, 0);
  const dashboard = await browser.request("/api/dashboard");
  assert.equal(dashboard.status, 200);
  assert.equal(dashboard.body.dashboard.username, username);
  const session = await browser.request("/api/session");
  assert.equal(session.status, 200);
  assert.equal(session.body.session.username, username);
  assert.deepEqual(Object.keys(session.body.session).sort(), ["account_status", "created_at", "expires_at", "username"]);

  const replayBrowser = client();
  assert.equal((await loginPassword(replayBrowser, username)).status, 200);
  const replay = await replayBrowser.request("/api/auth/totp", { method: "POST", body: { token: loginCode } });
  assert.equal(replay.status, 401);
  assert.equal(replay.body.error.type, "AUTHENTICATION_FAILED");
  assert.ok(!replayBrowser.cookies.has("securebyte_session"));
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM sessions")).rows[0].count, 1);

  // Controlled fixture mutations exercise the existing guard's expiry/status checks.
  await pool.query("UPDATE sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE user_id = $1", [userId]);
  assert.equal((await browser.request("/api/dashboard")).status, 401);
  await pool.query("UPDATE sessions SET expires_at = NOW() + INTERVAL '30 minutes' WHERE user_id = $1", [userId]);
  await pool.query("UPDATE users SET account_status = 'DISABLED' WHERE user_id = $1", [userId]);
  assert.equal((await browser.request("/api/dashboard")).status, 401);
  await pool.query("UPDATE users SET account_status = 'ACTIVE' WHERE user_id = $1", [userId]);
  assert.equal((await browser.request("/api/dashboard")).status, 200);

  assert.equal((await browser.request("/api/session/logout", {
    method: "POST", headers: { "Content-Type": "text/plain" }, raw: "{}",
  })).status, 415);
  const logout = await browser.request("/api/session/logout", { method: "POST", body: {} });
  assert.equal(logout.status, 200);
  assert.equal(logout.body.result, "LOGGED_OUT");
  assert.ok(!browser.cookies.has("securebyte_session"));
  assert.equal((await browser.request("/api/dashboard", {
    headers: { Cookie: `securebyte_session=${sessionToken}` },
  })).status, 401);
  assert.ok((await pool.query("SELECT revoked_at FROM sessions WHERE user_id = $1", [userId])).rows[0].revoked_at);
});
