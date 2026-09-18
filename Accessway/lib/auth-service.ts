import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from "@simplewebauthn/server";
import { digest, randomToken, nowSeconds, hashPassword, verifyPassword, seal, unseal, makeTotp, verifyTotp, recoveryCodes, cleanRecovery } from "./auth-crypto";

export type AuthEnvironment = { DB: D1Database; MFA_ENCRYPTION_KEY: string; APP_ORIGIN: string };
type User = { id: string; password_hash: string; configured: number; totp_secret: string | null; totp_counter: number; created_at: number };
type Session = { id: string; user_id: string; phase: string; expires: number; created: number; auth_at: number; method: string | null; pending_totp: string | null };
type Credential = { id: string; user_id: string; public_key: string; counter: number; transports: string };
class AuthError extends Error { constructor(message: string, public status = 400, public retryAfter?: number) { super(message); } }
const COOKIE = "__Host-accessway";
const SESSION_SECONDS = 30 * 60;
const PREAUTH_SECONDS = 15 * 60;

export async function handleAuth(request: Request, environment: AuthEnvironment): Promise<Response> {
  const { DB: db, MFA_ENCRYPTION_KEY: key, APP_ORIGIN: origin } = environment;
  let responseCookie: string | undefined;
  const headers = new Headers({ "Cache-Control": "no-store, max-age=0", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" });
  const json = (value: unknown, status = 200) => {
    if (responseCookie) headers.set("Set-Cookie", responseCookie);
    headers.set("Content-Type", "application/json; charset=utf-8");
    return new Response(JSON.stringify(value), { status, headers });
  };
  try {
    if (!db || !origin || !key || Buffer.from(key, "base64url").length !== 32) throw new AuthError("Authentication is temporarily unavailable. Please try again later.", 503);
    const userId = request.headers.get("oai-authenticated-user-id");
    const email = request.headers.get("oai-authenticated-user-email");
    if (!userId || !email) throw new AuthError("Sign in with ChatGPT to open your private Accessway account.", 401);
    // These headers are supplied by the private Sites dispatcher, never by form data.
    const route = new URL(request.url).pathname.replace(/^\/api\/auth\//, "");
    const now = nowSeconds();
    const cookie = request.headers.get("cookie")?.split(";").map(s => s.trim()).find(s => s.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
    const tokenHash = cookie && /^[A-Za-z0-9_-]{43}$/.test(cookie) ? digest(cookie) : null;
    const user = await db.prepare("SELECT * FROM auth_users WHERE id = ?").bind(userId).first<User>();
    const session = tokenHash ? await db.prepare("SELECT * FROM auth_sessions WHERE id = ? AND user_id = ? AND expires > ?").bind(tokenHash, userId, now).first<Session>() : null;

    const requireSession = (phase: string) => {
      if (!session || session.phase !== phase) throw new AuthError(phase === "full" ? "Complete both sign-in steps to continue." : "Your sign-in step expired or was already used. Enter your password again.", 401);
      return session;
    };
    const requireEnrollment = () => {
      if (!user || !session) throw new AuthError("Enter your password before adding a second factor.", 401);
      if (session.phase === "enroll" && !user.configured) return;
      if (session.phase === "full" && user.configured && now - session.auth_at <= 300) return;
      throw new AuthError("For your security, sign out and verify both factors again before adding a method.", 403);
    };
    const rate = async (scope: string, maximum: number, window: number) => {
      const result = await db.prepare(`INSERT INTO auth_limits (id, count, reset) VALUES (?, 1, ?)
        ON CONFLICT(id) DO UPDATE SET count = CASE WHEN reset <= ? THEN 1 ELSE count + 1 END,
        reset = CASE WHEN reset <= ? THEN excluded.reset ELSE reset END RETURNING count, reset`)
        .bind(`${userId}:${scope}`, now + window, now, now).first<{ count: number; reset: number }>();
      if (!result || result.count > maximum) throw new AuthError(`Too many attempts. Please try again in ${Math.max(1, Math.ceil(((result?.reset ?? now + window) - now) / 60))} minutes.`, 429, Math.max(1, (result?.reset ?? now + window) - now));
    };
    const issueSession = async (phase: string, method: string | null = null) => {
      const token = randomToken();
      const lifetime = phase === "full" ? SESSION_SECONDS : PREAUTH_SECONDS;
      // Rotate the browser's previous session. No partially authenticated token is promoted.
      const operations = [db.prepare("INSERT INTO auth_sessions (id, user_id, phase, expires, created, auth_at, method) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(digest(token), userId, phase, now + lifetime, now, phase === "full" ? now : 0, method)];
      if (tokenHash) operations.push(db.prepare("DELETE FROM auth_sessions WHERE id = ? AND user_id = ?").bind(tokenHash, userId));
      operations.push(db.prepare("DELETE FROM auth_sessions WHERE user_id = ? AND expires <= ?").bind(userId, now));
      await db.batch(operations);
      responseCookie = `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${lifetime}`;
    };
    const complete = async (method: string, factorOperations: D1PreparedStatement[] = []) => {
      if (!session || !user) throw new AuthError("Please enter your password again.", 401);
      // A compare-and-swap claim serializes concurrent verification of the same session.
      // Failure after this point fails closed and requires a fresh password login.
      const claimed = await db.prepare("UPDATE auth_sessions SET phase = 'finishing' WHERE id = ? AND user_id = ? AND phase = ? AND expires > ? RETURNING id")
        .bind(session.id, userId, session.phase, now).first();
      if (!claimed) throw new AuthError("This verification was already completed. Reload the page or sign in again.", 409);
      let issuedCodes: string[] | undefined;
      if (!user.configured) {
        issuedCodes = recoveryCodes();
        factorOperations.unshift(db.prepare("INSERT INTO auth_enrollments (user_id) VALUES (?)").bind(userId));
        factorOperations.push(db.prepare("UPDATE auth_users SET configured = 1 WHERE id = ?").bind(userId));
        factorOperations.push(...issuedCodes.map(code => db.prepare("INSERT INTO auth_recovery (hash, user_id) VALUES (?, ?)").bind(digest(`${userId}:${cleanRecovery(code)}`), userId)));
      }
      const token = randomToken();
      factorOperations.push(db.prepare("INSERT INTO auth_sessions (id, user_id, phase, expires, created, auth_at, method) VALUES (?, ?, 'full', ?, ?, ?, ?)").bind(digest(token), userId, now + SESSION_SECONDS, now, now, method));
      factorOperations.push(db.prepare("DELETE FROM auth_sessions WHERE user_id = ? AND phase != 'full'").bind(userId));
      if (session.phase === "full") factorOperations.push(db.prepare("DELETE FROM auth_sessions WHERE id = ?").bind(session.id));
      await db.batch(factorOperations);
      responseCookie = `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}`;
      return { verified: true, ...(issuedCodes ? { recoveryCodes: issuedCodes } : {}) };
    };
    const credentialList = async () => (await db.prepare("SELECT * FROM auth_credentials WHERE user_id = ?").bind(userId).all<Credential>()).results;

    if (request.method === "GET") {
      if (route !== "status" && route !== "account") throw new AuthError("That page is unavailable.", 404);
      if (route === "account") requireSession("full");
      const keys = await credentialList();
      const full = session?.phase === "full";
      const remaining = full ? await db.prepare("SELECT COUNT(*) AS count FROM auth_recovery WHERE user_id = ?").bind(userId).first<{ count: number }>() : null;
      return json({ configured: !!user?.configured, hasPassword: !!user, email, phase: full ? "authenticated" : session?.phase === "enroll" ? "enroll" : session?.phase === "pre" ? "verify" : "password", hasTotp: !!user?.totp_secret, hasKey: keys.length > 0, ...(full ? { recoveryRemaining: remaining?.count ?? 0, recent: now - session.auth_at <= 300 } : {}), ...(session && session.phase !== "finishing" ? { expiresAt: session.expires } : {}) });
    }
    if (request.method !== "POST") throw new AuthError("This request method is not supported.", 405);
    if (request.headers.get("origin") !== origin) throw new AuthError("The request could not be verified. Open Accessway directly and try again.", 403);
    if (!request.headers.get("content-type")?.startsWith("application/json")) throw new AuthError("A JSON request is required.", 415);
    if (Number(request.headers.get("content-length") || 0) > 24000) throw new AuthError("The request is too large.", 413);
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).length > 24000) throw new AuthError("The request is too large.", 413);
    let body: Record<string, any>;
    try { body = JSON.parse(rawBody); } catch { throw new AuthError("The request was not readable."); }
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new AuthError("The request was not readable.");

    if (route === "logout") {
      if (tokenHash) await db.prepare("DELETE FROM auth_sessions WHERE id = ? AND user_id = ?").bind(tokenHash, userId).run();
      responseCookie = `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
      return json({ signedOut: true });
    }
    await rate("requests", 80, 900);
    if (route === "extend") {
      if (!session || !["full", "enroll", "pre"].includes(session.phase)) throw new AuthError("Your session expired. Please enter your password again.", 401);
      const duration = session.phase === "full" ? SESSION_SECONDS : PREAUTH_SECONDS;
      const maximum = session.created + duration * 11;
      const expires = Math.min(session.expires + duration, maximum);
      if (expires <= session.expires) throw new AuthError("This session has reached its limit. Sign in again to continue.");
      await db.prepare("UPDATE auth_sessions SET expires = ? WHERE id = ? AND user_id = ? AND expires > ?").bind(expires, session.id, userId, now).run();
      responseCookie = `${COOKIE}=${cookie}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${expires - now}`;
      return json({ expiresAt: expires });
    }
    if (route === "setup" || route === "password") {
      await rate("password", 8, 900);
      if (typeof body.password !== "string" || body.password.length > 128 || !body.password.length) throw new AuthError("Enter a password of up to 128 characters.");
      if (!user) {
        if (route !== "setup") throw new AuthError("Set up a password for this account first.");
        if ([...body.password.normalize("NFC")].length < 15) throw new AuthError("Use at least 15 characters. A phrase of several words works well.");
        const common = new Set(["passwordpassword", "123456789012345", "1234567890123456", "qwertyuiopasdfgh", "thisismypassword", "password123456789", "abcdefghijklmnop"]);
        if (common.has(body.password.toLowerCase()) || /^(.)\1+$/u.test(body.password)) throw new AuthError("That password is too easy to guess. Choose a different phrase.");
        const hashed = await hashPassword(body.password);
        const inserted = await db.prepare("INSERT INTO auth_users (id, password_hash, configured, totp_counter, created_at) VALUES (?, ?, 0, -1, ?) ON CONFLICT(id) DO NOTHING RETURNING id").bind(userId, hashed, now).first();
        if (!inserted) throw new AuthError("Setup has already started in another window. Enter the password you chose there.", 409);
        await issueSession("enroll");
      } else {
        if (!(await verifyPassword(body.password, user.password_hash))) throw new AuthError("The password wasn’t accepted. Check it and try again.", 401);
        await issueSession(user.configured ? "pre" : "enroll");
      }
      return json({ passwordVerified: true });
    }
    if (route === "totp/setup") {
      requireEnrollment();
      if (user!.totp_secret) throw new AuthError("An authenticator is already connected to this account.", 409);
      const setup = makeTotp(email);
      const encrypted = seal(setup.secret, key, `${userId}:totp`);
      await db.prepare("UPDATE auth_sessions SET pending_totp = ? WHERE id = ? AND user_id = ?").bind(encrypted, session!.id, userId).run();
      return json(setup);
    }
    if (route === "totp/enroll" || route === "totp/verify") {
      await rate("verification", 10, 300);
      const enrolling = route === "totp/enroll";
      if (enrolling) requireEnrollment(); else requireSession("pre");
      const encrypted = enrolling ? session!.pending_totp : user?.totp_secret;
      if (!encrypted || !user) throw new AuthError("Connect an authenticator before verifying its code.");
      if (enrolling && user.totp_secret) throw new AuthError("An authenticator is already connected.", 409);
      const code = typeof body.code === "string" ? body.code.replace(/[\s-]/g, "") : "";
      const counter = verifyTotp(unseal(encrypted, key, `${userId}:totp`), code);
      if (counter === null) throw new AuthError("That code wasn’t accepted. Use the current 6-digit code from your app, and check your device’s clock.", 401);
      if (enrolling) {
        return json(await complete("totp", [db.prepare("UPDATE auth_users SET totp_secret = ?, totp_counter = ? WHERE id = ? AND totp_secret IS NULL").bind(encrypted, counter, userId)]));
      }
      const consumed = await db.prepare("UPDATE auth_users SET totp_counter = ? WHERE id = ? AND totp_counter < ? RETURNING id").bind(counter, userId, counter).first();
      if (!consumed) throw new AuthError("That code was already used. Wait for the next code in your app.", 401);
      return json(await complete("totp"));
    }
    if (route === "recovery/verify") {
      requireSession("pre"); await rate("verification", 10, 300);
      const code = typeof body.code === "string" ? cleanRecovery(body.code) : "";
      if (!/^[A-F0-9]{24}$/.test(code)) throw new AuthError("Paste one complete recovery code, including all 24 letters and numbers.");
      const used = await db.prepare("DELETE FROM auth_recovery WHERE hash = ? AND user_id = ? RETURNING hash").bind(digest(`${userId}:${code}`), userId).first();
      if (!used) throw new AuthError("That recovery code wasn’t accepted or has already been used. Try another saved code.", 401);
      return json(await complete("recovery"));
    }
    const rpID = new URL(origin).hostname;
    if (route === "key/register/options" || route === "key/authenticate/options") {
      const register = route === "key/register/options";
      if (register) requireEnrollment(); else requireSession("pre");
      const keys = await credentialList();
      if (register && keys.length) throw new AuthError("A passkey or security key is already registered.", 409);
      if (!register && !keys.length) throw new AuthError("No security key is registered. Choose another method.");
      const descriptors = keys.map(k => ({ id: k.id, transports: JSON.parse(k.transports) }));
      const options = register ? await generateRegistrationOptions({ rpName: "Accessway", rpID, userName: email, userID: new Uint8Array(Buffer.from(digest(userId), "hex")), timeout: 300000, attestationType: "none", excludeCredentials: descriptors, authenticatorSelection: { residentKey: "preferred", userVerification: "required" } }) : await generateAuthenticationOptions({ rpID, timeout: 300000, allowCredentials: descriptors, userVerification: "required" });
      await db.prepare("INSERT INTO auth_challenges (session_id, challenge, mode, expires) VALUES (?, ?, ?, ?) ON CONFLICT(session_id) DO UPDATE SET challenge = excluded.challenge, mode = excluded.mode, expires = excluded.expires")
        .bind(session!.id, options.challenge, register ? "register" : "authenticate", now + 300).run();
      return json(options);
    }
    if (route === "key/register/verify" || route === "key/authenticate/verify") {
      const register = route === "key/register/verify";
      if (register) requireEnrollment(); else requireSession("pre");
      await rate("verification", 10, 300);
      const challenge = await db.prepare("DELETE FROM auth_challenges WHERE session_id = ? AND mode = ? AND expires > ? RETURNING challenge").bind(session!.id, register ? "register" : "authenticate", now).first<{ challenge: string }>();
      if (!challenge || !body.response || typeof body.response.id !== "string") throw new AuthError("The security prompt expired or was already used. Open it again.", 401);
      if (register) {
        let verification;
        try { verification = await verifyRegistrationResponse({ response: body.response, expectedChallenge: challenge.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true }); }
        catch { throw new AuthError("The security key could not be verified. Try again or choose another method.", 401); }
        if (!verification.verified) throw new AuthError("The security key could not be verified.", 401);
        const credential = verification.registrationInfo.credential;
        return json(await complete("key", [db.prepare("INSERT INTO auth_credentials (id, user_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)").bind(credential.id, userId, Buffer.from(credential.publicKey).toString("base64url"), credential.counter, JSON.stringify(credential.transports || []))]));
      }
      const credential = await db.prepare("SELECT * FROM auth_credentials WHERE id = ? AND user_id = ?").bind(body.response.id, userId).first<Credential>();
      if (!credential) throw new AuthError("This key is not registered to your account. Choose another method.", 401);
      let verification;
      try { verification = await verifyAuthenticationResponse({ response: body.response, expectedChallenge: challenge.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true, credential: { id: credential.id, publicKey: new Uint8Array(Buffer.from(credential.public_key, "base64url")), counter: credential.counter, transports: JSON.parse(credential.transports) } }); }
      catch { throw new AuthError("The security key could not be verified. Try again or choose another method.", 401); }
      if (!verification.verified) throw new AuthError("The security key could not be verified.", 401);
      const updated = await db.prepare("UPDATE auth_credentials SET counter = ? WHERE id = ? AND user_id = ? AND counter = ? RETURNING id").bind(verification.authenticationInfo.newCounter, credential.id, userId, credential.counter).first();
      if (!updated) throw new AuthError("This key was used in another window. Try again.", 409);
      return json(await complete("key"));
    }
    throw new AuthError("That authentication action is unavailable.", 404);
  } catch (error) {
    if (error instanceof AuthError) {
      if (error.retryAfter) headers.set("Retry-After", String(error.retryAfter));
      return json({ error: error.message }, error.status);
    }
    // Do not log credentials, tokens, request bodies, or low-level verification errors.
    console.error("Accessway: an authentication storage or service operation failed.");
    return json({ error: "Authentication is temporarily unavailable. Your account has not been unlocked. Please try again." }, 503);
  }
}
