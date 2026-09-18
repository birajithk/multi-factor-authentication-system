import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readdirSync, readFileSync } from 'node:fs';
import { randomBytes, createHash, generateKeyPairSync, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { handleAuth } from '../.sites-runtime/tests/auth-service.mjs';
import { digest, totp, seal, unseal } from '../.sites-runtime/tests/auth-crypto.mjs';

const origin = 'https://auth.example.test';
const password = 'Accessible rivers carry bright stars 824';
function fixture() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec('PRAGMA foreign_keys = ON');
  for (const file of readdirSync(new URL('../drizzle/', import.meta.url)).filter(n => n.endsWith('.sql')).sort()) sqlite.exec(readFileSync(new URL(`../drizzle/${file}`, import.meta.url), 'utf8'));
  class Statement {
    constructor(sql, args = []) { this.sql = sql; this.args = args; }
    bind(...args) { return new Statement(this.sql, args); }
    async first() { return sqlite.prepare(this.sql).get(...this.args) || null; }
    async all() { return { results: sqlite.prepare(this.sql).all(...this.args) }; }
    async run() { const r = sqlite.prepare(this.sql).run(...this.args); return { success: true, meta: { changes: Number(r.changes) } }; }
  }
  const env = { DB: { prepare: sql => new Statement(sql), async batch(statements) {
    sqlite.exec('BEGIN');
    try { const values = []; for (const statement of statements) values.push(await statement.run()); sqlite.exec('COMMIT'); return values; }
    catch (error) { sqlite.exec('ROLLBACK'); throw error; }
  } }, MFA_ENCRYPTION_KEY: randomBytes(32).toString('base64url'), APP_ORIGIN: origin };
  let cookie = '';
  async function call(action, body, options = {}) {
    const headers = new Headers({ 'oai-authenticated-user-id': options.user || 'test-user', 'oai-authenticated-user-email': 'test@example.test', cookie: options.cookie ?? cookie });
    if (options.anonymous) { headers.delete('oai-authenticated-user-id'); headers.delete('oai-authenticated-user-email'); }
    if (body !== undefined) { headers.set('content-type', 'application/json'); headers.set('origin', options.origin || origin); }
    const response = await handleAuth(new Request(`${origin}/api/auth/${action}`, { method: body === undefined ? 'GET' : 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body) }), env);
    const setCookie = response.headers.get('set-cookie');
    if (setCookie && !options.noAdopt) cookie = setCookie.split(';')[0];
    return { status: response.status, data: await response.json(), headers: response.headers, cookie: setCookie };
  }
  return { sqlite, env, call, get cookie() { return cookie; }, close() { sqlite.close(); } };
}
async function enrollTotp(f) {
  assert.equal((await f.call('setup', { password })).status, 200);
  const setup = await f.call('totp/setup', {});
  assert.equal(setup.status, 200);
  const token = totp(setup.data.secret).generate();
  const enrolled = await f.call('totp/enroll', { code: token });
  assert.equal(enrolled.status, 200, JSON.stringify(enrolled.data));
  return { secret: setup.data.secret, token, codes: enrolled.data.recoveryCodes };
}
const sha = b => createHash('sha256').update(b).digest();
const b64 = b => Buffer.from(b).toString('base64url');
function softwareKey() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const id = randomBytes(32);
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const cose = isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1], [-2, new Uint8Array(Buffer.from(jwk.x, 'base64url'))], [-3, new Uint8Array(Buffer.from(jwk.y, 'base64url'))]]));
  function registration(options, uv = true) {
    const size = Buffer.alloc(2); size.writeUInt16BE(id.length);
    const authData = Buffer.concat([sha(Buffer.from(new URL(origin).hostname)), Buffer.from([uv ? 0x45 : 0x41]), Buffer.alloc(4), Buffer.alloc(16), size, Buffer.from(id), Buffer.from(cose)]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin }));
    return { id: b64(id), rawId: b64(id), type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64(clientData), attestationObject: b64(isoCBOR.encode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', new Uint8Array(authData)]]))), transports: ['internal'] } };
  }
  function authentication(options, counter = 1, overrides = {}) {
    const count = Buffer.alloc(4); count.writeUInt32BE(counter);
    const authData = Buffer.concat([sha(Buffer.from(new URL(origin).hostname)), Buffer.from([0x05]), count]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, ...overrides }));
    const signature = sign('sha256', Buffer.concat([authData, sha(clientData)]), pair.privateKey);
    return { id: b64(id), rawId: b64(id), type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: b64(clientData), authenticatorData: b64(authData), signature: b64(signature) } };
  }
  return { registration, authentication };
}

test('identity, CSRF, input, and first-factor gates fail closed', async () => {
  const f = fixture();
  assert.equal((await f.call('status', undefined, { anonymous: true })).status, 401);
  assert.equal((await f.call('setup', { password }, { origin: 'https://attacker.test' })).status, 403);
  assert.equal((await f.call('setup', { password: 'too short' })).status, 400);
  assert.equal((await f.call('account')).status, 401);
  assert.equal((await f.call('totp/setup', {})).status, 401);
  assert.equal((await f.call('setup', { password })).status, 200);
  assert.equal((await f.call('account')).status, 401);
  assert.equal((await f.call('recovery/verify', { code: 'A'.repeat(24) })).status, 401);
  assert.equal((await f.call('status')).data.phase, 'enroll');
  assert.equal((await f.call('status')).headers.get('cache-control'), 'no-store, max-age=0');
  f.close();
});

test('TOTP enrollment requires possession, rotates session, encrypts secrets, and hashes recovery codes', async () => {
  const f = fixture();
  await f.call('setup', { password });
  const oldCookie = f.cookie;
  const setup = await f.call('totp/setup', {});
  assert.equal((await f.call('totp/enroll', { code: 'invalid' })).status, 401);
  assert.equal((await f.call('account')).status, 401);
  const enrolled = await f.call('totp/enroll', { code: totp(setup.data.secret).generate() });
  assert.equal(enrolled.status, 200);
  assert.equal(enrolled.data.recoveryCodes.length, 8);
  assert.notEqual(f.cookie, oldCookie);
  assert.match(enrolled.cookie, /HttpOnly; Secure; SameSite=Lax/);
  const row = f.sqlite.prepare('SELECT * FROM auth_users').get();
  assert.notEqual(row.password_hash, password);
  assert.notEqual(row.totp_secret, setup.data.secret);
  assert.equal(unseal(row.totp_secret, f.env.MFA_ENCRYPTION_KEY, 'test-user:totp'), setup.data.secret);
  assert.equal(f.sqlite.prepare('SELECT length(hash) AS length FROM auth_recovery LIMIT 1').get().length, 64);
  assert.equal((await f.call('account')).status, 200);
  assert.equal((await f.call('account', undefined, { cookie: oldCookie })).status, 401);
  assert.equal((await f.call('account', undefined, { user: 'different-user' })).status, 401);
  f.close();
});

test('TOTP replay is rejected; a later code completes both factors', async () => {
  const f = fixture(); const data = await enrollTotp(f);
  await f.call('logout', {});
  assert.equal((await f.call('password', { password: 'wrong-password' })).status, 401);
  assert.equal((await f.call('password', { password })).status, 200);
  assert.equal((await f.call('account')).status, 401);
  assert.equal((await f.call('totp/verify', { code: data.token })).status, 401);
  const future = Date.now() + 31000;
  // The adjacent time step is accepted for limited clock skew; still single use.
  const next = totp(data.secret).generate({ timestamp: future });
  assert.equal((await f.call('totp/verify', { code: next })).status, 200);
  assert.equal((await f.call('account')).status, 200);
  f.close();
});

test('recovery codes are single use even with concurrent requests', async () => {
  const f = fixture(); const data = await enrollTotp(f);
  await f.call('logout', {}); await f.call('password', { password });
  const cookie = f.cookie;
  const results = await Promise.all([f.call('recovery/verify', { code: data.codes[0] }, { cookie, noAdopt: true }), f.call('recovery/verify', { code: data.codes[0] }, { cookie, noAdopt: true })]);
  assert.equal(results.filter(r => r.status === 200).length, 1);
  assert.equal(f.sqlite.prepare('SELECT count(*) AS count FROM auth_recovery').get().count, 7);
  await f.call('password', { password });
  assert.equal((await f.call('recovery/verify', { code: data.codes[0] })).status, 401);
  assert.equal((await f.call('account')).status, 401);
  f.close();
});

test('expired sessions fail, and adding a factor requires recent MFA', async () => {
  const f = fixture(); await enrollTotp(f);
  const hash = digest(f.cookie.split('=')[1]);
  f.sqlite.prepare('UPDATE auth_sessions SET auth_at = auth_at - 301 WHERE id = ?').run(hash);
  assert.equal((await f.call('key/register/options', {})).status, 403);
  assert.equal((await f.call('account')).status, 200);
  f.sqlite.prepare('UPDATE auth_sessions SET expires = 1 WHERE id = ?').run(hash);
  assert.equal((await f.call('account')).status, 401);
  assert.equal((await f.call('extend', {})).status, 401);
  f.close();
});

test('session time can be extended ten times without refreshing recent-MFA age', async () => {
  const f = fixture(); await enrollTotp(f);
  const initial = f.sqlite.prepare("SELECT * FROM auth_sessions WHERE phase = 'full'").get();
  for (let i = 0; i < 10; i++) assert.equal((await f.call('extend', {})).status, 200);
  assert.equal((await f.call('extend', {})).status, 400);
  const updated = f.sqlite.prepare("SELECT * FROM auth_sessions WHERE phase = 'full'").get();
  assert.equal(updated.auth_at, initial.auth_at);
  assert.equal(updated.expires - initial.expires, 18000);
  f.close();
});

test('verification attempts are throttled independently of new sessions', async () => {
  const f = fixture(); await f.call('setup', { password });
  await f.call('totp/setup', {});
  for (let i = 0; i < 10; i++) assert.equal((await f.call('totp/enroll', { code: 'invalid' })).status, 401);
  const limited = await f.call('totp/enroll', { code: 'invalid' });
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get('retry-after')) > 0);
  assert.equal((await f.call('account')).status, 401);
  f.close();
});

test('password attempts are limited', async () => {
  const f = fixture(); await f.call('setup', { password });
  for (let i = 0; i < 7; i++) assert.equal((await f.call('password', { password: 'wrong-password' })).status, 401);
  assert.equal((await f.call('password', { password })).status, 429);
  f.close();
});

test('passkey requires user verification, correct origin, cryptographic proof, and a fresh challenge', async () => {
  const f = fixture(); const key = softwareKey();
  await f.call('setup', { password });
  let options = await f.call('key/register/options', {});
  assert.equal((await f.call('key/register/verify', { response: key.registration(options.data, false) })).status, 401);
  assert.equal((await f.call('account')).status, 401);
  options = await f.call('key/register/options', {});
  const enrolled = await f.call('key/register/verify', { response: key.registration(options.data) });
  assert.equal(enrolled.status, 200, JSON.stringify(enrolled.data));
  assert.equal(enrolled.data.recoveryCodes.length, 8);
  assert.equal((await f.call('account')).data.hasKey, true);
  await f.call('logout', {}); await f.call('password', { password });
  let authOptions = await f.call('key/authenticate/options', {});
  const wrongOrigin = key.authentication(authOptions.data, 1, { origin: 'https://attacker.test' });
  assert.equal((await f.call('key/authenticate/verify', { response: wrongOrigin })).status, 401);
  // A consumed challenge cannot be retried with a corrected response.
  assert.equal((await f.call('key/authenticate/verify', { response: key.authentication(authOptions.data) })).status, 401);
  authOptions = await f.call('key/authenticate/options', {});
  const valid = key.authentication(authOptions.data, 2);
  assert.equal((await f.call('key/authenticate/verify', { response: valid })).status, 200);
  assert.equal((await f.call('account')).status, 200);
  assert.equal((await f.call('key/authenticate/verify', { response: valid })).status, 401);
  assert.equal(f.sqlite.prepare('SELECT counter FROM auth_credentials').get().counter, 2);
  f.close();
});

test('encrypted authenticator data is bound to the owner and rejects tampering', () => {
  const key = randomBytes(32).toString('base64url');
  const value = seal('TEST-SECRET', key, 'user-one:totp');
  assert.equal(unseal(value, key, 'user-one:totp'), 'TEST-SECRET');
  assert.throws(() => unseal(value, key, 'user-two:totp'));
  const parts = value.split('.'); parts[1] = b64(randomBytes(11));
  assert.throws(() => unseal(parts.join('.'), key, 'user-one:totp'));
});
