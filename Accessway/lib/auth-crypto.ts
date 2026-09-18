import { randomBytes, scrypt, timingSafeEqual, createHash, createCipheriv, createDecipheriv } from "node:crypto";
import * as OTPAuth from "otpauth";

export const nowSeconds = () => Math.floor(Date.now() / 1000);
export const randomToken = () => randomBytes(32).toString("base64url");
export const digest = (text: string) => createHash("sha256").update(text).digest("hex");

function derive(password: string, salt: Buffer) {
  return new Promise<Buffer>((resolve, reject) => scrypt(password.normalize("NFC"), salt, 32, { N: 32768, r: 8, p: 3, maxmem: 48 * 1024 * 1024 }, (err, value) => err ? reject(err) : resolve(value)));
}
export async function hashPassword(password: string) {
  const salt = randomBytes(16);
  return `scrypt-32768-8-3$${salt.toString("base64url")}$${(await derive(password, salt)).toString("base64url")}`;
}
export async function verifyPassword(password: string, value: string) {
  const [version, salt, hash] = value.split("$");
  if (version !== "scrypt-32768-8-3" || !salt || !hash) return false;
  const expected = Buffer.from(hash, "base64url");
  const actual = await derive(password, Buffer.from(salt, "base64url"));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
export function seal(secret: string, key: string, context: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key, "base64url"), iv);
  cipher.setAAD(Buffer.from(context));
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${ciphertext.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}`;
}
export function unseal(value: string, key: string, context: string) {
  const [iv, ciphertext, tag] = value.split(".");
  const cipher = createDecipheriv("aes-256-gcm", Buffer.from(key, "base64url"), Buffer.from(iv, "base64url"));
  cipher.setAAD(Buffer.from(context)); cipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([cipher.update(Buffer.from(ciphertext, "base64url")), cipher.final()]).toString("utf8");
}
export function totp(secret: string, email = "account") {
  return new OTPAuth.TOTP({ issuer: "Accessway", label: email, algorithm: "SHA1", digits: 6, period: 30, secret: OTPAuth.Secret.fromBase32(secret) });
}
export function makeTotp(email: string) {
  const secret = new OTPAuth.Secret({ size: 20 }).base32;
  return { secret, uri: totp(secret, email).toString() };
}
export function verifyTotp(secret: string, code: string, timestamp = Date.now()) {
  if (!/^\d{6}$/.test(code)) return null;
  const delta = totp(secret).validate({ token: code, window: 1, timestamp });
  return delta === null ? null : Math.floor(timestamp / 30000) + delta;
}
export function recoveryCodes() {
  return Array.from({ length: 8 }, () => randomBytes(12).toString("hex").toUpperCase().match(/.{4}/g)!.join("-"));
}
export const cleanRecovery = (code: string) => code.replace(/[\s-]/g, "").toUpperCase();
