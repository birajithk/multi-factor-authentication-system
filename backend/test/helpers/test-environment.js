// Tests reset application tables. Require explicit, separate test configuration.
// Do not load .env: a developer's normal application database must not be selected.
export function assertTestEnvironment() {
  if (process.env.NODE_ENV !== "test" || !process.env.DATABASE_NAME?.endsWith("_test")) {
    throw new Error("Use NODE_ENV=test and a dedicated DATABASE_NAME ending in _test.");
  }
  for (const name of ["DATABASE_HOST", "DATABASE_PORT", "DATABASE_USER", "DATABASE_PASSWORD"]) {
    if (!process.env[name]) throw new Error(`Set ${name} explicitly for the test database.`);
  }
  if (!/^[a-fA-F0-9]{64}$/.test(process.env.TOTP_ENCRYPTION_KEY ?? "")) {
    throw new Error("Supply a disposable 64-hex-character TOTP_ENCRYPTION_KEY for tests.");
  }
  if (process.env.COOKIE_SECURE !== "true") {
    throw new Error("Tests require COOKIE_SECURE=true so the production cookie flags are checked.");
  }
}
