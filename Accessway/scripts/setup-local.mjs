import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import './sites-env.mjs';

const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 13)) throw new Error('Use Node.js 22.13 or newer. Node.js 24 is recommended.');
const root = fileURLToPath(new URL('../', import.meta.url));
process.chdir(root);
if (!existsSync('node_modules/wrangler/bin/wrangler.js')) throw new Error('Run pnpm install --frozen-lockfile first.');
if (existsSync('.dev.vars')) throw new Error('An existing .dev.vars takes precedence over .env. Preserve it and configure APP_ORIGIN and MFA_ENCRYPTION_KEY explicitly before continuing.');
if (!existsSync('.env')) {
  writeFileSync('.env', `APP_ORIGIN=http://localhost:5173\nMFA_ENCRYPTION_KEY=${randomBytes(32).toString('base64url')}\n`, { flag: 'wx', mode: 0o600 });
  console.log('Created a fresh, private local configuration.');
} else console.log('Preserving your existing .env configuration.');
mkdirSync('.wrangler/state', { recursive: true });
const result = spawnSync(process.execPath, [
  'node_modules/wrangler/bin/wrangler.js', 'd1', 'migrations', 'apply', 'DB',
  '--local', '--config', 'wrangler.local.json', '--persist-to', '.wrangler/state',
], { cwd: root, stdio: ['pipe', 'inherit', 'inherit'], input: 'y\n', env: { ...process.env, CI: '1' } });
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status || 1);
console.log('\nLocal setup complete. Run pnpm dev, then open http://localhost:5173');
console.log('Use the local Sign in with ChatGPT link to select the built-in demo identity.');
console.log('The demo identity does not bypass the Accessway password or second factor.');
