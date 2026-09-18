import ts from 'typescript';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
await mkdir(new URL('../.sites-runtime/tests/', import.meta.url), { recursive: true });
for (const name of ['auth-crypto', 'auth-service']) {
  const source = await readFile(new URL(`../lib/${name}.ts`, import.meta.url), 'utf8');
  const output = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText.replace('"./auth-crypto"', '"./auth-crypto.mjs"');
  await writeFile(new URL(`../.sites-runtime/tests/${name}.mjs`, import.meta.url), output);
}
await import('./auth.test.mjs');
