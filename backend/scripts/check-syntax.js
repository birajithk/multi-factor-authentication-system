import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

async function checkDirectory(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      await checkDirectory(path);
    } else if (path.endsWith(".js")) {
      const result = spawnSync(process.execPath, ["--check", path], { stdio: "inherit" });
      if (result.error) throw result.error;
      if (result.status !== 0) process.exit(result.status ?? 1);
    }
  }
}

for (const directory of ["src", "scripts", "test"]) await checkDirectory(directory);
// Also load the real import graph, native Argon2 module and password blocklist.
await import("../src/app.js");
console.log("Backend syntax and application imports passed.");
