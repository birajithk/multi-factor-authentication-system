import { readFile } from "node:fs/promises";
import pool from "../src/config/database.js";
import { assertTestEnvironment } from "../test/helpers/test-environment.js";

assertTestEnvironment();
try {
  const schema = await readFile(new URL("../src/database/schema.sql", import.meta.url), "utf8");
  // One query uses one connection and applies the schema atomically. SQL errors fail CI.
  await pool.query(`BEGIN;\n${schema}\nCOMMIT;`);
  console.log("Test database schema applied.");
} finally {
  await pool.end();
}
