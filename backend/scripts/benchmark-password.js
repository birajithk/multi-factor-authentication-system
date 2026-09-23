import { performance } from "node:perf_hooks";

import {
  hashPassword,
  verifyPassword,
} from "../src/services/password.service.js";

const BENCHMARK_PASSWORD =
  "SecureByte benchmark password 2026";

const WARMUP_RUNS = 3;
const MEASURED_RUNS = 20;

function calculateStatistics(values) {
  const sorted = [...values].sort((a, b) => a - b);

  const total = sorted.reduce(
    (sum, value) => sum + value,
    0,
  );

  const average = total / sorted.length;

  const middle = Math.floor(sorted.length / 2);

  const median =
    sorted.length % 2 === 0
      ? (sorted[middle - 1] + sorted[middle]) / 2
      : sorted[middle];

  return {
    min: sorted[0],
    max: sorted[sorted.length - 1],
    average,
    median,
  };
}

async function measure(operation) {
  const start = performance.now();

  await operation();

  const end = performance.now();

  return end - start;
}

console.log("SecureByte Argon2id benchmark");
console.log("----------------------------");
console.log(`Warm-up runs: ${WARMUP_RUNS}`);
console.log(`Measured runs: ${MEASURED_RUNS}`);
console.log();

//
// Warm up the implementation before recording results.
//
for (let i = 0; i < WARMUP_RUNS; i++) {
  const hash = await hashPassword(
    BENCHMARK_PASSWORD,
  );

  await verifyPassword(
    hash,
    BENCHMARK_PASSWORD,
  );
}

const hashTimes = [];
const verifyTimes = [];

for (let i = 0; i < MEASURED_RUNS; i++) {
  let generatedHash;

  const hashTime = await measure(async () => {
    generatedHash = await hashPassword(
      BENCHMARK_PASSWORD,
    );
  });

  hashTimes.push(hashTime);

  const verifyTime = await measure(async () => {
    const valid = await verifyPassword(
      generatedHash,
      BENCHMARK_PASSWORD,
    );

    if (!valid) {
      throw new Error(
        "Benchmark verification unexpectedly failed.",
      );
    }
  });

  verifyTimes.push(verifyTime);
}

const hashStats =
  calculateStatistics(hashTimes);

const verifyStats =
  calculateStatistics(verifyTimes);

function printStats(label, stats) {
  console.log(label);
  console.log(
    `  Average: ${stats.average.toFixed(2)} ms`,
  );
  console.log(
    `  Median:  ${stats.median.toFixed(2)} ms`,
  );
  console.log(
    `  Minimum: ${stats.min.toFixed(2)} ms`,
  );
  console.log(
    `  Maximum: ${stats.max.toFixed(2)} ms`,
  );
}

console.log();
printStats("Password hashing:", hashStats);

console.log();
printStats(
  "Password verification:",
  verifyStats,
);