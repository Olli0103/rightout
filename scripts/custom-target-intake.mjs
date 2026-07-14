#!/usr/bin/env node

import { createCustomTargetVault } from "../dist/lib/custom-targets.mjs";
import { createEncryptedFileKeyedStore } from "../dist/lib/file-keyed-store.mjs";

function stateDirFromArgs(argv) {
  const index = argv.indexOf("--state-dir");
  if (index < 0 || index + 1 >= argv.length || argv.length !== 2) throw new Error("usage: --state-dir PATH");
  return argv[index + 1];
}

async function readInput() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 16 * 1024) throw new Error("intake input too large");
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw new Error("intake input must be JSON"); }
}

try {
  const stateDir = stateDirFromArgs(process.argv.slice(2));
  const secret = process.env.RIGHTOUT_STATE_ENCRYPTION_KEY;
  if (typeof secret !== "string" || secret.length < 32) throw new Error("RIGHTOUT_STATE_ENCRYPTION_KEY is required");
  const store = createEncryptedFileKeyedStore({
    stateDir,
    namespace: "rightout-custom-targets-v1",
    maxEntries: 500,
    defaultTtlMs: 365 * 24 * 60 * 60_000,
    getSecret: () => secret,
  });
  const result = await createCustomTargetVault(store).intake(await readInput());
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  const message = error instanceof Error && /^rightout_[a-z0-9_]+$/u.test(error.message)
    ? error.message
    : "rightout_custom_target_intake_failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}
