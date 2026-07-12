import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createCaseLedger } from "../../lib/cases.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { __test as fileStoreTest } from "../../lib/file-keyed-store.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const stateKey = "dummy-state-key-with-more-than-32-characters";

function registerPlugin(plugin, stateDir, stateRetentionDays = 45) {
  const tools = new Map();
  let beforeToolCall;
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
    registerTool(tool) {
      const resolved = typeof tool === "function" ? tool({ browser: {} }) : tool;
      tools.set(resolved.name, resolved);
    },
    registerSecurityAuditCollector() {},
    pluginConfig: {
      stateEncryptionKey: stateKey,
      stateRetentionDays,
      profiles: { [profileId]: { payload: JSON.stringify({ fullName: "Avery Example", contactEmail: "avery@example.invalid" }) } },
    },
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  return { tools, beforeToolCall };
}

test("an untouched legacy case receives the configured finite retention on first read", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-retention-legacy-runtime-"));
  const legacyStore = createEncryptedFileKeyedStore({
    stateDir, namespace: "rightout-cases-v1", maxEntries: 100, getSecret: () => stateKey,
  });
  await legacyStore.register(profileId, {
    schema_version: 1,
    subject_ref: profileId,
    created_at: "2026-07-12T00:00:00.000Z",
    updated_at: "2026-07-12T00:00:00.000Z",
    brokers: {},
  });

  const plugin = (await import("../../index.ts")).default;
  const { tools } = registerPlugin(plugin, stateDir);
  await tools.get("rightout_case_status").execute("legacy-read", { profileId });

  const bytes = await readFile(join(stateDir, "rightout-plugin-state-v1", "rightout-cases-v1.json.enc"));
  const state = fileStoreTest.decryptState(bytes, stateKey, "rightout-cases-v1");
  const envelope = state.entries[profileId];
  assert.ok(envelope);
  assert.equal(envelope.expiresAt - envelope.createdAt, 45 * 24 * 60 * 60_000);
});

test("configured finite retention is persisted on encrypted subject cases", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-retention-runtime-"));
  const plugin = (await import("../../index.ts")).default;
  const { tools, beforeToolCall } = registerPlugin(plugin, stateDir);

  const bootstrapLedger = createCaseLedger(createEncryptedFileKeyedStore({
    stateDir, namespace: "rightout-cases-v1", maxEntries: 100, getSecret: () => stateKey,
  }));
  await bootstrapLedger.reserveSubmission(profileId, "fullenrich_eu", {
    channel: "smtp_email", discoveryRequirement: "not_required_for_data_subject_request",
  });
  await bootstrapLedger.recordRemoval({
    state: "submitted", subject_ref: profileId, broker_id: "fullenrich_eu",
    generated_at: "2026-07-12T10:00:00Z",
    delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"],
    disclosures: { to_broker: ["contact_email"] },
  }, 30);

  const input = { profileId, brokerId: "fullenrich_eu", outcome: "erasure_confirmed" };
  const approval = await beforeToolCall({
    toolName: "rightout_record_controller_outcome", params: input, toolCallId: "retention-approved",
  });
  approval.requireApproval.onResolution("allow-once");
  await tools.get("rightout_record_controller_outcome").execute("retention-approved", input);

  const bytes = await readFile(join(stateDir, "rightout-plugin-state-v1", "rightout-cases-v1.json.enc"));
  const state = fileStoreTest.decryptState(bytes, stateKey, "rightout-cases-v1");
  const envelope = state.entries[profileId];
  assert.ok(envelope);
  assert.equal(envelope.expiresAt - envelope.createdAt, 45 * 24 * 60 * 60_000);
  assert.equal(JSON.stringify(state).includes("Avery Example"), false);
  assert.equal(JSON.stringify(state).includes("avery@example.invalid"), false);
});
