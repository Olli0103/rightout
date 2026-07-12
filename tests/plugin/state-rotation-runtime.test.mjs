import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";

const previousKey = "dummy-previous-state-key-with-more-than-32-characters";
const activeKey = "dummy-active-state-key-with-more-than-32-characters";

test("state-key rotation is separately approved, restart-safe, and provider-free", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-state-rotation-runtime-"));
  const previousStore = createEncryptedFileKeyedStore({
    stateDir,
    namespace: "rightout-cases-v1",
    maxEntries: 100,
    getSecret: () => previousKey,
  });
  await previousStore.register("profile_a1b2c3d4e5f60718", {
    schema_version: 1,
    subject_ref: "profile_a1b2c3d4e5f60718",
    created_at: "2026-07-12T00:00:00.000Z",
    updated_at: "2026-07-12T00:00:00.000Z",
    brokers: {},
  });

  const plugin = (await import("../../index.ts")).default;
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
    pluginConfig: { stateEncryptionKey: activeKey, previousStateEncryptionKeys: [previousKey] },
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });

  const denied = await beforeToolCall({ toolName: "rightout_rotate_state_key", params: {}, toolCallId: "rotate-denied" });
  assert.doesNotMatch(denied.requireApproval.description, new RegExp(previousKey));
  denied.requireApproval.onResolution("deny");
  await assert.rejects(tools.get("rightout_rotate_state_key").execute("rotate-denied", {}), /approval_binding_failed/);

  const approved = await beforeToolCall({ toolName: "rightout_rotate_state_key", params: {}, toolCallId: "rotate-approved" });
  approved.requireApproval.onResolution("allow-once");
  const result = await tools.get("rightout_rotate_state_key").execute("rotate-approved", {});
  assert.equal(result.details.state, "local_state_key_rotated");
  assert.equal(result.details.reencrypted_entries.cases, 1);
  assert.equal(result.details.provider_writes, 0);
  assert.equal(result.details.raw_pii_in_report, false);

  const activeOnly = createEncryptedFileKeyedStore({
    stateDir, namespace: "rightout-cases-v1", maxEntries: 100, getSecret: () => activeKey,
  });
  assert.ok(await activeOnly.lookup("profile_a1b2c3d4e5f60718"));
  await assert.rejects(previousStore.lookup("profile_a1b2c3d4e5f60718"), /decryption_failed/);
});
