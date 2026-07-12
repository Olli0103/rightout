import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createCaseLedger } from "../../lib/cases.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const stateKey = "dummy-state-key-with-more-than-32-characters";

function openStore(stateDir, namespace, maxEntries = 100) {
  return createEncryptedFileKeyedStore({ stateDir, namespace, maxEntries, getSecret: () => stateKey });
}

test("subject purge is separately approved and removes only local encrypted subject state", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-purge-runtime-"));
  const runtime = { state: { resolveStateDir() { return stateDir; } } };
  const plugin = (await import("../../index.ts")).default;
  const tools = new Map();
  let beforeToolCall;
  plugin.register({
    runtime,
    on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
    registerTool(tool) {
      const resolved = typeof tool === "function" ? tool({ browser: {} }) : tool;
      tools.set(resolved.name, resolved);
    },
    registerSecurityAuditCollector() {},
    pluginConfig: { stateEncryptionKey: stateKey },
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });

  const cases = openStore(stateDir, "rightout-cases-v1");
  const ledger = createCaseLedger(cases);
  await ledger.recordScan({
    mode: "approval_gated_live_scan", scan_id: "scan_0123456789abcdef", subject_ref: profileId,
    generated_at: "2026-07-12T08:00:00Z",
    results: [{ broker_id: "beenverified", state: "indirect_exposure", reason: "search_index_candidate_observed" }],
  });
  const verification = openStore(stateDir, "rightout-verification-tokens-v1", 200);
  const listings = openStore(stateDir, "rightout-listing-tokens-v1", 500);
  const dedupe = openStore(stateDir, "rightout-submission-dedupe-v1", 500);
  await verification.register("verify_0123456789abcdef01234567", { profileId, brokerId: "beenverified" });
  await listings.register("listing_0123456789abcdef01234567", { profileId, brokerId: "beenverified" });
  await dedupe.register("dedupe_" + "a".repeat(64), { profileId, brokerId: "beenverified", channel: "smtp_email" });

  const input = { profileId };
  const denied = await beforeToolCall({ toolName: "rightout_purge_subject_state", params: input, toolCallId: "purge-denied" });
  assert.match(denied.requireApproval.description, /P profile_/);
  denied.requireApproval.onResolution("deny");
  await assert.rejects(tools.get("rightout_purge_subject_state").execute("purge-denied", input), /rightout_approval_binding_failed/);
  assert.ok(await cases.lookup(profileId));

  const approved = await beforeToolCall({ toolName: "rightout_purge_subject_state", params: input, toolCallId: "purge-approved" });
  approved.requireApproval.onResolution("allow-once");
  const result = await tools.get("rightout_purge_subject_state").execute("purge-approved", input);
  assert.equal(result.details.state, "local_subject_state_purged");
  assert.deepEqual(result.details.deleted, { case_record: 1, verification_handles: 1, listing_handles: 1, dedupe_records: 1 });
  assert.equal(result.details.config_profile_deleted, false);
  assert.equal(result.details.provider_writes, 0);
  assert.equal(await cases.lookup(profileId), undefined);
  assert.equal(await verification.lookup("verify_0123456789abcdef01234567"), undefined);
  assert.equal(await listings.lookup("listing_0123456789abcdef01234567"), undefined);
});
