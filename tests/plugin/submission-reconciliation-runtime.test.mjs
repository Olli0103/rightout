import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createCaseLedger } from "../../lib/cases.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const stateKey = "dummy-state-key-with-more-than-32-characters";

test("submission reconciliation is separately approved and re-enables retry only after not-started review", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-reconcile-"));
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
    pluginConfig: {
      stateEncryptionKey: stateKey,
      profiles: { [profileId]: { payload: JSON.stringify({ fullName: "Avery Example", contactEmail: "avery@example.invalid" }) } },
    },
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });

  const ledger = createCaseLedger(createEncryptedFileKeyedStore({
    stateDir,
    namespace: "rightout-cases-v1",
    maxEntries: 100,
    getSecret: () => stateKey,
  }));
  await ledger.recordScan({
    mode: "approval_gated_live_scan",
    scan_id: "scan_0123456789abcdef",
    subject_ref: profileId,
    generated_at: "2026-07-12T10:00:00Z",
    results: [{ broker_id: "beenverified", state: "indirect_exposure", reason: "search_index_candidate_observed" }],
  });
  await ledger.reserveSubmission(profileId, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" });
  await ledger.recordSubmissionUncertain(profileId, "beenverified", { channel: "smtp_email", reason: "rightout_removal_transport_failed" });

  const input = { profileId, brokerId: "beenverified", outcome: "provider_write_not_started" };
  const denied = await beforeToolCall({ toolName: "rightout_reconcile_submission", params: input, toolCallId: "reconcile-denied" });
  assert.match(denied.requireApproval.description, /personally reviewed/);
  assert.doesNotMatch(denied.requireApproval.description, /Avery|avery@example/);
  denied.requireApproval.onResolution("deny");
  await assert.rejects(
    tools.get("rightout_reconcile_submission").execute("reconcile-denied", input),
    /rightout_approval_binding_failed/,
  );

  const approved = await beforeToolCall({ toolName: "rightout_reconcile_submission", params: input, toolCallId: "reconcile-approved" });
  assert.deepEqual(approved.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  approved.requireApproval.onResolution("allow-once");
  const result = await tools.get("rightout_reconcile_submission").execute("reconcile-approved", input);
  assert.equal(result.details.state, "action_selected");
  assert.equal(result.details.retry_allowed, true);
  assert.equal(result.details.provider_writes, 0);
  assert.equal(result.details.invariants.agent_inference_used, false);
  assert.equal((await ledger.status(profileId)).counts.action_selected, 1);

  await assert.rejects(
    tools.get("rightout_reconcile_submission").execute("reconcile-approved", input),
    /rightout_approval_binding_failed/,
  );
});
