import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createCaseLedger } from "../../lib/cases.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const stateKey = "dummy-state-key-with-more-than-32-characters";

test("EU controller outcome requires a separate human-review approval", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-controller-outcome-"));
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
  await ledger.reserveSubmission(profileId, "adsquare_eu", {
    channel: "smtp_email",
    discoveryRequirement: "not_required_for_data_subject_request",
  });
  await ledger.recordRemoval({
    state: "submitted",
    subject_ref: profileId,
    broker_id: "adsquare_eu",
    generated_at: "2026-07-12T10:00:00Z",
    delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"],
    disclosures: { to_broker: ["contact_email"] },
  }, 30);

  const input = { profileId, brokerId: "adsquare_eu", outcome: "erasure_confirmed" };
  const denied = await beforeToolCall({ toolName: "rightout_record_controller_outcome", params: input, toolCallId: "controller-denied" });
  assert.match(denied.requireApproval.description, /personally reviewed/);
  assert.doesNotMatch(denied.requireApproval.description, /Avery|avery@example/);
  denied.requireApproval.onResolution("deny");
  await assert.rejects(
    tools.get("rightout_record_controller_outcome").execute("controller-denied", input),
    /rightout_approval_binding_failed/,
  );

  const approved = await beforeToolCall({ toolName: "rightout_record_controller_outcome", params: input, toolCallId: "controller-approved" });
  assert.deepEqual(approved.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  approved.requireApproval.onResolution("allow-once");
  const result = await tools.get("rightout_record_controller_outcome").execute("controller-approved", input);
  assert.equal(result.details.state, "confirmed_removed");
  assert.equal(result.details.removal_confirmation_scope, "controller_response_only");
  assert.equal(result.details.provider_writes, 0);
  assert.equal(result.details.invariants.smtp_acceptance_used_as_outcome, false);
  assert.equal((await ledger.status(profileId)).counts.confirmed_removed, 1);

  const unsupported = await beforeToolCall({
    toolName: "rightout_record_controller_outcome",
    params: { ...input, brokerId: "beenverified" },
    toolCallId: "controller-unsupported",
  });
  assert.equal(unsupported.block, true);
});
