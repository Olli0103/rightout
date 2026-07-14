import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createCaseLedger } from "../../lib/cases.mjs";
import { createCustomTargetVault } from "../../lib/custom-targets.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";

const profileId = "profile_0123456789abcdef";
const brokerId = "fullenrich_eu";
const stateKey = "dummy-evidence-runtime-key-with-more-than-32-characters";

test("runtime snapshots sanitized case evidence, exports only after approval, and keeps custom targets opaque", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-evidence-runtime-"));
  const runtime = { state: { resolveStateDir() { return stateDir; } } };
  const config = {
    stateEncryptionKey: stateKey,
    profiles: { [profileId]: { payload: "{}" } },
  };
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
    pluginConfig: config,
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });

  const ledger = createCaseLedger(createEncryptedFileKeyedStore({
    stateDir, namespace: "rightout-cases-v1", maxEntries: 100, getSecret: () => stateKey,
  }));
  await ledger.reserveSubmission(profileId, brokerId, {
    channel: "smtp_email", discoveryRequirement: "not_required_for_data_subject_request",
  });
  await ledger.recordRemoval({
    state: "submitted", subject_ref: profileId, broker_id: brokerId,
    generated_at: "2026-07-14T08:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"], disclosures: { to_broker: ["contact_email", "country"] },
  }, 30);

  const createInput = { profileId, brokerId };
  const created = await tools.get("rightout_create_evidence_snapshot").execute("evidence-create", createInput);
  assert.equal(created.details.state, "encrypted_evidence_snapshot_created");
  assert.match(created.details.evidence_ref, /^evidence_[a-f0-9]{64}$/);
  assert.equal("content" in created.details, false);
  assert.doesNotMatch(JSON.stringify(created.details), /Avery|@|https?:\/\//);
  const encrypted = readFileSync(join(stateDir, "rightout-plugin-state-v1", "rightout-evidence-vault-v1.json.enc"), "utf8");
  assert.doesNotMatch(encrypted, /submitted|smtp_012345|fullenrich/);

  const refInput = { profileId, evidenceRef: created.details.evidence_ref };
  const status = await tools.get("rightout_evidence_status").execute("evidence-status", refInput);
  assert.equal(status.details.state, "encrypted_evidence_available");
  assert.equal("content" in status.details, false);

  const exportInput = { ...refInput, format: "json" };
  await assert.rejects(tools.get("rightout_export_evidence").execute("evidence-unapproved", exportInput), /approval_binding_failed/);
  const denied = await beforeToolCall({ toolName: "rightout_export_evidence", params: exportInput, toolCallId: "evidence-denied" });
  denied.requireApproval.onResolution("deny");
  await assert.rejects(tools.get("rightout_export_evidence").execute("evidence-denied", exportInput), /approval_binding_failed/);
  const approval = await beforeToolCall({ toolName: "rightout_export_evidence", params: exportInput, toolCallId: "evidence-approved" });
  assert.doesNotMatch(approval.requireApproval.description, /submitted|smtp_012345/);
  approval.requireApproval.onResolution("allow-once");
  const exported = await tools.get("rightout_export_evidence").execute("evidence-approved", exportInput);
  assert.equal(exported.details.state, "redacted_evidence_exported");
  assert.match(exported.details.artifact_name, /^evidence_[a-f0-9]{64}\.json$/);
  assert.equal("artifact_path" in exported.details, false);
  assert.equal(exported.details.raw_pii_in_report, false);

  const customStore = createEncryptedFileKeyedStore({
    stateDir, namespace: "rightout-custom-targets-v1", maxEntries: 500, getSecret: () => stateKey,
  });
  const custom = await createCustomTargetVault(customStore, { randomHandle: () => "custom_0123456789abcdef01234567" }).intake({
    profileId,
    actionUrl: "https://privacy.controller.example/remove",
    sourceUrl: "https://controller.example/privacy",
    officialDomain: "controller.example",
    method: "web_form",
  });
  const customStatus = await tools.get("rightout_custom_target_status").execute("custom-status", {
    profileId, customTargetHandle: custom.custom_target_handle,
  });
  assert.equal(customStatus.details.state, "quarantined");
  assert.equal(customStatus.details.provider_action_available, false);
  assert.doesNotMatch(JSON.stringify(customStatus.details), /controller\.example|\/remove|\/privacy/);
});
