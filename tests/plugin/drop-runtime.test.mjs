import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { DROP_CONTRACT, dropRegistrySnapshot } from "../../lib/drop.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const profile = JSON.stringify({
  fullName: "Avery Example", city: "Exampleville", region: "CA", country: "US",
  contactEmail: "avery@example.invalid", jurisdictions: ["US", "US-CA"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["broker_removal"], method: "self" },
});

test("DROP contract and registry snapshot identity are immutable and freshness-bound", () => {
  assert.equal(Object.isFrozen(DROP_CONTRACT), true);
  assert.equal(Object.isFrozen(DROP_CONTRACT.sources), true);
  const registry = {
    schema_version: 1,
    state: "registry_ready",
    jurisdiction: "US-CA",
    source_url: "https://cppa.ca.gov/data_broker_registry/registry2026.csv",
    source_sha256: "0".repeat(64),
    retrieved_at: "2026-07-15T12:00:00.000Z",
    record_count: 600,
    chunk_count: 6,
  };
  const snapshot = dropRegistrySnapshot(registry, { now: Date.parse("2026-07-16T12:00:00.000Z") });
  assert.match(snapshot.registry_snapshot_digest, /^[a-f0-9]{64}$/);
  assert.throws(
    () => dropRegistrySnapshot(registry, { now: Date.parse("2026-09-01T12:00:00.000Z") }),
    /rightout_drop_registry_invalid/,
  );
  assert.notEqual(
    snapshot.registry_snapshot_digest,
    dropRegistrySnapshot({ ...registry, source_sha256: "1".repeat(64) }, { now: Date.parse("2026-07-16T12:00:00.000Z") }).registry_snapshot_digest,
  );
});

test("DROP filing requires current official registry state and a separate human attestation approval", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-drop-runtime-"));
  const stateKey = "dummy-drop-runtime-key-with-more-than-32-characters";
  const registryStore = createEncryptedFileKeyedStore({
    stateDir,
    namespace: "rightout-registry-v1",
    maxEntries: 20,
    defaultTtlMs: 45 * 24 * 60 * 60_000,
    getSecret: () => stateKey,
  });
  await registryStore.register("registry_chunk_000", { records: [] });
  const registryMeta = {
    schema_version: 1,
    state: "registry_ready",
    jurisdiction: "US-CA",
    source_url: "https://cppa.ca.gov/data_broker_registry/registry2025.csv",
    source_sha256: "0".repeat(64),
    retrieved_at: new Date(Date.now() - 24 * 60 * 60_000).toISOString(),
    record_count: 120,
    fcra_count: 40,
    chunk_count: 1,
    portals: [],
    raw_contact_addresses_in_report: false,
  };
  await registryStore.register("registry_meta", registryMeta);

    const tools = new Map();
    let beforeToolCall;
    const plugin = (await import("../../index.ts")).default;
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
        profiles: { [profileId]: { payload: profile } },
      },
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const registry = await tools.get("rightout_registry_status").execute("registry", {});
    assert.equal(registry.details.state, "registry_ready");
    assert.equal(registry.details.record_count, 120);

    const input = { profileId };
    const gate = await beforeToolCall({ toolName: "rightout_record_drop_filed", params: input, toolCallId: "drop-filed" });
    assert.ok(gate.requireApproval);
    assert.match(gate.requireApproval.description, /120-broker official registry snapshot/);
    gate.requireApproval.onResolution("allow-once");
    await registryStore.register("registry_meta", { ...registryMeta, source_sha256: "1".repeat(64) });
    await assert.rejects(
      tools.get("rightout_record_drop_filed").execute("drop-filed", input),
      /rightout_approval_binding_failed/,
    );
    const currentGate = await beforeToolCall({ toolName: "rightout_record_drop_filed", params: input, toolCallId: "drop-filed-current" });
    currentGate.requireApproval.onResolution("allow-once");
    const filed = await tools.get("rightout_record_drop_filed").execute("drop-filed-current", input);
    assert.equal(filed.details.state, "submitted");
    assert.equal(filed.details.phase, "filed_before_broker_processing");
    assert.equal(filed.details.registry_scope, 120);
    assert.match(filed.details.registry_snapshot_digest, /^[a-f0-9]{64}$/);
    assert.equal(filed.details.processing_starts_at, "2026-08-01T00:00:00.000Z");
    assert.equal(filed.details.deletion_confirmed, false);
    assert.equal(filed.details.confirmation_scope, null);
    assert.equal(filed.details.portal_status_is_direct_deletion_proof, false);
    assert.equal(filed.details.portal_action_performed_by_rightout, false);
    assert.equal(filed.details.provider_writes, 0);
    assert.doesNotMatch(JSON.stringify(filed.details), /Avery Example|avery@example\.invalid/);

    const statusInput = { profileId, observedStatus: "pending" };
    const statusGate = await beforeToolCall({ toolName: "rightout_record_drop_status", params: statusInput, toolCallId: "drop-status" });
    const staleStatusInput = { profileId, observedStatus: "needs_manual_check" };
    const staleStatusGate = await beforeToolCall({ toolName: "rightout_record_drop_status", params: staleStatusInput, toolCallId: "drop-status-stale" });
    assert.match(statusGate.requireApproval.description, /never direct deletion proof/);
    statusGate.requireApproval.onResolution("allow-once");
    staleStatusGate.requireApproval.onResolution("allow-once");
    const observed = await tools.get("rightout_record_drop_status").execute("drop-status", statusInput);
    assert.equal(observed.details.state, "submitted");
    assert.equal(observed.details.deletion_confirmed, false);
    assert.equal(observed.details.portal_status_is_direct_deletion_proof, false);
    assert.equal(observed.details.provider_reads, 0);
    assert.equal(observed.details.provider_writes, 0);
    await assert.rejects(
      tools.get("rightout_record_drop_status").execute("drop-status-stale", staleStatusInput),
      /rightout_approval_binding_failed/,
    );

    const deletedInput = { profileId, observedStatus: "deleted" };
    const deletedGate = await beforeToolCall({ toolName: "rightout_record_drop_status", params: deletedInput, toolCallId: "drop-deleted" });
    deletedGate.requireApproval.onResolution("allow-once");
    await assert.rejects(
      tools.get("rightout_record_drop_status").execute("drop-deleted", deletedInput),
      /rightout_drop_status_invalid/,
    );

    const gpcInput = { profileId, surface: "browser_native_setting" };
    const gpcGate = await beforeToolCall({ toolName: "rightout_record_gpc_observed", params: gpcInput, toolCallId: "gpc-observed" });
    const staleGpcInput = { profileId, surface: "browser_extension" };
    const staleGpcGate = await beforeToolCall({ toolName: "rightout_record_gpc_observed", params: staleGpcInput, toolCallId: "gpc-stale" });
    assert.match(gpcGate.requireApproval.description, /not deletion proof/);
    gpcGate.requireApproval.onResolution("allow-once");
    staleGpcGate.requireApproval.onResolution("allow-once");
    const gpc = await tools.get("rightout_record_gpc_observed").execute("gpc-observed", gpcInput);
    assert.equal(gpc.details.state, "enabled_human_verified");
    assert.equal(gpc.details.deletion_request, false);
    assert.equal(gpc.details.deletion_confirmed, false);
    assert.equal(gpc.details.site_compliance_verified, false);
    assert.equal(gpc.details.browser_configuration_performed_by_rightout, false);
    assert.equal(gpc.details.provider_reads, 0);
    assert.equal(gpc.details.provider_writes, 0);
    await assert.rejects(
      tools.get("rightout_record_gpc_observed").execute("gpc-stale", staleGpcInput),
      /rightout_approval_binding_failed/,
    );

    const status = await tools.get("rightout_case_status").execute("status", input);
    assert.equal(status.details.cases.find((item) => item.broker_id === "ca_drop").state, "submitted");
    assert.equal(status.details.metrics.confirmed_removed, 0);
    assert.equal(status.details.preference_controls[0].state, "enabled_human_verified");
    assert.equal(status.details.preference_controls[0].deletion_confirmed, false);

    const exported = await tools.get("rightout_export_report").execute("export", input);
    assert.equal(exported.details.structured.preference_controls[0].deletion_confirmed, false);
    assert.match(exported.details.markdown, /Preference signals are not deletion requests or deletion proof/);

    const preferenceStore = createEncryptedFileKeyedStore({
      stateDir,
      namespace: "rightout-preference-controls-v1",
      maxEntries: 100,
      getSecret: () => stateKey,
    });
    const preferenceKey = `gpc_${createHash("sha256").update(profileId).digest("hex")}`;
    const corrupted = await preferenceStore.lookup(preferenceKey);
    await preferenceStore.register(preferenceKey, {
      ...corrupted,
      profileId: "profile_ffffffffffffffff",
    });
    await assert.rejects(
      tools.get("rightout_case_status").execute("status-corrupted-preference", input),
      /rightout_gpc_status_invalid/,
    );
});
