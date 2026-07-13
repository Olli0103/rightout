import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const profile = JSON.stringify({
  fullName: "Avery Example", city: "Exampleville", region: "CA", country: "US",
  contactEmail: "avery@example.invalid", jurisdictions: ["US", "US-CA"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["broker_removal"], method: "self" },
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
  await registryStore.register("registry_meta", {
    schema_version: 1,
    state: "registry_ready",
    jurisdiction: "US-CA",
    source_url: "https://cppa.ca.gov/data_broker_registry/registry2025.csv",
    source_sha256: "0".repeat(64),
    retrieved_at: "2026-07-13T08:00:00.000Z",
    record_count: 120,
    fcra_count: 40,
    chunk_count: 1,
    portals: [],
    raw_contact_addresses_in_report: false,
  });

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
    const filed = await tools.get("rightout_record_drop_filed").execute("drop-filed", input);
    assert.equal(filed.details.state, "awaiting_processing");
    assert.equal(filed.details.registry_scope, 120);
    assert.equal(filed.details.portal_action_performed_by_rightout, false);
    assert.equal(filed.details.provider_writes, 0);
    assert.doesNotMatch(JSON.stringify(filed.details), /Avery Example|avery@example\.invalid/);

    const status = await tools.get("rightout_case_status").execute("status", input);
    assert.equal(status.details.cases.find((item) => item.broker_id === "ca_drop").state, "awaiting_processing");
});
