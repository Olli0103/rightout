import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";
import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";
import { formAttestations } from "./form-attestation-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const profile = JSON.stringify({
  fullName: "Avery Example", city: "Exampleville", region: "CA", country: "US",
  dateOfBirth: "1990-01-01",
  contactEmail: "avery@example.invalid", jurisdictions: ["US", "US-CA"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["scan", "broker_removal"], method: "self" },
});

test("every optional tool factory declares its OpenClaw manifest name", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-factory-metadata-"));
  const factoryOptions = [];
  const plugin = (await import("../../index.ts")).default;
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    on() {},
    registerTool(tool, options) {
      if (typeof tool === "function") factoryOptions.push(options);
    },
    registerSecurityAuditCollector() {},
    pluginConfig: {},
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  assert.ok(factoryOptions.length > 0);
  assert.ok(factoryOptions.every((options) => typeof options?.name === "string" && options.name.startsWith("rightout_")));
  assert.ok(factoryOptions.some((options) => options.name === "rightout_unbroker_parity_health"));
});

test("setup, doctor, reports, and deterministic campaign control are executable runtime tools", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-feature-runtime-"));
  const tools = new Map();
  let beforeToolCall;
  const plugin = (await import("../../index.ts")).default;
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
    registerTool(tool) {
      const resolved = typeof tool === "function" ? tool({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } }) : tool;
      tools.set(resolved.name, resolved);
    },
    registerSecurityAuditCollector() {},
    pluginConfig: {
      stateEncryptionKey: "dummy-feature-runtime-key-with-more-than-32-characters",
      profiles: { [profileId]: { payload: profile } },
      formAttestations: formAttestations(profileId, profile, ["intelius"]),
      publisherAutomationPermissions: publisherAutomationPermissions(["intelius", "familytreenow", "mylife", "spokeo"]),
    },
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });

  const setup = await tools.get("rightout_setup").execute("setup", {});
  assert.equal(setup.details.state, "needs_configuration");
  assert.equal(setup.details.initialized_profiles, 1);
  assert.equal(setup.details.capability_detection.browser, "managed_openclaw");
  assert.equal(setup.details.capability_detection.email_send, "unavailable");
  assert.ok(setup.details.missing.includes("braveApiKey_secretref"));

  const doctor = await tools.get("rightout_doctor").execute("doctor", {});
  assert.equal(doctor.details.state, "needs_attention");
  assert.deepEqual(doctor.details.parity_release_blockers, []);
  assert.deepEqual(doctor.details.external_runtime_degradations, ["clustrmaps", "peekyou"]);
  assert.equal(doctor.details.checks.normalized_unbroker_contract_surface, true);
  assert.equal(doctor.details.checks.primary_reference_routes_available, false);
  assert.equal(doctor.details.checks.autonomous_external_route_rescue, true);
  assert.equal(doctor.details.checks.managed_openclaw_browser, true);
  assert.equal(doctor.details.checks.brave_discovery, false);
  assert.equal(doctor.details.checks.email_send, false);
  assert.equal(doctor.details.checks.verification, false);
  assert.equal(doctor.details.checks.managed_openclaw_browser, true);

  const parity = await tools.get("rightout_unbroker_parity_health").execute("parity", {});
  assert.equal(parity.details.broker_count, 22);
  assert.equal(parity.details.broker_ids.length, 22);
  assert.equal(parity.details.broker_routes.length, 22);
  assert.equal(parity.details.release_ready, true);
  assert.equal(parity.details.software_release_ready, true);
  assert.equal(parity.details.autonomous_form_execution_ready, false);
  assert.equal(parity.details.exact_provider_playbook_choreography_complete, false);
  assert.equal(parity.details.provider_terms.explicit_automation_prohibitions.length, 8);
  assert.equal(parity.details.provider_terms.needs_evidence.length, 14);
  assert.deepEqual(parity.details.externally_unavailable_routes, ["clustrmaps", "peekyou"]);

  const globalScanInput = {
    profileId,
    brokerIds: ["emetriq_eu", "fullenrich_eu", "dealfront_eu", "snov_eu", "kaspr_eu"],
    effects: ["discover"], durationHours: 24, maxEffects: 5,
  };
  const globalApproval = await beforeToolCall({
    toolName: "rightout_start_campaign", params: globalScanInput, toolCallId: "global-scan-start",
  });
  assert.ok(globalApproval.requireApproval);
  assert.ok(globalApproval.requireApproval.description.length <= 256);
  globalApproval.requireApproval.onResolution("allow-once");
  const globalCampaign = await tools.get("rightout_start_campaign").execute("global-scan-start", globalScanInput);
  const globalNext = await tools.get("rightout_campaign_next").execute("global-scan-next", {
    campaignId: globalCampaign.details.campaign_id,
  });
  assert.equal(globalNext.details.command.tool, "rightout_live_scan");
  assert.deepEqual(globalNext.details.command.parameters.brokerIds, [...globalScanInput.brokerIds].sort().slice(0, 4));
  assert.equal(globalNext.details.batch_size, 4);

  const sensitiveCampaignInput = {
    profileId, brokerIds: ["intelius"], effects: ["submit_form"], durationHours: 24, maxEffects: 1,
  };
  const sensitiveApproval = await beforeToolCall({ toolName: "rightout_start_campaign", params: sensitiveCampaignInput, toolCallId: "sensitive-start" });
  sensitiveApproval.requireApproval.onResolution("allow-once");
  const sensitiveCampaign = await tools.get("rightout_start_campaign").execute("sensitive-start", sensitiveCampaignInput);
  await assert.rejects(
    () => tools.get("rightout_begin_form_session").execute("sensitive-form", {
      profileId, brokerId: "intelius", campaignId: sensitiveCampaign.details.campaign_id,
    }),
    /rightout_peopleconnect_named_browser_profile_required/,
  );

  const registry = await tools.get("rightout_registry_status").execute("registry", {});
  assert.equal(registry.details.state, "registry_not_initialized");

  const report = await tools.get("rightout_export_report").execute("report", { profileId });
  assert.match(report.details.markdown, /RightOut status/);
  assert.deepEqual(report.details.google_sheets_rows[0].slice(0, 3), ["subject_ref", "broker_id", "state"]);

  const next = await tools.get("rightout_next_actions").execute("next", { profileId });
  assert.equal(next.details.invariants.raw_pii_in_report, false);
  const due = await tools.get("rightout_due_rechecks").execute("due", { profileId });
  assert.deepEqual(due.details.due, []);

  const campaignInput = {
    profileId,
    brokerIds: ["familytreenow", "mylife", "spokeo"],
    effects: ["discover", "submit_email", "submit_form"],
    durationHours: 24,
    maxEffects: 12,
  };
  const startApproval = await beforeToolCall({ toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "start" });
  startApproval.requireApproval.onResolution("allow-once");
  const started = await tools.get("rightout_start_campaign").execute("start", campaignInput);
  assert.equal(started.details.status, "active");

  const campaignNext = await tools.get("rightout_campaign_next").execute("campaign-next", { campaignId: started.details.campaign_id });
  assert.equal(campaignNext.details.state, "action_ready");
  assert.equal(campaignNext.details.command.tool, "rightout_live_scan");
  assert.equal(campaignNext.details.deterministic_next_loop, true);

  const status = await tools.get("rightout_campaign_status").execute("campaign-status", { campaignId: started.details.campaign_id });
  assert.equal(status.details.remaining_effects, 12);

  const revokeInput = { campaignId: started.details.campaign_id };
  const revokeApproval = await beforeToolCall({ toolName: "rightout_revoke_campaign", params: revokeInput, toolCallId: "revoke" });
  revokeApproval.requireApproval.onResolution("allow-once");
  const revoked = await tools.get("rightout_revoke_campaign").execute("revoke", revokeInput);
  assert.equal(revoked.details.status, "revoked");
});

test("autonomous form readiness requires a passing deep browser snapshot, not a warning", async () => {
  const originalFetch = globalThis.fetch;
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-form-readiness-"));
  const tools = new Map();
  const plugin = (await import("../../index.ts")).default;
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    on() {},
    registerTool(tool) {
      const resolved = typeof tool === "function"
        ? tool({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } })
        : tool;
      tools.set(resolved.name, resolved);
    },
    registerSecurityAuditCollector() {},
    pluginConfig: {
      stateEncryptionKey: "dummy-form-readiness-key-with-more-than-32-characters",
      profiles: { [profileId]: { payload: profile } },
      formAttestations: formAttestations(profileId, profile, ["familytreenow"]),
      publisherAutomationPermissions: publisherAutomationPermissions(["familytreenow"]),
    },
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });

  try {
    globalThis.fetch = async () => new Response(JSON.stringify({
      ok: true,
      checks: [{ id: "live-snapshot", status: "warning" }],
    }), { status: 200, headers: { "content-type": "application/json" } });
    const warning = await tools.get("rightout_unbroker_parity_health").execute("warning", {});
    assert.equal(warning.details.autonomous_form_policy_configuration_ready, true);
    assert.equal(warning.details.browser_readiness.operational, true);
    assert.equal(warning.details.browser_readiness.deep_snapshot, false);
    assert.equal(warning.details.autonomous_form_execution_ready, false);
    assert.ok(warning.details.autonomous_form_execution_blockers.includes("browser_deep_snapshot_not_verified"));

    globalThis.fetch = async () => new Response(JSON.stringify({
      ok: true,
      checks: [{ id: "live-snapshot", status: "pass" }],
    }), { status: 200, headers: { "content-type": "application/json" } });
    const pass = await tools.get("rightout_unbroker_parity_health").execute("pass", {});
    assert.equal(pass.details.autonomous_form_policy_configuration_ready, true);
    assert.equal(pass.details.browser_readiness.operational, true);
    assert.equal(pass.details.browser_readiness.deep_snapshot, true);
    assert.equal(pass.details.autonomous_form_execution_ready, true);
    assert.deepEqual(pass.details.autonomous_form_execution_blockers, []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
