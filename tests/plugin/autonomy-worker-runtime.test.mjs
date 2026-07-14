import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { scanProfileDigest } from "../../lib/live-scan.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const profilePayload = JSON.stringify({
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  consent: {
    authorized: true,
    recordedAt: CONSENT_RECORDED_AT,
    validUntil: CONSENT_VALID_UNTIL,
    scope: ["scan"],
  },
});
const trusted = { sessionKey: "agent:main:rightout-worker-test", agentId: "main", browser: {} };

async function runtimeFixture({ schedulerAvailable = true, stateDir = mkdtempSync(join(tmpdir(), "rightout-worker-runtime-")) } = {}) {
  const tools = new Map();
  const scheduled = [];
  let beforeToolCall;
  let afterToolCall;
  const config = {
    stateEncryptionKey: "dummy-worker-runtime-state-key-with-more-than-32-characters",
    braveApiKey: "dummy-brave-api-key",
    profiles: { [profileId]: { payload: profilePayload } },
    operatorAttestations: {
      braveTermsAccepted: true,
      braveTermsVersion: "2026-02-11",
      braveCustomerResponsibilitiesAccepted: true,
      subjectConsentReviewed: true,
      authorizedProfileIds: [profileId],
      authorizedProfileDigests: { [profileId]: scanProfileDigest(profilePayload) },
      authorizedBrokerIds: [
        "advancedbackgroundchecks", "dealfront_eu", "emetriq_eu", "fullenrich_eu", "kaspr_eu", "snov_eu", "truepeoplesearch",
      ],
    },
  };
  const plugin = (await import("../../index.ts")).default;
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    session: {
      workflow: {
        async scheduleSessionTurn(params) {
          scheduled.push(structuredClone(params));
          if (!schedulerAvailable) return undefined;
          return { id: `job-${scheduled.length}`, pluginId: "rightout", sessionKey: params.sessionKey, kind: "cron" };
        },
        async unscheduleSessionTurnsByTag({ tag }) {
          const retained = scheduled.filter((item) => item.tag !== tag);
          const removed = scheduled.length - retained.length;
          scheduled.splice(0, scheduled.length, ...retained);
          return { removed, failed: 0 };
        },
      },
    },
    on(name, handler) {
      if (name === "before_tool_call") beforeToolCall = handler;
      if (name === "after_tool_call") afterToolCall = handler;
    },
    registerTool(tool) {
      const resolved = typeof tool === "function" ? tool(trusted) : tool;
      tools.set(resolved.name, resolved);
    },
    registerSecurityAuditCollector() {},
    pluginConfig: config,
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  return {
    tools,
    scheduled,
    stateDir,
    beforeToolCall: (event, context = trusted) => beforeToolCall(event, { ...context, toolName: event.toolName, toolCallId: event.toolCallId }),
    afterToolCall: (event, context = trusted) => afterToolCall(event, { ...context, toolName: event.toolName, toolCallId: event.toolCallId }),
  };
}

test("durable worker schedules, executes one evidenced effect, survives a turn boundary, and closes with its campaign", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    return new Response(JSON.stringify({ web: { results: [] } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    const runtime = await runtimeFixture();
    const campaignInput = {
      profileId,
      brokerIds: ["truepeoplesearch"],
      effects: ["discover"],
      durationHours: 24,
      maxEffects: 1,
    };
    const campaignApproval = await runtime.beforeToolCall({
      toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "worker-campaign-start",
    });
    campaignApproval.requireApproval.onResolution("allow-once");
    const campaign = await runtime.tools.get("rightout_start_campaign").execute("worker-campaign-start", campaignInput);

    const enableInput = { campaignId: campaign.details.campaign_id, intervalMinutes: 15, maxConsecutiveFailures: 2 };
    const enableApproval = await runtime.beforeToolCall({
      toolName: "rightout_worker_enable", params: enableInput, toolCallId: "worker-enable",
    });
    assert.equal(enableApproval.requireApproval.severity, "critical");
    enableApproval.requireApproval.onResolution("allow-once");
    const enabled = await runtime.tools.get("rightout_worker_enable").execute("worker-enable", enableInput);
    assert.equal(enabled.details.scheduler_state, "host_scheduled");
    assert.match(enabled.details.worker_id, /^worker_[a-f0-9]{32}$/);
    assert.equal(runtime.scheduled.length, 1);
    assert.equal(runtime.scheduled[0].sessionKey, trusted.sessionKey);
    assert.doesNotMatch(runtime.scheduled[0].message, /Avery|Exampleville|profile_/u);

    const tick = await runtime.tools.get("rightout_worker_tick").execute("worker-tick", { workerId: enabled.details.worker_id });
    assert.equal(tick.details.state, "action_ready");
    assert.equal(tick.details.command.tool, "rightout_live_scan");
    assert.deepEqual(tick.details.command.parameters, {
      profileId,
      brokerIds: ["truepeoplesearch"],
      campaignId: campaign.details.campaign_id,
    });

    const liveHook = await runtime.beforeToolCall({
      toolName: tick.details.command.tool,
      params: tick.details.command.parameters,
      toolCallId: "worker-effect",
    });
    assert.equal(liveHook.requireApproval, undefined);
    const effect = await runtime.tools.get(tick.details.command.tool).execute("worker-effect", tick.details.command.parameters);
    assert.equal(effect.details.mode, "campaign_gated_live_scan");
    assert.equal(effect.details.results.length, 1);
    assert.ok(effect.details.results[0].vectors_attempted > 0);
    await runtime.afterToolCall({
      toolName: tick.details.command.tool,
      params: tick.details.command.parameters,
      toolCallId: "worker-effect",
      result: effect,
    });

    const completed = await runtime.tools.get("rightout_worker_complete").execute("worker-complete", {
      workerId: enabled.details.worker_id,
      leaseId: tick.details.lease_id,
      outcome: "action_succeeded",
    });
    assert.equal(completed.details.exact_command_completed, true);
    assert.equal(completed.details.worker.actions_completed, 1);
    assert.equal(completed.details.scheduler_state, "host_scheduled");

    const terminal = await runtime.tools.get("rightout_worker_tick").execute("worker-terminal", { workerId: enabled.details.worker_id });
    assert.equal(terminal.details.state, "done");
    assert.equal(terminal.details.worker.status, "done");
    assert.equal(JSON.stringify(terminal.details).includes("Avery"), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker enable fails closed without a trusted session before approval", async () => {
  const runtime = await runtimeFixture();
  const campaignInput = { profileId, brokerIds: ["truepeoplesearch"], effects: ["discover"], durationHours: 24, maxEffects: 1 };
  const campaignApproval = await runtime.beforeToolCall({
    toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "fallback-campaign",
  });
  campaignApproval.requireApproval.onResolution("allow-once");
  const campaign = await runtime.tools.get("rightout_start_campaign").execute("fallback-campaign", campaignInput);
  const enableInput = { campaignId: campaign.details.campaign_id, intervalMinutes: 15, maxConsecutiveFailures: 2 };
  const denied = await runtime.beforeToolCall(
    { toolName: "rightout_worker_enable", params: enableInput, toolCallId: "missing-session" },
    { agentId: "main" },
  );
  assert.equal(denied.block, true);
  assert.equal(denied.requireApproval, undefined);
});

test("worker enable returns a deterministic PII-free Cron handoff when host scheduling is unavailable", async () => {
  const runtime = await runtimeFixture({ schedulerAvailable: false });
  const campaignInput = { profileId, brokerIds: ["truepeoplesearch"], effects: ["discover"], durationHours: 24, maxEffects: 1 };
  const campaignApproval = await runtime.beforeToolCall({
    toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "handoff-campaign",
  });
  campaignApproval.requireApproval.onResolution("allow-once");
  const campaign = await runtime.tools.get("rightout_start_campaign").execute("handoff-campaign", campaignInput);
  const enableInput = { campaignId: campaign.details.campaign_id, intervalMinutes: 30, maxConsecutiveFailures: 3 };
  const approval = await runtime.beforeToolCall({ toolName: "rightout_worker_enable", params: enableInput, toolCallId: "handoff-enable" });
  approval.requireApproval.onResolution("allow-once");
  const enabled = await runtime.tools.get("rightout_worker_enable").execute("handoff-enable", enableInput);
  assert.equal(enabled.details.scheduler_state, "explicit_handoff_required");
  assert.deepEqual(enabled.details.cron_handoff, {
    target: "current_trusted_session",
    delay_ms: 1_000,
    delete_after_run: true,
    delivery_mode: "none",
    message: runtime.scheduled[0].message,
  });
  assert.doesNotMatch(JSON.stringify(enabled.details.cron_handoff), /Avery|Exampleville|profile_|agent:main/u);
});

test("worker rejects cross-broker campaign activity as proof of its exact issued command", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ web: { results: [] } }), {
    status: 200, headers: { "content-type": "application/json" },
  });
  try {
    const runtime = await runtimeFixture();
    const brokerIds = ["dealfront_eu", "emetriq_eu", "fullenrich_eu", "kaspr_eu", "snov_eu"];
    const campaignInput = { profileId, brokerIds, effects: ["discover"], durationHours: 24, maxEffects: 5 };
    const campaignApproval = await runtime.beforeToolCall({
      toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "cross-campaign",
    });
    campaignApproval.requireApproval.onResolution("allow-once");
    const campaign = await runtime.tools.get("rightout_start_campaign").execute("cross-campaign", campaignInput);
    const enableInput = { campaignId: campaign.details.campaign_id, intervalMinutes: 15, maxConsecutiveFailures: 2 };
    const enableApproval = await runtime.beforeToolCall({ toolName: "rightout_worker_enable", params: enableInput, toolCallId: "cross-enable" });
    enableApproval.requireApproval.onResolution("allow-once");
    const enabled = await runtime.tools.get("rightout_worker_enable").execute("cross-enable", enableInput);
    const tick = await runtime.tools.get("rightout_worker_tick").execute("cross-tick", { workerId: enabled.details.worker_id });
    assert.equal(tick.details.state, "action_ready");
    assert.equal(tick.details.command.parameters.brokerIds.includes("snov_eu"), false);

    const wrongParams = { profileId, brokerIds: ["snov_eu"], campaignId: campaign.details.campaign_id };
    const wrongHook = await runtime.beforeToolCall({ toolName: "rightout_live_scan", params: wrongParams, toolCallId: "cross-wrong-effect" });
    assert.equal(wrongHook.requireApproval, undefined);
    const wrongEffect = await runtime.tools.get("rightout_live_scan").execute("cross-wrong-effect", wrongParams);
    await runtime.afterToolCall({ toolName: "rightout_live_scan", params: wrongParams, toolCallId: "cross-wrong-effect", result: wrongEffect });

    await assert.rejects(runtime.tools.get("rightout_worker_complete").execute("cross-complete", {
      workerId: enabled.details.worker_id,
      leaseId: tick.details.lease_id,
      outcome: "action_succeeded",
    }), /rightout_worker_success_evidence_missing/);
    const status = await runtime.tools.get("rightout_worker_status").execute("cross-status", { workerId: enabled.details.worker_id });
    assert.equal(status.details.actions_completed, 0);
    assert.equal(status.details.unresolved_action, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("worker startup recovery re-registers a lease watchdog after restart", async () => {
  const runtime = await runtimeFixture();
  const campaignInput = { profileId, brokerIds: ["truepeoplesearch"], effects: ["discover"], durationHours: 24, maxEffects: 1 };
  const campaignApproval = await runtime.beforeToolCall({ toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "recovery-campaign" });
  campaignApproval.requireApproval.onResolution("allow-once");
  const campaign = await runtime.tools.get("rightout_start_campaign").execute("recovery-campaign", campaignInput);
  const enableInput = { campaignId: campaign.details.campaign_id, intervalMinutes: 15, maxConsecutiveFailures: 2 };
  const enableApproval = await runtime.beforeToolCall({ toolName: "rightout_worker_enable", params: enableInput, toolCallId: "recovery-enable" });
  enableApproval.requireApproval.onResolution("allow-once");
  const enabled = await runtime.tools.get("rightout_worker_enable").execute("recovery-enable", enableInput);
  const tick = await runtime.tools.get("rightout_worker_tick").execute("recovery-tick", { workerId: enabled.details.worker_id });
  assert.equal(tick.details.lease_watchdog_registered, true);
  assert.equal(runtime.scheduled.length, 1);

  const restarted = await runtimeFixture({ stateDir: runtime.stateDir });
  for (let attempt = 0; attempt < 20 && restarted.scheduled.length === 0; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(restarted.scheduled.length, 1);
  assert.match(restarted.scheduled[0].tag, /^rightout-worker-/);
  assert.equal(restarted.scheduled[0].sessionKey, trusted.sessionKey);
  assert.ok(restarted.scheduled[0].delayMs >= 1_000);
  assert.doesNotMatch(restarted.scheduled[0].message, /Avery|Exampleville|profile_/u);
});
