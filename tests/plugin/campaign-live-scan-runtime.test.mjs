import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { scanProfileDigest } from "../../lib/live-scan.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const brokerId = "truepeoplesearch";
const profile = JSON.stringify({
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  consent: {
    authorized: true,
    recordedAt: CONSENT_RECORDED_AT,
    validUntil: CONSENT_VALID_UNTIL,
    scope: ["scan"],
    method: "self",
  },
});
async function registerRuntime(stateDir) {
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
      stateEncryptionKey: "dummy-campaign-live-scan-key-with-more-than-32-characters",
      braveApiKey: "dummy-brave-key",
      profiles: { [profileId]: { payload: profile } },
      operatorAttestations: {
        braveTermsAccepted: true,
        braveTermsVersion: "2026-02-11",
        braveCustomerResponsibilitiesAccepted: true,
        subjectConsentReviewed: true,
        authorizedProfileIds: [profileId],
        authorizedProfileDigests: { [profileId]: scanProfileDigest(profile) },
        authorizedBrokerIds: [brokerId],
      },
    },
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  return { tools, beforeToolCall: (...args) => beforeToolCall(...args) };
}

test("discover campaign advances through live scan persistence to done_for_now", async () => {
  const originalFetch = globalThis.fetch;
  const fetchMock = async () => new Response(JSON.stringify({ web: { results: [] } }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
  fetchMock.mock = {};
  globalThis.fetch = fetchMock;
  try {
    const runtime = await registerRuntime(mkdtempSync(join(tmpdir(), "rightout-campaign-live-scan-")));
    const startInput = {
      profileId,
      brokerIds: [brokerId],
      effects: ["discover"],
      durationHours: 1,
      maxEffects: 4,
    };
    const startApproval = await runtime.beforeToolCall({
      toolName: "rightout_start_campaign",
      params: startInput,
      toolCallId: "campaign-live-scan-start",
    });
    startApproval.requireApproval.onResolution("allow-once");
    const started = await runtime.tools.get("rightout_start_campaign").execute("campaign-live-scan-start", startInput);

    const first = await runtime.tools.get("rightout_campaign_next").execute("campaign-live-scan-next-1", {
      campaignId: started.details.campaign_id,
    });
    assert.equal(first.details.state, "action_ready");
    assert.equal(first.details.command.tool, "rightout_live_scan");

    const scanHook = await runtime.beforeToolCall({
      toolName: first.details.command.tool,
      params: first.details.command.parameters,
      toolCallId: "campaign-live-scan-effect",
    });
    assert.equal(scanHook.block, undefined);
    const scanned = await runtime.tools.get("rightout_live_scan").execute(
      "campaign-live-scan-effect",
      scanHook.params,
    );
    assert.equal(scanned.details.mode, "campaign_gated_live_scan");
    assert.equal(scanned.details.tracking.durable_case_recorded, true);

    const caseStatus = await runtime.tools.get("rightout_case_status").execute("campaign-live-scan-status", { profileId });
    assert.equal(caseStatus.details.counts.inconclusive, 1);
    const second = await runtime.tools.get("rightout_campaign_next").execute("campaign-live-scan-next-2", {
      campaignId: started.details.campaign_id,
    });
    assert.equal(second.details.state, "done_for_now");
    assert.equal(second.details.reason, "global_catalog_scan_scope_complete");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
