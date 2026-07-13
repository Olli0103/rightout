import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { scanProfileDigest } from "../../lib/live-scan.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";
import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const profile = {
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  contactEmail: "avery@example.invalid",
  currentAddress: { line1: "100 Example Avenue", city: "Exampleville", region: "CA", postal: "90001", country: "US" },
  jurisdictions: ["US", "US-CA"],
  consent: {
    authorized: true,
    recordedAt: CONSENT_RECORDED_AT,
    validUntil: CONSENT_VALID_UNTIL,
    scope: ["scan", "broker_removal"],
    method: "self",
  },
};
const profilePayload = JSON.stringify(profile);

function json(value) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
}

function page(url, snapshot, refs = {}) {
  return json({ ok: true, format: "ai", targetId: "tab-discovery", url, snapshot, refs });
}

test("an inconclusive index result can escalate to separately authorized publisher browser discovery", async () => {
  const originalFetch = globalThis.fetch;
  const browserUrls = [];
  const root = "https://familytreenow.com/";
  const results = "https://familytreenow.com/search/opaque";
  const candidate = "https://familytreenow.com/person/opaque";
  const responses = [
    json({ ok: true, targetId: "tab-discovery", url: root }),
    page(root, "Search for Avery Example", {
      n1: { role: "textbox", name: "Full name Avery Example" },
      c1: { role: "textbox", name: "City Exampleville" },
      s1: { role: "button", name: "Search" },
    }),
    page(root, "Search for Avery Example", {
      n1: { role: "textbox", name: "Full name Avery Example" },
      c1: { role: "textbox", name: "City Exampleville" },
      s1: { role: "button", name: "Search" },
    }),
    json({ ok: true }),
    page(results, "Search results for Avery Example in Exampleville", {
      r1: { role: "link", name: "Select record Avery Example 100 Example Avenue Exampleville" },
    }),
    page(results, "Search results for Avery Example in Exampleville", {
      r1: { role: "link", name: "Select record Avery Example 100 Example Avenue Exampleville" },
    }),
    json({ ok: true }),
    page(candidate, "Avery Example in Exampleville", {}),
    page(candidate, "Avery Example in Exampleville", {}),
    page(candidate, "Avery Example in Exampleville", {}),
    json({ ok: true, image: "opaque-dummy-image" }),
    json({ ok: true }),
  ];
  globalThis.fetch = async (url) => {
    browserUrls.push(String(url));
    const response = responses.shift();
    if (!response) throw new Error("unexpected browser call");
    return response;
  };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-discovery-session-runtime-"));
    const tools = new Map();
    let beforeToolCall;
    const plugin = (await import("../../index.ts")).default;
    plugin.register({
      runtime: { state: { resolveStateDir() { return stateDir; } } },
      on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
      registerTool(tool) {
        const resolved = typeof tool === "function"
          ? tool({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } })
          : tool;
        tools.set(resolved.name, resolved);
      },
      registerSecurityAuditCollector() {},
      pluginConfig: {
        stateEncryptionKey: "dummy-discovery-session-key-with-more-than-32-characters",
        profiles: { [profileId]: { payload: profilePayload } },
        publisherAutomationPermissions: publisherAutomationPermissions(["familytreenow"]),
        directScanAttestations: {
          rightoutDirectScanPolicyAccepted: true,
          rightoutDirectScanPolicyVersion: "2026-07-12",
          subjectConsentReviewed: true,
          publisherAccessAuthorized: true,
          publisherTermsReviewed: true,
          authorizedProfileIds: [profileId],
          authorizedProfileDigests: { [profileId]: scanProfileDigest(profilePayload) },
          authorizedBrokerIds: ["familytreenow"],
        },
      },
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const campaignInput = {
      profileId,
      brokerIds: ["familytreenow"],
      effects: ["publisher_discover", "direct_recheck", "submit_form"],
      durationHours: 24,
      maxEffects: 4,
    };
    const approval = await beforeToolCall({ toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "campaign-start" });
    approval.requireApproval.onResolution("allow-once");
    const campaign = await tools.get("rightout_start_campaign").execute("campaign-start", campaignInput);

    const opened = await tools.get("rightout_begin_discovery_session").execute("begin", {
      profileId,
      brokerId: "familytreenow",
      campaignId: campaign.details.campaign_id,
    });
    assert.equal(opened.details.state, "publisher_discovery_session_ready");
    assert.equal(opened.details.browser_backend, "managed_openclaw");
    assert.doesNotMatch(JSON.stringify(opened.details), /Avery Example|avery@example\.invalid/);

    await tools.get("rightout_discovery_session_step").execute("fill", {
      sessionId: opened.details.session_id,
      action: { kind: "fill", fields: [
        { ref: "n1", profile_field: "full_name", type: "text" },
        { ref: "c1", profile_field: "city", type: "text" },
      ] },
    });
    await tools.get("rightout_discovery_session_step").execute("select", {
      sessionId: opened.details.session_id,
      action: { kind: "click", ref: "r1", purpose: "select_record" },
    });
    const captured = await tools.get("rightout_discovery_session_step").execute("capture", {
      sessionId: opened.details.session_id,
      action: { kind: "capture_candidate" },
    });
    assert.equal(captured.details.state, "indirect_exposure");
    assert.match(captured.details.listing_handle, /^listing_[a-f0-9]{24}$/);
    assert.equal(captured.details.raw_url_in_report, false);
    assert.doesNotMatch(JSON.stringify(captured.details), /familytreenow\.com\/person|Avery Example/);

    const status = await tools.get("rightout_case_status").execute("status", { profileId });
    assert.equal(status.details.cases[0].state, "indirect_exposure");
    assert.equal(status.details.cases[0].listing_handle, captured.details.listing_handle);
    const campaignStatus = await tools.get("rightout_campaign_status").execute("campaign-status", { campaignId: campaign.details.campaign_id });
    assert.equal(campaignStatus.details.used_effects, 1);
    assert.equal(browserUrls.some((url) => url.includes("profile=rightout-remote-cloud")), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
