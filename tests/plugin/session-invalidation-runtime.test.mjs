import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { scanProfileDigest } from "../../lib/live-scan.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";
import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";
import { formAttestations } from "./form-attestation-fixture.mjs";

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

function browserMock(calls) {
  return async (url, init = {}) => {
    const parsed = new URL(url);
    calls.push({ path: parsed.pathname, method: init.method ?? "GET" });
    if (parsed.pathname.endsWith("/tabs/open")) {
      const body = JSON.parse(init.body);
      return json({ targetId: "tab-invalidation", suggestedTargetId: "tab-invalidation", url: body.url });
    }
    if (parsed.pathname.endsWith("/snapshot")) {
      return json({
        ok: true,
        format: "ai",
        targetId: "tab-invalidation",
        url: "https://www.familytreenow.com/optout",
        snapshot: "First name. Last name. Search. Submit opt out.",
        refs: {
          f1: { role: "textbox", name: "First name" },
          l1: { role: "textbox", name: "Last name" },
          s1: { role: "button", name: "Search" },
          b1: { role: "button", name: "Submit opt out" },
        },
      });
    }
    if (init.method === "DELETE" && parsed.pathname.includes("/tabs/")) return json({ ok: true });
    throw new Error(`unexpected browser call ${init.method ?? "GET"} ${parsed.pathname}`);
  };
}

async function runtimeFixture() {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-session-invalidation-"));
  const tools = new Map();
  let beforeToolCall;
  const config = {
    stateEncryptionKey: "dummy-session-invalidation-key-with-more-than-32-characters",
    profiles: { [profileId]: { payload: profilePayload } },
    formAttestations: formAttestations(profileId, profilePayload, ["familytreenow"]),
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
  };
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
    pluginConfig: config,
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  async function campaign(effect) {
    const input = { profileId, brokerIds: ["familytreenow"], effects: [effect], durationHours: 24, maxEffects: 1 };
    const approval = await beforeToolCall({ toolName: "rightout_start_campaign", params: input, toolCallId: `start-${effect}` });
    approval.requireApproval.onResolution("allow-once");
    return (await tools.get("rightout_start_campaign").execute(`start-${effect}`, input)).details.campaign_id;
  }
  return { tools, config, campaign, beforeToolCall };
}

test("expired form sessions close their PII-bearing tab before returning expired", async () => {
  const originalFetch = globalThis.fetch;
  const originalNow = Date.now;
  const calls = [];
  globalThis.fetch = browserMock(calls);
  try {
    const runtime = await runtimeFixture();
    const campaignId = await runtime.campaign("submit_form");
    const opened = await runtime.tools.get("rightout_begin_form_session").execute("begin-form", {
      profileId, brokerId: "familytreenow", campaignId,
    });
    const at = originalNow();
    Date.now = () => at + 31 * 60_000;
    await assert.rejects(
      () => runtime.tools.get("rightout_form_session_step").execute("expired-form", {
        sessionId: opened.details.session_id, action: { kind: "inspect" },
      }),
      /rightout_form_session_expired/,
    );
    assert.equal(calls.filter((call) => call.method === "DELETE").length, 1);
  } finally {
    Date.now = originalNow;
    globalThis.fetch = originalFetch;
  }
});

test("publisher-permission mutation invalidates and closes a discovery session", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = browserMock(calls);
  try {
    const runtime = await runtimeFixture();
    const campaignId = await runtime.campaign("publisher_discover");
    const opened = await runtime.tools.get("rightout_begin_discovery_session").execute("begin-discovery", {
      profileId, brokerId: "familytreenow", campaignId,
    });
    delete runtime.config.publisherAutomationPermissions.familytreenow;
    await assert.rejects(
      () => runtime.tools.get("rightout_discovery_session_step").execute("mutated-discovery", {
        sessionId: opened.details.session_id, action: { kind: "inspect" },
      }),
      /rightout_publisher_automation_not_authorized/,
    );
    assert.equal(calls.filter((call) => call.method === "DELETE").length, 1);
    await assert.rejects(
      () => runtime.tools.get("rightout_discovery_session_step").execute("mutated-discovery-again", {
        sessionId: opened.details.session_id, action: { kind: "inspect" },
      }),
      /rightout_discovery_session_expired/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("publisher-discovery attestation mutation invalidates before another browser action", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = browserMock(calls);
  try {
    const runtime = await runtimeFixture();
    const campaignId = await runtime.campaign("publisher_discover");
    const opened = await runtime.tools.get("rightout_begin_discovery_session").execute("begin-attested-discovery", {
      profileId, brokerId: "familytreenow", campaignId,
    });
    runtime.config.directScanAttestations.authorizedProfileDigests[profileId] = "f".repeat(64);
    const callsBeforeStep = calls.length;
    await assert.rejects(
      () => runtime.tools.get("rightout_discovery_session_step").execute("mutated-attestation", {
        sessionId: opened.details.session_id, action: { kind: "inspect" },
      }),
      /rightout_direct_scan_profile_snapshot_changed|rightout_campaign_runtime_scope_changed/,
    );
    assert.equal(calls.length, callsBeforeStep + 1);
    assert.equal(calls.at(-1).method, "DELETE");
  } finally { globalThis.fetch = originalFetch; }
});

test("missing form attestation blocks before provider I/O and before campaign effect consumption", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = browserMock(calls);
  try {
    const runtime = await runtimeFixture();
    const campaignId = await runtime.campaign("submit_form");
    delete runtime.config.formAttestations;
    await assert.rejects(
      () => runtime.tools.get("rightout_begin_form_session").execute("missing-form-attestation", {
        profileId, brokerId: "familytreenow", campaignId,
      }),
      /rightout_form_attestation_required/,
    );
    assert.equal(calls.length, 0);
    const status = await runtime.tools.get("rightout_campaign_status").execute("missing-form-attestation-status", { campaignId });
    assert.equal(status.details.used_effects, 0);
  } finally { globalThis.fetch = originalFetch; }
});

test("campaign revocation immediately closes an already-open form session", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = browserMock(calls);
  try {
    const runtime = await runtimeFixture();
    const campaignId = await runtime.campaign("submit_form");
    await runtime.tools.get("rightout_begin_form_session").execute("begin-revoked-form", {
      profileId, brokerId: "familytreenow", campaignId,
    });
    const input = { campaignId };
    const approval = await runtime.beforeToolCall({ toolName: "rightout_revoke_campaign", params: input, toolCallId: "revoke-open-session" });
    approval.requireApproval.onResolution("allow-once");
    const revoked = await runtime.tools.get("rightout_revoke_campaign").execute("revoke-open-session", input);
    assert.equal(revoked.details.status, "revoked");
    assert.equal(revoked.details.active_sessions_invalidated, 1);
    assert.equal(calls.filter((call) => call.method === "DELETE").length, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("failed tab DELETE is reported as manual cleanup instead of clean revocation", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const parsed = new URL(url);
    calls.push({ path: parsed.pathname, method: init.method ?? "GET" });
    if (parsed.pathname.endsWith("/tabs/open")) return json({ targetId: "tab-invalidation", url: "https://www.familytreenow.com/optout" });
    if (parsed.pathname.endsWith("/snapshot")) return json({
      ok: true, format: "ai", targetId: "tab-invalidation", url: "https://www.familytreenow.com/optout",
      snapshot: "First name Search", refs: { f1: { role: "textbox", name: "First name" }, s1: { role: "button", name: "Search" } },
    });
    if (init.method === "DELETE") return new Response("gateway unavailable", { status: 503 });
    throw new Error(`unexpected browser call ${init.method ?? "GET"} ${parsed.pathname}`);
  };
  try {
    const runtime = await runtimeFixture();
    const campaignId = await runtime.campaign("submit_form");
    await runtime.tools.get("rightout_begin_form_session").execute("begin-close-failure", {
      profileId, brokerId: "familytreenow", campaignId,
    });
    const input = { campaignId };
    const approval = await runtime.beforeToolCall({ toolName: "rightout_revoke_campaign", params: input, toolCallId: "revoke-close-failure" });
    approval.requireApproval.onResolution("allow-once");
    const revoked = await runtime.tools.get("rightout_revoke_campaign").execute("revoke-close-failure", input);
    assert.equal(revoked.details.browser_tabs_closed, 0);
    assert.equal(revoked.details.browser_tabs_needing_manual_cleanup, 1);
    const cases = await runtime.tools.get("rightout_case_status").execute("close-failure-cases", { profileId });
    assert.equal(cases.details.cases.find((item) => item.broker_id === "familytreenow").state, "human_task_queued");
  } finally { globalThis.fetch = originalFetch; }
});

test("host timer closes an expired browser session without requiring another tool call", async () => {
  const originalFetch = globalThis.fetch;
  const originalSetTimeout = globalThis.setTimeout;
  const originalClearTimeout = globalThis.clearTimeout;
  const calls = [];
  let expiryCallback;
  const fakeTimer = { unref() {} };
  globalThis.setTimeout = (callback, delay, ...args) => {
    if (delay > 1_000_000) {
      expiryCallback = () => callback(...args);
      return fakeTimer;
    }
    return originalSetTimeout(callback, delay, ...args);
  };
  globalThis.clearTimeout = (timer) => timer === fakeTimer ? undefined : originalClearTimeout(timer);
  globalThis.fetch = browserMock(calls);
  try {
    const runtime = await runtimeFixture();
    const campaignId = await runtime.campaign("submit_form");
    await runtime.tools.get("rightout_begin_form_session").execute("begin-timed-form", {
      profileId, brokerId: "familytreenow", campaignId,
    });
    assert.equal(typeof expiryCallback, "function");
    expiryCallback();
    for (let index = 0; index < 20 && calls.filter((call) => call.method === "DELETE").length === 0; index += 1) {
      await new Promise((resolve) => originalSetTimeout(resolve, 0));
    }
    assert.equal(calls.filter((call) => call.method === "DELETE").length, 1);
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.setTimeout = originalSetTimeout;
    globalThis.clearTimeout = originalClearTimeout;
  }
});
