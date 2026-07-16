import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";
import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";
import { formAttestations } from "./form-attestation-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const profile = {
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  dateOfBirth: "1990-01-01",
  contactEmail: "avery@example.invalid",
  jurisdictions: ["US", "US-CA"],
  consent: {
    authorized: true,
    recordedAt: CONSENT_RECORDED_AT,
    validUntil: CONSENT_VALID_UNTIL,
    scope: ["scan", "broker_removal"],
    method: "self",
  },
};
const stateKey = "dummy-generic-form-session-key-with-more-than-32-characters";
const profilePayload = JSON.stringify(profile);

function json(value) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
}

function page(text, refs) {
  return json({
    ok: true,
    format: "ai",
    targetId: "tab-family",
    url: "https://www.familytreenow.com/optout",
    snapshot: text,
    refs,
  });
}

test("a generic parity route submits under one campaign approval with redacted snapshots", async () => {
  const originalFetch = globalThis.fetch;
  const responses = [
    json({ ok: true, targetId: "tab-family", url: "https://www.familytreenow.com/optout" }),
    page("First name Avery. Last name Example. Submit opt out.", {
      f1: { role: "textbox", name: "First name Avery" },
      l1: { role: "textbox", name: "Last name Example" },
      b1: { role: "button", name: "Submit opt out" },
    }),
    page("First name Avery. Last name Example. Submit opt out.", {
      f1: { role: "textbox", name: "First name Avery" },
      l1: { role: "textbox", name: "Last name Example" },
      b1: { role: "button", name: "Submit opt out" },
    }),
    json({ ok: true }),
    page("First name Avery. Last name Example. Submit opt out.", {
      f1: { role: "textbox", name: "First name Avery" },
      l1: { role: "textbox", name: "Last name Example" },
      b1: { role: "button", name: "Submit opt out" },
    }),
    page("First name Avery. Last name Example. Submit opt out.", {
      f1: { role: "textbox", name: "First name Avery" },
      l1: { role: "textbox", name: "Last name Example" },
      b1: { role: "button", name: "Submit opt out" },
    }),
    json({ ok: true }),
    page("Thank you. Your opt-out request was submitted.", {}),
    page("Thank you. Your opt-out request was submitted.", {}),
    json({ ok: true, image: "opaque-dummy-image" }),
    json({ ok: true }),
  ];
  globalThis.fetch = async () => {
    const response = responses.shift();
    if (!response) throw new Error("unexpected browser call");
    return response;
  };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-form-session-runtime-"));
    const runtime = { state: { resolveStateDir() { return stateDir; } } };
    const tools = new Map();
    let beforeToolCall;
    const plugin = (await import("../../index.ts")).default;
    plugin.register({
      runtime,
      on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
      registerTool(tool) {
        const resolved = typeof tool === "function"
          ? tool({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } })
          : tool;
        tools.set(resolved.name, resolved);
      },
      registerSecurityAuditCollector() {},
      pluginConfig: {
        stateEncryptionKey: stateKey,
        profiles: { [profileId]: { payload: profilePayload } },
        formAttestations: formAttestations(profileId, profilePayload, ["familytreenow"]),
        publisherAutomationPermissions: publisherAutomationPermissions(["familytreenow"]),
      },
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const campaignInput = {
      profileId,
      brokerIds: ["familytreenow"],
      effects: ["submit_form"],
      durationHours: 24,
      maxEffects: 1,
    };
    const approval = await beforeToolCall({ toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "campaign-start" });
    approval.requireApproval.onResolution("allow-once");
    const campaign = await tools.get("rightout_start_campaign").execute("campaign-start", campaignInput);

    const opened = await tools.get("rightout_begin_form_session").execute("begin", {
      profileId,
      brokerId: "familytreenow",
      campaignId: campaign.details.campaign_id,
    });
    assert.equal(opened.details.state, "form_session_ready");
    assert.match(opened.details.snapshot.snapshot, /generic_form_content_redacted/);
    assert.ok(opened.details.form_fields_available.includes("first_name"));
    assert.ok(opened.details.form_fields_available.includes("last_name"));
    assert.deepEqual(opened.details.disclosures_allowed, ["full_name"]);
    assert.doesNotMatch(JSON.stringify(opened.details), /Avery Example/);

    const filled = await tools.get("rightout_form_session_step").execute("fill", {
      sessionId: opened.details.session_id,
      action: { kind: "fill", fields: [
        { ref: "f1", profile_field: "first_name", type: "text" },
        { ref: "l1", profile_field: "last_name", type: "text" },
      ] },
    });
    assert.equal(filled.details.state, "form_session_active");

    const submitted = await tools.get("rightout_form_session_step").execute("submit", {
      sessionId: opened.details.session_id,
      action: { kind: "click", ref: "b1", purpose: "submit" },
    });
    assert.equal(submitted.details.state, "verification_pending");
    assert.equal(submitted.details.delivery.form_submitted, true);
    assert.match(submitted.details.redacted_state_receipt.receipt_reference, /^receipt_[a-f0-9]{24}$/);
    assert.equal(JSON.stringify(submitted.details).includes("Avery Example"), false);

    const status = await tools.get("rightout_campaign_status").execute("status", { campaignId: campaign.details.campaign_id });
    assert.equal(status.details.used_effects, 1);
    assert.equal(status.details.status, "completed");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("PeopleConnect refuses to consume campaign scope without an exact named browser profile", async () => {
  const originalFetch = globalThis.fetch;
  let browserCalls = 0;
  globalThis.fetch = async () => { browserCalls += 1; throw new Error("browser bridge must not be reached"); };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-sensitive-form-runtime-"));
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
        stateEncryptionKey: stateKey,
        profiles: { [profileId]: { payload: profilePayload } },
        formAttestations: formAttestations(profileId, profilePayload, ["intelius"]),
        publisherAutomationPermissions: publisherAutomationPermissions(["intelius"]),
      },
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });
    const campaignInput = { profileId, brokerIds: ["intelius"], effects: ["submit_form"], durationHours: 24, maxEffects: 1 };
    const approval = await beforeToolCall({ toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "sensitive-campaign" });
    approval.requireApproval.onResolution("allow-once");
    const campaign = await tools.get("rightout_start_campaign").execute("sensitive-campaign", campaignInput);
    await assert.rejects(
      () => tools.get("rightout_begin_form_session").execute("missing-profile", {
        profileId, brokerId: "intelius", campaignId: campaign.details.campaign_id,
      }),
      /rightout_peopleconnect_named_browser_profile_required/,
    );
    const status = await tools.get("rightout_campaign_status").execute("status", { campaignId: campaign.details.campaign_id });
    assert.equal(status.details.used_effects, 0);
    assert.equal(browserCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("an unrelated stale parity route blocks form runtime before browser I/O or effect consumption", async () => {
  const originalFetch = globalThis.fetch;
  let browserCalls = 0;
  globalThis.fetch = async () => { browserCalls += 1; throw new Error("browser bridge must not be reached"); };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-stale-global-form-runtime-"));
    const staleCatalogPath = join(stateDir, "unbroker-parity-stale.json");
    const catalog = JSON.parse(readFileSync(
      new URL("../../skills/data-broker-removal/references/brokers/unbroker-parity.json", import.meta.url),
      "utf8",
    ));
    const unrelated = catalog.brokers.find((row) => row.id === "addresses");
    assert.ok(unrelated);
    unrelated.last_checked = "2026-01-01";
    writeFileSync(staleCatalogPath, `${JSON.stringify(catalog)}\n`, { mode: 0o600 });

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
        stateEncryptionKey: stateKey,
        profiles: { [profileId]: { payload: profilePayload } },
        formAttestations: formAttestations(profileId, profilePayload, ["familytreenow"]),
        publisherAutomationPermissions: publisherAutomationPermissions(["familytreenow"]),
      },
      resolvePath(value) {
        return value.endsWith("unbroker-parity.json") ? staleCatalogPath : value;
      },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const campaignInput = {
      profileId,
      brokerIds: ["familytreenow"],
      effects: ["submit_form"],
      durationHours: 24,
      maxEffects: 1,
    };
    const approval = await beforeToolCall({
      toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "stale-campaign",
    });
    approval.requireApproval.onResolution("allow-once");
    const campaign = await tools.get("rightout_start_campaign").execute("stale-campaign", campaignInput);

    await assert.rejects(
      () => tools.get("rightout_begin_form_session").execute("stale-form", {
        profileId, brokerId: "familytreenow", campaignId: campaign.details.campaign_id,
      }),
      /rightout_catalog_lane_stale/,
    );
    const status = await tools.get("rightout_campaign_status").execute("stale-status", {
      campaignId: campaign.details.campaign_id,
    });
    assert.equal(status.details.used_effects, 0);
    assert.equal(browserCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("a due market route blocks a parity form before SecretRef access or browser I/O", async () => {
  const originalNow = Date.now;
  const originalFetch = globalThis.fetch;
  let at = Date.parse("2026-07-31T23:59:30.000Z");
  let browserCalls = 0;
  let secretReads = 0;
  Date.now = () => at;
  globalThis.fetch = async () => {
    browserCalls += 1;
    throw new Error("browser bridge must not be reached");
  };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-form-market-route-boundary-"));
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
        get stateEncryptionKey() { secretReads += 1; return stateKey; },
        get profiles() { secretReads += 1; return { [profileId]: { payload: profilePayload } }; },
        formAttestations: formAttestations(profileId, profilePayload, ["familytreenow"]),
        publisherAutomationPermissions: publisherAutomationPermissions(["familytreenow"]),
      },
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const campaignInput = {
      profileId,
      brokerIds: ["familytreenow"],
      effects: ["submit_form"],
      durationHours: 1,
      maxEffects: 1,
    };
    const approval = await beforeToolCall({
      toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "market-route-campaign",
    });
    approval.requireApproval.onResolution("allow-once");
    const campaign = await tools.get("rightout_start_campaign").execute("market-route-campaign", campaignInput);
    secretReads = 0;

    at = Date.parse("2026-08-01T00:00:10.000Z");
    await assert.rejects(
      () => tools.get("rightout_begin_form_session").execute("market-route-form", {
        profileId, brokerId: "familytreenow", campaignId: campaign.details.campaign_id,
      }),
      /rightout_market_policy_source_not_current/,
    );
    assert.equal(secretReads, 0);
    assert.equal(browserCalls, 0);
    const status = await tools.get("rightout_campaign_status").execute("market-route-status", {
      campaignId: campaign.details.campaign_id,
    });
    assert.equal(status.details.used_effects, 0);
  } finally {
    Date.now = originalNow;
    globalThis.fetch = originalFetch;
  }
});

test("externally unavailable archived form routes cannot bypass their autonomous rescue lane", async () => {
  const originalFetch = globalThis.fetch;
  let browserCalls = 0;
  globalThis.fetch = async () => {
    browserCalls += 1;
    throw new Error("browser bridge must not be reached");
  };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-unavailable-form-runtime-"));
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
        stateEncryptionKey: stateKey,
        profiles: { [profileId]: { payload: JSON.stringify(profile) } },
        publisherAutomationPermissions: publisherAutomationPermissions(["clustrmaps", "peekyou"]),
      },
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const campaignInput = {
      profileId,
      brokerIds: ["clustrmaps", "peekyou"],
      effects: ["submit_form"],
      durationHours: 24,
      maxEffects: 2,
    };
    const approval = await beforeToolCall({
      toolName: "rightout_start_campaign",
      params: campaignInput,
      toolCallId: "unavailable-form-campaign",
    });
    approval.requireApproval.onResolution("allow-once");
    const campaign = await tools.get("rightout_start_campaign").execute("unavailable-form-campaign", campaignInput);

    for (const brokerId of campaignInput.brokerIds) {
      await assert.rejects(
        () => tools.get("rightout_begin_form_session").execute(`unavailable-${brokerId}`, {
          profileId,
          brokerId,
          campaignId: campaign.details.campaign_id,
        }),
        /rightout_parity_route_not_executable/,
      );
    }
    assert.equal(browserCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
