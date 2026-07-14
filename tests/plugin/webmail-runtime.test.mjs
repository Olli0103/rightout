import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { createListingTokenVault } from "../../lib/listing-tokens.mjs";
import { removalProfileDigest } from "../../lib/removal.mjs";
import { browserVerificationProfileDigest } from "../../lib/verification.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";
import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const stateKey = "dummy-webmail-runtime-key-with-more-than-32-characters";
const profile = {
  fullName: "Avery Example", city: "Exampleville", region: "CA", country: "US",
  contactEmail: "avery@example.invalid", jurisdictions: ["US", "US-CA"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["scan", "broker_removal"], method: "self" },
};

function json(value) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
}

function page(url, text, refs) {
  return json({ ok: true, format: "ai", targetId: "tab-mail", url, snapshot: text, refs });
}

async function createWebmailRuntime() {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-webmail-negative-runtime-"));
  const tools = new Map();
  let beforeToolCall;
  const config = {
    stateEncryptionKey: stateKey,
    browserProfile: "logged-in-gmail",
    browserBackendMode: "existing_logged_in_cdp",
    browserControlBaseUrl: "http://127.0.0.1:3000/browser",
    browserControlToken: "dummy-browser-control-token",
    profiles: { [profileId]: { payload: JSON.stringify(profile) } },
  };
  const plugin = (await import("../../index.ts")).default;
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
    registerTool(tool) {
      const resolved = typeof tool === "function" ? tool({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } }) : tool;
      tools.set(resolved.name, resolved);
    },
    registerSecurityAuditCollector() {}, pluginConfig: config,
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  const campaignInput = { profileId, brokerIds: ["peekyou"], effects: ["submit_email"], durationHours: 24, maxEffects: 1 };
  const approval = await beforeToolCall({ toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "negative-campaign" });
  approval.requireApproval.onResolution("allow-once");
  const campaign = await tools.get("rightout_start_campaign").execute("negative-campaign", campaignInput);
  return { tools, config, campaignId: campaign.details.campaign_id };
}

test("one campaign sends and opens an authenticated broker confirmation through redacted browser webmail", async () => {
  const mailUrl = "https://mail.google.com/mail/u/0/#compose";
  const composeRefs = {
    to1: { role: "textbox", name: "To legal@spokeo.com" },
    subject1: { role: "textbox", name: "Subject Privacy request: delete and opt out" },
    body1: { role: "textbox", name: "Message body for Avery Example" },
    send1: { role: "button", name: "Send" },
    private1: { role: "link", name: "Unrelated private@example.invalid" },
  };
  const responses = [
    json({ ok: true, targetId: "tab-mail", url: mailUrl }),
    page(mailUrl, "Inbox secret for Avery Example", composeRefs),
    page(mailUrl, "Compose for Avery Example", composeRefs),
    page(mailUrl, "Compose for Avery Example", composeRefs), json({ ok: true }),
    page(mailUrl, "Compose for Avery Example", composeRefs),
    page(mailUrl, "Compose for Avery Example", composeRefs), json({ ok: true }),
    page(mailUrl, "Message sent for Avery Example", composeRefs),
    page(mailUrl, "Message sent for Avery Example", composeRefs), json({ ok: true }),
    json({ ok: true, targetId: "tab-mail", url: "https://mail.google.com/mail/u/0/#search/broker" }),
    page("https://mail.google.com/mail/u/0/#search/broker", "Inbox private content", {
      message1: { role: "row", name: "Spokeo verify removal from privacy@spokeo.invalid" },
      unrelated: { role: "row", name: "Bank account statement" },
    }),
    page("https://mail.google.com/mail/u/0/#search/broker", "Inbox private content", {
      message1: { role: "row", name: "Spokeo verify removal from privacy@spokeo.invalid" },
    }), json({ ok: true }),
    page("https://mail.google.com/mail/u/0/#inbox/message", "Message body private content", {
      details1: { role: "button", name: "Show details" },
    }),
    page("https://mail.google.com/mail/u/0/#inbox/message", "Message body private content", {
      details1: { role: "button", name: "Show details" },
    }), json({ ok: true }),
    page("https://mail.google.com/mail/u/0/#inbox/message", "To: avery@example.invalid Signed-by: privacy.spokeo.com", {
      details1: { role: "button", name: "Show details" },
      auth1: { role: "dialog", name: "Message details To: avery@example.invalid Signed-by: privacy.spokeo.com" },
      confirm1: { role: "link", name: "Confirm removal", href: "https://www.spokeo.com/privacy/confirm?id=private-token" },
    }),
    page("https://mail.google.com/mail/u/0/#inbox/message", "To: avery@example.invalid Signed-by: privacy.spokeo.com", {
      auth1: { role: "dialog", name: "Message details To: avery@example.invalid Signed-by: privacy.spokeo.com" },
      confirm1: { role: "link", name: "Confirm removal", href: "https://www.spokeo.com/privacy/confirm?id=private-token" },
    }), json({ ok: true }),
    page("https://www.spokeo.com/privacy/confirm?id=private-token", "Request confirmed", {}),
    page("https://www.spokeo.com/privacy/confirm?id=private-token", "Request confirmed", {}),
    json({ ok: true }),
  ];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    const response = responses.shift();
    if (!response) throw new Error("unexpected browser call");
    return response;
  };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-webmail-runtime-"));
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
        stateEncryptionKey: stateKey,
        browserProfile: "logged-in-gmail",
        browserBackendMode: "existing_logged_in_cdp",
        browserControlBaseUrl: "http://127.0.0.1:3000/browser",
        browserControlToken: "dummy-browser-control-token",
        profiles: { [profileId]: { payload: JSON.stringify(profile) } },
        verificationAttestations: {
          rightoutVerificationPolicyAccepted: true,
          rightoutVerificationPolicyVersion: "2026-07-12",
          subjectConsentReviewed: true,
          inboxReadAuthorized: true,
          verificationLinkOpenAuthorized: true,
          authorizedProfileIds: [profileId],
          authorizedProfileDigests: { [profileId]: removalProfileDigest(JSON.stringify(profile)) },
          authorizedBrokerIds: ["spokeo"],
          browserProfileDigest: browserVerificationProfileDigest({
            browserControlBaseUrl: "http://127.0.0.1:3000/browser",
            browserProfile: "logged-in-gmail",
            browserBackendMode: "existing_logged_in_cdp",
          }),
        },
        publisherAutomationPermissions: publisherAutomationPermissions(["spokeo"]),
      },
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const listingStore = createEncryptedFileKeyedStore({
      stateDir, namespace: "rightout-listing-tokens-v1", maxEntries: 500,
      defaultTtlMs: 180 * 24 * 60 * 60_000, getSecret: () => stateKey, getPreviousSecrets: () => [],
    });
    const listingHandle = await createListingTokenVault(listingStore, stateKey).storeCandidate({
      profileId, brokerId: "spokeo", urls: ["https://www.spokeo.com/Avery-Example/opaque"],
      officialDomains: ["spokeo.com"], observedAt: "2026-07-13T08:00:00.000Z",
    });

    const campaignInput = {
      profileId, brokerIds: ["spokeo"],
      effects: ["open_verification", "poll_verification", "submit_email"],
      durationHours: 24, maxEffects: 3,
    };
    const approval = await beforeToolCall({ toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "campaign" });
    approval.requireApproval.onResolution("allow-once");
    const campaign = await tools.get("rightout_start_campaign").execute("campaign", campaignInput);

    const opened = await tools.get("rightout_begin_webmail_session").execute("begin-mail", {
      profileId, brokerId: "spokeo", campaignId: campaign.details.campaign_id, listingHandle,
    });
    assert.equal(opened.details.state, "webmail_session_ready");
    assert.equal(JSON.stringify(opened.details).includes("Avery Example"), false);
    assert.equal(JSON.stringify(opened.details).includes("private@example.invalid"), false);

    const beforeInvalid = responses.length;
    await assert.rejects(tools.get("rightout_webmail_session_step").execute("select-recipient", {
      sessionId: opened.details.session_id,
      action: { kind: "select", ref: "to1", values: ["attacker@example.invalid"] },
    }), /rightout_webmail_session_input_invalid/);
    assert.equal(responses.length, beforeInvalid);

    await assert.rejects(tools.get("rightout_webmail_session_step").execute("failed-fill", {
      sessionId: opened.details.session_id,
      action: { kind: "fill", fields: [
        { ref: "invented", profile_field: "recipient", type: "email" },
        { ref: "subject1", profile_field: "message_subject", type: "text" },
        { ref: "body1", profile_field: "message_body", type: "text" },
      ] },
    }), /rightout_form_ref_invalid/);
    const beforePrematureSend = responses.length;
    await assert.rejects(tools.get("rightout_webmail_session_step").execute("premature-send", {
      sessionId: opened.details.session_id,
      action: { kind: "click", ref: "send1", purpose: "send" },
    }), /rightout_webmail_fields_incomplete/);
    assert.equal(responses.length, beforePrematureSend);

    await tools.get("rightout_webmail_session_step").execute("fill-mail", {
      sessionId: opened.details.session_id,
      action: { kind: "fill", fields: [
        { ref: "to1", profile_field: "recipient", type: "email" },
        { ref: "subject1", profile_field: "message_subject", type: "text" },
        { ref: "body1", profile_field: "message_body", type: "text" },
      ] },
    });
    const sent = await tools.get("rightout_webmail_session_step").execute("send-mail", {
      sessionId: opened.details.session_id,
      action: { kind: "click", ref: "send1", purpose: "send" },
    });
    assert.equal(sent.details.state, "submitted");
    assert.equal(sent.details.delivery.webmail_sent, true);
    assert.equal(sent.details.raw_message_in_report, false);

    const verification = await tools.get("rightout_begin_webmail_verification").execute("begin-verify", {
      profileId, brokerId: "spokeo", campaignId: campaign.details.campaign_id,
    });
    assert.equal(verification.details.state, "webmail_verification_session_ready");
    assert.equal(verification.details.provider_reads, 1);
    assert.equal(verification.details.provider_writes, 0);

    const message = await tools.get("rightout_webmail_session_step").execute("open-message", {
      sessionId: verification.details.session_id,
      action: { kind: "click", ref: "message1", purpose: "open_message" },
    });
    assert.equal(message.details.message_authenticated, false);
    const authenticated = await tools.get("rightout_webmail_session_step").execute("inspect-authentication", {
      sessionId: verification.details.session_id,
      action: { kind: "click", ref: "details1", purpose: "inspect_authentication" },
    });
    assert.equal(authenticated.details.message_authenticated, true);
    assert.equal(JSON.stringify(authenticated.details).includes("private-token"), false);
    assert.equal(JSON.stringify(authenticated.details).includes("avery@example.invalid"), false);
    const confirmed = await tools.get("rightout_webmail_session_step").execute("open-confirmation", {
      sessionId: verification.details.session_id,
      action: { kind: "click", ref: "confirm1", purpose: "open_confirmation" },
    });
    assert.equal(confirmed.details.state, "awaiting_processing", `${JSON.stringify(confirmed.details)} remaining=${responses.length}`);
    assert.equal(confirmed.details.authenticated_browser_message_bound, true);
    assert.equal(confirmed.details.raw_mailbox_content_in_report, false);
    assert.equal(JSON.stringify(confirmed.details).includes("private-token"), false);

    const status = await tools.get("rightout_campaign_status").execute("status", { campaignId: campaign.details.campaign_id });
    assert.equal(status.details.status, "completed");
    assert.equal(status.details.used_effects, 3);
    assert.equal(responses.length, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("an externally unavailable PeekYou form can use the official regulator email without a listing URL", async () => {
  const mailUrl = "https://mail.google.com/mail/u/0/#compose";
  const composeRefs = {
    to1: { role: "textbox", name: "To ccpa@peekyou.com" },
    subject1: { role: "textbox", name: "Subject Privacy request: delete and opt out" },
    body1: { role: "textbox", name: "Message body for Avery Example" },
    send1: { role: "button", name: "Send" },
  };
  const responses = [
    json({ ok: true, targetId: "tab-mail", url: mailUrl }),
    page(mailUrl, "Compose for Avery Example", composeRefs),
    page(mailUrl, "Compose for Avery Example", composeRefs), json({ ok: true }),
    page(mailUrl, "Compose for Avery Example", composeRefs),
    page(mailUrl, "Compose for Avery Example", composeRefs), json({ ok: true }),
    page(mailUrl, "Message sent for Avery Example", composeRefs),
    page(mailUrl, "Message sent for Avery Example", composeRefs), json({ ok: true }),
  ];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    const response = responses.shift();
    if (!response) throw new Error("unexpected browser call");
    return response;
  };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-peekyou-webmail-runtime-"));
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
        stateEncryptionKey: stateKey,
        browserProfile: "logged-in-gmail",
        browserBackendMode: "existing_logged_in_cdp",
        browserControlBaseUrl: "http://127.0.0.1:3000/browser",
        browserControlToken: "dummy-browser-control-token",
        profiles: { [profileId]: { payload: JSON.stringify(profile) } },
      },
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const campaignInput = {
      profileId, brokerIds: ["peekyou"], effects: ["submit_email"], durationHours: 24, maxEffects: 1,
    };
    const approval = await beforeToolCall({ toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "campaign-peekyou" });
    approval.requireApproval.onResolution("allow-once");
    const campaign = await tools.get("rightout_start_campaign").execute("campaign-peekyou", campaignInput);
    const opened = await tools.get("rightout_begin_webmail_session").execute("begin-peekyou", {
      profileId, brokerId: "peekyou", campaignId: campaign.details.campaign_id,
    });
    assert.equal(opened.details.state, "webmail_session_ready");

    await tools.get("rightout_webmail_session_step").execute("fill-peekyou", {
      sessionId: opened.details.session_id,
      action: { kind: "fill", fields: [
        { ref: "to1", profile_field: "recipient", type: "email" },
        { ref: "subject1", profile_field: "message_subject", type: "text" },
        { ref: "body1", profile_field: "message_body", type: "text" },
      ] },
    });
    const sent = await tools.get("rightout_webmail_session_step").execute("send-peekyou", {
      sessionId: opened.details.session_id,
      action: { kind: "click", ref: "send1", purpose: "send" },
    });
    assert.equal(sent.details.state, "submitted");
    assert.deepEqual(sent.details.disclosures.to_broker, ["full_name", "contact_email"]);
    assert.equal(sent.details.raw_message_in_report, false);
    assert.equal(JSON.stringify(sent.details).includes("Avery Example"), false);
    assert.equal(responses.length, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("uncertain webmail fill discards the possible autosaved draft, closes the tab, and cannot retry", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  const mailUrl = "https://mail.google.com/mail/u/0/#compose";
  const composeRefs = {
    to1: { role: "textbox", name: "To ccpa@peekyou.com" },
    subject1: { role: "textbox", name: "Subject Privacy request" },
    body1: { role: "textbox", name: "Message body" },
  };
  let snapshotCount = 0;
  globalThis.fetch = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ path, method: init.method ?? "GET", body });
    if (path.endsWith("/tabs/open")) return json({ ok: true, targetId: "tab-mail", url: mailUrl });
    if (path.endsWith("/snapshot")) {
      snapshotCount += 1;
      if (snapshotCount === 3) return new Response("post-fill snapshot failed", { status: 503 });
      const refs = snapshotCount >= 4 ? { ...composeRefs, trash1: { role: "button", name: "Discard draft" } } : composeRefs;
      return page(mailUrl, "Compose", refs);
    }
    if (path.endsWith("/act")) return json({ ok: true });
    if (init.method === "DELETE" && path.includes("/tabs/")) return json({ ok: true });
    throw new Error(`unexpected ${init.method ?? "GET"} ${path}`);
  };
  try {
    const runtime = await createWebmailRuntime();
    const opened = await runtime.tools.get("rightout_begin_webmail_session").execute("negative-begin", {
      profileId, brokerId: "peekyou", campaignId: runtime.campaignId,
    });
    const result = await runtime.tools.get("rightout_webmail_session_step").execute("uncertain-fill", {
      sessionId: opened.details.session_id,
      action: { kind: "fill", fields: [
        { ref: "to1", profile_field: "recipient", type: "email" },
        { ref: "subject1", profile_field: "message_subject", type: "text" },
        { ref: "body1", profile_field: "message_body", type: "text" },
      ] },
    });
    assert.equal(result.details.state, "human_task_queued");
    assert.equal(result.details.automatic_retry_allowed, false);
    assert.equal(result.details.draft_cleanup, "discard_control_activated");
    assert.equal(result.details.tab_cleanup, "closed");
    assert.ok(calls.some((call) => call.path.endsWith("/act") && call.body?.ref === "trash1"));
    assert.equal(calls.filter((call) => call.method === "DELETE").length, 1);
    await assert.rejects(runtime.tools.get("rightout_webmail_session_step").execute("uncertain-fill-repeat", {
      sessionId: opened.details.session_id, action: { kind: "inspect" },
    }), /rightout_webmail_session_expired/);
  } finally { globalThis.fetch = originalFetch; }
});

test("runtime-scope mutation after webmail fill immediately discards and closes the draft session", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  const mailUrl = "https://mail.google.com/mail/u/0/#compose";
  const composeRefs = {
    to1: { role: "textbox", name: "To ccpa@peekyou.com" },
    subject1: { role: "textbox", name: "Subject Privacy request" },
    body1: { role: "textbox", name: "Message body" },
    trash1: { role: "button", name: "Discard draft" },
  };
  globalThis.fetch = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ path, method: init.method ?? "GET", body });
    if (path.endsWith("/tabs/open")) return json({ ok: true, targetId: "tab-mail", url: mailUrl });
    if (path.endsWith("/snapshot")) return page(mailUrl, "Compose", composeRefs);
    if (path.endsWith("/act")) return json({ ok: true });
    if (init.method === "DELETE" && path.includes("/tabs/")) return json({ ok: true });
    throw new Error(`unexpected ${init.method ?? "GET"} ${path}`);
  };
  try {
    const runtime = await createWebmailRuntime();
    const opened = await runtime.tools.get("rightout_begin_webmail_session").execute("mutation-begin", {
      profileId, brokerId: "peekyou", campaignId: runtime.campaignId,
    });
    await runtime.tools.get("rightout_webmail_session_step").execute("mutation-fill", {
      sessionId: opened.details.session_id,
      action: { kind: "fill", fields: [
        { ref: "to1", profile_field: "recipient", type: "email" },
        { ref: "subject1", profile_field: "message_subject", type: "text" },
        { ref: "body1", profile_field: "message_body", type: "text" },
      ] },
    });
    runtime.config.browserProfile = "changed-profile";
    await assert.rejects(runtime.tools.get("rightout_webmail_session_step").execute("mutation-inspect", {
      sessionId: opened.details.session_id, action: { kind: "inspect" },
    }), /rightout_campaign_runtime_scope_changed/);
    assert.ok(calls.some((call) => call.path.endsWith("/act") && call.body?.ref === "trash1"));
    assert.equal(calls.filter((call) => call.method === "DELETE").length, 1);
  } finally { globalThis.fetch = originalFetch; }
});
