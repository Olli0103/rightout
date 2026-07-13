import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { ImapFlow } from "imapflow";

import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { imapTransportDigest } from "../../lib/imap.mjs";
import { removalProfileDigest } from "../../lib/removal.mjs";
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
const payload = JSON.stringify(profile);
const stateKey = "dummy-peopleconnect-state-key-with-more-than-32-characters";
const imap = {
  host: "imap.gmail.com", port: 993, secure: true,
  username: profile.contactEmail, password: "app-password", address: profile.contactEmail,
};

function json(value) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
}

function browserHarness() {
  const tabs = new Map();
  const calls = [];
  let nextTab = 0;
  let emailStage = "entry";
  let consentChecked = false;
  let guidedStage = "identity";

  function page(targetId) {
    const url = tabs.get(targetId);
    if (targetId === "tab-email") {
      if (emailStage === "success") return {
        ok: true, format: "ai", targetId, url,
        snapshot: "Check your email for the verification link.", refs: {},
      };
      return {
        ok: true, format: "ai", targetId, url,
        snapshot: "Email suppression entry. I agree to terms. Continue.",
        refs: {
          e1: { role: "textbox", name: "Contact email" },
          a1: { role: "checkbox", name: "I agree to terms", ...(consentChecked ? { checked: true } : {}) },
          c1: { role: "button", name: "Continue" },
        },
      };
    }
    if (guidedStage === "records") return {
      ok: true, format: "ai", targetId, url,
      snapshot: "Select exactly one matching subject record.",
      refs: { r1: { role: "button", name: "Select record Avery Example 100 Example Avenue Exampleville 90001" } },
    };
    if (guidedStage === "suppress") return {
      ok: true, format: "ai", targetId, url,
      snapshot: "Choose suppression control.",
      refs: { s1: { role: "button", name: "Suppress my record" } },
    };
    if (guidedStage === "success") return {
      ok: true, format: "ai", targetId, url,
      snapshot: "Control: suppressed.", refs: {},
    };
    return {
      ok: true, format: "ai", targetId, url,
      snapshot: "Enter legal name and date of birth, then continue.",
      refs: {
        n1: { role: "textbox", name: "Full name" },
        d1: { role: "textbox", name: "Date of birth" },
        c2: { role: "button", name: "Continue" },
      },
    };
  }

  const fetchImpl = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    const parsed = new URL(url);
    const path = parsed.pathname;
    const body = options.body ? JSON.parse(options.body) : undefined;
    if (path.endsWith("/tabs/open")) {
      const targetId = nextTab++ === 0 ? "tab-email" : "tab-guided";
      tabs.set(targetId, body.url);
      return json({ ok: true, targetId, url: body.url });
    }
    if (path.endsWith("/snapshot")) return json(page(parsed.searchParams.get("targetId")));
    if (path.endsWith("/act")) {
      if (body.kind === "click" && body.ref === "a1") consentChecked = true;
      else if (body.kind === "click" && body.ref === "c1") emailStage = "success";
      else if (body.kind === "click" && body.ref === "c2") guidedStage = "records";
      else if (body.kind === "click" && body.ref === "r1") guidedStage = "suppress";
      else if (body.kind === "click" && body.ref === "s1") guidedStage = "success";
      return json({ ok: true });
    }
    if (path.endsWith("/screenshot")) throw new Error("screenshot endpoint must never be called");
    if (options.method === "DELETE" && /\/tabs\//u.test(path)) return json({ ok: true });
    throw new Error(`unexpected_browser_call:${path}`);
  };
  return { fetchImpl, calls };
}

async function registerPlugin({ stateDir, browserProfile, fetchImpl }) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  const tools = new Map();
  let beforeToolCall;
  const plugin = (await import("../../index.ts")).default;
  const config = {
    stateEncryptionKey: stateKey,
    profiles: { [profileId]: { payload } },
    formAttestations: formAttestations(profileId, payload, ["intelius"]),
    browserControlBaseUrl: "http://127.0.0.1:3000/browser",
    browserControlToken: "dummy-browser-control-token",
    browserBackendMode: "existing_logged_in_cdp",
    ...(browserProfile ? { browserProfile } : {}),
    imapTransport: imap,
    verificationAttestations: {
      rightoutVerificationPolicyAccepted: true,
      rightoutVerificationPolicyVersion: "2026-07-12",
      subjectConsentReviewed: true,
      inboxReadAuthorized: true,
      verificationLinkOpenAuthorized: true,
      authorizedProfileIds: [profileId],
      authorizedProfileDigests: { [profileId]: removalProfileDigest(payload) },
      authorizedBrokerIds: ["intelius"],
      imapTransportDigest: imapTransportDigest(imap),
    },
    publisherAutomationPermissions: publisherAutomationPermissions(["intelius"]),
  };
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
    registerTool(tool) {
      const resolved = typeof tool === "function" ? tool({}) : tool;
      tools.set(resolved.name, resolved);
    },
    registerSecurityAuditCollector() {},
    pluginConfig: config,
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  globalThis.fetch = originalFetch;
  return { tools, beforeToolCall, config };
}

async function startSubmitFormCampaign(runtime, toolCallId) {
  const input = { profileId, brokerIds: ["intelius"], effects: ["submit_form"], durationHours: 24, maxEffects: 2 };
  const approval = await runtime.beforeToolCall({ toolName: "rightout_start_campaign", params: input, toolCallId });
  approval.requireApproval.onResolution("allow-once");
  return (await runtime.tools.get("rightout_start_campaign").execute(toolCallId, input)).details.campaign_id;
}

async function seedPortalFlow(stateDir, campaignId, expiresAt) {
  const store = createEncryptedFileKeyedStore({
    stateDir, namespace: "rightout-verified-portal-flows-v1", maxEntries: 100,
    defaultTtlMs: 24 * 60 * 60_000, getSecret: () => stateKey, getPreviousSecrets: () => [],
  });
  const key = `portal_${createHash("sha256").update(JSON.stringify([profileId, "intelius"])).digest("hex")}`;
  await store.register(key, {
    profileId, brokerId: "intelius", campaignId, targetId: "lost-guided-tab",
    browserProfile: "rightout-persistent-profile", bridgeUrl: "http://127.0.0.1:3000/browser",
    browserBackend: "existing_logged_in_cdp", stage: "peopleconnect_guided_identity", expiresAt,
  });
}

test("PeopleConnect runs email, authenticated IMAP, same-profile verification, DOB gate, selection, and suppression", async () => {
  const originalImap = {
    connect: ImapFlow.prototype.connect,
    getMailboxLock: ImapFlow.prototype.getMailboxLock,
    search: ImapFlow.prototype.search,
    fetchOne: ImapFlow.prototype.fetchOne,
    logout: ImapFlow.prototype.logout,
    close: ImapFlow.prototype.close,
  };
  ImapFlow.prototype.connect = async function () {};
  ImapFlow.prototype.getMailboxLock = async function (_name, options) {
    assert.deepEqual(options, { readOnly: true });
    return { release() {} };
  };
  ImapFlow.prototype.search = async function () { return [1]; };
  ImapFlow.prototype.fetchOne = async function () {
    const messageDate = new Date(Date.now() + 1_000);
    return {
      uid: 1,
      internalDate: messageDate,
      envelope: { messageId: "<opaque@peopleconnect.us>", date: messageDate, from: [{ address: "opaque@peopleconnect.us" }] },
      source: Buffer.from([
        "From: opaque@peopleconnect.us",
        "To: avery@example.invalid",
        `Date: ${messageDate.toUTCString()}`,
        "Authentication-Results: mx.google.com; dkim=pass header.d=peopleconnect.us",
        "Subject: Verify suppression request",
        "Content-Type: text/plain; charset=utf-8",
        "",
        "Verify https://suppression.peopleconnect.us/verify?id=opaque-token",
      ].join("\r\n")),
    };
  };
  ImapFlow.prototype.logout = async function () {};
  ImapFlow.prototype.close = function () {};

  const originalFetch = globalThis.fetch;
  const harness = browserHarness();
  globalThis.fetch = harness.fetchImpl;
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-peopleconnect-runtime-"));
    const runtime = await registerPlugin({ stateDir, browserProfile: "rightout-persistent-profile", fetchImpl: harness.fetchImpl });
    globalThis.fetch = harness.fetchImpl;
    const campaignInput = {
      profileId,
      brokerIds: ["intelius"],
      effects: ["submit_form", "poll_verification", "open_verification"],
      durationHours: 24,
      maxEffects: 3,
    };
    const approval = await runtime.beforeToolCall({ toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "campaign-start" });
    approval.requireApproval.onResolution("allow-once");
    const campaign = await runtime.tools.get("rightout_start_campaign").execute("campaign-start", campaignInput);
    const campaignId = campaign.details.campaign_id;

    const opened = await runtime.tools.get("rightout_begin_form_session").execute("begin-email", { profileId, brokerId: "intelius", campaignId });
    assert.equal(opened.details.flow_stage, "peopleconnect_email_entry");
    await runtime.tools.get("rightout_form_session_step").execute("fill-email", {
      sessionId: opened.details.session_id,
      action: { kind: "fill", fields: [{ ref: "e1", profile_field: "contact_email", type: "email" }] },
    });
    const agreed = await runtime.tools.get("rightout_form_session_step").execute("agree", {
      sessionId: opened.details.session_id,
      action: { kind: "click", ref: "a1", purpose: "agree" },
    });
    assert.equal(agreed.details.durable_provider_intent, true);
    const verificationRequested = await runtime.tools.get("rightout_form_session_step").execute("continue-email", {
      sessionId: opened.details.session_id,
      action: { kind: "click", ref: "c1", purpose: "continue" },
    });
    assert.equal(verificationRequested.details.state, "verification_pending");

    const assistedPollInput = { profileId, brokerId: "intelius" };
    const assistedApproval = await runtime.beforeToolCall({
      toolName: "rightout_poll_verification", params: assistedPollInput, toolCallId: "assisted-poll",
    });
    assistedApproval.requireApproval.onResolution("allow-once");
    const assistedPoll = await runtime.tools.get("rightout_poll_verification").execute("assisted-poll", assistedPollInput);
    assert.equal(assistedPoll.details.state, "requires_finite_campaign");
    assert.equal(assistedPoll.details.approval_boundary, "assisted_allow_once");
    assert.equal(assistedPoll.details.verification_handle, undefined);
    assert.equal(assistedPoll.details.next_command, undefined);
    assert.equal(assistedPoll.details.provider_writes, 0);
    assert.ok(Date.parse(assistedPoll.details.next_recheck_at) > Date.now());

    const polled = await runtime.tools.get("rightout_poll_verification").execute("poll", { profileId, brokerId: "intelius", campaignId });
    assert.match(polled.details.verification_handle, /^verify_[a-f0-9]{24}$/u);
    assert.equal(polled.details.next_command.tool, "rightout_open_verification");
    assert.equal(polled.details.next_command.approval_boundary, "finite_campaign_grant");
    const openInput = polled.details.next_command.parameters;
    assert.deepEqual(openInput, { profileId, brokerId: "intelius", verificationHandle: polled.details.verification_handle, campaignId });

    const callsBeforeMissingProfile = harness.calls.length;
    const missingProfileRuntime = await registerPlugin({ stateDir, fetchImpl: harness.fetchImpl });
    globalThis.fetch = harness.fetchImpl;
    await assert.rejects(
      () => missingProfileRuntime.tools.get("rightout_open_verification").execute("missing-profile", openInput),
      /rightout_peopleconnect_named_browser_profile_required/,
    );
    assert.equal(harness.calls.length, callsBeforeMissingProfile);
    const beforeOpen = await runtime.tools.get("rightout_campaign_status").execute("status-before-open", { campaignId });
    assert.equal(beforeOpen.details.used_effects, 2);

    const guided = await runtime.tools.get("rightout_open_verification").execute("open", openInput);
    assert.equal(guided.details.state, "guided_suppression_ready");
    assert.equal(guided.details.same_browser_profile_retained, true);
    const fillInput = {
      sessionId: guided.details.session_id,
      action: { kind: "fill", fields: [
        { ref: "n1", profile_field: "full_name", type: "text" },
        { ref: "d1", profile_field: "date_of_birth", type: "date" },
      ] },
    };
    await assert.rejects(
      () => runtime.tools.get("rightout_form_session_step").execute("dob-denied", fillInput),
      /rightout_form_sensitive_field_human_gate/,
    );
    const dobApproval = await runtime.beforeToolCall({
      toolName: "rightout_form_session_step", params: fillInput, toolCallId: "dob-approved",
    });
    assert.equal(dobApproval.requireApproval.severity, "critical");
    dobApproval.requireApproval.onResolution("allow-once");
    await runtime.tools.get("rightout_form_session_step").execute("dob-approved", fillInput);

    const records = await runtime.tools.get("rightout_form_session_step").execute("guided-continue", {
      sessionId: guided.details.session_id,
      action: { kind: "click", ref: "c2", purpose: "continue" },
    });
    assert.equal(records.details.durable_provider_intent, true);
    assert.equal(records.details.record_corroborated, false);
    await runtime.tools.get("rightout_form_session_step").execute("select-record", {
      sessionId: guided.details.session_id,
      action: { kind: "click", ref: "r1", purpose: "select_record" },
    });
    const suppressed = await runtime.tools.get("rightout_form_session_step").execute("suppress", {
      sessionId: guided.details.session_id,
      action: { kind: "click", ref: "s1", purpose: "suppress" },
    });
    assert.equal(suppressed.details.state, "awaiting_processing");
    assert.equal(suppressed.details.provider_control_verified, "suppressed");
    assert.equal(suppressed.details.delete_control_used, false);
    assert.doesNotMatch(JSON.stringify(suppressed.details), /Avery|1990-01-01|opaque-token/u);

    const status = await runtime.tools.get("rightout_campaign_status").execute("status", { campaignId });
    assert.equal(status.details.used_effects, 3);
    assert.equal(status.details.status, "completed");
    const terminal = await runtime.tools.get("rightout_campaign_next").execute("terminal", { campaignId });
    assert.equal(terminal.details.state, "campaign_completed");
    assert.equal(terminal.details.terminal, true);
    assert.equal(terminal.details.reason, "effect_budget_exhausted");
    assert.ok(harness.calls.filter((call) => call.url.includes("profile=rightout-persistent-profile")).length > 0);
  } finally {
    globalThis.fetch = originalFetch;
    Object.assign(ImapFlow.prototype, originalImap);
  }
});

test("a failed primary PeopleConnect browser open consumes once and never auto-retries", async () => {
  const originalFetch = globalThis.fetch;
  let openCalls = 0;
  const failingFetch = async (url) => {
    if (new URL(url).pathname.endsWith("/tabs/open")) openCalls += 1;
    throw new Error("synthetic browser open failure");
  };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-peopleconnect-open-failure-"));
    const runtime = await registerPlugin({ stateDir, browserProfile: "rightout-persistent-profile", fetchImpl: failingFetch });
    globalThis.fetch = failingFetch;
    const campaignInput = {
      profileId, brokerIds: ["intelius"], effects: ["submit_form"], durationHours: 24, maxEffects: 2,
    };
    const approval = await runtime.beforeToolCall({
      toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "open-failure-campaign",
    });
    approval.requireApproval.onResolution("allow-once");
    const campaign = await runtime.tools.get("rightout_start_campaign").execute("open-failure-campaign", campaignInput);
    const campaignId = campaign.details.campaign_id;

    const blocked = await runtime.tools.get("rightout_begin_form_session").execute("open-failure-begin", {
      profileId, brokerId: "intelius", campaignId,
    });
    assert.equal(blocked.details.state, "blocked");
    assert.equal(blocked.details.reason, "primary_browser_open_failed_after_effect_consumed");
    assert.equal(blocked.details.effect_consumed, true);
    assert.equal(blocked.details.automatic_retry_allowed, false);
    assert.equal(openCalls, 1);
    await assert.rejects(
      runtime.tools.get("rightout_begin_form_session").execute("open-failure-repeat", {
        profileId, brokerId: "intelius", campaignId,
      }),
      /rightout_peopleconnect_manual_reconciliation_required/,
    );

    for (const id of ["open-failure-next-1", "open-failure-next-2"]) {
      const next = await runtime.tools.get("rightout_campaign_next").execute(id, { campaignId });
      assert.equal(next.details.state, "done_for_now");
      assert.equal(next.details.consolidated_digest.human_gates, 1);
      assert.equal(next.details.consolidated_digest.deferred_human_gates.length, 0);
    }
    assert.equal(openCalls, 1);
    const status = await runtime.tools.get("rightout_campaign_status").execute("open-failure-status", { campaignId });
    assert.equal(status.details.used_effects, 1);
    assert.equal(status.details.status, "active");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("restart with a lost durable PeopleConnect target hands off without reopening the verification link", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  const lostFetch = async (url, options = {}) => {
    const path = new URL(url).pathname;
    calls.push({ path, method: options.method ?? "GET" });
    if (path.endsWith("/snapshot")) return new Response("target missing", { status: 404 });
    if (options.method === "DELETE" && path.includes("/tabs/")) return json({ ok: true });
    if (path.endsWith("/tabs/open")) throw new Error("verification link must not be reopened");
    throw new Error(`unexpected_browser_call:${path}`);
  };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-peopleconnect-lost-restart-"));
    const first = await registerPlugin({ stateDir, browserProfile: "rightout-persistent-profile", fetchImpl: lostFetch });
    const campaignId = await startSubmitFormCampaign(first, "lost-restart-campaign");
    await seedPortalFlow(stateDir, campaignId, Date.now() + 30 * 60_000);
    const restarted = await registerPlugin({ stateDir, browserProfile: "rightout-persistent-profile", fetchImpl: lostFetch });
    globalThis.fetch = lostFetch;
    const resumed = await restarted.tools.get("rightout_begin_form_session").execute("lost-restart-begin", {
      profileId, brokerId: "intelius", campaignId,
    });
    assert.equal(resumed.details.state, "human_task_queued");
    assert.equal(resumed.details.reason, "verified_portal_target_lost_after_restart");
    assert.equal(resumed.details.verification_link_reopened, false);
    assert.equal(calls.some((call) => call.path.endsWith("/tabs/open")), false);
    await assert.rejects(restarted.tools.get("rightout_begin_form_session").execute("lost-restart-repeat", {
      profileId, brokerId: "intelius", campaignId,
    }), /rightout_peopleconnect_manual_reconciliation_required/);
    const next = await restarted.tools.get("rightout_campaign_next").execute("lost-restart-next", { campaignId });
    assert.notEqual(next.details.command?.tool, "rightout_begin_form_session");
  } finally { globalThis.fetch = originalFetch; }
});

test("expired durable PeopleConnect flow is pruned after restart and never treated as already open", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    const path = new URL(url).pathname;
    calls.push({ path, method: options.method ?? "GET" });
    if (options.method === "DELETE" && path.includes("/tabs/")) return json({ ok: true });
    if (path.endsWith("/tabs/open")) throw new Error("expired link must not be reopened");
    throw new Error(`unexpected_browser_call:${path}`);
  };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-peopleconnect-expired-restart-"));
    const first = await registerPlugin({ stateDir, browserProfile: "rightout-persistent-profile", fetchImpl });
    const campaignId = await startSubmitFormCampaign(first, "expired-restart-campaign");
    await seedPortalFlow(stateDir, campaignId, Date.now() - 1);
    const restarted = await registerPlugin({ stateDir, browserProfile: "rightout-persistent-profile", fetchImpl });
    globalThis.fetch = fetchImpl;
    const next = await restarted.tools.get("rightout_campaign_next").execute("expired-restart-next", { campaignId });
    assert.notEqual(next.details.command?.tool, "rightout_begin_form_session");
    await assert.rejects(restarted.tools.get("rightout_begin_form_session").execute("expired-restart-begin", {
      profileId, brokerId: "intelius", campaignId,
    }), /rightout_peopleconnect_manual_reconciliation_required/);
    assert.equal(calls.filter((call) => call.method === "DELETE").length, 1);
    assert.equal(calls.some((call) => call.path.endsWith("/tabs/open")), false);
  } finally { globalThis.fetch = originalFetch; }
});
