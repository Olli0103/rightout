import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createCaseLedger } from "../../lib/cases.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { removalProfileDigest } from "../../lib/removal.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";
import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const profile = {
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  contactEmail: "avery@example.invalid",
  jurisdictions: ["US", "US-CA"],
  consent: {
    authorized: true,
    recordedAt: CONSENT_RECORDED_AT,
    validUntil: CONSENT_VALID_UNTIL,
    scope: ["scan", "broker_removal"],
  },
};
const payload = JSON.stringify(profile);
const stateKey = "dummy-autonomous-campaign-key-with-more-than-32-characters";

function json(value) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
}

test("one native campaign approval drives a later browser submission without a second prompt", async () => {
  const originalFetch = globalThis.fetch;
  const responses = [
    json({ targetId: "tab-1", title: "Suppression", url: "https://suppression.peopleconnect.us/" }),
    json({
      ok: true,
      format: "ai",
      targetId: "tab-1",
      snapshot: "Email Agree Continue",
      refs: {
        e1: { role: "textbox", name: "Email" },
        e2: { role: "checkbox", name: "Agree to Terms" },
        e3: { role: "button", name: "Continue" },
      },
    }),
    json({ ok: true, targetId: "tab-1" }),
    json({ ok: true, targetId: "tab-1" }),
    json({ ok: true, targetId: "tab-1" }),
    json({ ok: true, format: "ai", targetId: "tab-1", snapshot: "Check your email for a verification email", refs: {} }),
    json({ ok: true }),
  ];
  globalThis.fetch = async () => responses.shift();
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-campaign-runtime-"));
    const runtime = { state: { resolveStateDir() { return stateDir; } } };
    const tools = new Map();
    let beforeToolCall;
    const formAttestations = {
      rightoutFormPolicyAccepted: true,
      rightoutFormPolicyVersion: "2026-07-12",
      subjectConsentReviewed: true,
      browserFormAuthorized: true,
      minimumDisclosureAccepted: true,
      authorizedProfileIds: [profileId],
      authorizedProfileDigests: { [profileId]: removalProfileDigest(payload) },
      authorizedBrokerIds: ["intelius"],
    };
    const plugin = (await import("../../index.ts")).default;
    const pluginConfig = {
      stateEncryptionKey: stateKey,
      profiles: { [profileId]: { payload } },
      formAttestations,
      publisherAutomationPermissions: publisherAutomationPermissions(["intelius"]),
    };
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
      pluginConfig,
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const campaignInput = {
      profileId,
      brokerIds: ["intelius"],
      effects: ["submit_form"],
      durationHours: 24,
      maxEffects: 2,
    };
    const campaignApproval = await beforeToolCall({
      toolName: "rightout_start_campaign",
      params: campaignInput,
      toolCallId: "campaign-start",
    });
    assert.ok(campaignApproval.requireApproval);
    campaignApproval.requireApproval.onResolution("allow-once");
    const callsBeforeApprovalMutation = responses.length;
    pluginConfig.browserProfile = "changed-between-approval-and-start";
    await assert.rejects(
      tools.get("rightout_start_campaign").execute("campaign-start", campaignInput),
      /rightout_approval_binding_failed/,
    );
    assert.equal(responses.length, callsBeforeApprovalMutation, "approval/runtime mutation must fail before provider I/O");
    delete pluginConfig.browserProfile;
    const renewedApproval = await beforeToolCall({
      toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "campaign-start-renewed",
    });
    renewedApproval.requireApproval.onResolution("allow-once");
    const campaign = await tools.get("rightout_start_campaign").execute("campaign-start-renewed", campaignInput);
    assert.match(campaign.details.campaign_id, /^campaign_[a-f0-9]{32}$/);

    const ledger = createCaseLedger(createEncryptedFileKeyedStore({
      stateDir,
      namespace: "rightout-cases-v1",
      maxEntries: 100,
      getSecret: () => stateKey,
    }));
    await ledger.recordScan({
      mode: "approval_gated_live_scan",
      scan_id: "scan_0123456789abcdef",
      subject_ref: profileId,
      generated_at: "2026-07-12T08:30:00Z",
      results: [{ broker_id: "intelius", state: "indirect_exposure", reason: "search_index_candidate_observed" }],
    });

    const formInput = {
      profileId,
      brokerId: "intelius",
      requestKind: "delete_and_opt_out",
      campaignId: campaign.details.campaign_id,
    };
    const autonomous = await beforeToolCall({
      toolName: "rightout_submit_form_removal",
      params: formInput,
      toolCallId: "campaign-form",
    });
    assert.equal(autonomous.requireApproval, undefined, "campaign-scoped effect must not prompt again");
    const submitted = await tools.get("rightout_submit_form_removal").execute("campaign-form", formInput);
    assert.equal(submitted.details.state, "verification_pending");
    assert.equal(submitted.details.delivery.form_submitted, true);

    const status = await tools.get("rightout_campaign_status").execute("campaign-status", {
      campaignId: campaign.details.campaign_id,
    });
    assert.equal(status.details.used_effects, 1);
    assert.equal(status.details.remaining_effects, 1);
    assert.equal(JSON.stringify(status.details).includes(profile.contactEmail), false);

    const outsideScope = await beforeToolCall({
      toolName: "rightout_submit_form_removal",
      params: { ...formInput, brokerId: "beenverified" },
      toolCallId: "campaign-outside",
    });
    assert.equal(outsideScope.block, true);

    const providerCallsBeforeMutation = responses.length;
    pluginConfig.browserProfile = "changed-after-campaign-start";
    const changedRuntime = await beforeToolCall({
      toolName: "rightout_submit_form_removal",
      params: formInput,
      toolCallId: "campaign-runtime-mutated",
    });
    assert.equal(changedRuntime.block, true);
    assert.equal(responses.length, providerCallsBeforeMutation, "runtime-scope mismatch must fail before provider I/O");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("every publisher-effect campaign is denied before approval or provider I/O without written authorization", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    throw new Error("provider I/O must not occur");
  };
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-campaign-no-provider-permission-"));
    let beforeToolCall;
    const plugin = (await import("../../index.ts")).default;
    plugin.register({
      runtime: { state: { resolveStateDir() { return stateDir; } } },
      on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
      registerTool() {},
      registerSecurityAuditCollector() {},
      pluginConfig: {
        stateEncryptionKey: stateKey,
        profiles: { [profileId]: { payload } },
      },
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    for (const brokerId of ["addresses", "familytreenow"]) {
      for (const effect of ["publisher_discover", "submit_form", "open_verification", "direct_recheck"]) {
        const result = await beforeToolCall({
          toolName: "rightout_start_campaign",
          params: {
            profileId,
            brokerIds: [brokerId],
            effects: [effect],
            durationHours: 24,
            maxEffects: 2,
          },
          toolCallId: `campaign-no-provider-permission-${brokerId}-${effect}`,
        });
        assert.equal(result.block, true, `${brokerId}/${effect}`);
        assert.equal(result.requireApproval, undefined, `${brokerId}/${effect}`);
      }
    }
    assert.equal(providerCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("campaign pre-approval binds only opaque scope and never reads resolved profile or runtime secrets", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-campaign-preapproval-boundary-"));
  let beforeToolCall;
  let secretReads = 0;
  const resolvedSecrets = {
    get stateEncryptionKey() { secretReads += 1; return stateKey; },
    get profiles() { secretReads += 1; return { [profileId]: { payload } }; },
    get smtpTransport() { secretReads += 1; return { password: "must-not-be-read" }; },
    get imapTransport() { secretReads += 1; return { password: "must-not-be-read" }; },
    get browserControlToken() { secretReads += 1; return "must-not-be-read"; },
  };
  const plugin = (await import("../../index.ts")).default;
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
    registerTool() {},
    registerSecurityAuditCollector() {},
    pluginConfig: resolvedSecrets,
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });

  const result = await beforeToolCall({
    toolName: "rightout_start_campaign",
    params: {
      profileId,
      brokerIds: ["intelius"],
      effects: ["discover"],
      durationHours: 1,
      maxEffects: 1,
    },
    toolCallId: "campaign-opaque-preapproval",
  });
  assert.ok(result.requireApproval);
  assert.equal(result.block, undefined);
  assert.equal(secretReads, 0);
});
