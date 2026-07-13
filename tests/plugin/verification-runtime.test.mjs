import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

import { ImapFlow } from "imapflow";

import { imapTransportDigest } from "../../lib/imap.mjs";
import { removalProfileDigest } from "../../lib/removal.mjs";
import { createCaseLedger } from "../../lib/cases.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const profile = {
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  contactEmail: "avery@example.invalid",
  jurisdictions: ["US", "US-CA"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["scan", "broker_removal"] },
};
const payload = JSON.stringify(profile);
const imap = {
  host: "imap.gmail.com", port: 993, secure: true,
  username: profile.contactEmail, password: "app-password", address: profile.contactEmail,
};

function fakeRuntime() {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-verification-runtime-"));
  return { state: { resolveStateDir() { return stateDir; } } };
}

test("runtime binds inbox read and confirmation-link open to two separate approvals", async () => {
  const original = {
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
    return {
      uid: 1,
      internalDate: new Date("2026-07-12T09:00:00Z"),
      envelope: { messageId: "<opaque@beenverified.com>", date: new Date("2026-07-12T09:00:00Z"), from: [{ address: "privacy@beenverified.com" }] },
      source: Buffer.from([
        "From: privacy@beenverified.com",
        "To: avery@example.invalid",
        "Date: Sun, 12 Jul 2026 09:00:00 +0000",
        "Authentication-Results: mx.google.com; dkim=pass header.d=beenverified.com",
        "Subject: Confirm request",
        "Content-Type: text/plain; charset=utf-8",
        "",
        "Confirm https://www.beenverified.com/privacy/confirm?id=private-token",
      ].join("\r\n")),
    };
  };
  ImapFlow.prototype.logout = async function () {};
  ImapFlow.prototype.close = function () {};

  try {
    const plugin = (await import("../../index.ts")).default;
    const tools = new Map();
    let beforeToolCall;
    const config = {
      stateEncryptionKey: "dummy-state-key-with-more-than-32-characters",
      profiles: { [profileId]: { payload } },
      imapTransport: imap,
      verificationAttestations: {
        rightoutVerificationPolicyAccepted: true,
        rightoutVerificationPolicyVersion: "2026-07-12",
        subjectConsentReviewed: true,
        inboxReadAuthorized: true,
        verificationLinkOpenAuthorized: true,
        authorizedProfileIds: [profileId],
        authorizedProfileDigests: { [profileId]: removalProfileDigest(payload) },
        authorizedBrokerIds: ["beenverified"],
        imapTransportDigest: imapTransportDigest(imap),
      },
    };
    const runtime = fakeRuntime();
    plugin.register({
      runtime,
      on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
      registerTool(tool) {
        const resolved = typeof tool === "function" ? tool({ browser: {} }) : tool;
        tools.set(resolved.name, resolved);
      },
      registerSecurityAuditCollector() {},
      pluginConfig: config,
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const caseLedger = createCaseLedger(createEncryptedFileKeyedStore({
      stateDir: runtime.state.resolveStateDir(),
      namespace: "rightout-cases-v1",
      maxEntries: 100,
      getSecret: () => config.stateEncryptionKey,
    }));
    await caseLedger.recordScan({
      mode: "approval_gated_live_scan", scan_id: "scan_0123456789abcdef", subject_ref: profileId,
      generated_at: "2026-07-12T08:00:00Z",
      results: [{ broker_id: "beenverified", state: "indirect_exposure", reason: "search_index_candidate_observed" }],
    });
    await caseLedger.reserveSubmission(profileId, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" });
    await caseLedger.recordRemoval({
      state: "submitted", subject_ref: profileId, broker_id: "beenverified",
      generated_at: "2026-07-12T08:30:00Z", delivery: { accepted_by_outbound_smtp: true },
      proof_references: ["smtp_0123456789abcdef01234567"], disclosures: { to_broker: ["contact_email"] },
    });

    const pollInput = { profileId, brokerId: "beenverified" };
    const denied = await beforeToolCall({ toolName: "rightout_poll_verification", params: pollInput, toolCallId: "poll-denied" });
    assert.match(denied.requireApproval.description, /30 post-submission inbox messages/);
    assert.doesNotMatch(denied.requireApproval.description, /Avery|avery@example|app-password/);
    denied.requireApproval.onResolution("deny");
    await assert.rejects(tools.get("rightout_poll_verification").execute("poll-denied", pollInput), /rightout_approval_binding_failed/);

    const approved = await beforeToolCall({ toolName: "rightout_poll_verification", params: pollInput, toolCallId: "poll-approved" });
    approved.requireApproval.onResolution("allow-once");
    const result = await tools.get("rightout_poll_verification").execute("poll-approved", pollInput);
    const report = result.details;
    assert.equal(report.state, "verification_pending");
    assert.match(report.verification_handle, /^verify_[a-f0-9]{24}$/);
    assert.match(report.message_reference, /^mail_[a-f0-9]{24}$/);
    assert.equal(report.next_command.tool, "rightout_open_verification");
    assert.deepEqual(report.next_command.parameters, { ...pollInput, verificationHandle: report.verification_handle });
    assert.equal(report.next_command.approval_boundary, "assisted_allow_once_required");
    const serialized = JSON.stringify(report);
    assert.doesNotMatch(serialized, /private-token|Avery|avery@example|app-password/);

    config.publisherAutomationPermissions = publisherAutomationPermissions(["beenverified"]);
    const openInput = { ...pollInput, verificationHandle: report.verification_handle };
    const open = await beforeToolCall({ toolName: "rightout_open_verification", params: openInput, toolCallId: "open-denied" });
    assert.match(open.requireApproval.description, /external broker write/);
    assert.doesNotMatch(open.requireApproval.description, /private-token|Avery|avery@example/);
    open.requireApproval.onResolution("deny");
    await assert.rejects(tools.get("rightout_open_verification").execute("open-denied", openInput), /rightout_approval_binding_failed/);

    const scanApproval = await beforeToolCall({ toolName: "rightout_live_scan", params: { profileId, brokerIds: ["beenverified"] }, toolCallId: "scan-approval" });
    assert.equal(scanApproval.block, true, "missing scan attestations must not accidentally authorize verification");
  } finally {
    Object.assign(ImapFlow.prototype, original);
  }
});

test("a campaign defers a negative IMAP poll instead of immediately scheduling the same effect again", async () => {
  const original = {
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
  ImapFlow.prototype.search = async function () { return []; };
  ImapFlow.prototype.fetchOne = async function () { throw new Error("negative poll must not fetch a message"); };
  ImapFlow.prototype.logout = async function () {};
  ImapFlow.prototype.close = function () {};

  try {
    const plugin = (await import("../../index.ts")).default;
    const tools = new Map();
    let beforeToolCall;
    const config = {
      stateEncryptionKey: "dummy-negative-imap-key-with-more-than-32-characters",
      profiles: { [profileId]: { payload } },
      imapTransport: imap,
      verificationAttestations: {
        rightoutVerificationPolicyAccepted: true,
        rightoutVerificationPolicyVersion: "2026-07-12",
        subjectConsentReviewed: true,
        inboxReadAuthorized: true,
        verificationLinkOpenAuthorized: true,
        authorizedProfileIds: [profileId],
        authorizedProfileDigests: { [profileId]: removalProfileDigest(payload) },
        authorizedBrokerIds: ["beenverified"],
        imapTransportDigest: imapTransportDigest(imap),
      },
    };
    const runtime = fakeRuntime();
    plugin.register({
      runtime,
      on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
      registerTool(tool) {
        const resolved = typeof tool === "function" ? tool({ browser: {} }) : tool;
        tools.set(resolved.name, resolved);
      },
      registerSecurityAuditCollector() {},
      pluginConfig: config,
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });

    const caseLedger = createCaseLedger(createEncryptedFileKeyedStore({
      stateDir: runtime.state.resolveStateDir(), namespace: "rightout-cases-v1", maxEntries: 100,
      getSecret: () => config.stateEncryptionKey,
    }));
    await caseLedger.recordScan({
      mode: "approval_gated_live_scan", scan_id: "scan_0123456789abcdef", subject_ref: profileId,
      generated_at: "2026-07-01T08:00:00Z",
      results: [{ broker_id: "beenverified", state: "indirect_exposure", reason: "search_index_candidate_observed" }],
    });
    await caseLedger.reserveSubmission(profileId, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" });
    await caseLedger.recordRemoval({
      state: "submitted", subject_ref: profileId, broker_id: "beenverified",
      generated_at: "2026-07-01T08:30:00Z", delivery: { accepted_by_outbound_smtp: true },
      proof_references: ["smtp_0123456789abcdef01234567"], disclosures: { to_broker: ["contact_email"] },
    }, 1);

    const campaignInput = {
      profileId, brokerIds: ["beenverified"], effects: ["poll_verification"], durationHours: 24, maxEffects: 2,
    };
    const campaignApproval = await beforeToolCall({
      toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "negative-imap-campaign",
    });
    campaignApproval.requireApproval.onResolution("allow-once");
    const campaign = await tools.get("rightout_start_campaign").execute("negative-imap-campaign", campaignInput);
    const campaignRef = { campaignId: campaign.details.campaign_id };

    const firstNext = await tools.get("rightout_campaign_next").execute("negative-imap-next-1", campaignRef);
    assert.equal(firstNext.details.state, "action_ready");
    assert.equal(firstNext.details.command.tool, "rightout_poll_verification");
    const beforePoll = Date.now();
    const negative = await tools.get(firstNext.details.command.tool).execute("negative-imap-poll", firstNext.details.command.parameters);
    assert.equal(negative.details.state, "verification_not_observed");
    assert.equal(negative.details.retry_deferred, true);
    assert.ok(Date.parse(negative.details.next_recheck_at) >= beforePoll + 23 * 60 * 60_000);

    const secondNext = await tools.get("rightout_campaign_next").execute("negative-imap-next-2", campaignRef);
    assert.equal(secondNext.details.state, "done_for_now");
    assert.equal(secondNext.details.next_wake_at, negative.details.next_recheck_at);
    assert.equal(secondNext.details.consolidated_digest.in_flight, 1);
    const status = await tools.get("rightout_campaign_status").execute("negative-imap-status", campaignRef);
    assert.equal(status.details.status, "active");
    assert.equal(status.details.used_effects, 1);
  } finally {
    Object.assign(ImapFlow.prototype, original);
  }
});
