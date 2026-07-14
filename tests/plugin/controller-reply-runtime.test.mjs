import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { ImapFlow } from "imapflow";

import { RIGHTOUT_CONTROLLER_REPLY_POLICY_VERSION } from "../../lib/controller-replies.mjs";
import { createCaseLedger } from "../../lib/cases.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { imapTransportDigest } from "../../lib/imap.mjs";
import { parseRemovalProfile, removalMessageId, removalProfileDigest } from "../../lib/removal.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const brokerId = "fullenrich_eu";
const stateKey = "dummy-controller-reply-key-with-more-than-32-characters";
const profile = {
  fullName: "Avery Example", city: "Berlin", region: "BE", country: "DE",
  contactEmail: "avery@example.invalid", jurisdictions: ["DE", "EU"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["broker_removal"], method: "self" },
};
const payload = JSON.stringify(profile);
const imap = {
  host: "imap.gmail.com", port: 993, secure: true,
  username: profile.contactEmail, password: "app-password", address: profile.contactEmail,
};
const core = JSON.parse(readFileSync(new URL("../../skills/data-broker-removal/references/brokers/core.json", import.meta.url), "utf8"));
const broker = core.brokers.find((row) => row.id === brokerId);
const expectedMessageId = removalMessageId(
  { profileId, brokerId, requestKind: "gdpr_erasure_objection" },
  parseRemovalProfile(payload),
  broker,
);

test("runtime stores authenticated controller replies as encrypted candidates and still requires human outcome approval", async () => {
  const original = {
    connect: ImapFlow.prototype.connect,
    getMailboxLock: ImapFlow.prototype.getMailboxLock,
    search: ImapFlow.prototype.search,
    fetchOne: ImapFlow.prototype.fetchOne,
    logout: ImapFlow.prototype.logout,
    close: ImapFlow.prototype.close,
  };
  ImapFlow.prototype.connect = async function () {};
  ImapFlow.prototype.getMailboxLock = async function (name, options) {
    assert.equal(name, "INBOX");
    assert.deepEqual(options, { readOnly: true });
    return { release() {} };
  };
  ImapFlow.prototype.search = async function () { return [1]; };
  ImapFlow.prototype.fetchOne = async function () {
    return {
      uid: 1,
      internalDate: new Date(Date.now() - 30_000),
      envelope: { messageId: "<controller-reply@controller.invalid>", from: [{ address: "support@fullenrich.com" }] },
      source: Buffer.from([
        "From: FullEnrich Support <support@fullenrich.com>",
        `To: ${profile.contactEmail}`,
        "Authentication-Results: mx.google.com; dkim=pass header.d=fullenrich.com",
        `In-Reply-To: ${expectedMessageId}`,
        `References: ${expectedMessageId}`,
        "Subject: Re: GDPR request",
        "Message-ID: <controller-reply@controller.invalid>",
        "Content-Type: text/plain; charset=utf-8",
        "",
        "We have successfully erased your personal data.",
      ].join("\r\n")),
    };
  };
  ImapFlow.prototype.logout = async function () {};
  ImapFlow.prototype.close = function () {};

  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-controller-reply-runtime-"));
    const runtime = { state: { resolveStateDir() { return stateDir; } } };
    const config = {
      stateEncryptionKey: stateKey,
      profiles: { [profileId]: { payload } },
      imapTransport: imap,
      controllerReplyAttestations: {
        rightoutControllerReplyPolicyAccepted: true,
        rightoutControllerReplyPolicyVersion: RIGHTOUT_CONTROLLER_REPLY_POLICY_VERSION,
        subjectConsentReviewed: true,
        inboxReadAuthorized: true,
        authorizedProfileIds: [profileId],
        authorizedProfileDigests: { [profileId]: removalProfileDigest(payload) },
        authorizedBrokerIds: [brokerId],
        imapTransportDigest: imapTransportDigest(imap),
      },
    };
    const plugin = (await import("../../index.ts")).default;
    const tools = new Map();
    let beforeToolCall;
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

    const ledger = createCaseLedger(createEncryptedFileKeyedStore({
      stateDir, namespace: "rightout-cases-v1", maxEntries: 100, getSecret: () => stateKey,
    }));
    await ledger.reserveSubmission(profileId, brokerId, {
      channel: "smtp_email", discoveryRequirement: "not_required_for_data_subject_request",
    });
    await ledger.recordRemoval({
      state: "submitted", subject_ref: profileId, broker_id: brokerId,
      generated_at: new Date(Date.now() - 60_000).toISOString(),
      delivery: { accepted_by_outbound_smtp: true },
      proof_references: ["smtp_0123456789abcdef01234567"],
      disclosures: { to_broker: ["contact_email", "country"] },
    }, 30);

    const pollInput = { profileId, brokerId };
    const denied = await beforeToolCall({ toolName: "rightout_poll_controller_reply", params: pollInput, toolCallId: "reply-poll-denied" });
    assert.doesNotMatch(denied.requireApproval.description, /Avery|avery@example|app-password/);
    denied.requireApproval.onResolution("deny");
    await assert.rejects(tools.get("rightout_poll_controller_reply").execute("reply-poll-denied", pollInput), /approval_binding_failed/);

    const approved = await beforeToolCall({ toolName: "rightout_poll_controller_reply", params: pollInput, toolCallId: "reply-poll-approved" });
    approved.requireApproval.onResolution("allow-once");
    const result = await tools.get("rightout_poll_controller_reply").execute("reply-poll-approved", pollInput);
    assert.equal(result.details.state, "authenticated_controller_reply_candidate");
    assert.equal(result.details.outcome_candidate, "erasure_confirmed");
    assert.equal(result.details.terminal_candidate, true);
    assert.match(result.details.candidate_handle, /^reply_[a-f0-9]{24}$/);
    assert.doesNotMatch(JSON.stringify(result.details), /Avery|avery@example|personal data|app-password/);
    assert.equal((await ledger.status(profileId)).counts.submitted, 1, "polling must not record the terminal outcome");

    const outcomeInput = {
      profileId, brokerId, outcome: "erasure_confirmed", candidateHandle: result.details.candidate_handle,
    };
    await assert.rejects(
      tools.get("rightout_record_controller_outcome").execute("candidate-outcome-unapproved", outcomeInput),
      /approval_binding_failed/,
    );
    const outcomeApproval = await beforeToolCall({
      toolName: "rightout_record_controller_outcome", params: outcomeInput, toolCallId: "candidate-outcome-approved",
    });
    assert.match(outcomeApproval.requireApproval.description, /personally reviewed/);
    outcomeApproval.requireApproval.onResolution("allow-once");
    const outcome = await tools.get("rightout_record_controller_outcome").execute("candidate-outcome-approved", outcomeInput);
    assert.equal(outcome.details.state, "confirmed_removed");
    assert.equal(outcome.details.authenticated_candidate_consumed, true);
    assert.equal((await ledger.status(profileId)).counts.confirmed_removed, 1);

    const candidateStore = createEncryptedFileKeyedStore({
      stateDir, namespace: "rightout-controller-reply-candidates-v1", maxEntries: 500, getSecret: () => stateKey,
    });
    assert.equal(await candidateStore.lookup(result.details.candidate_handle), undefined);
  } finally {
    Object.assign(ImapFlow.prototype, original);
  }
});
