import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  RIGHTOUT_CONTROLLER_REPLY_POLICY_VERSION,
  classifyControllerReply,
  controllerReplyScopeBinding,
  validateControllerReplyAttestations,
  validateControllerReplyPreflight,
} from "../../lib/controller-replies.mjs";
import { createControllerReplyPoller, imapTransportDigest } from "../../lib/imap.mjs";
import { removalProfileDigest } from "../../lib/removal.mjs";

const profileId = "profile_0123456789abcdef";
const brokerId = "fullenrich_eu";
const now = Date.now();
const profilePayload = JSON.stringify({
  fullName: "Synthetic Subject",
  city: "Berlin",
  region: "BE",
  country: "DE",
  contactEmail: "subject@example.invalid",
  jurisdictions: ["DE", "EU"],
  consent: {
    authorized: true,
    recordedAt: new Date(now - 60_000).toISOString(),
    validUntil: new Date(now + 60 * 60_000).toISOString(),
    scope: ["broker_removal"],
    method: "self",
  },
});
const imap = {
  host: "imap.gmail.com", port: 993, secure: true,
  username: "subject@example.invalid", password: "app-password", address: "subject@example.invalid",
};
const attestations = {
  rightoutControllerReplyPolicyAccepted: true,
  rightoutControllerReplyPolicyVersion: RIGHTOUT_CONTROLLER_REPLY_POLICY_VERSION,
  subjectConsentReviewed: true,
  inboxReadAuthorized: true,
  authorizedProfileIds: [profileId],
  authorizedProfileDigests: { [profileId]: removalProfileDigest(profilePayload) },
  authorizedBrokerIds: [brokerId],
  imapTransportDigest: imapTransportDigest(imap),
};

async function catalog() {
  return JSON.parse(await readFile(new URL("../../skills/data-broker-removal/references/brokers/core.json", import.meta.url), "utf8"));
}

function rawReply(expectedMessageId, {
  from = "support@fullenrich.com",
  to = "subject@example.invalid",
  authenticationResults = "mx.google.com; dkim=pass header.d=fullenrich.com",
  inReplyTo = expectedMessageId,
  body = "We have received your request and it is being processed.",
} = {}) {
  return Buffer.from([
    `From: Controller <${from}>`, `To: ${to}`,
    `Authentication-Results: ${authenticationResults}`,
    `In-Reply-To: ${inReplyTo}`, `References: ${inReplyTo}`,
    "Subject: Re: GDPR request", "Message-ID: <reply@controller.invalid>",
    "Content-Type: text/plain; charset=utf-8", "", body,
  ].join("\r\n"));
}

function fakeClient(messages) {
  const events = [];
  return {
    events,
    async connect() { events.push("connect"); },
    async getMailboxLock(name, options) { events.push([name, options]); return { release() { events.push("release"); } }; },
    async search() { return messages.map((_, index) => index + 1); },
    async fetchOne(uid) {
      return {
        uid: Number(uid), source: messages[Number(uid) - 1], internalDate: new Date(now),
        envelope: { messageId: `<${uid}@fullenrich.com>`, from: [{ address: "support@fullenrich.com" }] },
      };
    },
    async logout() { events.push("logout"); }, close() { events.push("close"); },
  };
}

test("controller-reply attestations bind exact profile, digest, broker, IMAP transport, and policy", async () => {
  const core = await catalog();
  assert.deepEqual(validateControllerReplyAttestations({ profileId, brokerId }, attestations), attestations);
  const preflight = validateControllerReplyPreflight({
    input: { profileId, brokerId }, catalog: core, profilePayload, imapTransport: imap, attestations,
  });
  assert.equal(preflight.broker.processClass, "eu_controller_email_erasure");
  assert.match(preflight.expectedMessageId, /^<rightout\.[a-f0-9]{32}@local\.invalid>$/);
  assert.match(controllerReplyScopeBinding({ profileId, brokerId }, attestations, preflight.broker), /controller-reply-poll-v1/);
  assert.throws(() => validateControllerReplyAttestations({ profileId, brokerId }, { ...attestations, inboxReadAuthorized: false }), /attestation_required/);
  assert.throws(() => validateControllerReplyPreflight({
    input: { profileId, brokerId }, catalog: core, profilePayload, imapTransport: { ...imap, password: "changed" }, attestations,
  }), /snapshot_changed/);
});

test("literal controller classifications remain candidates and conflicting or quoted text needs manual review", () => {
  assert.deepEqual(classifyControllerReply({
    text: "We have received your request and it is being processed.", processClass: "eu_controller_email_erasure",
  }), { outcome_candidate: "processing_acknowledged", confidence: "high", evidence_signals: ["literal_processing_phrase"], terminal: false });
  assert.equal(classifyControllerReply({
    text: "We have successfully erased your personal data.", processClass: "eu_controller_email_erasure",
  }).outcome_candidate, "erasure_confirmed");
  assert.equal(classifyControllerReply({
    text: "We have successfully deleted your personal data.", processClass: "us_data_broker_email_deletion",
  }).outcome_candidate, "deletion_confirmed");
  assert.equal(classifyControllerReply({
    text: "Thanks.\nOn Tue someone wrote:\n> We have successfully erased your personal data.", processClass: "eu_controller_email_erasure",
  }).outcome_candidate, "needs_manual_check");
  assert.equal(classifyControllerReply({
    text: "We received your request, but we cannot process your request.", processClass: "eu_controller_email_erasure",
  }).outcome_candidate, "needs_manual_check");
  for (const text of [
    "We have not deleted your data.",
    "No data has been deleted.",
    "None of your data has been deleted.",
    "Nothing has been successfully deleted.",
    "We have deleted none of your data.",
    "We have deleted some records, but retained the remaining profile.",
    "Ihre Daten wurden nicht gelöscht.",
    "Ihre Daten wurden gelöscht, jedoch werden bestimmte Datensätze aufbewahrt.",
  ]) {
    const classified = classifyControllerReply({ text, processClass: "us_data_broker_email_deletion" });
    assert.equal(classified.outcome_candidate, "needs_manual_check");
    assert.equal(classified.confidence, "none");
    assert.equal(classified.terminal, false);
  }
});

test("controller poller requires exact recipient, aligned receiver DKIM, official sender, time, and thread", async () => {
  const preflight = validateControllerReplyPreflight({
    input: { profileId, brokerId }, catalog: await catalog(), profilePayload, imapTransport: imap, attestations,
  });
  const client = fakeClient([rawReply(preflight.expectedMessageId)]);
  const poll = createControllerReplyPoller({ clientFactory: () => client, classifier: classifyControllerReply, now: () => new Date(now) });
  const result = await poll({
    transport: imap, expectedAddress: preflight.profile.contactEmail, broker: preflight.broker.raw,
    expectedMessageId: preflight.expectedMessageId, notBefore: new Date(now - 60_000).toISOString(),
  });
  assert.equal(result.found, true);
  assert.equal(result.outcome_candidate, "processing_acknowledged");
  assert.deepEqual(result.authentication_signals, ["exact_recipient", "receiver_added_aligned_dkim", "allowed_sender_domain", "exact_message_thread"]);
  assert.match(result.message_reference, /^mail_[a-f0-9]{24}$/);
  assert.deepEqual(client.events[1], ["INBOX", { readOnly: true }]);

  for (const mutation of [
    { from: "attacker.invalid", value: { from: "privacy@attacker.invalid" } },
    { to: "wrong recipient", value: { to: "other@example.invalid" } },
    { dkim: "unaligned", value: { authenticationResults: "mx.google.com; dkim=pass header.d=attacker.invalid" } },
    { thread: "wrong", value: { inReplyTo: "<other@example.invalid>" } },
  ]) {
    const denied = createControllerReplyPoller({
      clientFactory: () => fakeClient([rawReply(preflight.expectedMessageId, mutation.value)]),
      classifier: classifyControllerReply, now: () => new Date(now),
    });
    assert.deepEqual(await denied({
      transport: imap, expectedAddress: preflight.profile.contactEmail, broker: preflight.broker.raw,
      expectedMessageId: preflight.expectedMessageId, notBefore: new Date(now - 60_000).toISOString(),
    }), { found: false, broker_id: brokerId }, mutation.from);
  }
});
