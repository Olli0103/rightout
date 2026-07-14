import assert from "node:assert/strict";
import test from "node:test";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

import { imapTransportDigest } from "../../lib/imap.mjs";
import { removalProfileDigest } from "../../lib/removal.mjs";
import {
  browserVerificationProfileDigest,
  resolveVerificationCatalogEntry,
  validateBrowserVerificationPreflight,
  validateVerificationOpenInput,
  validateVerificationPollInput,
  validateVerificationPreflight,
  verificationOpenApprovalDescription,
  verificationOpenScopeBinding,
  verificationPollApprovalDescription,
  verificationPollScopeBinding,
} from "../../lib/verification.mjs";

const profileId = "profile_0123456789abcdef";
const input = { profileId, brokerId: "beenverified" };
const profile = {
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  contactEmail: "avery@example.invalid",
  jurisdictions: ["US", "US-CA"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["broker_removal", "scan"] },
};
const profilePayload = JSON.stringify(profile);
const imap = { host: "imap.gmail.com", port: 993, secure: true, username: profile.contactEmail, password: "app-password", address: profile.contactEmail };
const catalog = { brokers: [{
  id: "beenverified", name: "BeenVerified", category: "people_search",
  verification: {
    supported: true, channel: "imap", open_link: "approval_gated_https_get",
    sender_domains: ["beenverified.com"], link_domains: ["beenverified.com"], processing_days: 14,
  },
}] };
const attestations = {
  rightoutVerificationPolicyAccepted: true,
  rightoutVerificationPolicyVersion: "2026-07-12",
  subjectConsentReviewed: true,
  inboxReadAuthorized: true,
  verificationLinkOpenAuthorized: true,
  authorizedProfileIds: [profileId],
  authorizedProfileDigests: { [profileId]: removalProfileDigest(profilePayload) },
  authorizedBrokerIds: ["beenverified"],
  imapTransportDigest: imapTransportDigest(imap),
};

test("verification public inputs contain opaque references only", () => {
  assert.deepEqual(validateVerificationPollInput(input), input);
  assert.deepEqual(validateVerificationOpenInput({ ...input, verificationHandle: "verify_0123456789abcdef01234567" }), {
    ...input, verificationHandle: "verify_0123456789abcdef01234567",
  });
  assert.throws(() => validateVerificationOpenInput({ ...input, verificationHandle: "https://beenverified.com/confirm" }), /invalid_verification_handle/);
});

test("preflight binds the exact profile and IMAP transport snapshots", () => {
  const result = validateVerificationPreflight({ input, catalog, profilePayload, imapTransport: imap, attestations });
  assert.equal(result.profile.contactEmail, profile.contactEmail);
  assert.deepEqual(result.broker.linkDomains, ["beenverified.com"]);
  assert.throws(() => validateVerificationPreflight({
    input, catalog, profilePayload: JSON.stringify({ ...profile, fullName: "Changed Example" }), imapTransport: imap, attestations,
  }), /rightout_verification_snapshot_changed/);
  assert.throws(() => validateVerificationPreflight({
    input, catalog, profilePayload, imapTransport: { ...imap, password: "changed" }, attestations,
  }), /rightout_verification_snapshot_changed/);
});

test("browser verification preflight binds one exact logged-in browser profile", () => {
  const browserControl = {
    browserControlBaseUrl: "http://127.0.0.1:3000/browser",
    browserProfile: "logged-in-gmail",
    browserBackendMode: "existing_logged_in_cdp",
  };
  const browserAttestations = {
    ...attestations,
    browserProfileDigest: browserVerificationProfileDigest(browserControl),
  };
  const result = validateBrowserVerificationPreflight({
    input, catalog, profilePayload, browserControl, attestations: browserAttestations,
  });
  assert.equal(result.profile.contactEmail, profile.contactEmail);
  assert.throws(() => validateBrowserVerificationPreflight({
    input,
    catalog,
    profilePayload,
    browserControl: { ...browserControl, browserProfile: "another-profile" },
    attestations: browserAttestations,
  }), /rightout_verification_snapshot_changed/);
  assert.throws(() => browserVerificationProfileDigest({
    ...browserControl, browserControlBaseUrl: "https://remote.example/browser",
  }), /rightout_browser_webmail_profile_required/);
});

test("unsupported catalog records cannot enable inbox polling", () => {
  assert.throws(() => resolveVerificationCatalogEntry({ brokers: [{ id: "beenverified", category: "people_search" }] }, input), /unsupported_verification_lane/);
});

test("poll and open approvals are separate, exact, and PII-free", () => {
  const broker = resolveVerificationCatalogEntry(catalog, input);
  const pollText = verificationPollApprovalDescription(input, broker);
  assert.match(pollText, /30 post-submission inbox messages/);
  assert.doesNotMatch(pollText, /Avery|avery@example|app-password/);
  const openInput = { ...input, verificationHandle: "verify_0123456789abcdef01234567" };
  const openText = verificationOpenApprovalDescription(openInput, broker);
  assert.match(openText, /external broker write/);
  assert.doesNotMatch(openText, /id=secret|Avery|avery@example/);
  assert.notEqual(
    verificationPollScopeBinding(input, attestations, broker),
    verificationOpenScopeBinding(openInput, attestations, broker),
  );
});

test("open approval binding is exact to subject, broker, and opaque handle without reading its token", () => {
  const broker = resolveVerificationCatalogEntry(catalog, input);
  const openInput = { ...input, verificationHandle: "verify_0123456789abcdef01234567" };
  const binding = verificationOpenScopeBinding(openInput, attestations, broker);
  assert.notEqual(binding, verificationOpenScopeBinding({ ...openInput, profileId: "profile_ffffffffffffffff" }, {
    ...attestations,
    authorizedProfileIds: ["profile_ffffffffffffffff"],
    authorizedProfileDigests: { profile_ffffffffffffffff: "f".repeat(64) },
  }, broker));
  assert.notEqual(binding, verificationOpenScopeBinding({ ...openInput, verificationHandle: "verify_ffffffffffffffffffffffff" }, attestations, broker));
});
