import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";

import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";
import {
  removalApprovalDescription,
  removalProfileDigest,
  removalSmtpDigest,
  resolveRemovalCatalogEntry,
  runRemovalSubmission,
} from "../../lib/removal.mjs";

const catalog = JSON.parse(readFileSync(new URL("../../skills/data-broker-removal/references/brokers/core.json", import.meta.url), "utf8"));
const profileId = "profile_1122334455667788";

function fixtureFor(broker) {
  const isEu = broker.process_class === "eu_controller_email_erasure";
  const isUk = broker.process_class === "uk_controller_email_erasure";
  const profile = {
    fullName: "Avery Example",
    city: isEu ? "Berlin" : isUk ? "London" : "Exampleville",
    region: isEu ? "BE" : isUk ? "ENG" : "CA",
    country: isEu ? "DE" : isUk ? "GB" : "US",
    contactEmail: "avery@example.invalid",
    jurisdictions: isEu ? ["DE", "EU", "EEA"] : isUk ? ["GB", "UK"] : ["US", "US-CA"],
    ...(broker.removal.disclosure_fields.includes("mobile_advertising_id")
      ? { mobileAdvertisingId: "12345678-1234-4234-9234-123456789abc" }
      : {}),
    consent: {
      authorized: true,
      recordedAt: CONSENT_RECORDED_AT,
      validUntil: CONSENT_VALID_UNTIL,
      scope: ["scan", "broker_removal"],
    },
  };
  const profilePayload = JSON.stringify(profile);
  const smtpConfig = {
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    username: "smtp-user",
    password: "smtp-app-password",
    fromAddress: profile.contactEmail,
  };
  const input = {
    profileId,
    brokerId: broker.id,
    requestKind: broker.removal.request_kinds[0],
  };
  const attestations = {
    rightoutRemovalPolicyAccepted: true,
    rightoutRemovalPolicyVersion: "2026-07-16-global2",
    subjectConsentReviewed: true,
    smtpAccountAuthorized: true,
    minimumDisclosureAccepted: true,
    authorizedProfileIds: [profileId],
    authorizedProfileDigests: { [profileId]: removalProfileDigest(profilePayload) },
    authorizedBrokerIds: [broker.id],
    authorizedRequestKinds: [input.requestKind],
    smtpTransportDigest: removalSmtpDigest(smtpConfig),
  };
  return { input, profile, profilePayload, smtpConfig, attestations };
}

test("catalog exposes twenty-nine independently locked executable removal targets", () => {
  const executable = catalog.brokers.filter((broker) => broker.removal?.supported === true && broker.human_only === false);
  assert.equal(executable.length, 29);
  assert.equal(new Set(executable.map((broker) => broker.id)).size, 29);
  assert.equal(executable.filter((broker) => broker.removal.channel === "email").length, 28);
  assert.equal(executable.filter((broker) => broker.removal.channel === "browser_form").length, 1);
  assert.equal(executable.filter((broker) => broker.process_class === "uk_controller_email_erasure").length, 1);
  assert.equal(executable.filter((broker) => broker.process_class === "us_data_broker_email_deletion").length, 8);
});

for (const broker of catalog.brokers.filter((entry) => entry.removal?.supported === true && entry.removal.channel === "email")) {
  test(`email removal target is exact, approval-gated, and PII-safe: ${broker.id}`, async () => {
    const { input, profile, profilePayload, smtpConfig, attestations } = fixtureFor(broker);
    const resolved = resolveRemovalCatalogEntry(catalog, input);
    const approval = removalApprovalDescription(input, resolved);
    assert.match(approval, new RegExp(broker.removal.recipient.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
    assert.doesNotMatch(approval, /Avery|avery@example/);
    assert.ok(approval.length <= 256);

    let message;
    const report = await runRemovalSubmission({
      input,
      catalog,
      profilePayload,
      smtpConfig,
      operatorAttestations: attestations,
      now: () => new Date("2026-07-12T12:00:00.000Z"),
      async sendMail(value) {
        message = value.message;
        return { accepted: [broker.removal.recipient], rejected: [], messageId: value.message.messageId };
      },
    });

    assert.equal(message.to, broker.removal.recipient);
    assert.equal(message.from, profile.contactEmail);
    assert.equal(report.broker_id, broker.id);
    assert.equal(report.state, "submitted");
    assert.equal(report.delivery.removal_confirmed, false);
    assert.equal(report.invariants.provider_writes, 1);
    const serialized = JSON.stringify(report);
    assert.equal(serialized.includes(profile.fullName), false);
    assert.equal(serialized.includes(profile.contactEmail), false);
    if (profile.mobileAdvertisingId) assert.equal(serialized.includes(profile.mobileAdvertisingId), false);
  });
}
