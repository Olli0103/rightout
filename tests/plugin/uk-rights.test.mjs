import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";
import {
  removalProfileDigest,
  removalSmtpDigest,
  resolveRemovalCatalogEntry,
  runRemovalSubmission,
} from "../../lib/removal.mjs";
import {
  calculateUkRightsResponseWindow,
  UK_RIGHTS_CONTRACT,
  ukRightsContractDigest,
} from "../../lib/uk-rights.mjs";

const catalog = JSON.parse(readFileSync(
  new URL("../../skills/data-broker-removal/references/brokers/core.json", import.meta.url),
  "utf8",
));
const profileId = "profile_89abcdef01234567";
const brokerId = "cognism_uk";
const input = { profileId, brokerId, requestKind: "uk_erasure_objection" };
const profile = {
  fullName: "Avery Example",
  city: "London",
  region: "ENG",
  country: "GB",
  contactEmail: "avery@example.invalid",
  jurisdictions: ["GB", "UK"],
  consent: {
    authorized: true,
    recordedAt: CONSENT_RECORDED_AT,
    validUntil: CONSENT_VALID_UNTIL,
    scope: ["broker_removal"],
    method: "self",
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
const attestations = {
  rightoutRemovalPolicyAccepted: true,
  rightoutRemovalPolicyVersion: "2026-07-16-global2",
  subjectConsentReviewed: true,
  smtpAccountAuthorized: true,
  minimumDisclosureAccepted: true,
  authorizedProfileIds: [profileId],
  authorizedProfileDigests: { [profileId]: removalProfileDigest(profilePayload) },
  authorizedBrokerIds: [brokerId],
  authorizedRequestKinds: ["uk_erasure_objection"],
  smtpTransportDigest: removalSmtpDigest(smtpConfig),
};

test("UK rights contract is stable, ICO-bound, and calculates a calendar month conservatively", () => {
  assert.equal(UK_RIGHTS_CONTRACT.contract_id, "uk_controller_erasure_objection_v1");
  assert.deepEqual(UK_RIGHTS_CONTRACT.eligible_jurisdictions, ["UK"]);
  assert.equal(Object.isFrozen(UK_RIGHTS_CONTRACT), true);
  assert.equal(Object.isFrozen(UK_RIGHTS_CONTRACT.eligible_jurisdictions), true);
  assert.equal(UK_RIGHTS_CONTRACT.legal_sources.every((url) => url.startsWith("https://ico.org.uk/")), true);
  assert.match(ukRightsContractDigest(), /^[a-f0-9]{64}$/);
  assert.deepEqual(
    calculateUkRightsResponseWindow("2027-01-31T12:00:00.000Z"),
    {
      policy: "one_calendar_month_conservative_recheck_v1",
      ordinary_due_date: "2027-02-28",
      conservative_recheck_at: "2027-02-28T00:00:00.000Z",
      extension_applied: false,
      identity_clock_change_applied: false,
      weekend_or_public_holiday_adjustment: "not_applied_conservative_earlier_recheck",
      extension_or_identity_change_requires: "human_reviewed_controller_evidence",
    },
  );
  assert.equal(
    calculateUkRightsResponseWindow("2028-01-31T12:00:00.000Z").ordinary_due_date,
    "2028-02-29",
  );
  assert.equal(
    calculateUkRightsResponseWindow("2026-12-31T12:00:00.000Z").ordinary_due_date,
    "2027-01-31",
  );
  assert.throws(() => calculateUkRightsResponseWindow("2026-01-31"), /rightout_uk_deadline_invalid/);
});

test("UK request uses its own route, wording, identity boundary, and response window", async () => {
  const resolved = resolveRemovalCatalogEntry(catalog, input);
  assert.equal(resolved.processClass, "uk_controller_email_erasure");
  assert.equal(resolved.templateId, "uk_erasure_objection_v1");
  assert.equal(resolved.rightsContractId, "uk_controller_erasure_objection_v1");
  assert.equal(resolved.deadlinePolicy, "one_calendar_month_conservative_recheck_v1");

  const calls = [];
  const report = await runRemovalSubmission({
    input,
    catalog,
    profilePayload,
    smtpConfig,
    operatorAttestations: attestations,
    now: () => new Date("2027-01-31T12:00:00.000Z"),
    async sendMail(value) {
      calls.push(value);
      return { accepted: ["privacy@cognism.com"], rejected: [] };
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].message.to, "privacy@cognism.com");
  assert.match(calls[0].message.subject, /^UK data-protection request/);
  assert.match(calls[0].message.text, /UK GDPR/);
  assert.match(calls[0].message.text, /necessary and proportionate/);
  assert.doesNotMatch(calls[0].message.text, /GDPR Article 17|Article 19|EU\/EEA/);
  assert.equal(report.process_class, "uk_controller_email_erasure");
  assert.equal(report.rights_contract.contract_id, "uk_controller_erasure_objection_v1");
  assert.equal(report.response_window.ordinary_due_date, "2027-02-28");
  assert.equal(report.response_window.conservative_recheck_at, "2027-02-28T00:00:00.000Z");
  assert.equal(report.disclosures.identity_documents, 0);
  assert.ok(report.coverage_gaps.includes("identity_clock_change_requires_human_reviewed_controller_evidence"));
  assert.ok(report.coverage_gaps.includes("no_universal_uk_broker_erasure_registry"));
  assert.doesNotMatch(JSON.stringify(report), /Avery|avery@example|UK GDPR/);
});

test("UK and EU contracts cannot be substituted and ineligible profiles fail before SMTP", async () => {
  const eu = catalog.brokers.find((broker) => broker.id === "cognism_eu");
  assert.throws(
    () => resolveRemovalCatalogEntry(catalog, { ...input, brokerId: "cognism_eu" }),
    /unsupported_removal_lane/,
  );
  assert.throws(
    () => resolveRemovalCatalogEntry(catalog, { ...input, requestKind: "gdpr_erasure_objection" }),
    /unsupported_removal_lane/,
  );
  assert.throws(
    () => resolveRemovalCatalogEntry({
      ...catalog,
      brokers: catalog.brokers.map((broker) => broker.id === brokerId
        ? {
          ...broker,
          process_class: "eu_controller_email_erasure",
          eu_process: eu.eu_process,
          removal: {
            ...broker.removal,
            request_kinds: ["gdpr_erasure_objection"],
            template_id: "gdpr_erasure_objection_v1",
            eligible_jurisdictions: ["EU", "EEA"],
            processing_days: 30,
          },
        }
        : broker),
    }, { ...input, requestKind: "gdpr_erasure_objection" }),
    /unsupported_removal_lane/,
  );

  let sends = 0;
  for (const changed of [
    { ...profile, country: "DE", region: "BE", jurisdictions: ["DE", "EU", "EEA"] },
    { ...profile, jurisdictions: ["GB"] },
  ]) {
    const changedPayload = JSON.stringify(changed);
    await assert.rejects(runRemovalSubmission({
      input,
      catalog,
      profilePayload: changedPayload,
      smtpConfig,
      operatorAttestations: {
        ...attestations,
        authorizedProfileDigests: { [profileId]: removalProfileDigest(changedPayload) },
      },
      async sendMail() { sends += 1; },
    }), /profile_not_eligible_for_removal_lane/);
  }
  assert.equal(sends, 0);
});
