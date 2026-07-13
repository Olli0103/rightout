import assert from "node:assert/strict";
import test from "node:test";

import { buildParityMessage, runParityEmail } from "../../lib/parity-email.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

const profile = JSON.stringify({
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  contactEmail: "avery@example.invalid",
  jurisdictions: ["US", "US-CA"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["broker_removal"], method: "self" },
});
const smtp = {
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  username: "avery@example.invalid",
  password: "dummy-password",
  fromAddress: "avery@example.invalid",
};
const broker = {
  id: "spokeo",
  name: "Spokeo",
  official_domains: ["spokeo.com"],
  disclosure_fields: ["listing_url", "contact_email"],
  rescue_email: "legal@spokeo.com",
  rescue_source_url: "https://cppa.ca.gov/data_broker_registry/registry2025.csv",
  rescue_disclosure_fields: ["full_name", "contact_email", "listing_url"],
  rescue_last_checked: "2026-07-13",
  rescue_source_status: "observed_official_registry",
};

test("official registry rescue sends one minimum-disclosure request and returns no PII", async () => {
  let message;
  const report = await runParityEmail({
    input: { profileId: "profile_a1b2c3d4e5f60718", brokerId: "spokeo" },
    broker,
    profilePayload: profile,
    smtpConfig: smtp,
    listingUrl: "https://www.spokeo.com/Avery-Example/opaque",
    sendMail: async (value) => { message = value.message; return { accepted: ["legal@spokeo.com"], rejected: [] }; },
    now: () => new Date("2026-07-13T08:00:00Z"),
  });
  assert.equal(message.to, "legal@spokeo.com");
  assert.match(message.text, /Avery Example/);
  assert.equal(report.state, "submitted");
  assert.equal(report.raw_pii_in_report, false);
  assert.equal(JSON.stringify(report).includes("Avery Example"), false);
  assert.equal(JSON.stringify(report).includes("avery@example.invalid"), false);
});

test("rescue lane rejects foreign recipient and listing domains", async () => {
  await assert.rejects(runParityEmail({
    input: { profileId: "profile_a1b2c3d4e5f60718", brokerId: "spokeo" },
    broker: { ...broker, rescue_email: "collect@evil.invalid" },
    profilePayload: profile,
    smtpConfig: smtp,
    listingUrl: "https://www.spokeo.com/opaque",
    sendMail: async () => ({ accepted: ["collect@evil.invalid"] }),
  }), /rightout_parity_email_lane_invalid/);
  await assert.rejects(runParityEmail({
    input: { profileId: "profile_a1b2c3d4e5f60718", brokerId: "spokeo" },
    broker,
    profilePayload: profile,
    smtpConfig: smtp,
    listingUrl: "https://evil.example/opaque",
    sendMail: async () => ({ accepted: ["legal@spokeo.com"] }),
  }), /rightout_parity_email_lane_invalid/);
});

test("official registry rescue can omit a listing URL when the regulator does not require one", () => {
  const built = buildParityMessage({
    input: { profileId: "profile_a1b2c3d4e5f60718", brokerId: "peekyou" },
    broker: {
      ...broker,
      id: "peekyou",
      name: "PeekYou",
      official_domains: ["peekyou.com"],
      rescue_email: "ccpa@peekyou.com",
      rescue_disclosure_fields: ["full_name", "contact_email"],
    },
    profilePayload: profile,
  });
  assert.deepEqual(built.disclosureFields, ["full_name", "contact_email"]);
  assert.equal(built.text.includes("Listing URL:"), false);
});

test("browser webmail uses the same catalog-locked message builder", () => {
  const message = buildParityMessage({
    input: { profileId: "profile_a1b2c3d4e5f60718", brokerId: "spokeo" },
    broker,
    profilePayload: profile,
    listingUrl: "https://www.spokeo.com/Avery-Example/opaque",
  });
  assert.equal(message.recipient, "legal@spokeo.com");
  assert.match(message.text, /Avery Example/);
  assert.deepEqual(message.disclosureFields, ["full_name", "contact_email", "listing_url"]);
});
