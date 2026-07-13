import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { runLiveScan, scanProfileDigest } from "../../lib/live-scan.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

const parity = JSON.parse(await readFile("skills/data-broker-removal/references/brokers/unbroker-parity.json", "utf8"));
const core = JSON.parse(await readFile("skills/data-broker-removal/references/brokers/core.json", "utf8"));
const profileId = "profile_a1b2c3d4e5f60718";
const profilePayload = JSON.stringify({
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
    method: "self",
  },
});

test("one autonomous scan batch covers the 21 policy-permitted Unbroker brokers and leaves Spokeo human-only", async () => {
  const scanRoutes = parity.brokers.filter((route) => route.id !== "spokeo");
  const spokeo = core.brokers.find((broker) => broker.id === "spokeo");
  assert.equal(scanRoutes.length, 21);
  assert.equal(spokeo.scan.supported, false);
  assert.equal(spokeo.scan.automated_access_policy, "prohibited_by_published_terms");
  const catalog = {
    brokers: scanRoutes.map((route) => ({
      id: route.id,
      name: route.name,
      category: "people_search",
      official_domains: route.official_domains,
      scan: { supported: true, automated_access_policy: "search_index_only_no_publisher_access" },
    })),
  };
  const report = await runLiveScan({
    input: { profileId, brokerIds: scanRoutes.map((route) => route.id), subject: profilePayload },
    catalog,
    apiKey: "dummy-brave-key",
    operatorAttestations: {
      braveTermsAccepted: true,
      braveTermsVersion: "2026-02-11",
      braveCustomerResponsibilitiesAccepted: true,
      subjectConsentReviewed: true,
      authorizedProfileIds: [profileId],
      authorizedProfileDigests: { [profileId]: scanProfileDigest(profilePayload) },
      authorizedBrokerIds: scanRoutes.map((route) => route.id).sort(),
    },
    guardedFetch: async ({ init }) => {
      const query = JSON.parse(init.body).q;
      const domain = query.match(/^site:([^ ]+)/)[1];
      return {
        response: new Response(JSON.stringify({ web: { results: [{ url: `https://${domain}/person/opaque` }] } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
        async release() {},
      };
    },
  });
  assert.equal(report.summary.checked, 21);
  assert.equal(report.provider.broker_parallelism, 4);
  assert.equal(report.summary.indirect_exposure, 21);
  assert.equal(report.invariants.brave_candidate_urls_persisted, 0);
  assert.equal(report.invariants.brave_candidate_urls_returned, 0);
  assert.ok(report.results.every((item) => !("listing_handle" in item)));
  assert.equal(JSON.stringify(report).includes("Avery Example"), false);
  assert.equal(JSON.stringify(report).includes("/person/opaque"), false);
});
