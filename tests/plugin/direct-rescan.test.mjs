import assert from "node:assert/strict";
import test from "node:test";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

import {
  __test,
  directScanApprovalDescription,
  runDirectRescan,
  validateDirectScanAttestations,
} from "../../lib/direct-rescan.mjs";
import { scanProfileDigest } from "../../lib/live-scan.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const brokerId = "truepeoplesearch";
const listingHandle = "listing_1234567890abcdef12345678";
const profilePayload = JSON.stringify({
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  contactEmail: "avery@example.invalid",
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["scan"] },
});
const input = { profileId, brokerId, listingHandle };
const catalog = { brokers: [{
  id: brokerId,
  name: "TruePeopleSearch",
  category: "people_search",
  direct_rescan: {
    supported: true,
    strategy: "exact_encrypted_index_candidate_urls",
    publisher_terms_gate: "operator_attestation_required",
  },
}] };
const token = {
  profileId,
  brokerId,
  urls: ["https://www.truepeoplesearch.com/find/person/private-record"],
  officialDomains: ["truepeoplesearch.com"],
  observedAt: "2026-07-12T12:00:00.000Z",
};
const attestations = {
  rightoutDirectScanPolicyAccepted: true,
  rightoutDirectScanPolicyVersion: "2026-07-12",
  subjectConsentReviewed: true,
  publisherAccessAuthorized: true,
  publisherTermsReviewed: true,
  authorizedProfileIds: [profileId],
  authorizedProfileDigests: { [profileId]: scanProfileDigest(profilePayload) },
  authorizedBrokerIds: [brokerId],
};

function guarded(status, body = "") {
  const calls = [];
  const fn = async (request) => {
    calls.push(request);
    return { response: new Response(body, { status }), release: async () => {} };
  };
  fn.calls = calls;
  return fn;
}

test("direct 404 confirms absence only for the encrypted known listing set", async () => {
  const fetcher = guarded(404);
  const report = await runDirectRescan({ input, catalog, profilePayload, attestations, token, guardedFetch: fetcher });
  assert.equal(report.observation, "direct_absent_known_listing_set");
  assert.equal(report.removal_confirmation_scope, "known_listing_set_only");
  assert.equal(report.coverage_gap, "new_or_unindexed_listing_urls_not_checked");
  assert.deepEqual(fetcher.calls[0].allowedHosts, ["truepeoplesearch.com"]);
  assert.equal(fetcher.calls[0].maxRedirects, 0);
  const output = JSON.stringify(report);
  for (const secret of ["private-record", "Avery", "Exampleville", "avery@example.invalid"]) assert.equal(output.includes(secret), false);
});

test("direct 200 requires full name plus a configured corroborator", async () => {
  const present = await runDirectRescan({
    input, catalog, profilePayload, attestations, token,
    guardedFetch: guarded(200, "<html><body>Avery Example — Exampleville CA</body></html>"),
  });
  assert.equal(present.observation, "direct_present");
  assert.equal(present.match_basis, "full_name_plus_location");
  const nameOnly = await runDirectRescan({
    input, catalog, profilePayload, attestations, token,
    guardedFetch: guarded(200, "<html><body>Avery Example</body></html>"),
  });
  assert.equal(nameOnly.observation, "inconclusive");
});

test("CAPTCHA, redirects, and partial failures fail closed", async () => {
  const captcha = await runDirectRescan({
    input, catalog, profilePayload, attestations, token,
    guardedFetch: guarded(200, "<html>Verify you are human Avery Example Exampleville CA</html>"),
  });
  assert.equal(captcha.observation, "inconclusive");
  const redirect = await runDirectRescan({ input, catalog, profilePayload, attestations, token, guardedFetch: guarded(302) });
  assert.equal(redirect.observation, "inconclusive");
});

test("direct approval and attestations are exact-scope and PII-safe", () => {
  assert.deepEqual(validateDirectScanAttestations(input, attestations), attestations);
  assert.throws(() => validateDirectScanAttestations(input, { ...attestations, publisherTermsReviewed: false }), /attestation_required/);
  const text = directScanApprovalDescription(input, { id: brokerId }, token);
  assert.match(text, /publisher terms reviewed/);
  assert.doesNotMatch(text, /private-record|Avery|Exampleville/);
  assert.deepEqual(__test.pageMatch("Avery Example Exampleville CA", __test.subjectSignals(profilePayload)), { matched: true, corroborator: "location" });
});

test("direct page matching ignores non-visible HTML without regex parsing", () => {
  const signals = __test.subjectSignals(profilePayload);
  for (const hidden of [
    "<script>Avery Example Exampleville CA</script >",
    "<style>.x::after { content: 'Avery Example Exampleville CA'; }</style >",
    "<template>Avery Example Exampleville CA</template>",
    "<noscript>Avery Example Exampleville CA</noscript>",
    "<a href='https://example.invalid/Avery-Example-Exampleville-CA'>unrelated</a>",
    "<img alt='Avery Example Exampleville CA'>",
  ]) {
    assert.deepEqual(__test.pageMatch(`<html><body>${hidden}</body></html>`, signals), { matched: false });
  }
  assert.deepEqual(
    __test.pageMatch("<html><body><p>Avery Example</p><p>Exampleville CA</p></body></html>", signals),
    { matched: true, corroborator: "location" },
  );
});
