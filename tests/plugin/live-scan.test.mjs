import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";
import test from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  __test,
  approvalDescription,
  buildSearchVectors,
  runLiveScan,
  scanProfileDigest,
  validateLiveScanInput,
} from "../../lib/live-scan.mjs";

function fakeRuntime() {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-live-runtime-"));
  return { state: { resolveStateDir() { return stateDir; } } };
}

const privateProfile = {
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  consent: {
    authorized: true,
    recordedAt: CONSENT_RECORDED_AT,
    validUntil: CONSENT_VALID_UNTIL,
    scope: ["scan"],
  },
};
const profilePayload = JSON.stringify(privateProfile);

const toolInput = {
  profileId: "profile_a1b2c3d4e5f60718",
  brokerIds: ["truepeoplesearch"],
};

const operatorAttestations = {
  braveTermsAccepted: true,
  braveTermsVersion: "2026-02-11",
  braveCustomerResponsibilitiesAccepted: true,
  subjectConsentReviewed: true,
  authorizedProfileIds: [toolInput.profileId],
  authorizedProfileDigests: { [toolInput.profileId]: scanProfileDigest(profilePayload) },
  authorizedBrokerIds: ["truepeoplesearch"],
};

const scanInput = {
  ...toolInput,
  subject: profilePayload,
};

const catalog = {
  brokers: [
    {
      id: "truepeoplesearch",
      category: "people_search",
      official_domains: ["truepeoplesearch.com"],
      scan: {
        supported: true,
        automated_access_policy: "search_index_only_no_publisher_access",
      },
    },
  ],
};

function response(body, { status = 200, headers = {} } = {}) {
  return new Response(body, { status, headers });
}

function mockGuardedFetch(steps) {
  const calls = [];
  let index = 0;
  const fn = async (request) => {
    calls.push(request);
    const step = steps[index++];
    if (!step) {
      throw new Error("unexpected_mock_request");
    }
    const result = typeof step === "function" ? await step(request) : step;
    return {
      response: result.response,
      finalUrl: result.finalUrl || request.url,
      release: async () => {
        result.released = true;
      },
    };
  };
  fn.calls = calls;
  return fn;
}

test("approval text names scope without exposing PII values", () => {
  const text = approvalDescription(toolInput);
  assert.match(text, new RegExp(toolInput.profileId));
  assert.match(text, /truepeoplesearch/);
  assert.match(text, /names\/aliases\/addresses\/emails\/phones/);
  assert.match(text, /logs <=90d\/ZDR/);
  assert.match(text, /terms 2026-02-11/);
  assert.match(text, /consent\+duties/);
  assert.match(text, /No broker request\/email\/write/);
  assert.doesNotMatch(text, /Avery|Exampleville|CA/);
  assert.ok(text.length <= 256);
  const maximumScopeText = approvalDescription({
    profileId: `profile_${"a".repeat(32)}`,
    brokerIds: ["a".repeat(24), "b".repeat(24)],
  });
  assert.ok(maximumScopeText.length <= 256, maximumScopeText);
});

test("configured aliases, prior locations, emails, and phones become bounded Brave vectors only", async () => {
  const extended = {
    ...privateProfile,
    alsoKnownAs: ["Avery Prior"],
    priorLocations: [{ city: "Oldtown", region: "WA", country: "US" }],
    emails: ["avery.old@example.invalid"],
    phones: ["+1 202 555 0100"],
    mobileAdvertisingId: "12345678-1234-4234-9234-123456789abc",
  };
  const extendedPayload = JSON.stringify(extended);
  const extendedInput = { ...toolInput, subject: extendedPayload };
  const extendedAttestations = {
    ...operatorAttestations,
    authorizedProfileDigests: { [toolInput.profileId]: scanProfileDigest(extendedPayload) },
  };
  const guardedFetch = mockGuardedFetch(Array.from({ length: 6 }, () => ({
    response: response(JSON.stringify({ web: { results: [] } }), { headers: { "content-type": "application/json" } }),
  })));
  const report = await runLiveScan({ input: extendedInput, catalog, apiKey: "dummy-test-key", guardedFetch, operatorAttestations: extendedAttestations });
  assert.equal(guardedFetch.calls.length, 6);
  assert.equal(report.results[0].vectors_attempted, 6);
  assert.deepEqual(report.results[0].vector_types, ["name_location", "email", "phone"]);
  const serialized = JSON.stringify(report);
  for (const secret of ["Avery Prior", "Oldtown", "avery.old@example.invalid", "+1 202 555 0100", extended.mobileAdvertisingId]) {
    assert.equal(serialized.includes(secret), false, secret);
  }
  assert.equal(JSON.stringify(guardedFetch.calls).includes(extended.mobileAdvertisingId), false);
  assert.deepEqual(report.disclosures.to_search_provider, [
    "full_name", "aliases_if_configured", "current_and_prior_locations_and_addresses", "emails_if_configured", "phones_if_configured",
  ]);
});

test("input validation accepts opaque refs and ISO-country profiles including DE", () => {
  assert.deepEqual(validateLiveScanInput(scanInput), {
    profileId: toolInput.profileId,
    subject: {
      ...privateProfile,
      consent: { ...privateProfile.consent, method: "self" },
    },
    brokerIds: toolInput.brokerIds,
  });
  const exactMaxConsent = {
    ...privateProfile.consent,
    validUntil: new Date(Date.parse(privateProfile.consent.recordedAt) + 365 * 24 * 60 * 60_000).toISOString(),
  };
  assert.doesNotThrow(() => validateLiveScanInput({
    ...scanInput,
    subject: JSON.stringify({ ...privateProfile, consent: exactMaxConsent }),
  }));
  const german = validateLiveScanInput({
    ...scanInput,
    subject: JSON.stringify({
      ...privateProfile, city: "Berlin", region: "Berlin", country: "DE",
      currentAddress: { line1: "1 Beispielweg", city: "Berlin", region: "Berlin", postal: "10115" },
      priorLocations: [{ city: "Hamburg", region: "Hamburg" }],
    }),
  });
  assert.equal(german.subject.country, "DE");
  assert.equal(german.subject.currentAddress.country, "DE");
  assert.equal(german.subject.priorLocations[0].country, "DE");
  assert.throws(
    () => validateLiveScanInput({ ...scanInput, subject: JSON.stringify({ ...privateProfile, country: "XX" }) }),
    /unsupported_country/,
  );
  const { country: _country, ...countrylessProfile } = privateProfile;
  assert.throws(
    () => validateLiveScanInput({ ...scanInput, subject: JSON.stringify(countrylessProfile) }),
    /invalid_profile/,
  );
  assert.throws(() => validateLiveScanInput({ ...scanInput, profileId: "Avery Example" }), /invalid_profile_ref/);
  assert.throws(() => validateLiveScanInput({ ...scanInput, brokerIds: ["../escape"] }), /invalid_broker_ids/);
  assert.equal(
    validateLiveScanInput({ ...scanInput, subject: JSON.stringify({ ...privateProfile, dateOfBirth: "2000-01-01" }) }).subject.fullName,
    privateProfile.fullName,
  );
  for (const consent of [
    undefined,
    { ...privateProfile.consent, authorized: false },
    { ...privateProfile.consent, scope: ["broker_removal"] },
    { ...privateProfile.consent, recordedAt: "2999-01-01T00:00:00.000Z" },
    { ...privateProfile.consent, validUntil: "2000-01-01T00:00:00.000Z" },
    { ...privateProfile.consent, validUntil: privateProfile.consent.recordedAt },
    { ...privateProfile.consent, validUntil: new Date(Date.parse(privateProfile.consent.recordedAt) + 366 * 24 * 60 * 60_000).toISOString() },
  ]) {
    assert.throws(
      () => validateLiveScanInput({ ...scanInput, subject: JSON.stringify({ ...privateProfile, consent }) }),
      /subject_consent_required/,
    );
  }
});

test("profile payload accepts the manifest boundary through 4096 bytes and rejects larger values", () => {
  const within = JSON.stringify({ ...privateProfile, mobileAdvertisingId: "x".repeat(3_500) });
  assert.ok(within.length > 2_048 && within.length <= 4_096);
  assert.doesNotThrow(() => scanProfileDigest(within));
  const oversized = JSON.stringify({ ...privateProfile, mobileAdvertisingId: "x".repeat(4_100) });
  assert.ok(oversized.length > 4_096);
  assert.throws(() => scanProfileDigest(oversized), /profile_unavailable/);
});

test("DE live scan targets the German Brave index and supports data-broker catalog lanes", async () => {
  const germanProfile = JSON.stringify({ ...privateProfile, city: "Berlin", region: "Berlin", country: "DE" });
  const germanInput = { ...toolInput, brokerIds: ["emetriq_eu"], subject: germanProfile };
  const germanCatalog = { brokers: [{
    id: "emetriq_eu", category: "data_broker", official_domains: ["emetriq.com"],
    scan: { supported: true, automated_access_policy: "search_index_only_no_publisher_access" },
  }] };
  const germanAttestation = {
    ...operatorAttestations,
    authorizedProfileDigests: { [toolInput.profileId]: scanProfileDigest(germanProfile) },
    authorizedBrokerIds: ["emetriq_eu"],
  };
  const guardedFetch = mockGuardedFetch([({ init }) => {
    const body = JSON.parse(init.body);
    assert.equal(body.country, "DE");
    assert.equal(body.search_lang, "de");
    return { response: response(JSON.stringify({ web: { results: [] } })) };
  }]);
  const report = await runLiveScan({
    input: germanInput, catalog: germanCatalog, apiKey: "dummy-test-key", guardedFetch,
    operatorAttestations: germanAttestation,
  });
  assert.equal(report.provider.locale_targeting, "country_targeted");
  assert.equal(report.provider.country_target, "DE");
  assert.equal(report.provider.search_language, "de");
  assert.equal(report.results[0].state, "inconclusive");
});

test("valid ISO countries without a Brave country target use worldwide targeting, never US", () => {
  assert.deepEqual(__test.braveLocaleForCountry("IS"), {
    country: "ALL", search_lang: "en", localization: "worldwide_fallback",
  });
});

test("localized non-US scans remain explicitly inconclusive public-index signals", async () => {
  for (const country of ["DE", "JP", "BR"]) {
    const payload = JSON.stringify({ ...privateProfile, city: "Example City", region: "Example Region", country });
    const localizedInput = { ...toolInput, subject: payload };
    const localizedAttestations = {
      ...operatorAttestations,
      authorizedProfileDigests: { [toolInput.profileId]: scanProfileDigest(payload) },
    };
    const guardedFetch = mockGuardedFetch([{
      response: response(JSON.stringify({ web: { results: [] } }), { headers: { "content-type": "application/json" } }),
    }]);
    const report = await runLiveScan({
      input: localizedInput,
      catalog,
      apiKey: "dummy-test-key",
      guardedFetch,
      operatorAttestations: localizedAttestations,
    });
    assert.equal(report.results[0].state, "inconclusive", country);
    assert.equal(report.summary.indirect_exposure, 0, country);
    assert.equal(report.coverage_scope.source, "public_web_search_index_only", country);
    assert.equal(report.coverage_scope.discovery_effectiveness, "needs_evidence", country);
    assert.equal(report.coverage_scope.private_broker_inventory_visibility, false, country);
    assert.ok(report.summary.coverage_gaps.includes("country_localization_does_not_establish_broker_discovery_effectiveness"), country);
  }
});

test("index absence is inconclusive rather than not-found", async () => {
  const brave = response(JSON.stringify({ web: { results: [] } }), { headers: { "content-type": "application/json" } });
  const guardedFetch = mockGuardedFetch([{ response: brave }]);
  const report = await runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch, operatorAttestations });
  assert.equal(report.summary.not_found, 0);
  assert.equal(report.summary.inconclusive, 1);
  assert.equal(report.results[0].reason, "no_index_candidates_not_proof_of_absence");
  assert.equal(guardedFetch.calls[0].init.method, "POST");
  assert.deepEqual(guardedFetch.calls[0].allowedHosts, ["api.search.brave.com"]);
  assert.doesNotMatch(guardedFetch.calls[0].url, /Avery|Exampleville/);
});

test("same-domain Brave result yields only an indirect signal and no publisher request", async () => {
  const bravePayload = {
    web: {
      results: [
        { url: "https://www.truepeoplesearch.com/find/person/opaque-record" },
        { url: "https://evil.invalid/Avery-Example" },
      ],
    },
  };
  const guardedFetch = mockGuardedFetch([
    { response: response(JSON.stringify(bravePayload), { headers: { "content-type": "application/json" } }) },
  ]);
  const report = await runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch, operatorAttestations });
  assert.equal(report.results[0].state, "indirect_exposure");
  assert.equal(report.results[0].reason, "search_index_candidate_observed");
  assert.equal(report.summary.found, 0);
  assert.equal(report.summary.indirect_exposure, 1);
  assert.equal(report.provider.query_log_retention, "up_to_90_days_standard_plan_unless_applicable_zdr_agreement");
  assert.equal(report.provider.terms_version, "2026-02-11");
  assert.deepEqual(report.results[0].proof_references, []);
  assert.deepEqual(report.disclosures.to_broker_pages, []);
  assert.equal(guardedFetch.calls.length, 1);
  assert.deepEqual(guardedFetch.calls[0].allowedHosts, ["api.search.brave.com"]);
  const serialized = JSON.stringify(report);
  for (const secret of [privateProfile.fullName, privateProfile.city, privateProfile.region, "dummy-test-key", "opaque-record"]) {
    assert.equal(serialized.includes(secret), false, secret);
  }
  assert.deepEqual(report.invariants, {
    operator_attestations_checked: true,
    submissions: 0,
    emails: 0,
    provider_writes: 0,
    publisher_requests: 0,
    local_plaintext_pii_storage: 0,
    raw_search_result_storage: 0,
    brave_candidate_urls_persisted: 0,
    brave_candidate_urls_returned: 0,
    raw_pii_in_report: false,
    raw_response_content_in_report: false,
    candidate_urls_in_report: false,
  });
});

test("Brave candidate URLs stay transient and are neither persisted nor returned", async () => {
  const url = "https://www.truepeoplesearch.com/find/person/private-record";
  const guardedFetch = mockGuardedFetch([{
    response: response(JSON.stringify({ web: { results: [{ url }] } }), { headers: { "content-type": "application/json" } }),
  }]);
  const report = await runLiveScan({
    input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch, operatorAttestations,
  });
  assert.equal("listing_handle" in report.results[0], false);
  assert.equal(report.invariants.brave_candidate_urls_persisted, 0);
  assert.equal(report.invariants.brave_candidate_urls_returned, 0);
  assert.equal(JSON.stringify(report).includes("private-record"), false);
  assert.equal(JSON.stringify(report).includes("https://"), false);
});

test("all configured vectors are evaluated without exposing distinct candidate URLs", async () => {
  const value = { ...privateProfile, emails: ["avery.old@example.invalid"] };
  const payload = JSON.stringify(value);
  const guardedFetch = mockGuardedFetch([
    { response: response(JSON.stringify({ web: { results: [{ url: "https://www.truepeoplesearch.com/a/record-one" }] } })) },
    { response: response(JSON.stringify({ web: { results: [{ url: "https://www.truepeoplesearch.com/b/record-two" }] } })) },
  ]);
  const report = await runLiveScan({
    input: { ...toolInput, subject: payload }, catalog, apiKey: "dummy-test-key", guardedFetch,
    operatorAttestations: { ...operatorAttestations, authorizedProfileDigests: { [toolInput.profileId]: scanProfileDigest(payload) } },
  });
  assert.equal(guardedFetch.calls.length, 2);
  assert.equal("listing_handle" in report.results[0], false);
  assert.equal(JSON.stringify(report).includes("record-one"), false);
  assert.equal(JSON.stringify(report).includes("record-two"), false);
});

test("Brave vectors never exceed current q limits and oversized identity values are omitted without truncation", async () => {
  const bounded = buildSearchVectors(privateProfile, "truepeoplesearch.com");
  assert.equal(bounded.omitted, 0);
  assert.ok(bounded.vectors.every(({ query }) => query.length <= 400 && query.trim().split(/\s+/u).length <= 50));

  const oversizedName = Array.from({ length: 60 }, () => "A").join(" ");
  const payload = JSON.stringify({ ...privateProfile, fullName: oversizedName });
  const neverCalled = async () => { throw new Error("provider_must_not_be_called"); };
  const report = await runLiveScan({
    input: { ...toolInput, subject: payload }, catalog, apiKey: "dummy-test-key", guardedFetch: neverCalled,
    operatorAttestations: { ...operatorAttestations, authorizedProfileDigests: { [toolInput.profileId]: scanProfileDigest(payload) } },
  });
  assert.equal(report.results[0].state, "inconclusive");
  assert.equal(report.results[0].vectors_attempted, 0);
  assert.equal(report.results[0].vectors_omitted_for_provider_limits, 1);
  assert.equal(report.results[0].reason, "query_scope_partially_or_fully_exceeds_brave_limits");
});

test("cross-domain candidates are discarded without fetching", async () => {
  const payload = { web: { results: [{ url: "https://evil.invalid/profile" }] } };
  const guardedFetch = mockGuardedFetch([
    { response: response(JSON.stringify(payload), { headers: { "content-type": "application/json" } }) },
  ]);
  const report = await runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch, operatorAttestations });
  assert.equal(guardedFetch.calls.length, 1);
  assert.equal(report.results[0].state, "inconclusive");
});

test("provider failures are sanitized", async () => {
  const authFetch = mockGuardedFetch([{ response: response("denied", { status: 401 }) }]);
  const authReport = await runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch: authFetch, operatorAttestations });
  assert.equal(authReport.results[0].reason, "provider_auth_failed");
});

test("unsupported catalog lanes cannot be scanned", async () => {
  const unsafeCatalog = { brokers: [{ ...catalog.brokers[0], category: "registry" }] };
  await assert.rejects(
    runLiveScan({ input: scanInput, catalog: unsafeCatalog, apiKey: "dummy-test-key", guardedFetch: mockGuardedFetch([]), operatorAttestations }),
    /unsupported_broker/,
  );
  await assert.rejects(
    runLiveScan({
      input: scanInput,
      catalog: { brokers: [{ ...catalog.brokers[0], official_domains: ["127.0.0.1"] }] },
      apiKey: "dummy-test-key",
      guardedFetch: mockGuardedFetch([]),
      operatorAttestations,
    }),
    /unsupported_broker/,
  );
});

test("library rejects missing, Boolean, profile-mismatched, and broker-mismatched attestations before network", async () => {
  const guardedFetch = mockGuardedFetch([]);
  const invalidAttestations = [
    undefined,
    true,
    { ...operatorAttestations, braveTermsVersion: "2025-01-01" },
    { ...operatorAttestations, braveCustomerResponsibilitiesAccepted: false },
    { ...operatorAttestations, subjectConsentReviewed: false },
    { ...operatorAttestations, authorizedProfileIds: ["profile_ffffffffffffffff"] },
    { ...operatorAttestations, authorizedProfileDigests: { [toolInput.profileId]: "not-a-digest" } },
    { ...operatorAttestations, authorizedBrokerIds: ["spokeo"] },
  ];
  for (const value of invalidAttestations) {
    await assert.rejects(
      runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch, operatorAttestations: value }),
      /rightout_operator_attestation_required/,
    );
  }
  assert.equal(guardedFetch.calls.length, 0);
});

test("index candidate parsing accepts only HTTPS publisher-domain results", () => {
  assert.equal(__test.hasIndexCandidate({ web: { results: [
    { url: "https://sub.truepeoplesearch.com/find/person/valid-record?q=opaque#fragment" },
  ] } }, ["truepeoplesearch.com"]), true);
  assert.equal(__test.hasIndexCandidate({ web: { results: [
    { url: "https://evil.invalid/profile" },
    { url: "http://truepeoplesearch.com/profile" },
  ] } }, ["truepeoplesearch.com"]), false);
});

test("abort signal prevents and cancels outbound work", async () => {
  const preAborted = new AbortController();
  preAborted.abort();
  const neverCalled = mockGuardedFetch([]);
  await assert.rejects(
    runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch: neverCalled, signal: preAborted.signal, operatorAttestations }),
    /rightout_scan_cancelled/,
  );
  assert.equal(neverCalled.calls.length, 0);

  const midAbort = new AbortController();
  const abortingFetch = mockGuardedFetch([
    (request) => {
      assert.equal(request.signal, midAbort.signal);
      midAbort.abort();
      return { response: response(JSON.stringify({ web: { results: [] } })) };
    },
  ]);
  await assert.rejects(
    runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch: abortingFetch, signal: midAbort.signal, operatorAttestations }),
    /rightout_scan_cancelled/,
  );
  assert.equal(abortingFetch.calls.length, 1);
});

test("response reader enforces declared and streamed byte limits", async () => {
  await assert.rejects(
    __test.readBoundedText(response("123456", { headers: { "content-length": "6" } }), 5),
    /response_too_large/,
  );
  await assert.rejects(__test.readBoundedText(response("123456"), 5), /response_too_large/);
});

test("plugin manifest declares the full autonomous campaign surface with correct replay semantics", async () => {
  const manifest = JSON.parse(await readFile(new URL("../../openclaw.plugin.json", import.meta.url), "utf8"));
  assert.deepEqual(manifest.contracts.tools, [
    "rightout_live_scan",
    "rightout_direct_rescan",
    "rightout_submit_removal",
    "rightout_submit_form_removal",
    "rightout_poll_verification",
    "rightout_poll_controller_reply",
    "rightout_open_verification",
    "rightout_rotate_state_key",
    "rightout_purge_subject_state",
    "rightout_record_controller_outcome",
    "rightout_create_evidence_snapshot",
    "rightout_evidence_status",
    "rightout_export_evidence",
    "rightout_custom_target_status",
    "rightout_effectiveness",
    "rightout_team_session_binding",
    "rightout_team_overview",
    "rightout_export_dashboard",
    "rightout_reconcile_submission",
    "rightout_next_actions",
    "rightout_case_status",
    "rightout_export_report",
    "rightout_catalog_health",
    "rightout_setup",
    "rightout_doctor",
    "rightout_due_rechecks",
    "rightout_start_campaign",
    "rightout_campaign_status",
    "rightout_campaign_next",
    "rightout_worker_enable",
    "rightout_worker_status",
    "rightout_worker_tick",
    "rightout_worker_complete",
    "rightout_worker_resume",
    "rightout_worker_revoke",
    "rightout_revoke_campaign",
    "rightout_refresh_registries",
    "rightout_registry_status",
    "rightout_record_drop_filed",
    "rightout_registry_search",
    "rightout_unbroker_parity_health",
    "rightout_refresh_parity_sources",
    "rightout_submit_parity_email",
    "rightout_begin_webmail_session",
    "rightout_webmail_session_step",
    "rightout_begin_webmail_verification",
    "rightout_begin_discovery_session",
    "rightout_discovery_session_step",
    "rightout_begin_form_session",
    "rightout_form_session_step",
  ]);
  assert.deepEqual(manifest.activation, { onStartup: false });
  assert.equal(manifest.toolMetadata.rightout_live_scan.optional, true);
  assert.equal(manifest.toolMetadata.rightout_live_scan.replaySafe, false);
  assert.equal(manifest.toolMetadata.rightout_submit_removal.optional, true);
  assert.equal(manifest.toolMetadata.rightout_submit_removal.replaySafe, false);
  assert.equal(manifest.toolMetadata.rightout_submit_form_removal.optional, true);
  assert.equal(manifest.toolMetadata.rightout_submit_form_removal.replaySafe, false);
  for (const name of ["rightout_direct_rescan", "rightout_poll_verification", "rightout_poll_controller_reply", "rightout_open_verification", "rightout_purge_subject_state", "rightout_record_controller_outcome", "rightout_create_evidence_snapshot", "rightout_export_evidence", "rightout_export_dashboard", "rightout_reconcile_submission", "rightout_rotate_state_key", "rightout_start_campaign", "rightout_worker_enable", "rightout_worker_tick", "rightout_worker_complete", "rightout_worker_resume", "rightout_worker_revoke", "rightout_revoke_campaign", "rightout_refresh_registries", "rightout_refresh_parity_sources", "rightout_record_drop_filed", "rightout_submit_parity_email", "rightout_begin_webmail_session", "rightout_webmail_session_step", "rightout_begin_webmail_verification", "rightout_begin_discovery_session", "rightout_discovery_session_step", "rightout_begin_form_session", "rightout_form_session_step"]) {
    assert.equal(manifest.toolMetadata[name].optional, true);
    assert.equal(manifest.toolMetadata[name].replaySafe, false);
  }
  for (const name of ["rightout_next_actions", "rightout_case_status", "rightout_export_report", "rightout_catalog_health", "rightout_setup", "rightout_doctor", "rightout_due_rechecks", "rightout_campaign_status", "rightout_campaign_next", "rightout_worker_status", "rightout_registry_status", "rightout_registry_search", "rightout_unbroker_parity_health", "rightout_evidence_status", "rightout_custom_target_status", "rightout_effectiveness", "rightout_team_session_binding", "rightout_team_overview"]) {
    assert.equal(manifest.toolMetadata[name].optional, true);
    assert.equal(manifest.toolMetadata[name].replaySafe, true);
  }
  assert.equal(manifest.toolMetadata.rightout_setup.configSignals, undefined);
  assert.equal(manifest.toolMetadata.rightout_campaign_next.configSignals, undefined);
  const secretPaths = manifest.configContracts.secretInputs.paths.map((item) => item.path);
  assert.deepEqual(secretPaths, [
    "braveApiKey",
    "profiles.*.payload",
    "smtpTransport.username",
    "smtpTransport.password",
    "smtpTransport.oauthAccessToken",
    "smtpTransport.fromAddress",
    "imapTransport.username",
    "imapTransport.password",
    "imapTransport.oauthAccessToken",
    "imapTransport.address",
    "stateEncryptionKey",
    "previousStateEncryptionKeys.*",
    "browserControlToken",
  ]);
  assert.ok(manifest.toolMetadata.rightout_live_scan.configSignals[0].required.includes("operatorAttestations"));
  assert.equal(manifest.configSchema.properties.operatorAttestations.properties.authorizedBrokerIds.maxItems, 100);
  assert.ok(manifest.toolMetadata.rightout_direct_rescan.configSignals[0].required.includes("publisherAutomationPermissions"));
  assert.ok(manifest.toolMetadata.rightout_refresh_parity_sources.configSignals[0].required.includes("publisherAutomationPermissions"));
  assert.ok(manifest.toolMetadata.rightout_begin_discovery_session.configSignals[0].required.includes("publisherAutomationPermissions"));
  assert.ok(manifest.toolMetadata.rightout_discovery_session_step.configSignals[0].required.includes("publisherAutomationPermissions"));
  assert.ok(manifest.toolMetadata.rightout_begin_form_session.configSignals[0].required.includes("formAttestations"));
  assert.ok(manifest.toolMetadata.rightout_form_session_step.configSignals[0].required.includes("formAttestations"));
  assert.deepEqual(manifest.toolMetadata.rightout_submit_removal.configSignals[0].required, [
    "smtpTransport",
    "stateEncryptionKey",
    "profiles",
    "removalAttestations",
  ]);
  assert.deepEqual(manifest.configSchema.properties.operatorAttestations.required, [
    "braveTermsAccepted",
    "braveTermsVersion",
    "braveCustomerResponsibilitiesAccepted",
    "subjectConsentReviewed",
    "authorizedProfileIds",
    "authorizedProfileDigests",
    "authorizedBrokerIds",
  ]);
  assert.deepEqual(manifest.configSchema.properties.braveApiKey.type, ["string", "object"]);
  assert.deepEqual(
    manifest.configSchema.properties.profiles.additionalProperties.properties.payload.type,
    ["string", "object"],
  );
  assert.equal(manifest.configSchema.properties.removalAttestations.properties.rightoutRemovalPolicyVersion.const, "2026-07-12-eu1");
  assert.deepEqual(
    manifest.configSchema.properties.removalAttestations.properties.authorizedRequestKinds.items.enum,
    ["delete_and_opt_out", "gdpr_erasure_objection"],
  );
  assert.deepEqual(manifest.skills, ["./skills"]);
  assert.deepEqual(manifest.configSchema.properties.teamAccess.additionalProperties.properties.role.enum, ["owner", "manager", "viewer"]);
  assert.equal(manifest.configSchema.properties.effectivenessCanaries.additionalProperties.maxItems, 500);
});

test("runtime hook requires allow-once or deny and fails closed", async () => {
  const plugin = (await import("../../index.ts")).default;
  const hooks = new Map();
  const tools = [];
  let auditCollector;
  const configuredPluginConfig = {
    stateEncryptionKey: "dummy-state-key-with-more-than-32-characters",
    braveApiKey: "dummy-test-key",
    profiles: { [toolInput.profileId]: { payload: profilePayload } },
    operatorAttestations: structuredClone(operatorAttestations),
  };
  plugin.register({
    runtime: fakeRuntime(),
    on(name, handler) {
      hooks.set(name, handler);
    },
    registerTool(tool, options) {
      const resolved = typeof tool === "function"
        ? tool({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } })
        : tool;
      tools.push({ tool: resolved, options });
    },
    registerSecurityAuditCollector(collector) {
      auditCollector = collector;
    },
    pluginConfig: configuredPluginConfig,
    resolvePath(value) {
      return value;
    },
  });
  assert.equal(tools.length, 50);
  assert.equal(tools[0].tool.name, "rightout_live_scan");
  assert.equal(tools[1].tool.name, "rightout_direct_rescan");
  assert.equal(tools[2].tool.name, "rightout_submit_removal");
  const manifest = JSON.parse(await readFile(new URL("../../openclaw.plugin.json", import.meta.url), "utf8"));
  assert.deepEqual(tools.map(({ tool }) => tool.name).sort(), [...manifest.contracts.tools].sort());
  assert.deepEqual(tools[0].options, { name: "rightout_live_scan", optional: true });
  const healthTool = tools.find(({ tool }) => tool.name === "rightout_catalog_health").tool;
  const health = await healthTool.execute("catalog-health", {});
  assert.equal(health.details.network_requests, 0);
  assert.equal(health.details.catalog_entries, 56);
  assert.equal(health.details.summary.stale, 0);
  assert.equal(health.details.live_provider_io_allowed, true);
  const decision = await hooks.get("before_tool_call")({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-approved" });
  assert.deepEqual(decision.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  assert.equal(decision.requireApproval.timeoutMs, 120_000);
  assert.equal(Object.hasOwn(decision.requireApproval, "timeoutBehavior"), false);
  assert.equal(decision.requireApproval.severity, "critical");
  assert.deepEqual(decision.params, toolInput);
  assert.match(decision.requireApproval.description, new RegExp(toolInput.profileId));
  assert.match(decision.requireApproval.description, /truepeoplesearch/);
  assert.doesNotMatch(decision.requireApproval.description, /Avery|Exampleville/);
  const publicSchema = JSON.stringify(tools[0].tool.parameters);
  assert.doesNotMatch(publicSchema, /fullName|city|region|country/);
  assert.match(publicSchema, /profileId/);

  const unsafe = await auditCollector({
    config: {},
    sourceConfig: {
      plugins: { entries: { rightout: { config: {
        braveApiKey: "plaintext-key",
        profiles: { [toolInput.profileId]: { payload: JSON.stringify(privateProfile) } },
      } } } },
    },
  });
  assert.deepEqual(unsafe.map((item) => item.severity), ["critical", "critical", "critical", "critical", "warn"]);

  const safe = await auditCollector({
    config: { gateway: { tools: { deny: [
      "rightout_live_scan",
      "rightout_submit_removal",
      "rightout_submit_form_removal",
      "rightout_poll_verification",
      "rightout_poll_controller_reply",
      "rightout_open_verification",
      "rightout_direct_rescan",
      "rightout_purge_subject_state",
      "rightout_record_controller_outcome",
      "rightout_create_evidence_snapshot",
      "rightout_export_evidence",
      "rightout_export_dashboard",
      "rightout_reconcile_submission",
      "rightout_rotate_state_key",
      "rightout_start_campaign",
      "rightout_revoke_campaign",
      "rightout_refresh_registries",
      "rightout_refresh_parity_sources",
      "rightout_record_drop_filed",
      "rightout_submit_parity_email",
      "rightout_begin_webmail_session",
      "rightout_webmail_session_step",
      "rightout_begin_webmail_verification",
      "rightout_begin_discovery_session",
      "rightout_discovery_session_step",
      "rightout_begin_form_session",
      "rightout_form_session_step",
      "rightout_worker_enable",
      "rightout_worker_tick",
      "rightout_worker_complete",
      "rightout_worker_resume",
      "rightout_worker_revoke",
    ] } } },
    sourceConfig: {
      plugins: { entries: { rightout: { config: {
        braveApiKey: { source: "env", provider: "default", id: "RIGHTOUT_BRAVE_KEY" },
        stateEncryptionKey: { source: "env", provider: "default", id: "RIGHTOUT_STATE_KEY" },
        profiles: { [toolInput.profileId]: { payload: { source: "file", provider: "profiles", id: "/subject" } } },
        operatorAttestations: structuredClone(operatorAttestations),
      } } } },
    },
  });
  assert.deepEqual(safe, []);

  const unsafeTeamBoundary = await auditCollector({
    config: {},
    sourceConfig: {
      plugins: { entries: { rightout: { config: {
        braveApiKey: { source: "env", provider: "default", id: "RIGHTOUT_BRAVE_KEY" },
        stateEncryptionKey: { source: "env", provider: "default", id: "RIGHTOUT_STATE_KEY" },
        profiles: { [toolInput.profileId]: { payload: { source: "file", provider: "profiles", id: "/subject" } } },
        operatorAttestations: structuredClone(operatorAttestations),
        teamAccess: {
          member_0123456789abcdef: {
            role: "owner",
            sessionBindingDigest: "a".repeat(64),
            authorizedProfileIds: [toolInput.profileId],
          },
        },
      } } } },
    },
  });
  assert.ok(unsafeTeamBoundary.some((item) => item.checkId === "rightout.team_access.gateway_boundary" && item.severity === "critical"));

  const missingId = await hooks.get("before_tool_call")({ toolName: "rightout_live_scan", params: toolInput });
  assert.equal(missingId.block, true);
  const invalid = await hooks.get("before_tool_call")({ toolName: "rightout_live_scan", params: { ...toolInput, brokerIds: ["../escape"] }, toolCallId: "call-invalid" });
  assert.equal(invalid.block, true);
  decision.requireApproval.onResolution("deny");
  await assert.rejects(tools[0].tool.execute("call-approved", toolInput), /rightout_approval_binding_failed/);

  const bound = await hooks.get("before_tool_call")({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-bound" });
  bound.requireApproval.onResolution("allow-once");
  await assert.rejects(
    tools[0].tool.execute("call-bound", { ...toolInput, profileId: "profile_ffffffffffffffff" }),
    /rightout_approval_binding_failed/,
  );

  const exact = await hooks.get("before_tool_call")({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-exact" });
  exact.requireApproval.onResolution("allow-once");
  const cancelled = new AbortController();
  cancelled.abort();
  await assert.rejects(
    tools[0].tool.execute("call-exact", toolInput, cancelled.signal),
    /rightout_scan_cancelled/,
  );
  await assert.rejects(
    tools[0].tool.execute("call-exact", toolInput, cancelled.signal),
    /rightout_approval_binding_failed/,
  );

  const revoked = await hooks.get("before_tool_call")({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-revoked" });
  revoked.requireApproval.onResolution("allow-once");
  configuredPluginConfig.operatorAttestations.authorizedBrokerIds = ["truepeoplesearch", "otherbroker"];
  await assert.rejects(
    tools[0].tool.execute("call-revoked", toolInput),
    /rightout_approval_binding_failed/,
  );
  configuredPluginConfig.operatorAttestations.authorizedBrokerIds = ["truepeoplesearch"];

  const snapshotBound = await hooks.get("before_tool_call")({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-profile-snapshot" });
  snapshotBound.requireApproval.onResolution("allow-once");
  configuredPluginConfig.profiles[toolInput.profileId].payload = JSON.stringify({ ...privateProfile, fullName: "Changed Example" });
  await assert.rejects(
    tools[0].tool.execute("call-profile-snapshot", toolInput),
    /rightout_profile_snapshot_changed/,
  );
  configuredPluginConfig.profiles[toolInput.profileId].payload = profilePayload;

  const freshnessBound = await hooks.get("before_tool_call")({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-freshness-drift" });
  freshnessBound.requireApproval.onResolution("allow-once");
  const realDateNow = Date.now;
  Date.now = () => Date.parse("2027-12-31T00:00:00.000Z");
  try {
    await assert.rejects(
      tools[0].tool.execute("call-freshness-drift", toolInput),
      /rightout_catalog_lane_stale/,
    );
  } finally {
    Date.now = realDateNow;
  }

  let unattestedHook;
  plugin.register({
    runtime: fakeRuntime(),
    on(name, handler) { if (name === "before_tool_call") unattestedHook = handler; },
    registerTool() {},
    registerSecurityAuditCollector() {},
    pluginConfig: {
      braveApiKey: "dummy-test-key",
      stateEncryptionKey: "dummy-state-key-with-more-than-32-characters",
      profiles: { [toolInput.profileId]: { payload: JSON.stringify(privateProfile) } },
    },
    resolvePath(value) { return value; },
  });
  const unattested = await unattestedHook({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-unattested" });
  assert.equal(unattested.block, true);
  assert.match(unattested.blockReason, /unattested/);

  let missingStateHook;
  plugin.register({
    runtime: fakeRuntime(),
    on(name, handler) { if (name === "before_tool_call") missingStateHook = handler; },
    registerTool() {}, registerSecurityAuditCollector() {},
    pluginConfig: {
      braveApiKey: "dummy-test-key",
      profiles: { [toolInput.profileId]: { payload: profilePayload } },
      operatorAttestations: structuredClone(operatorAttestations),
    },
    resolvePath(value) { return value; },
  });
  const missingState = await missingStateHook({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-missing-state" });
  assert.ok(missingState.requireApproval, "state encryption secret must not be read before approval");
  missingState.requireApproval.onResolution("allow-once");

  let unconfiguredTool;
  plugin.register({
    runtime: fakeRuntime(),
    on() {},
    registerTool(tool) {
      const resolved = typeof tool === "function" ? tool({}) : tool;
      if (resolved.name === "rightout_live_scan") unconfiguredTool = resolved;
    },
    registerSecurityAuditCollector() {},
    pluginConfig: {},
    resolvePath(value) { return value; },
  });
  await assert.rejects(
    unconfiguredTool.execute("call-unconfigured", toolInput),
    /rightout_approval_binding_failed/,
  );
});
