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

test("input validation accepts only opaque refs and a private US profile", () => {
  assert.deepEqual(validateLiveScanInput(scanInput), {
    profileId: toolInput.profileId,
    subject: privateProfile,
    brokerIds: toolInput.brokerIds,
  });
  assert.throws(
    () => validateLiveScanInput({ ...scanInput, subject: JSON.stringify({ ...privateProfile, country: "DE" }) }),
    /unsupported_country/,
  );
  assert.throws(() => validateLiveScanInput({ ...scanInput, profileId: "Avery Example" }), /invalid_profile_ref/);
  assert.throws(() => validateLiveScanInput({ ...scanInput, brokerIds: ["../escape"] }), /invalid_broker_ids/);
  assert.throws(() => validateLiveScanInput({ ...scanInput, subject: JSON.stringify({ ...privateProfile, dateOfBirth: "2000-01-01" }) }), /profile_invalid/);
  for (const consent of [
    undefined,
    { ...privateProfile.consent, authorized: false },
    { ...privateProfile.consent, scope: ["broker_removal"] },
    { ...privateProfile.consent, recordedAt: "2999-01-01T00:00:00.000Z" },
    { ...privateProfile.consent, validUntil: "2000-01-01T00:00:00.000Z" },
    { ...privateProfile.consent, validUntil: new Date(Date.parse(privateProfile.consent.recordedAt) + 366 * 24 * 60 * 60_000).toISOString() },
  ]) {
    assert.throws(
      () => validateLiveScanInput({ ...scanInput, subject: JSON.stringify({ ...privateProfile, consent }) }),
      /subject_consent_required/,
    );
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
    encrypted_candidate_url_tokens_created: 0,
    raw_pii_in_report: false,
    raw_response_content_in_report: false,
    candidate_urls_in_report: false,
  });
});

test("candidate URLs are passed only to the host vault and represented by an opaque handle", async () => {
  const url = "https://www.truepeoplesearch.com/find/person/private-record";
  const guardedFetch = mockGuardedFetch([{
    response: response(JSON.stringify({ web: { results: [{ url }] } }), { headers: { "content-type": "application/json" } }),
  }]);
  let stored;
  const report = await runLiveScan({
    input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch, operatorAttestations,
    async storeCandidate(value) { stored = value; return "listing_1234567890abcdef12345678"; },
  });
  assert.deepEqual(stored.urls, [url]);
  assert.equal(report.results[0].listing_handle, "listing_1234567890abcdef12345678");
  assert.equal(report.invariants.encrypted_candidate_url_tokens_created, 1);
  assert.equal(JSON.stringify(report).includes("private-record"), false);
  assert.equal(JSON.stringify(report).includes("https://"), false);
});

test("all configured vectors are evaluated and distinct candidate URLs share one encrypted handle", async () => {
  const value = { ...privateProfile, emails: ["avery.old@example.invalid"] };
  const payload = JSON.stringify(value);
  const guardedFetch = mockGuardedFetch([
    { response: response(JSON.stringify({ web: { results: [{ url: "https://www.truepeoplesearch.com/a/record-one" }] } })) },
    { response: response(JSON.stringify({ web: { results: [{ url: "https://www.truepeoplesearch.com/b/record-two" }] } })) },
  ]);
  let stored;
  const report = await runLiveScan({
    input: { ...toolInput, subject: payload }, catalog, apiKey: "dummy-test-key", guardedFetch,
    operatorAttestations: { ...operatorAttestations, authorizedProfileDigests: { [toolInput.profileId]: scanProfileDigest(payload) } },
    async storeCandidate(candidate) { stored = candidate; return "listing_1234567890abcdef12345678"; },
  });
  assert.equal(guardedFetch.calls.length, 2);
  assert.deepEqual(stored.urls, [
    "https://www.truepeoplesearch.com/a/record-one",
    "https://www.truepeoplesearch.com/b/record-two",
  ]);
  assert.equal(JSON.stringify(report).includes("record-one"), false);
  assert.equal(JSON.stringify(report).includes("record-two"), false);
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

test("plugin manifest declares separate optional non-replay-safe scan and removal tools", async () => {
  const manifest = JSON.parse(await readFile(new URL("../../openclaw.plugin.json", import.meta.url), "utf8"));
  assert.deepEqual(manifest.contracts.tools, [
    "rightout_live_scan",
    "rightout_direct_rescan",
    "rightout_submit_removal",
    "rightout_submit_form_removal",
    "rightout_poll_verification",
    "rightout_open_verification",
    "rightout_purge_subject_state",
    "rightout_record_controller_outcome",
    "rightout_reconcile_submission",
    "rightout_next_actions",
    "rightout_case_status",
    "rightout_due_rechecks",
  ]);
  assert.deepEqual(manifest.activation, { onStartup: false });
  assert.equal(manifest.toolMetadata.rightout_live_scan.optional, true);
  assert.equal(manifest.toolMetadata.rightout_live_scan.replaySafe, false);
  assert.equal(manifest.toolMetadata.rightout_submit_removal.optional, true);
  assert.equal(manifest.toolMetadata.rightout_submit_removal.replaySafe, false);
  assert.equal(manifest.toolMetadata.rightout_submit_form_removal.optional, true);
  assert.equal(manifest.toolMetadata.rightout_submit_form_removal.replaySafe, false);
  for (const name of ["rightout_direct_rescan", "rightout_poll_verification", "rightout_open_verification", "rightout_purge_subject_state", "rightout_record_controller_outcome", "rightout_reconcile_submission"]) {
    assert.equal(manifest.toolMetadata[name].optional, true);
    assert.equal(manifest.toolMetadata[name].replaySafe, false);
  }
  for (const name of ["rightout_next_actions", "rightout_case_status", "rightout_due_rechecks"]) {
    assert.equal(manifest.toolMetadata[name].optional, true);
    assert.equal(manifest.toolMetadata[name].replaySafe, true);
  }
  const secretPaths = manifest.configContracts.secretInputs.paths.map((item) => item.path);
  assert.deepEqual(secretPaths, [
    "braveApiKey",
    "profiles.*.payload",
    "smtpTransport.username",
    "smtpTransport.password",
    "smtpTransport.fromAddress",
    "imapTransport.username",
    "imapTransport.password",
    "imapTransport.address",
    "stateEncryptionKey",
  ]);
  assert.ok(manifest.toolMetadata.rightout_live_scan.configSignals[0].required.includes("operatorAttestations"));
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
  assert.equal(tools.length, 12);
  assert.equal(tools[0].tool.name, "rightout_live_scan");
  assert.equal(tools[1].tool.name, "rightout_direct_rescan");
  assert.equal(tools[2].tool.name, "rightout_submit_removal");
  assert.deepEqual(tools.slice(3).map(({ tool }) => tool.name), [
    "rightout_submit_form_removal",
    "rightout_poll_verification",
    "rightout_open_verification",
    "rightout_purge_subject_state",
    "rightout_record_controller_outcome",
    "rightout_reconcile_submission",
    "rightout_next_actions",
    "rightout_case_status",
    "rightout_due_rechecks",
  ]);
  assert.deepEqual(tools[0].options, { optional: true });
  const decision = await hooks.get("before_tool_call")({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-approved" });
  assert.deepEqual(decision.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  assert.equal(decision.requireApproval.timeoutMs, 120_000);
  assert.equal(decision.requireApproval.timeoutBehavior, "deny");
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
      "rightout_open_verification",
      "rightout_direct_rescan",
      "rightout_purge_subject_state",
      "rightout_record_controller_outcome",
      "rightout_reconcile_submission",
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
    /rightout_scan_profile_snapshot_changed/,
  );
  configuredPluginConfig.profiles[toolInput.profileId].payload = profilePayload;

  let unattestedHook;
  plugin.register({
    runtime: fakeRuntime(),
    on(_name, handler) { unattestedHook = handler; },
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
    on(_name, handler) { missingStateHook = handler; },
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
    registerTool(tool) { if (tool.name === "rightout_live_scan") unconfiguredTool = tool; },
    registerSecurityAuditCollector() {},
    pluginConfig: {},
    resolvePath(value) { return value; },
  });
  await assert.rejects(
    unconfiguredTool.execute("call-unconfigured", toolInput),
    /rightout_approval_binding_failed/,
  );
});
