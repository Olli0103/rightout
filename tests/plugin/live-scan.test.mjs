import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  __test,
  approvalDescription,
  runLiveScan,
  validateLiveScanInput,
} from "../../lib/live-scan.mjs";

const privateProfile = {
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
};

const toolInput = {
  profileId: "profile_a1b2c3d4e5f60718",
  brokerIds: ["truepeoplesearch"],
};

const operatorAttestations = {
  braveTermsAccepted: true,
  braveTermsVersion: "2026-02-11",
  braveCustomerResponsibilitiesAccepted: true,
  authorizedProfileIds: [toolInput.profileId],
  authorizedBrokerIds: ["truepeoplesearch"],
};

const scanInput = {
  ...toolInput,
  subject: JSON.stringify(privateProfile),
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
  assert.match(text, /name\+city\+region\+country/);
  assert.match(text, /logs <=90d unless ZDR/);
  assert.match(text, /terms 2026-02-11/);
  assert.match(text, /duties attested/);
  assert.match(text, /No broker fetch\/write\/email; RightOut stores none/);
  assert.doesNotMatch(text, /Avery|Exampleville|CA/);
  assert.ok(text.length <= 256);
  const maximumScopeText = approvalDescription({
    profileId: `profile_${"a".repeat(32)}`,
    brokerIds: ["a".repeat(24), "b".repeat(24)],
  });
  assert.ok(maximumScopeText.length <= 256, maximumScopeText);
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
  assert.throws(() => validateLiveScanInput({ ...scanInput, subject: JSON.stringify({ ...privateProfile, email: "x@example.invalid" }) }), /profile_invalid/);
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
    local_pii_storage: 0,
    search_result_storage: 0,
    raw_pii_in_report: false,
    raw_response_content_in_report: false,
    candidate_urls_in_report: false,
  });
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
    { ...operatorAttestations, authorizedProfileIds: ["profile_ffffffffffffffff"] },
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

test("plugin manifest declares an optional non-replay-safe secret-backed tool", async () => {
  const manifest = JSON.parse(await readFile(new URL("../../openclaw.plugin.json", import.meta.url), "utf8"));
  assert.deepEqual(manifest.contracts.tools, ["rightout_live_scan"]);
  assert.equal(manifest.toolMetadata.rightout_live_scan.optional, true);
  assert.equal(manifest.toolMetadata.rightout_live_scan.replaySafe, false);
  assert.equal(manifest.configContracts.secretInputs.paths[0].path, "braveApiKey");
  assert.equal(manifest.configContracts.secretInputs.paths[1].path, "profiles.*.payload");
  assert.ok(manifest.toolMetadata.rightout_live_scan.configSignals[0].required.includes("operatorAttestations"));
  assert.deepEqual(manifest.configSchema.properties.operatorAttestations.required, [
    "braveTermsAccepted",
    "braveTermsVersion",
    "braveCustomerResponsibilitiesAccepted",
    "authorizedProfileIds",
    "authorizedBrokerIds",
  ]);
  assert.deepEqual(manifest.configSchema.properties.braveApiKey.type, ["string", "object"]);
  assert.deepEqual(
    manifest.configSchema.properties.profiles.additionalProperties.properties.payload.type,
    ["string", "object"],
  );
  assert.deepEqual(manifest.skills, ["./skills"]);
});

test("runtime hook requires allow-once or deny and fails closed", async () => {
  const plugin = (await import("../../index.ts")).default;
  const hooks = new Map();
  const tools = [];
  let auditCollector;
  const configuredPluginConfig = {
    braveApiKey: "dummy-test-key",
    profiles: { [toolInput.profileId]: { payload: JSON.stringify(privateProfile) } },
    operatorAttestations: {
      braveTermsAccepted: true,
      braveTermsVersion: "2026-02-11",
      braveCustomerResponsibilitiesAccepted: true,
      authorizedProfileIds: [toolInput.profileId],
      authorizedBrokerIds: ["truepeoplesearch"],
    },
  };
  plugin.register({
    on(name, handler) {
      hooks.set(name, handler);
    },
    registerTool(tool, options) {
      tools.push({ tool, options });
    },
    registerSecurityAuditCollector(collector) {
      auditCollector = collector;
    },
    pluginConfig: configuredPluginConfig,
    resolvePath(value) {
      return value;
    },
  });
  assert.equal(tools.length, 1);
  assert.equal(tools[0].tool.name, "rightout_live_scan");
  assert.deepEqual(tools[0].options, { optional: true });
  const decision = await hooks.get("before_tool_call")({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-approved" });
  assert.deepEqual(decision.requireApproval.allowedDecisions, ["allow-once", "deny"]);
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
  assert.deepEqual(unsafe.map((item) => item.severity), ["critical", "critical", "critical", "warn"]);

  const safe = await auditCollector({
    config: { gateway: { tools: { deny: ["rightout_live_scan"] } } },
    sourceConfig: {
      plugins: { entries: { rightout: { config: {
        braveApiKey: { source: "env", provider: "default", id: "RIGHTOUT_BRAVE_KEY" },
        profiles: { [toolInput.profileId]: { payload: { source: "file", provider: "profiles", id: "/subject" } } },
        operatorAttestations: {
          braveTermsAccepted: true,
          braveTermsVersion: "2026-02-11",
          braveCustomerResponsibilitiesAccepted: true,
          authorizedProfileIds: [toolInput.profileId],
          authorizedBrokerIds: ["truepeoplesearch"],
        },
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

  let unattestedHook;
  plugin.register({
    on(_name, handler) { unattestedHook = handler; },
    registerTool() {},
    registerSecurityAuditCollector() {},
    pluginConfig: {
      braveApiKey: "dummy-test-key",
      profiles: { [toolInput.profileId]: { payload: JSON.stringify(privateProfile) } },
    },
    resolvePath(value) { return value; },
  });
  const unattested = await unattestedHook({ toolName: "rightout_live_scan", params: toolInput, toolCallId: "call-unattested" });
  assert.equal(unattested.block, true);
  assert.match(unattested.blockReason, /unattested/);

  let unconfiguredTool;
  plugin.register({
    on() {},
    registerTool(tool) { unconfiguredTool = tool; },
    registerSecurityAuditCollector() {},
    pluginConfig: {},
    resolvePath(value) { return value; },
  });
  await assert.rejects(
    unconfiguredTool.execute("call-unconfigured", toolInput),
    /rightout_approval_binding_failed/,
  );
});
