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
        candidate_path_pattern: "^/find/person/(?:[A-Za-z0-9%._~-]+/){0,5}[A-Za-z0-9%._~-]+/?$",
        max_candidates: 3,
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
  assert.match(text, /name, city, region, country/);
  assert.match(text, /no storage, submission, email, or write/i);
  assert.doesNotMatch(text, /Avery|Exampleville|CA/);
  assert.ok(text.length <= 256);
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
  const report = await runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch });
  assert.equal(report.summary.not_found, 0);
  assert.equal(report.summary.inconclusive, 1);
  assert.equal(report.results[0].reason, "no_index_candidates_not_proof_of_absence");
  assert.equal(guardedFetch.calls[0].init.method, "POST");
  assert.deepEqual(guardedFetch.calls[0].allowedHosts, ["api.search.brave.com"]);
  assert.doesNotMatch(guardedFetch.calls[0].url, /Avery|Exampleville/);
});

test("query-free same-domain structured Person match yields opaque proof only", async () => {
  const bravePayload = {
    web: {
      results: [
        { url: "https://www.truepeoplesearch.com/find/person/opaque-record" },
        { url: "https://evil.invalid/Avery-Example" },
      ],
    },
  };
  const directHtml = `<html><script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Person",
    name: "Avery Example",
    address: { "@type": "PostalAddress", addressLocality: "Exampleville", addressRegion: "CA" },
  })}</script></html>`;
  const guardedFetch = mockGuardedFetch([
    { response: response(JSON.stringify(bravePayload), { headers: { "content-type": "application/json" } }) },
    {
      response: response(directHtml, { headers: { "content-type": "text/html; charset=utf-8" } }),
      finalUrl: "https://www.truepeoplesearch.com/find/person/opaque-record",
    },
  ]);
  const report = await runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch });
  assert.equal(report.results[0].state, "found");
  assert.match(report.results[0].proof_references[0], /^proof_[a-f0-9]{24}$/);
  assert.equal(guardedFetch.calls.length, 2);
  assert.deepEqual(guardedFetch.calls[1].allowedHosts, ["truepeoplesearch.com"]);
  assert.equal(guardedFetch.calls[1].url.includes("?"), false);
  const serialized = JSON.stringify(report);
  for (const secret of [privateProfile.fullName, privateProfile.city, privateProfile.region, "dummy-test-key", "opaque-record", directHtml]) {
    assert.equal(serialized.includes(secret), false, secret);
  }
  assert.deepEqual(report.invariants, {
    submissions: 0,
    emails: 0,
    provider_writes: 0,
    local_pii_storage: 0,
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
  const report = await runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch });
  assert.equal(guardedFetch.calls.length, 1);
  assert.equal(report.results[0].state, "inconclusive");
});

test("cross-domain final redirects fail closed even after an allowed candidate", async () => {
  const payload = { web: { results: [{ url: "https://truepeoplesearch.com/find/person/opaque" }] } };
  const guardedFetch = mockGuardedFetch([
    { response: response(JSON.stringify(payload), { headers: { "content-type": "application/json" } }) },
    {
      response: response("<p>Avery Example</p><p>Exampleville, CA</p>", { headers: { "content-type": "text/html" } }),
      finalUrl: "https://evil.invalid/find/person/opaque",
    },
  ]);
  const report = await runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch });
  assert.equal(report.results[0].state, "inconclusive");
  assert.equal(report.results[0].reason, "candidate_blocked");
  assert.equal(JSON.stringify(report).includes("evil.invalid"), false);
});

test("provider and candidate failures are sanitized", async () => {
  const authFetch = mockGuardedFetch([{ response: response("denied", { status: 401 }) }]);
  const authReport = await runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch: authFetch });
  assert.equal(authReport.results[0].reason, "provider_auth_failed");

  const payload = { web: { results: [{ url: "https://truepeoplesearch.com/find/person/opaque" }] } };
  const blockedFetch = mockGuardedFetch([
    { response: response(JSON.stringify(payload), { headers: { "content-type": "application/json" } }) },
    { response: response("blocked", { status: 403 }) },
  ]);
  const blockedReport = await runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch: blockedFetch });
  assert.equal(blockedReport.results[0].reason, "candidate_blocked");
  assert.equal(JSON.stringify(blockedReport).includes("blocked"), true);
  assert.equal(JSON.stringify(blockedReport).includes("find/person/opaque"), false);
});

test("unsupported catalog lanes cannot be scanned", async () => {
  const unsafeCatalog = { brokers: [{ ...catalog.brokers[0], category: "registry" }] };
  await assert.rejects(
    runLiveScan({ input: scanInput, catalog: unsafeCatalog, apiKey: "dummy-test-key", guardedFetch: mockGuardedFetch([]) }),
    /unsupported_broker/,
  );
});

test("candidate parsing and proof hashing are deterministic", () => {
  const candidates = __test.candidateUrls(
    { web: { results: [
      { url: "https://sub.truepeoplesearch.com/find/person/valid-record" },
      { url: "https://sub.truepeoplesearch.com/find/person/reflected?q=Avery" },
      { url: "https://sub.truepeoplesearch.com/find/person/fragment#Avery" },
      { url: "http://truepeoplesearch.com/find/person/bad" },
      { url: `https://truepeoplesearch.com/find/person/${"a".repeat(3_000)}` },
    ] } },
    ["truepeoplesearch.com"],
    2,
    catalog.brokers[0].scan.candidate_path_pattern,
  );
  assert.deepEqual(candidates, ["https://sub.truepeoplesearch.com/find/person/valid-record"]);
  const secretA = Buffer.alloc(32, 1);
  const secretB = Buffer.alloc(32, 2);
  assert.equal(__test.proofRef("truepeoplesearch", candidates[0], secretA), __test.proofRef("truepeoplesearch", candidates[0], secretA));
  assert.notEqual(__test.proofRef("truepeoplesearch", candidates[0], secretA), __test.proofRef("truepeoplesearch", candidates[0], secretB));
});

test("direct match requires one structured Person record with exact name and location", () => {
  const record = (value) => `<script type="application/ld+json">${JSON.stringify(value)}</script>`;
  assert.equal(
    __test.directPageMatches(record({
      "@type": "Person",
      name: "Avery Example",
      address: { addressLocality: "Exampleville", addressRegion: "CA" },
    }), privateProfile),
    true,
  );
  assert.equal(
    __test.directPageMatches("<h1>Avery Example</h1><p>Exampleville, CA</p>", privateProfile),
    false,
  );
  assert.equal(
    __test.directPageMatches(record({
      "@graph": [
        { "@type": "Person", name: "Avery Example", address: { addressLocality: "Elsewhere", addressRegion: "CA" } },
        { "@type": "Place", name: "Exampleville", address: { addressRegion: "CA" } },
      ],
    }), privateProfile),
    false,
  );
});

test("abort signal prevents and cancels outbound work", async () => {
  const preAborted = new AbortController();
  preAborted.abort();
  const neverCalled = mockGuardedFetch([]);
  await assert.rejects(
    runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch: neverCalled, signal: preAborted.signal }),
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
    runLiveScan({ input: scanInput, catalog, apiKey: "dummy-test-key", guardedFetch: abortingFetch, signal: midAbort.signal }),
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
    pluginConfig: {
      braveApiKey: "dummy-test-key",
      profiles: { [toolInput.profileId]: { payload: JSON.stringify(privateProfile) } },
    },
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
  assert.deepEqual(unsafe.map((item) => item.severity), ["critical", "critical", "warn"]);

  const safe = await auditCollector({
    config: { gateway: { tools: { deny: ["rightout_live_scan"] } } },
    sourceConfig: {
      plugins: { entries: { rightout: { config: {
        braveApiKey: { source: "env", provider: "default", id: "RIGHTOUT_BRAVE_KEY" },
        profiles: { [toolInput.profileId]: { payload: { source: "file", provider: "profiles", id: "/subject" } } },
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
