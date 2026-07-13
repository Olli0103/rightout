import assert from "node:assert/strict";
import test from "node:test";

import { refreshParitySources } from "../../lib/parity-source-refresh.mjs";

const catalog = {
  reference_commit: "a".repeat(40),
  health: { source_blockers: ["unknown"] },
  brokers: [
    { id: "ok", source_url: "https://ok.example/optout", official_domains: ["ok.example"], source_status: "observed_200" },
    { id: "blocked", source_url: "https://blocked.example/optout", official_domains: ["blocked.example"], source_status: "observed_403_antibot" },
    { id: "unknown", source_url: "https://unknown.example/optout", official_domains: ["unknown.example"], source_status: "needs_evidence" },
    { id: "restricted", source_url: "https://restricted.example/optout", official_domains: ["restricted.example"], source_status: "observed_200_terms_restrict_automation" },
    { id: "degraded", source_url: "https://degraded.example/optout", official_domains: ["degraded.example"], source_status: "observed_official_archive_external_unavailable" },
  ],
};

test("official parity source refresh is bounded, content-free, and never clears human source blockers", async () => {
  const calls = [];
  const report = await refreshParitySources({
    catalog,
    permissionForRoute: (route) => !["unknown", "restricted"].includes(route.id),
    guardedFetch: async (request) => {
      calls.push(request);
      if (request.url.includes("degraded")) throw new Error("still unavailable");
      const status = request.url.includes("blocked") ? 403 : 200;
      return { response: new Response("private page body", { status }), async release() {} };
    },
    now: () => new Date("2026-07-13T12:00:00.000Z"),
  });
  assert.equal(report.evaluated_routes, 5);
  assert.equal(report.probed_routes, 3);
  assert.equal(report.skipped_permission_required, 2);
  assert.equal(report.provider_reads, 2);
  assert.equal(report.provider_read_attempts, 3);
  assert.equal(report.provider_writes, 0);
  assert.equal(report.release_ready, false);
  assert.deepEqual(report.source_blockers, ["unknown"]);
  assert.ok(report.needs_review.includes("unknown"));
  assert.equal(report.results.find((item) => item.broker_id === "restricted").state, "not_probed_permission_required");
  assert.deepEqual(report.permission_required, ["restricted", "unknown"]);
  assert.equal(report.results.find((item) => item.broker_id === "degraded").state, "external_unavailable_reconfirmed");
  assert.equal(report.needs_review.includes("degraded"), false);
  assert.ok(calls.every((call) => call.maxRedirects === 0 && call.init.redirect === "manual"));
  assert.equal(JSON.stringify(report).includes("private page body"), false);
});

test("a previously unavailable route recovering is quarantined for contract review", async () => {
  const degraded = catalog.brokers.find((route) => route.id === "degraded");
  const report = await refreshParitySources({
    catalog: { ...catalog, health: { source_blockers: [] }, brokers: [degraded] },
    permissionForRoute: () => true,
    guardedFetch: async () => ({ response: new Response("new form", { status: 200 }), async release() {} }),
  });
  assert.deepEqual(report.needs_review, ["degraded"]);
  assert.equal(report.results[0].state, "external_route_recovered_needs_catalog_review");
  assert.equal(report.automatic_catalog_mutation, false);
});

test("redirects and transport failures are quarantined instead of changing the catalog", async () => {
  const report = await refreshParitySources({
    catalog: { ...catalog, health: { source_blockers: [] }, brokers: catalog.brokers.slice(0, 2) },
    permissionForRoute: () => true,
    guardedFetch: async ({ url }) => {
      if (url.includes("ok")) return { response: new Response(null, { status: 302 }), async release() {} };
      throw new Error("network detail must not escape");
    },
  });
  assert.deepEqual(report.needs_review, ["blocked", "ok"]);
  assert.equal(report.automatic_catalog_mutation, false);
});

test("publisher routes are never probed without a current written permission decision", async () => {
  let calls = 0;
  const report = await refreshParitySources({
    catalog: { ...catalog, health: { source_blockers: [] } },
    permissionForRoute: () => null,
    guardedFetch: async () => { calls += 1; throw new Error("must not run"); },
  });
  assert.equal(calls, 0);
  assert.equal(report.provider_reads, 0);
  assert.equal(report.provider_read_attempts, 0);
  assert.equal(report.probed_routes, 0);
  assert.equal(report.skipped_permission_required, 5);
  assert.deepEqual(report.permission_required, catalog.brokers.map((route) => route.id).sort());
  assert.ok(report.results.every((item) => item.state === "not_probed_permission_required"));
});
