import assert from "node:assert/strict";
import test from "node:test";

import { assertFreshCatalogEntries, catalogPolicyHealth } from "../../lib/catalog-health.mjs";

const catalog = {
  brokers: [
    { id: "fresh_broker", last_verified: "2026-07-01", freshness_days: 90 },
    { id: "expiring_broker", last_verified: "2026-04-20", freshness_days: 90 },
    { id: "stale_broker", last_verified: "2026-01-01", freshness_days: 90 },
  ],
};

test("catalog health is deterministic, PII-free, and performs no network work", () => {
  const report = catalogPolicyHealth(catalog, { now: Date.parse("2026-07-12T00:00:00.000Z") });
  assert.deepEqual(report.summary, { fresh: 1, expiring: 1, stale: 1 });
  assert.equal(report.network_requests, 0);
  assert.equal(report.live_provider_io_allowed, false);
  assert.deepEqual(report.stale.map((entry) => entry.broker_id), ["stale_broker"]);
  assert.equal(JSON.stringify(report).includes("example@"), false);
});

test("live provider I/O fails closed for stale, missing, or malformed catalog facts", () => {
  const now = Date.parse("2026-07-12T00:00:00.000Z");
  const freshCatalog = { brokers: [catalog.brokers[0]] };
  assert.doesNotThrow(() => assertFreshCatalogEntries(freshCatalog, ["fresh_broker"], { now }));
  assert.throws(() => assertFreshCatalogEntries(catalog, ["fresh_broker"], { now }), /lane_stale/);
  assert.throws(() => assertFreshCatalogEntries(catalog, ["stale_broker"], { now }), /lane_stale/);
  assert.throws(() => assertFreshCatalogEntries(freshCatalog, ["missing_broker"], { now }), /lane_stale/);
  assert.throws(() => catalogPolicyHealth({ brokers: [{ id: "bad", last_verified: "2026-02-30", freshness_days: 90 }] }, { now }), /freshness_invalid/);
});
