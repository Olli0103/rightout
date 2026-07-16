import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { assertParityCatalogFresh, parityCatalogHealth, resolveParityBroker, validateParityCatalog } from "../../lib/parity-catalog.mjs";

const catalog = JSON.parse(await readFile("skills/data-broker-removal/references/brokers/unbroker-parity.json", "utf8"));

test("normalized Unbroker broker/method/route/input surface is exact", () => {
  const clean = validateParityCatalog(catalog);
  assert.equal(clean.health.broker_count, 22);
  assert.deepEqual(clean.health.methods, { web_form: 20, email: 1, phone: 1 });
  assert.deepEqual(clean.health.source_blockers, []);
  assert.deepEqual(clean.health.externally_unavailable_routes, ["clustrmaps", "peekyou"]);
  assert.deepEqual(clean.health.equivalent_outcome_gaps, []);
  assert.equal(clean.health.release_ready, true);
  assert.equal(clean.schema_version, 2);
  assert.equal(clean.brokers.every((route) => (
    JSON.stringify(route.execution_jurisdictions) === JSON.stringify(["US", "US-CA"])
    && JSON.stringify(route.execution_market_ids) === JSON.stringify(["us_california", "us_other"])
    && route.provider_request_contract === "us_provider_delete_opt_out_v1"
  )), true);
  assert.equal(resolveParityBroker(catalog, "rehold").action_url, "https://rehold.com/control/privacy");
  assert.equal(resolveParityBroker(catalog, "peekyou").source_status, "observed_official_archive_external_unavailable");
  assert.equal(resolveParityBroker(catalog, "peekyou").rescue_email, "ccpa@peekyou.com");
  assert.deepEqual(resolveParityBroker(catalog, "peekyou").rescue_disclosure_fields, ["full_name", "contact_email"]);
});

test("parity catalog rejects count substitution, foreign domains, and unapproved fields", () => {
  const missing = structuredClone(catalog);
  missing.brokers.pop();
  assert.throws(() => validateParityCatalog(missing), /rightout_parity_catalog_invalid/);

  const foreign = structuredClone(catalog);
  foreign.brokers[0].action_url = "https://example.com/collect";
  assert.throws(() => validateParityCatalog(foreign), /rightout_parity_catalog_invalid/);

  const field = structuredClone(catalog);
  field.brokers[0].disclosure_fields.push("government_id");
  assert.throws(() => validateParityCatalog(field), /rightout_parity_catalog_invalid/);

  const unsupportedRescueField = structuredClone(catalog);
  unsupportedRescueField.brokers.find((broker) => broker.id === "peekyou").rescue_disclosure_fields.push("street");
  assert.throws(() => validateParityCatalog(unsupportedRescueField), /rightout_parity_catalog_invalid/);

  const forgedExternalEvidence = structuredClone(catalog);
  forgedExternalEvidence.brokers.find((broker) => broker.id === "peekyou").source_evidence_url = "https://web.archive.org/web/20250426000851id_/https://example.com/optout/";
  assert.throws(() => validateParityCatalog(forgedExternalEvidence), /rightout_parity_catalog_invalid/);

  const reholdMethod = structuredClone(catalog);
  reholdMethod.brokers.find((broker) => broker.id === "rehold").current_contract.method = "email";
  assert.throws(() => validateParityCatalog(reholdMethod), /rightout_parity_catalog_invalid/);

  const reholdAction = structuredClone(catalog);
  reholdAction.brokers.find((broker) => broker.id === "rehold").current_contract.action_url = "https://rehold.com/optout";
  assert.throws(() => validateParityCatalog(reholdAction), /rightout_parity_catalog_invalid/);

  const reholdEvidence = structuredClone(catalog);
  reholdEvidence.brokers.find((broker) => broker.id === "rehold").current_contract.evidence[0].fact_scope = "generic_homepage";
  assert.throws(() => validateParityCatalog(reholdEvidence), /rightout_parity_catalog_invalid/);

  const missingMarket = structuredClone(catalog);
  delete missingMarket.brokers[0].execution_market_ids;
  assert.throws(() => validateParityCatalog(missingMarket), /rightout_parity_catalog_invalid/);

  const widenedJurisdiction = structuredClone(catalog);
  widenedJurisdiction.brokers[0].execution_jurisdictions.push("UK");
  assert.throws(() => validateParityCatalog(widenedJurisdiction), /rightout_parity_catalog_invalid/);

  const substitutedMarket = structuredClone(catalog);
  substitutedMarket.brokers[0].execution_market_ids = ["us_other"];
  assert.throws(() => validateParityCatalog(substitutedMarket), /rightout_parity_catalog_invalid/);
});

test("health separates normalized contract evidence from externally unavailable providers", () => {
  const health = parityCatalogHealth(catalog);
  assert.equal(health.release_ready, true);
  assert.deepEqual(health.source_blockers, []);
  assert.deepEqual(health.externally_unavailable_routes, ["clustrmaps", "peekyou"]);
  assert.equal(health.broker_ids.length, 22);
  const clustrMaps = health.broker_routes.find((row) => row.broker_id === "clustrmaps");
  assert.equal(clustrMaps.normalized_contract_evidence_complete, true);
  assert.equal(clustrMaps.route_technically_addressable_from_catalog, false);
  assert.equal(clustrMaps.primary_route_available, false);
  assert.equal(clustrMaps.autonomous_rescue_available, true);
  assert.equal(clustrMaps.equivalent_outcome_available, true);
  const spokeo = health.broker_routes.find((row) => row.broker_id === "spokeo");
  assert.equal(spokeo.route_technically_addressable_from_catalog, true);
  assert.equal(spokeo.autonomous_rescue_available, true);
  const intelius = health.broker_routes.find((row) => row.broker_id === "intelius");
  assert.equal(intelius.route_technically_addressable_from_catalog, true);
  assert.equal(intelius.explicit_human_only_gate, true);
  assert.equal(health.next_action, "run_normalized_contract_e2e");
});

test("one unrelated stale or future parity route globally closes health and live-route freshness", () => {
  const stale = structuredClone(catalog);
  stale.brokers.find((row) => row.id === "addresses").last_checked = "2026-01-01";
  const now = Date.parse("2026-07-13T12:00:00Z");
  const health = parityCatalogHealth(stale, { now, maxAgeDays: 180 });
  assert.equal(health.release_ready, false);
  assert.deepEqual(health.stale_routes, ["addresses"]);
  assert.throws(() => assertParityCatalogFresh(stale, { now, maxAgeDays: 180 }), /rightout_catalog_lane_stale/);

  const future = structuredClone(catalog);
  future.brokers.find((row) => row.id === "addresses").last_checked = "2026-12-31";
  assert.equal(parityCatalogHealth(future, { now }).release_ready, false);
  assert.throws(() => assertParityCatalogFresh(future, { now }), /rightout_catalog_lane_stale/);

  const invalid = structuredClone(catalog);
  invalid.brokers.find((row) => row.id === "addresses").last_checked = "2026-99-99";
  assert.throws(() => validateParityCatalog(invalid), /rightout_parity_catalog_invalid/);
});
