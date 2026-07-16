import assert from "node:assert/strict";
import test from "node:test";

import {
  assertMarketRouteExecution,
  assertMarketRightsExecution,
  assertProfileEligibleForMarketRoute,
  marketIdsForJurisdictions,
  marketPolicyDigest,
  marketPolicyHealth,
  marketPolicyOperatorHealth,
} from "../../lib/market-readiness.mjs";

test("market readiness is deterministic, PII-free, and separates discovery from rights execution", () => {
  const report = marketPolicyHealth({ now: Date.parse("2026-07-16T12:00:00.000Z") });
  assert.equal(report.market_count, 11);
  assert.equal(report.network_requests, 0);
  assert.equal(report.summary.current, 11);
  assert.equal(report.summary.rights_execution_core_markets, 3);
  assert.equal(report.summary.human_or_unsupported_markets, 8);
  assert.equal(report.markets.find((market) => market.market_id === "eu_eea").rightout_support.controller_request, "catalog_limited_18_email_routes");
  assert.equal(report.markets.find((market) => market.market_id === "uk").rightout_support.controller_request, "catalog_limited_1_uk_email_route");
  assert.equal(report.markets.find((market) => market.market_id === "us_california").rightout_support.gpc_preference, "human_verified_signal_record_only");
  assert.equal(report.markets.find((market) => market.market_id === "us_other").rightout_support.gpc_preference, "human_verified_signal_legal_effect_needs_market_evidence");
  assert.ok(report.cross_market_rules.includes("preference_signal_is_not_deletion_request_or_deletion_proof"));
  assert.equal(report.markets.every((market) => market.operational_authority === "diagnostic_only_not_authorization"), true);
  assert.doesNotMatch(JSON.stringify(report), /full_name|contact_email|street|postal|phone/);
  report.markets[0].rightout_support.controller_request = "tampered";
  assert.equal(
    marketPolicyHealth({ now: Date.parse("2026-07-16T12:00:00.000Z") }).markets[0].rightout_support.controller_request,
    "catalog_limited_18_email_routes",
  );
});

test("California DROP phase and source review are time-sensitive without automating identity", () => {
  const before = marketPolicyHealth({ now: Date.parse("2026-07-16T12:00:00.000Z") });
  const after = marketPolicyHealth({ now: Date.parse("2026-08-01T12:00:00.000Z") });
  const beforeCalifornia = before.markets.find((market) => market.market_id === "us_california");
  const afterCalifornia = after.markets.find((market) => market.market_id === "us_california");
  assert.equal(beforeCalifornia.drop_phase, "consumer_requests_open_broker_processing_not_started");
  assert.equal(afterCalifornia.drop_phase, "broker_processing_required");
  assert.equal(beforeCalifornia.safe_default, "drop_identity_and_submission_human_only");
  assert.equal(afterCalifornia.source_status, "review_due");
});

test("unknown and partially evidenced markets fail to human or unsupported rights execution", () => {
  const report = marketPolicyHealth({ now: Date.parse("2026-07-16T12:00:00.000Z") });
  for (const marketId of ["canada", "brazil", "australia", "japan", "singapore", "india", "other"]) {
    const market = report.markets.find((entry) => entry.market_id === marketId);
    assert.ok(market);
    assert.match(market.rightout_support.controller_request, /human_only|unsupported/);
    assert.notEqual(market.evidence_status, "evidenced");
  }
});

test("operator health warns only when a core market source is due or stale", () => {
  const current = marketPolicyOperatorHealth({ now: Date.parse("2026-07-16T12:00:00.000Z") });
  assert.equal(current.all_core_sources_current, true);
  assert.deepEqual(current.source_warnings, []);
  assert.deepEqual(current.core_markets.map((market) => market.market_id), ["eu_eea", "uk", "us_california"]);
  assert.equal(current.operational_authority, "diagnostic_only_not_authorization");
  assert.equal(current.full_policy_tool, "rightout_catalog_health");

  const reviewDue = marketPolicyOperatorHealth({ now: Date.parse("2026-08-01T12:00:00.000Z") });
  assert.equal(reviewDue.all_core_sources_current, false);
  assert.deepEqual(reviewDue.source_warnings, [
    "market_policy_source_review_due:us_california:2026-08-01",
  ]);

  const stale = marketPolicyOperatorHealth({ now: Date.parse("2026-11-20T12:00:00.000Z") });
  assert.equal(stale.all_core_sources_current, false);
  assert.ok(stale.source_warnings.some((warning) => warning.startsWith("market_policy_source_stale:eu_eea:")));
  assert.ok(stale.source_warnings.some((warning) => warning.startsWith("market_policy_source_stale:uk:")));
  assert.ok(stale.source_warnings.some((warning) => warning.startsWith("market_policy_source_stale:us_california:")));
});

test("market policy digest is stable within a contract phase and changes at a legal-source boundary", () => {
  const first = marketPolicyDigest({ now: Date.parse("2026-07-16T12:00:00.000Z") });
  const samePhase = marketPolicyDigest({ now: Date.parse("2026-07-30T12:00:00.000Z") });
  const dropProcessing = marketPolicyDigest({ now: Date.parse("2026-08-01T12:00:00.000Z") });
  assert.match(first, /^[a-f0-9]{64}$/);
  assert.equal(samePhase, first);
  assert.notEqual(dropProcessing, first);
});

test("rights execution permits only a current implemented market contract", () => {
  const now = Date.parse("2026-07-16T12:00:00.000Z");
  assert.deepEqual(marketIdsForJurisdictions(["DE", "EU", "EEA"]), ["eu_eea"]);
  assert.deepEqual(marketIdsForJurisdictions(["US", "US-CA"]), ["us_california", "us_other"]);
  assert.equal(assertMarketRightsExecution({ jurisdictions: ["EU", "EEA"], now }).market_id, "eu_eea");
  assert.equal(assertMarketRightsExecution({ jurisdictions: ["UK"], now }).market_id, "uk");
  assert.equal(assertMarketRightsExecution({ jurisdictions: ["US-CA"], now }).market_id, "us_california");
  assert.throws(
    () => assertMarketRightsExecution({ jurisdictions: ["UK"], now: Date.parse("2026-09-17T12:00:00.000Z") }),
    /rightout_market_policy_source_not_current/,
  );
  assert.throws(
    () => assertMarketRightsExecution({ jurisdictions: ["CA"], now }),
    /rightout_market_execution_unsupported/,
  );
  assert.throws(
    () => assertMarketRightsExecution({ jurisdictions: ["US-CA"], now: Date.parse("2026-08-01T12:00:00.000Z") }),
    /rightout_market_policy_source_not_current/,
  );
  assert.equal(
    assertMarketRightsExecution({ jurisdictions: ["US"], executionClass: "publisher_browser_or_form", now }).market_id,
    "us_other",
  );
});

test("provider route contracts bind every declared market before profile access", () => {
  const now = Date.parse("2026-07-16T12:00:00.000Z");
  const route = assertMarketRouteExecution({
    jurisdictions: ["US", "US-CA"],
    marketIds: ["us_california", "us_other"],
    now,
  });
  assert.deepEqual(route.market_ids, ["us_california", "us_other"]);
  assert.equal(route.execution_class, "provider_delete_opt_out");
  assert.deepEqual(
    assertProfileEligibleForMarketRoute({
      routeJurisdictions: ["US", "US-CA"],
      profileJurisdictions: ["US", "US-CA"],
    }).matched_jurisdictions,
    ["US", "US-CA"],
  );
  assert.throws(
    () => assertProfileEligibleForMarketRoute({
      routeJurisdictions: ["US", "US-CA"],
      profileJurisdictions: ["DE", "EU", "EEA"],
    }),
    /rightout_market_profile_ineligible/,
  );
  assert.throws(
    () => assertMarketRouteExecution({
      jurisdictions: ["US", "US-CA"],
      marketIds: ["us_other"],
      now,
    }),
    /rightout_market_route_contract_invalid/,
  );
  assert.throws(
    () => assertMarketRouteExecution({
      jurisdictions: ["US", "US-CA"],
      marketIds: ["us_california", "us_other"],
      now: Date.parse("2026-08-01T12:00:00.000Z"),
    }),
    /rightout_market_policy_source_not_current/,
  );
});
