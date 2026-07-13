import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { scanProfileDigest, runLiveScan } from "../../lib/live-scan.mjs";
import { planGlobalScanCampaignNext } from "../../lib/parity-autopilot.mjs";
import { buildCombinedScanCatalog, isBraveScanLane, scanCoverage } from "../../lib/scan-catalog.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

const core = JSON.parse(await readFile("skills/data-broker-removal/references/brokers/core.json", "utf8"));
const parity = JSON.parse(await readFile("skills/data-broker-removal/references/brokers/unbroker-parity.json", "utf8"));
const documented = JSON.parse(await readFile("docs/scan-coverage.json", "utf8"));

test("runtime scan coverage exactly matches the machine-readable public claim", () => {
  const combined = buildCombinedScanCatalog(core, parity);
  const actual = scanCoverage(combined);
  assert.deepEqual(actual, {
    runtime_combined_entries: documented.runtime_combined_entries,
    code_enforced_brave_scan_lanes: documented.code_enforced_brave_scan_lanes,
    people_search_brave_scan_lanes: documented.people_search_brave_scan_lanes,
    controller_b2b_brave_scan_lanes: documented.controller_b2b_brave_scan_lanes,
    human_only_controller_portal_lanes: documented.human_only_controller_portal_lanes,
  });
  assert.deepEqual(actual, {
    runtime_combined_entries: 65,
    code_enforced_brave_scan_lanes: 56,
    people_search_brave_scan_lanes: 30,
    controller_b2b_brave_scan_lanes: 26,
    human_only_controller_portal_lanes: 3,
  });
});

test("combined scan catalog preserves every human/manual/prohibited gate", () => {
  const combined = buildCombinedScanCatalog(core, parity);
  const byId = new Map(combined.brokers.map((entry) => [entry.id, entry]));
  for (const entry of [...core.brokers, ...parity.brokers]) {
    if (
      entry.human_only === true
      || entry.scan?.manual_only === true
      || entry.scan?.automated_access_policy === "prohibited_by_published_terms"
    ) {
      assert.notEqual(byId.get(entry.id)?.scan?.supported, true, entry.id);
    }
  }
});

test("a stricter overlay gate disables an existing core scan lane", () => {
  const combined = buildCombinedScanCatalog({
    brokers: [{
      id: "conflict",
      name: "Conflict",
      category: "people_search",
      scan: { supported: true, automated_access_policy: "search_index_only_no_publisher_access" },
    }],
  }, {
    brokers: [{
      id: "conflict",
      name: "Conflict",
      category: "people_search",
      human_only: true,
      scan: { supported: false, manual_only: true },
    }],
  });
  const conflict = combined.brokers.find((entry) => entry.id === "conflict");
  assert.equal(conflict.human_only, true);
  assert.equal(conflict.scan.supported, false);
  assert.equal(conflict.scan.manual_only, true);
  assert.equal(isBraveScanLane(conflict), false);
});

test("all 56 documented lanes execute through the live-scan catalog boundary", async () => {
  const combined = buildCombinedScanCatalog(core, parity);
  const brokerIds = combined.brokers.filter(isBraveScanLane).map((entry) => entry.id);
  const profileId = "profile_a1b2c3d4e5f60718";
  const profile = JSON.stringify({
    fullName: "Avery Example",
    city: "Exampleville",
    region: "BE",
    country: "DE",
    consent: {
      authorized: true,
      recordedAt: CONSENT_RECORDED_AT,
      validUntil: CONSENT_VALID_UNTIL,
      scope: ["scan"],
      method: "self",
    },
  });
  let calls = 0;
  const report = await runLiveScan({
    input: { profileId, subject: profile, brokerIds },
    catalog: combined,
    apiKey: "dummy-brave-key",
    guardedFetch: async (request) => {
      calls += 1;
      assert.equal(request.url, "https://api.search.brave.com/res/v1/web/search");
      assert.deepEqual(request.allowedHosts, ["api.search.brave.com"]);
      assert.equal(request.init.method, "POST");
      return {
        response: new Response(JSON.stringify({ web: { results: [] } }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      };
    },
    operatorAttestations: {
      braveTermsAccepted: true,
      braveTermsVersion: "2026-02-11",
      braveCustomerResponsibilitiesAccepted: true,
      subjectConsentReviewed: true,
      authorizedProfileIds: [profileId],
      authorizedProfileDigests: { [profileId]: scanProfileDigest(profile) },
      authorizedBrokerIds: brokerIds,
    },
  });
  assert.equal(report.summary.checked, 56);
  assert.equal(report.coverage_scope.selected_catalog_lanes, 56);
  assert.equal(report.summary.inconclusive, 56);
  assert.equal(calls, 56);
});

test("one exact discover campaign drains all 56 runtime lanes in fourteen bounded batches", () => {
  const combined = buildCombinedScanCatalog(core, parity);
  const brokerIds = combined.brokers.filter(isBraveScanLane).map((entry) => entry.id);
  const campaign = {
    campaign_id: `campaign_${"a".repeat(32)}`,
    subject_ref: "profile_a1b2c3d4e5f60718",
    broker_ids: brokerIds,
    effects: ["discover"],
    status: "active",
  };
  const cases = [];
  const observed = [];
  let batches = 0;
  while (true) {
    const next = planGlobalScanCampaignNext({ campaign, caseStatus: { cases }, scanCatalog: combined });
    if (next.state === "done_for_now") {
      assert.equal(next.reason, "global_catalog_scan_scope_complete");
      break;
    }
    assert.equal(next.state, "action_ready");
    assert.ok(next.command.parameters.brokerIds.length >= 1);
    assert.ok(next.command.parameters.brokerIds.length <= 4);
    for (const broker_id of next.command.parameters.brokerIds) {
      assert.equal(observed.includes(broker_id), false, broker_id);
      observed.push(broker_id);
      cases.push({ broker_id, state: "inconclusive" });
    }
    batches += 1;
    assert.ok(batches <= 14);
  }
  assert.equal(batches, 14);
  assert.deepEqual(observed.slice().sort(), brokerIds.slice().sort());
});
