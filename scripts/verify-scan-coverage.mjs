#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import { buildCombinedScanCatalog, scanCoverage } from "../lib/scan-catalog.mjs";

const core = JSON.parse(await readFile(new URL("../skills/data-broker-removal/references/brokers/core.json", import.meta.url), "utf8"));
const parity = JSON.parse(await readFile(new URL("../skills/data-broker-removal/references/brokers/unbroker-parity.json", import.meta.url), "utf8"));
const documented = JSON.parse(await readFile(new URL("../docs/scan-coverage.json", import.meta.url), "utf8"));
const actual = scanCoverage(buildCombinedScanCatalog(core, parity));
const expected = {
  runtime_combined_entries: documented.runtime_combined_entries,
  code_enforced_brave_scan_lanes: documented.code_enforced_brave_scan_lanes,
  people_search_brave_scan_lanes: documented.people_search_brave_scan_lanes,
  controller_b2b_brave_scan_lanes: documented.controller_b2b_brave_scan_lanes,
  human_only_controller_portal_lanes: documented.human_only_controller_portal_lanes,
};

if (
  documented.schema_version !== "rightout.scan-coverage.v1"
  || documented.transport !== "brave_web_search_post_body"
  || documented.visibility !== "public_web_search_index_only"
  || documented.publisher_requests !== 0
  || documented.private_broker_inventory_visibility !== false
  || documented.discovery_effectiveness !== "needs_evidence"
  || JSON.stringify(actual) !== JSON.stringify(expected)
) {
  console.error(JSON.stringify({ ok: false, actual, expected }));
  process.exit(1);
}

console.log(JSON.stringify({ ok: true, ...actual }));
