#!/usr/bin/env node
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const readJson = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));
const [baseline, evidence, catalog, upstream] = await Promise.all([
  readJson("docs/unbroker-parity-baseline.json"),
  readJson("docs/unbroker-parity-evidence.json"),
  readJson("skills/data-broker-removal/references/brokers/unbroker-parity.json"),
  readJson("docs/unbroker-upstream-refresh.json"),
]);

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const required = baseline.capabilities.filter((item) => item.required === true).map((item) => item.id).sort();
const classified = evidence.capabilities.map((item) => item.id).sort();
if (JSON.stringify(required) !== JSON.stringify(classified) || new Set(classified).size !== classified.length) {
  fail("rightout_technical_parity_capability_inventory_mismatch");
}
const accepted = new Set(["implemented", "equivalent_or_stronger"]);
const incomplete = evidence.capabilities.filter((item) => !accepted.has(item.status) || !Array.isArray(item.evidence) || item.evidence.length < 1);
if (incomplete.length) fail(`rightout_technical_parity_gap:${incomplete.map((item) => item.id).join(",")}`);
if (
  evidence.reference_commit !== baseline.reference.commit
  || catalog.reference_commit !== baseline.reference.commit
  || upstream.pinned_commit !== baseline.reference.commit
  || upstream.unbroker_subtree_unchanged !== true
  || upstream.pinned_subtree_sha !== upstream.current_subtree_sha
) fail("rightout_technical_parity_reference_mismatch");

const methodCounts = Object.fromEntries(["web_form", "email", "phone"].map((method) => [
  method,
  catalog.brokers.filter((item) => item.method === method).length,
]));
if (
  catalog.brokers.length !== 22
  || methodCounts.web_form !== 20 || methodCounts.email !== 1 || methodCounts.phone !== 1
  || catalog.brokers.some((item) => item.source_status === "needs_evidence")
) fail("rightout_technical_parity_contract_surface_incomplete");
if (
  evidence.policy?.complete_technical_capability_parity_claimed !== true
  || evidence.policy?.default_operational_autonomy_claimed !== false
  || evidence.unbroker_capability_parity_complete !== true
  || evidence.technical_parity_gate_passed !== true
  || evidence.unbroker_default_autonomy_complete !== false
  || evidence.autonomous_form_execution_ready !== false
) fail("rightout_technical_parity_verdict_invalid");

process.stdout.write(`${JSON.stringify({
  state: "technical_parity_verified",
  reference_commit: baseline.reference.commit,
  reference_subtree_sha: upstream.current_subtree_sha,
  capabilities: classified.length,
  implemented: evidence.capabilities.filter((item) => item.status === "implemented").length,
  equivalent_or_stronger: evidence.capabilities.filter((item) => item.status === "equivalent_or_stronger").length,
  contracts: { total: catalog.brokers.length, ...methodCounts },
  default_operational_autonomy: false,
})}\n`);
