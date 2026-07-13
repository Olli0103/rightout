import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const baseline = JSON.parse(await readFile("docs/unbroker-parity-baseline.json", "utf8"));
const evidence = JSON.parse(await readFile("docs/unbroker-parity-evidence.json", "utf8"));
const routes = JSON.parse(await readFile("skills/data-broker-removal/references/brokers/unbroker-parity.json", "utf8"));

test("parity evidence classifies every baseline capability exactly once without hiding gaps", async () => {
  assert.equal(evidence.reference_commit, baseline.reference.commit);
  const required = baseline.capabilities.filter((item) => item.required).map((item) => item.id).sort();
  const covered = evidence.capabilities.map((item) => item.id).sort();
  assert.deepEqual(covered, required);
  assert.equal(new Set(covered).size, covered.length);
  const acceptedStatuses = new Set(["implemented", "conditional", "gap", "human_only"]);
  for (const item of evidence.capabilities) {
    assert.ok(acceptedStatuses.has(item.status));
    assert.ok(Array.isArray(item.evidence) && item.evidence.length > 0);
    for (const reference of item.evidence) {
      const path = reference.split("#", 1)[0];
      await access(path);
    }
  }
  const routeBlockers = routes.brokers.filter((item) => item.source_status === "needs_evidence").map((item) => item.id).sort();
  const capabilityGaps = evidence.capabilities.filter((item) => item.status === "gap").map((item) => item.id).sort();
  assert.deepEqual(routeBlockers, []);
  assert.deepEqual(capabilityGaps, ["full_autonomy_default", "soft_managed_challenge_browser_clearance"]);
  assert.equal(evidence.release_ready, true);
  assert.equal(evidence.software_release_ready, true);
  assert.equal(evidence.unbroker_normalized_contract_surface_complete, true);
  assert.equal(evidence.unbroker_recipe_surface_complete, false);
  assert.equal(evidence.unbroker_exact_playbook_choreography_complete, false);
  assert.equal(evidence.unbroker_capability_parity_complete, false);
  assert.equal(evidence.unbroker_default_autonomy_complete, false);
  assert.equal(evidence.autonomous_form_execution_ready, false);
  assert.deepEqual(evidence.external_runtime_degradations, ["clustrmaps", "peekyou"]);
});
