import assert from "node:assert/strict";
import test from "node:test";

import {
  buildGpcObservation,
  GPC_CONTRACT,
  gpcContractDigest,
  gpcObservationScopeBinding,
  gpcPreferenceStatus,
  validateGpcObservationInput,
} from "../../lib/preference-controls.mjs";

const INPUT = {
  profileId: "profile_0123456789abcdef",
  surface: "browser_native_setting",
};

test("GPC contract is source-bound and explicitly not a deletion mechanism", () => {
  assert.equal(GPC_CONTRACT.signal_semantics, "opt_out_sale_or_sharing_preference");
  assert.equal(GPC_CONTRACT.deletion_semantics, "not_a_deletion_request_or_deletion_proof");
  assert.deepEqual(GPC_CONTRACT.sources, [
    "https://oag.ca.gov/privacy/ccpa",
    "https://globalprivacycontrol.org/",
  ]);
  assert.equal(Object.isFrozen(GPC_CONTRACT), true);
  assert.equal(Object.isFrozen(GPC_CONTRACT.sources), true);
  assert.match(gpcContractDigest(), /^[a-f0-9]{64}$/);
});

test("GPC observation is exact, human-verified local state with zero provider effects", () => {
  assert.deepEqual(validateGpcObservationInput(INPUT), INPUT);
  assert.match(gpcObservationScopeBinding(INPUT), /rightout_gpc_human_observation_v2/);
  assert.notEqual(
    gpcObservationScopeBinding(INPUT),
    gpcObservationScopeBinding(INPUT, "preference_0123456789abcdef01234567"),
  );
  const observation = buildGpcObservation(INPUT, { observedAt: "2026-07-16T12:00:00.000Z" });
  assert.equal(observation.state, "enabled_human_verified");
  assert.match(observation.proof_reference, /^preference_[a-f0-9]{24}$/);
  assert.equal(observation.deletion_request, false);
  assert.equal(observation.deletion_confirmed, false);
  assert.equal(observation.browser_configuration_performed_by_rightout, false);
  assert.equal(observation.provider_compliance, "needs_evidence_per_site");
  assert.equal(observation.provider_reads, 0);
  assert.equal(observation.provider_writes, 0);

  const status = gpcPreferenceStatus(observation, { generatedAt: "2026-07-16T12:01:00.000Z" });
  assert.equal(status.deletion_request, false);
  assert.equal(status.deletion_confirmed, false);
  assert.equal(status.provider_compliance, "needs_evidence_per_site");
  assert.doesNotMatch(JSON.stringify(status), /full_name|contact_email|street|postal|phone/);
});

test("GPC status defaults to human verification and rejects deletion inflation or loose input", () => {
  const missing = gpcPreferenceStatus(undefined, { generatedAt: "2026-07-16T12:00:00.000Z" });
  assert.equal(missing.state, "needs_human_verification");
  assert.equal(missing.deletion_confirmed, false);

  const observation = buildGpcObservation(INPUT, { observedAt: "2026-07-16T12:00:00.000Z" });
  assert.throws(() => gpcPreferenceStatus({ ...observation, deletion_confirmed: true }), /rightout_gpc_status_invalid/);
  assert.throws(() => gpcPreferenceStatus({ ...observation, provider_writes: 1 }), /rightout_gpc_status_invalid/);
  assert.throws(() => gpcPreferenceStatus({ ...observation, observed_at: "2026-07-16T12:00:00Z" }), /rightout_gpc_status_invalid/);
  assert.throws(
    () => validateGpcObservationInput({ ...INPUT, surface: "site_banner", assumedEnabled: true }),
    /rightout_gpc_observation_invalid/,
  );
});
