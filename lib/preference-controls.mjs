import { createHash } from "node:crypto";

const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_PROOF_REFERENCE = /^preference_[a-f0-9]{24}$/;
const GPC_SURFACES = new Set(["browser_native_setting", "browser_extension"]);

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

export const GPC_CONTRACT = deepFreeze({
  schema_version: 1,
  control_id: "global_privacy_control",
  reviewed_at: "2026-07-16",
  next_review_at: "2026-10-14",
  signal_semantics: "opt_out_sale_or_sharing_preference",
  deletion_semantics: "not_a_deletion_request_or_deletion_proof",
  california_effect: "recognized_opt_out_of_sale_or_sharing_signal",
  other_market_effect: "needs_evidence",
  sources: [
    "https://oag.ca.gov/privacy/ccpa",
    "https://globalprivacycontrol.org/",
  ],
});

export function gpcContractDigest() {
  return createHash("sha256").update(JSON.stringify(GPC_CONTRACT)).digest("hex");
}

export function validateGpcObservationInput(value) {
  if (
    !value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).some((key) => !["profileId", "surface"].includes(key))
    || typeof value.profileId !== "string" || !SAFE_PROFILE_ID.test(value.profileId)
    || typeof value.surface !== "string" || !GPC_SURFACES.has(value.surface)
  ) throw new Error("rightout_gpc_observation_invalid");
  return { profileId: value.profileId, surface: value.surface };
}

/** @param {unknown} value @param {string | null} [currentProofReference] */
export function gpcObservationScopeBinding(value, currentProofReference = null) {
  const input = validateGpcObservationInput(value);
  if (currentProofReference !== null && (
    typeof currentProofReference !== "string" || !SAFE_PROOF_REFERENCE.test(currentProofReference)
  )) throw new Error("rightout_gpc_observation_invalid");
  return JSON.stringify([
    "rightout_gpc_human_observation_v2",
    input,
    currentProofReference,
    gpcContractDigest(),
    GPC_CONTRACT.deletion_semantics,
  ]);
}

export function buildGpcObservation(value, { observedAt = new Date().toISOString() } = {}) {
  const input = validateGpcObservationInput(value);
  const at = new Date(observedAt);
  if (!Number.isFinite(at.getTime()) || at.toISOString() !== observedAt) {
    throw new Error("rightout_gpc_observation_invalid");
  }
  const proofReference = `preference_${createHash("sha256")
    .update(JSON.stringify([input.profileId, input.surface, observedAt, gpcContractDigest()]))
    .digest("hex").slice(0, 24)}`;
  return {
    schema_version: 1,
    profileId: input.profileId,
    control_id: GPC_CONTRACT.control_id,
    state: "enabled_human_verified",
    surface: input.surface,
    observed_at: observedAt,
    proof_reference: proofReference,
    contract_digest: gpcContractDigest(),
    signal_semantics: GPC_CONTRACT.signal_semantics,
    deletion_request: false,
    deletion_confirmed: false,
    provider_compliance: "needs_evidence_per_site",
    browser_configuration_performed_by_rightout: false,
    provider_reads: 0,
    provider_writes: 0,
    raw_pii_in_report: false,
  };
}

export function gpcPreferenceStatus(value, { generatedAt = new Date().toISOString() } = {}) {
  const generated = new Date(generatedAt);
  if (!Number.isFinite(generated.getTime()) || generated.toISOString() !== generatedAt) {
    throw new Error("rightout_gpc_status_invalid");
  }
  if (value === undefined) {
    return {
      control_id: GPC_CONTRACT.control_id,
      state: "needs_human_verification",
      generated_at: generatedAt,
      contract_digest: gpcContractDigest(),
      signal_semantics: GPC_CONTRACT.signal_semantics,
      deletion_request: false,
      deletion_confirmed: false,
      provider_compliance: "needs_evidence_per_site",
      browser_configuration_performed_by_rightout: false,
      raw_pii_in_report: false,
    };
  }
  if (
    !value || typeof value !== "object" || Array.isArray(value)
    || value.schema_version !== 1
    || !SAFE_PROFILE_ID.test(value.profileId ?? "")
    || value.control_id !== GPC_CONTRACT.control_id
    || value.state !== "enabled_human_verified"
    || !GPC_SURFACES.has(value.surface)
    || typeof value.observed_at !== "string" || !Number.isFinite(Date.parse(value.observed_at))
    || new Date(value.observed_at).toISOString() !== value.observed_at
    || typeof value.proof_reference !== "string" || !/^preference_[a-f0-9]{24}$/.test(value.proof_reference)
    || value.contract_digest !== gpcContractDigest()
    || value.signal_semantics !== GPC_CONTRACT.signal_semantics
    || value.deletion_request !== false || value.deletion_confirmed !== false
    || value.provider_compliance !== "needs_evidence_per_site"
    || value.browser_configuration_performed_by_rightout !== false
    || value.provider_reads !== 0 || value.provider_writes !== 0
    || value.raw_pii_in_report !== false
  ) throw new Error("rightout_gpc_status_invalid");
  return {
    control_id: value.control_id,
    state: value.state,
    surface: value.surface,
    observed_at: new Date(value.observed_at).toISOString(),
    proof_references: [value.proof_reference],
    generated_at: generatedAt,
    contract_digest: value.contract_digest,
    signal_semantics: value.signal_semantics,
    deletion_request: false,
    deletion_confirmed: false,
    provider_compliance: value.provider_compliance,
    browser_configuration_performed_by_rightout: false,
    raw_pii_in_report: false,
  };
}
