const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,80}$/;
const SAFE_PROOF = /^canary_[a-f0-9]{24}$/;
const CANARY_KINDS = new Set(["submission_delivered", "controller_confirmed", "direct_absence", "reappearance"]);

function validateCanaries(values, profileId, knownBrokers) {
  if (values === undefined) return [];
  if (!Array.isArray(values) || values.length > 500) throw new Error("rightout_effectiveness_canary_invalid");
  const refs = new Set();
  return values.map((value) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_effectiveness_canary_invalid");
    if (Object.keys(value).some((key) => !["profileId", "brokerId", "kind", "observedAt", "proofReference"].includes(key))) {
      throw new Error("rightout_effectiveness_canary_invalid");
    }
    if (
      value.profileId !== profileId || !SAFE_PROFILE_ID.test(value.profileId ?? "")
      || !SAFE_BROKER_ID.test(value.brokerId ?? "") || !knownBrokers.has(value.brokerId)
      || !CANARY_KINDS.has(value.kind) || typeof value.observedAt !== "string" || !Number.isFinite(Date.parse(value.observedAt))
      || !SAFE_PROOF.test(value.proofReference ?? "") || refs.has(value.proofReference)
    ) throw new Error("rightout_effectiveness_canary_invalid");
    refs.add(value.proofReference);
    return structuredClone(value);
  }).sort((a, b) => a.observedAt.localeCompare(b.observedAt) || a.brokerId.localeCompare(b.brokerId));
}

function ratio(numerator, denominator) {
  return { numerator, denominator, rate: denominator > 0 ? Number((numerator / denominator).toFixed(4)) : null };
}

export function buildEffectivenessReport(caseStatus, canaryFacts) {
  if (
    !caseStatus || typeof caseStatus !== "object" || !SAFE_PROFILE_ID.test(caseStatus.subject_ref ?? "")
    || typeof caseStatus.generated_at !== "string" || !Number.isFinite(Date.parse(caseStatus.generated_at))
    || !Array.isArray(caseStatus.cases)
  ) {
    throw new Error("rightout_effectiveness_input_invalid");
  }
  const cases = caseStatus.cases;
  const knownBrokers = new Set();
  for (const item of cases) {
    if (!item || !SAFE_BROKER_ID.test(item.broker_id ?? "") || knownBrokers.has(item.broker_id) || typeof item.state !== "string") {
      throw new Error("rightout_effectiveness_input_invalid");
    }
    knownBrokers.add(item.broker_id);
  }
  const canaries = validateCanaries(canaryFacts, caseStatus.subject_ref, knownBrokers);
  const caseByBroker = new Map(cases.map((item) => [item.broker_id, item]));
  const compatibleStates = {
    submission_delivered: new Set(["submitted", "verification_pending", "awaiting_processing", "identity_verification_required", "partially_removed", "request_rejected", "confirmed_removed", "reappeared"]),
    controller_confirmed: new Set(["confirmed_removed", "reappeared"]),
    direct_absence: new Set(["confirmed_removed", "reappeared"]),
    reappearance: new Set(["reappeared"]),
  };
  if (canaries.some((item) => (
    Date.parse(item.observedAt) > Date.parse(caseStatus.generated_at)
    || !compatibleStates[item.kind].has(caseByBroker.get(item.brokerId)?.state)
  ))) throw new Error("rightout_effectiveness_canary_state_conflict");
  const states = (set) => cases.filter((item) => set.has(item.state)).length;
  const discoveryEvidenced = states(new Set([
    "found", "indirect_exposure", "action_selected", "submission_pending", "submission_uncertain", "submitted",
    "verification_pending", "awaiting_processing", "identity_verification_required", "partially_removed",
    "request_rejected", "confirmed_removed", "reappeared",
  ]));
  const exactListing = cases.filter((item) => typeof item.listing_handle === "string" && /^listing_[a-f0-9]{24}$/.test(item.listing_handle)).length;
  const indirectIdentity = cases.filter((item) => ["found", "indirect_exposure"].includes(item.state) && !item.listing_handle).length;
  const submitted = states(new Set(["submitted", "verification_pending", "awaiting_processing", "identity_verification_required", "partially_removed", "request_rejected", "confirmed_removed", "reappeared"]));
  const confirmed = states(new Set(["confirmed_removed", "reappeared"]));
  const reappeared = states(new Set(["reappeared"]));
  const uncertain = states(new Set(["inconclusive", "submission_pending", "submission_uncertain"]));
  const human = states(new Set(["identity_verification_required", "partially_removed", "request_rejected", "human_task_queued", "blocked"]));
  const canaryCounts = Object.fromEntries([...CANARY_KINDS].sort().map((kind) => [kind, canaries.filter((item) => item.kind === kind).length]));
  const effectivenessEvidenced = canaries.some((item) => ["controller_confirmed", "direct_absence", "reappearance"].includes(item.kind));
  return {
    report_version: 1,
    subject_ref: caseStatus.subject_ref,
    generated_at: caseStatus.generated_at,
    target_count: cases.length,
    discovery: {
      evidenced_targets: discoveryEvidenced,
      inconclusive_targets: states(new Set(["new", "searching", "inconclusive", "not_found"])),
      signal_rate: ratio(discoveryEvidenced, cases.length),
    },
    identity_confidence: {
      exact_known_listing_targets: exactListing,
      indirect_signal_only_targets: indirectIdentity,
      not_evidenced_targets: Math.max(0, cases.length - exactListing - indirectIdentity),
    },
    submission: { evidenced_targets: submitted, rate_from_discovery: ratio(submitted, discoveryEvidenced) },
    provider_confirmation: { evidenced_targets: confirmed, rate_from_submission: ratio(confirmed, submitted) },
    reappearance: { evidenced_targets: reappeared, rate_from_confirmation: ratio(reappeared, confirmed) },
    uncertainty: { targets: uncertain },
    human_handoff: { targets: human },
    authorized_canaries: { count: canaries.length, by_kind: canaryCounts, proof_references: canaries.map((item) => item.proofReference) },
    operational_effectiveness: effectivenessEvidenced ? "evidenced_by_authorized_canaries" : "needs_evidence",
    invariants: { raw_pii_in_report: false, technical_capability_used_as_effectiveness_proof: false, missing_denominators_hidden: false },
  };
}

export const __test = { validateCanaries, ratio };
