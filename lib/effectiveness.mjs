const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,80}$/;
const SAFE_PROOF = /^canary_[a-f0-9]{24}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const CANARY_KINDS = new Set([
  "identity_reviewed", "submission_delivered", "controller_confirmed",
  "direct_absence", "reappearance", "human_handoff",
]);
const IDENTITY_OUTCOMES = new Set(["true_positive", "false_positive", "false_negative", "true_negative"]);
const MAX_CANARY_DURATION_MS = 366 * 24 * 60 * 60_000;

function validateCanaries(values, profileId, knownBrokers) {
  if (values === undefined) return [];
  if (!Array.isArray(values) || values.length > 500) throw new Error("rightout_effectiveness_canary_invalid");
  const refs = new Set();
  const observations = new Set();
  return values.map((value) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_effectiveness_canary_invalid");
    if (Object.keys(value).some((key) => ![
      "schemaVersion", "profileId", "brokerId", "kind", "identityOutcome",
      "startedAt", "observedAt", "proofReference",
      "authorizationReferenceSha256", "deploymentEvidenceSha256",
    ].includes(key))) {
      throw new Error("rightout_effectiveness_canary_invalid");
    }
    const startedAt = Date.parse(value.startedAt);
    const observedAt = Date.parse(value.observedAt);
    const identityKind = value.kind === "identity_reviewed";
    const observationKey = JSON.stringify([
      value.brokerId, value.kind, value.identityOutcome ?? null, value.startedAt, value.observedAt,
    ]);
    if (
      value.schemaVersion !== 2
      || value.profileId !== profileId || !SAFE_PROFILE_ID.test(value.profileId ?? "")
      || !SAFE_BROKER_ID.test(value.brokerId ?? "") || !knownBrokers.has(value.brokerId)
      || !CANARY_KINDS.has(value.kind)
      || typeof value.startedAt !== "string" || !Number.isFinite(startedAt)
      || typeof value.observedAt !== "string" || !Number.isFinite(observedAt)
      || new Date(startedAt).toISOString() !== value.startedAt
      || new Date(observedAt).toISOString() !== value.observedAt
      || startedAt > observedAt || observedAt - startedAt > MAX_CANARY_DURATION_MS
      || (identityKind ? !IDENTITY_OUTCOMES.has(value.identityOutcome) : value.identityOutcome !== undefined)
      || !SAFE_PROOF.test(value.proofReference ?? "") || refs.has(value.proofReference)
      || !SAFE_SHA256.test(value.authorizationReferenceSha256 ?? "")
      || !SAFE_SHA256.test(value.deploymentEvidenceSha256 ?? "")
      || observations.has(observationKey)
    ) throw new Error("rightout_effectiveness_canary_invalid");
    refs.add(value.proofReference);
    observations.add(observationKey);
    return structuredClone(value);
  }).sort((a, b) => a.observedAt.localeCompare(b.observedAt) || a.brokerId.localeCompare(b.brokerId));
}

function ratio(numerator, denominator) {
  return { numerator, denominator, rate: denominator > 0 ? Number((numerator / denominator).toFixed(4)) : null };
}

function durationSummary(values) {
  if (!values.length) return { evidenced: 0, minimum_hours: null, median_hours: null, average_hours: null, maximum_hours: null };
  const hours = values.map((value) => (Date.parse(value.observedAt) - Date.parse(value.startedAt)) / 3_600_000).sort((a, b) => a - b);
  const middle = Math.floor(hours.length / 2);
  const median = hours.length % 2 ? hours[middle] : (hours[middle - 1] + hours[middle]) / 2;
  const rounded = (value) => Number(value.toFixed(2));
  return {
    evidenced: hours.length,
    minimum_hours: rounded(hours[0]),
    median_hours: rounded(median),
    average_hours: rounded(hours.reduce((sum, value) => sum + value, 0) / hours.length),
    maximum_hours: rounded(hours.at(-1)),
  };
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
    identity_reviewed: new Set([
      "new", "searching", "inconclusive", "not_found", "found", "indirect_exposure",
      "action_selected", "submission_pending", "submission_uncertain", "submitted",
      "verification_pending", "awaiting_processing", "identity_verification_required",
      "partially_removed", "request_rejected", "confirmed_removed", "reappeared",
      "human_task_queued", "blocked",
    ]),
    submission_delivered: new Set(["submitted", "verification_pending", "awaiting_processing", "identity_verification_required", "partially_removed", "request_rejected", "confirmed_removed", "reappeared"]),
    controller_confirmed: new Set(["confirmed_removed", "reappeared"]),
    direct_absence: new Set(["confirmed_removed", "reappeared"]),
    reappearance: new Set(["reappeared"]),
    human_handoff: new Set(["identity_verification_required", "partially_removed", "request_rejected", "human_task_queued", "blocked"]),
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
  const identityCounts = Object.fromEntries([...IDENTITY_OUTCOMES].sort().map((outcome) => [
    outcome,
    canaries.filter((item) => item.kind === "identity_reviewed" && item.identityOutcome === outcome).length,
  ]));
  const identityReviewed = Object.values(identityCounts).reduce((sum, value) => sum + value, 0);
  const identityPrecisionDenominator = identityCounts.true_positive + identityCounts.false_positive;
  const identityRecallDenominator = identityCounts.true_positive + identityCounts.false_negative;
  const outcomeCanaries = canaries.filter((item) => ["controller_confirmed", "direct_absence", "reappearance"].includes(item.kind));
  const coveredBrokers = new Set(canaries.map((item) => item.brokerId)).size;
  const identityEvidenced = identityReviewed > 0;
  const effectivenessEvidenced = identityEvidenced && outcomeCanaries.length > 0;
  const partiallyEvidenced = canaries.length > 0 && !effectivenessEvidenced;
  return {
    report_version: 2,
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
    identity_accuracy: {
      reviewed_observations: identityReviewed,
      outcomes: identityCounts,
      precision: ratio(identityCounts.true_positive, identityPrecisionDenominator),
      recall: ratio(identityCounts.true_positive, identityRecallDenominator),
      accuracy: ratio(identityCounts.true_positive + identityCounts.true_negative, identityReviewed),
      evidence_status: identityEvidenced ? "evidenced_by_authorized_canaries" : "needs_evidence",
    },
    submission: { evidenced_targets: submitted, rate_from_discovery: ratio(submitted, discoveryEvidenced) },
    provider_confirmation: { evidenced_targets: confirmed, rate_from_submission: ratio(confirmed, submitted) },
    reappearance: { evidenced_targets: reappeared, rate_from_confirmation: ratio(reappeared, confirmed) },
    uncertainty: { targets: uncertain },
    human_handoff: { targets: human },
    time_to_observed_outcome: durationSummary(outcomeCanaries),
    authorized_canaries: {
      contract_version: 2,
      count: canaries.length,
      covered_brokers: coveredBrokers,
      coverage_rate: ratio(coveredBrokers, cases.length),
      by_kind: canaryCounts,
      distinct_authorizations: new Set(canaries.map((item) => item.authorizationReferenceSha256)).size,
      distinct_deployments: new Set(canaries.map((item) => item.deploymentEvidenceSha256)).size,
      proof_references: canaries.map((item) => item.proofReference),
    },
    operational_effectiveness: effectivenessEvidenced
      ? "evidenced_by_authorized_canaries"
      : partiallyEvidenced ? "partially_evidenced_by_authorized_canaries" : "needs_evidence",
    invariants: {
      raw_pii_in_report: false,
      technical_capability_used_as_effectiveness_proof: false,
      missing_denominators_hidden: false,
      identity_and_outcome_evidence_both_required: true,
      authorization_and_deployment_digests_required: true,
    },
  };
}

export const __test = { validateCanaries, ratio, durationSummary };
