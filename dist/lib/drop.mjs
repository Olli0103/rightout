import { createHash } from "node:crypto";
const DAY_MS = 24 * 60 * 60 * 1_000;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_PROOF_REFERENCE = /^drop_[a-f0-9]{16,64}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const DROP_STATUSES = new Set(["pending", "deleted", "needs_manual_check"]);
function deepFreeze(value) {
    if (value && typeof value === "object" && !Object.isFrozen(value)) {
        for (const nested of Object.values(value))
            deepFreeze(nested);
        Object.freeze(value);
    }
    return value;
}
export const DROP_CONTRACT = deepFreeze({
    contract_id: "california_drop_human_status_v2",
    reviewed_at: "2026-07-16",
    next_review_at: "2026-08-01",
    processing_starts_at: "2026-08-01T00:00:00.000Z",
    broker_access_cycle_days: 45,
    ordinary_processing_days: 90,
    filing_authority: "human_verified_only",
    status_authority: "human_observed_portal_claim_only",
    deletion_semantics: "portal_status_is_not_direct_record_level_deletion_proof",
    sources: [
        "https://privacy.ca.gov/drop/",
        "https://privacy.ca.gov/drop/how-drop-works/",
        "https://privacy.ca.gov/drop/help-with-drop/",
        "https://privacy.ca.gov/drop-for-data-brokers/process-drop-requests/",
    ],
});
function iso(value, code = "rightout_drop_contract_invalid") {
    if (typeof value !== "string")
        throw new Error(code);
    const parsed = new Date(value);
    if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value)
        throw new Error(code);
    return parsed;
}
export function dropContractDigest() {
    return createHash("sha256").update(JSON.stringify(DROP_CONTRACT)).digest("hex");
}
export function calculateDropSchedule(filedAt) {
    const filed = iso(filedAt);
    const processingStart = iso(DROP_CONTRACT.processing_starts_at);
    const effectiveStart = new Date(Math.max(filed.getTime(), processingStart.getTime()));
    const ordinaryDeadline = new Date(effectiveStart.getTime() + DROP_CONTRACT.ordinary_processing_days * DAY_MS);
    const firstStatusCheck = filed < processingStart
        ? processingStart
        : new Date(Math.min(filed.getTime() + DROP_CONTRACT.broker_access_cycle_days * DAY_MS, ordinaryDeadline.getTime()));
    return {
        contract_id: DROP_CONTRACT.contract_id,
        contract_digest: dropContractDigest(),
        phase_at_filing: filed < processingStart
            ? "filed_before_broker_processing"
            : "broker_processing_required",
        processing_starts_at: processingStart.toISOString(),
        first_status_check_at: firstStatusCheck.toISOString(),
        ordinary_deadline_at: ordinaryDeadline.toISOString(),
        broker_access_cycle_days: DROP_CONTRACT.broker_access_cycle_days,
        deletion_confirmed: false,
        deadline_authority: "operational_tracking_not_compliance_certification",
    };
}
export function validateDropStatusInput(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)
        || Object.keys(value).some((key) => !["profileId", "observedStatus"].includes(key))
        || typeof value.profileId !== "string" || !SAFE_PROFILE_ID.test(value.profileId)
        || typeof value.observedStatus !== "string" || !DROP_STATUSES.has(value.observedStatus))
        throw new Error("rightout_drop_status_invalid");
    return { profileId: value.profileId, observedStatus: value.observedStatus };
}
export function dropRegistrySnapshot(value, { now = Date.now() } = {}) {
    if (!Number.isFinite(now))
        throw new Error("rightout_drop_registry_invalid");
    const retrievedAt = Date.parse(value?.retrieved_at);
    if (!value || typeof value !== "object" || Array.isArray(value)
        || value.state !== "registry_ready" || value.schema_version !== 1
        || value.jurisdiction !== "US-CA"
        || typeof value.source_url !== "string"
        || !/^https:\/\/cppa\.ca\.gov\/data_broker_registry\/registry\d{4}\.csv$/.test(value.source_url)
        || typeof value.source_sha256 !== "string" || !SAFE_SHA256.test(value.source_sha256)
        || typeof value.retrieved_at !== "string" || !Number.isFinite(retrievedAt)
        || new Date(retrievedAt).toISOString() !== value.retrieved_at
        || retrievedAt > now + 5 * 60_000 || now - retrievedAt > 45 * DAY_MS
        || !Number.isInteger(value.record_count) || value.record_count < 100 || value.record_count > 10_000
        || !Number.isInteger(value.chunk_count) || value.chunk_count < 1 || value.chunk_count > 10)
        throw new Error("rightout_drop_registry_invalid");
    const snapshot = {
        schema_version: 1,
        jurisdiction: value.jurisdiction,
        source_url: value.source_url,
        source_sha256: value.source_sha256,
        retrieved_at: value.retrieved_at,
        record_count: value.record_count,
    };
    return {
        ...snapshot,
        registry_snapshot_digest: createHash("sha256")
            .update(JSON.stringify(["rightout_drop_registry_snapshot_v1", snapshot]))
            .digest("hex"),
    };
}
export function dropFiledScopeBinding(profileId, registry, options) {
    if (typeof profileId !== "string" || !SAFE_PROFILE_ID.test(profileId)) {
        throw new Error("rightout_drop_attestation_invalid");
    }
    const snapshot = dropRegistrySnapshot(registry, options);
    return JSON.stringify([
        "california_drop_filed_v3",
        profileId,
        snapshot,
        dropContractDigest(),
        DROP_CONTRACT.deletion_semantics,
    ]);
}
export function dropStatusScopeBinding(value, caseContext) {
    const input = validateDropStatusInput(value);
    if (!caseContext || typeof caseContext !== "object" || Array.isArray(caseContext)
        || caseContext.contractDigest !== dropContractDigest()
        || typeof caseContext.registrySnapshotDigest !== "string" || !SAFE_SHA256.test(caseContext.registrySnapshotDigest)
        || typeof caseContext.latestProofReference !== "string" || !SAFE_PROOF_REFERENCE.test(caseContext.latestProofReference))
        throw new Error("rightout_drop_status_invalid");
    return JSON.stringify([
        "rightout_drop_human_status_v3",
        input,
        caseContext,
        DROP_CONTRACT.deletion_semantics,
    ]);
}
export const __test = { DAY_MS, DROP_STATUSES, iso };
