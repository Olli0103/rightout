import { createHash } from "node:crypto";
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_PROOF_REF = /^(?:scan|intent|smtp|form|mail|verify|direct|controller|reconcile)_[a-f0-9]{16,64}$/;
const SAFE_LISTING_HANDLE = /^listing_[a-f0-9]{24}$/;
const MAX_HISTORY = 100;
const DEFAULT_PROCESSING_DAYS = 14;
const DEFAULT_RESCAN_DAYS = 120;
export const CASE_STATES = Object.freeze([
    "new",
    "searching",
    "inconclusive",
    "not_found",
    "found",
    "indirect_exposure",
    "action_selected",
    "submission_pending",
    "submission_uncertain",
    "submitted",
    "verification_pending",
    "awaiting_processing",
    "identity_verification_required",
    "partially_removed",
    "request_rejected",
    "confirmed_removed",
    "reappeared",
    "human_task_queued",
    "blocked",
]);
const TRANSITIONS = new Map([
    ["new", new Set(["searching", "inconclusive", "not_found", "found", "indirect_exposure", "action_selected", "human_task_queued", "blocked"])],
    ["searching", new Set(["inconclusive", "not_found", "found", "indirect_exposure", "human_task_queued", "blocked"])],
    ["inconclusive", new Set(["searching", "inconclusive", "not_found", "found", "indirect_exposure", "human_task_queued", "blocked"])],
    ["not_found", new Set(["searching", "inconclusive", "found", "indirect_exposure", "human_task_queued", "blocked"])],
    ["found", new Set(["action_selected", "submission_pending", "inconclusive", "not_found", "indirect_exposure", "human_task_queued", "blocked"])],
    ["indirect_exposure", new Set(["action_selected", "submission_pending", "inconclusive", "not_found", "found", "human_task_queued", "blocked"])],
    ["action_selected", new Set(["submission_pending", "inconclusive", "not_found", "found", "human_task_queued", "blocked"])],
    ["submission_pending", new Set(["submitted", "submission_uncertain", "action_selected", "human_task_queued", "blocked"])],
    ["submission_uncertain", new Set(["submitted", "action_selected", "human_task_queued", "blocked"])],
    ["submitted", new Set(["verification_pending", "awaiting_processing", "identity_verification_required", "partially_removed", "request_rejected", "confirmed_removed", "found", "human_task_queued", "blocked"])],
    ["verification_pending", new Set(["awaiting_processing", "identity_verification_required", "partially_removed", "request_rejected", "confirmed_removed", "found", "human_task_queued", "blocked"])],
    ["awaiting_processing", new Set(["identity_verification_required", "partially_removed", "request_rejected", "confirmed_removed", "found", "human_task_queued", "blocked"])],
    ["identity_verification_required", new Set(["submitted", "awaiting_processing", "partially_removed", "request_rejected", "confirmed_removed", "human_task_queued", "blocked"])],
    ["partially_removed", new Set(["action_selected", "submission_pending", "awaiting_processing", "identity_verification_required", "request_rejected", "confirmed_removed", "reappeared", "human_task_queued", "blocked"])],
    ["request_rejected", new Set(["action_selected", "submission_pending", "human_task_queued", "blocked"])],
    ["confirmed_removed", new Set(["confirmed_removed", "reappeared"])],
    ["reappeared", new Set(["found", "inconclusive", "not_found", "indirect_exposure", "action_selected", "submission_pending", "human_task_queued", "blocked"])],
    ["human_task_queued", new Set(["searching", "inconclusive", "not_found", "found", "indirect_exposure", "action_selected", "submission_pending", "submission_uncertain", "submitted", "verification_pending", "awaiting_processing", "identity_verification_required", "partially_removed", "request_rejected", "confirmed_removed", "blocked"])],
    ["blocked", new Set(["searching", "inconclusive", "not_found", "found", "indirect_exposure", "action_selected", "human_task_queued"])],
]);
function safeProfileId(value) {
    if (typeof value !== "string" || !SAFE_PROFILE_ID.test(value))
        throw new Error("invalid_profile_ref");
    return value;
}
function safeBrokerId(value) {
    if (typeof value !== "string" || !SAFE_BROKER_ID.test(value))
        throw new Error("invalid_broker_id");
    return value;
}
function safeDate(value, label = "timestamp") {
    if (typeof value !== "string" || !Number.isFinite(Date.parse(value)))
        throw new Error(`invalid_${label}`);
    return new Date(value).toISOString();
}
function safeStringArray(values, pattern, max = 24) {
    if (!Array.isArray(values) || values.length > max)
        throw new Error("invalid_case_evidence");
    const out = [...new Set(values)];
    if (out.length !== values.length || !out.every((value) => typeof value === "string" && pattern.test(value))) {
        throw new Error("invalid_case_evidence");
    }
    return out.sort();
}
function safeMetadataToken(value, fallback = "needs_evidence") {
    return typeof value === "string" && /^[a-z0-9_]{2,80}$/.test(value) ? value : fallback;
}
function safeOfficialActionUrl(broker) {
    const raw = broker?.eu_process?.official_action_url ?? broker?.us_process?.official_action_url ?? broker?.human_action_url ?? broker?.official_url;
    const domains = Array.isArray(broker?.official_domains) ? broker.official_domains : [];
    try {
        const url = new URL(raw);
        if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash
            || (url.port && url.port !== "443")
            || !domains.some((domain) => typeof domain === "string" && (url.hostname === domain || url.hostname.endsWith(`.${domain}`))))
            return undefined;
        return url.toString();
    }
    catch {
        return undefined;
    }
}
function addDays(iso, days) {
    const date = new Date(iso);
    date.setUTCDate(date.getUTCDate() + days);
    return date.toISOString();
}
function newBrokerCase(brokerId, now) {
    return {
        broker_id: safeBrokerId(brokerId),
        state: "new",
        last_observation: null,
        listing_handle: null,
        proof_references: [],
        disclosure_fields: [],
        submission_channel: null,
        submission_started_at: null,
        submission_outcome: null,
        next_recheck_at: null,
        direct_absence_observed_at: null,
        removal_confirmed_at: null,
        removal_confirmation_scope: null,
        coverage_gap: null,
        human_task_reason: null,
        updated_at: now,
        history: [],
    };
}
function newProfileCase(profileId, now) {
    return {
        schema_version: 1,
        subject_ref: safeProfileId(profileId),
        created_at: now,
        updated_at: now,
        brokers: {},
    };
}
function transition(brokerCase, state, at, reason) {
    if (!CASE_STATES.includes(state))
        throw new Error("invalid_case_state");
    const old = brokerCase.state;
    if (state !== old && !TRANSITIONS.get(old)?.has(state))
        throw new Error("illegal_case_transition");
    brokerCase.state = state;
    brokerCase.updated_at = at;
    brokerCase.history = [...brokerCase.history, { at, from: old, to: state, reason }].slice(-MAX_HISTORY);
}
function sanitizeStoredProfile(value, profileId) {
    if (!value)
        return undefined;
    if (value.schema_version !== 1 || value.subject_ref !== profileId || !value.brokers || typeof value.brokers !== "object") {
        throw new Error("rightout_case_store_invalid");
    }
    return structuredClone(value);
}
function opaqueEvidence(prefix, parts) {
    return `${prefix}_${createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0, 24)}`;
}
function catalogRows(catalog) {
    if (!catalog || !Array.isArray(catalog.brokers))
        throw new Error("catalog_invalid");
    return catalog.brokers.filter((entry) => entry && typeof entry === "object" && SAFE_BROKER_ID.test(entry.id));
}
function laneFor(broker) {
    if (broker.removal?.supported === true && broker.removal?.channel === "email")
        return "email";
    if (broker.removal?.supported === true && broker.removal?.channel === "browser_form")
        return "browser_form";
    if (broker.lane === "registry")
        return "registry";
    if (broker.human_only === true || broker.lane === "human_task")
        return "human_task";
    if (broker.scan?.supported === true)
        return "scan_only";
    return "unsupported";
}
function tierFor(broker, lane) {
    if (lane === "email")
        return "T1";
    if (lane === "browser_form" && broker.removal?.requires?.captcha !== true)
        return "T1";
    if (lane === "browser_form")
        return "T2";
    if (lane === "scan_only")
        return "T2";
    return "T3";
}
function nextActionFor(broker, brokerCase, at = new Date().toISOString()) {
    const isDue = typeof brokerCase.next_recheck_at === "string" && brokerCase.next_recheck_at <= at;
    const directAction = () => {
        if (broker.direct_rescan?.supported !== true)
            return "review_provider_status_human";
        return SAFE_LISTING_HANDLE.test(brokerCase.listing_handle ?? "") ? "run_direct_rescan" : "refresh_discovery_for_direct_handle";
    };
    if (brokerCase.state === "confirmed_removed")
        return isDue ? directAction() : "wait_for_reappearance_recheck";
    if (["submission_pending", "submission_uncertain"].includes(brokerCase.state))
        return "reconcile_submission";
    if (brokerCase.state === "identity_verification_required")
        return "complete_identity_verification_human_task";
    if (brokerCase.state === "partially_removed")
        return "review_partial_controller_outcome";
    if (brokerCase.state === "request_rejected")
        return "review_rejection_or_escalate";
    if (["submitted", "verification_pending"].includes(brokerCase.state)) {
        if (broker.removal?.confirmation_policy === "submitted_until_controller_response") {
            return isDue ? "follow_up_controller_response_human" : "wait_for_controller_response";
        }
        return brokerCase.state === "verification_pending" || broker.verification?.supported === true
            ? "poll_verification"
            : isDue ? directAction() : "wait_for_processing_window";
    }
    if (brokerCase.state === "awaiting_processing")
        return isDue ? directAction() : "wait_for_due_direct_rescan";
    if (brokerCase.state === "human_task_queued")
        return "complete_human_task";
    if (brokerCase.state === "blocked")
        return "retry_or_route_human";
    if (["found", "indirect_exposure", "reappeared", "action_selected"].includes(brokerCase.state)) {
        const lane = laneFor(broker);
        if (lane === "email")
            return "submit_email_removal";
        if (lane === "browser_form")
            return "submit_browser_form";
        return "queue_human_task";
    }
    if (broker.removal?.supported === true
        && broker.removal?.channel === "email"
        && broker.removal?.discovery_requirement === "not_required_for_data_subject_request")
        return "submit_email_removal";
    return broker.scan?.supported === true ? "run_discovery" : "queue_human_task";
}
export function createCaseLedger(store, { now = () => new Date() } = {}) {
    if (!store || typeof store.lookup !== "function" || typeof store.register !== "function") {
        throw new Error("rightout_case_store_unavailable");
    }
    const locks = new Map();
    async function withProfile(profileId, update) {
        const key = safeProfileId(profileId);
        const previous = locks.get(key) ?? Promise.resolve();
        let release;
        const current = new Promise((resolve) => { release = resolve; });
        const chain = previous.then(() => current);
        locks.set(key, chain);
        await previous;
        try {
            const at = now().toISOString();
            const existing = sanitizeStoredProfile(await store.lookup(key), key);
            const profile = existing ?? newProfileCase(key, at);
            const result = await update(profile, at);
            profile.updated_at = at;
            await store.register(key, profile);
            return result ?? structuredClone(profile);
        }
        finally {
            release();
            if (locks.get(key) === chain)
                locks.delete(key);
        }
    }
    async function load(profileId) {
        const key = safeProfileId(profileId);
        return sanitizeStoredProfile(await store.lookup(key), key) ?? newProfileCase(key, now().toISOString());
    }
    async function ensure(profileId, brokerIds = []) {
        const ids = safeStringArray(brokerIds, SAFE_BROKER_ID, 100);
        return withProfile(profileId, (profile, at) => {
            for (const brokerId of ids)
                profile.brokers[brokerId] ??= newBrokerCase(brokerId, at);
        });
    }
    async function recordScan(report) {
        if (!report || report.mode !== "approval_gated_live_scan" || !Array.isArray(report.results)) {
            throw new Error("invalid_scan_report");
        }
        const profileId = safeProfileId(report.subject_ref);
        const scanAt = safeDate(report.generated_at, "scan_timestamp");
        return withProfile(profileId, (profile) => {
            for (const result of report.results) {
                const brokerId = safeBrokerId(result?.broker_id);
                if (!["indirect_exposure", "inconclusive"].includes(result?.state))
                    throw new Error("invalid_scan_report");
                const brokerCase = profile.brokers[brokerId] ?? newBrokerCase(brokerId, scanAt);
                brokerCase.last_observation = {
                    at: scanAt,
                    kind: "search_index",
                    state: result.state,
                    reason: String(result.reason).slice(0, 80),
                };
                const proofRef = opaqueEvidence("scan", [report.scan_id, brokerId, result.state, scanAt]);
                brokerCase.proof_references = [...new Set([...brokerCase.proof_references, proofRef])].slice(-24);
                if (result.listing_handle !== undefined) {
                    if (typeof result.listing_handle !== "string" || !SAFE_LISTING_HANDLE.test(result.listing_handle))
                        throw new Error("invalid_scan_report");
                    brokerCase.listing_handle = result.listing_handle;
                }
                if (brokerCase.state === "confirmed_removed") {
                    // Search-index results can be stale and cannot prove reappearance.
                    transition(brokerCase, "confirmed_removed", scanAt, "index_observation_did_not_change_confirmed_state");
                }
                else if (!["submitted", "verification_pending", "awaiting_processing"].includes(brokerCase.state)) {
                    transition(brokerCase, result.state, scanAt, result.reason);
                }
                profile.brokers[brokerId] = brokerCase;
            }
        });
    }
    async function recordRemoval(report, processingDays = DEFAULT_PROCESSING_DAYS) {
        if (!report || report.state !== "submitted" || report.delivery?.accepted_by_outbound_smtp !== true) {
            throw new Error("invalid_removal_report");
        }
        const profileId = safeProfileId(report.subject_ref);
        const brokerId = safeBrokerId(report.broker_id);
        const at = safeDate(report.generated_at, "removal_timestamp");
        const proof = safeStringArray(report.proof_references ?? [], SAFE_PROOF_REF, 12);
        const disclosures = safeStringArray(report.disclosures?.to_broker ?? [], /^[a-z_]{2,32}$/, 24);
        if (!Number.isInteger(processingDays) || processingDays < 1 || processingDays > 365)
            throw new Error("invalid_processing_window");
        return withProfile(profileId, (profile) => {
            const brokerCase = profile.brokers[brokerId] ?? newBrokerCase(brokerId, at);
            if (brokerCase.state !== "submission_pending")
                throw new Error("submission_intent_required");
            transition(brokerCase, "submitted", at, "approved_email_submission");
            brokerCase.submission_outcome = "accepted_by_outbound_smtp";
            brokerCase.proof_references = [...new Set([...brokerCase.proof_references, ...proof])].slice(-24);
            brokerCase.disclosure_fields = disclosures;
            brokerCase.next_recheck_at = addDays(at, processingDays);
            profile.brokers[brokerId] = brokerCase;
        });
    }
    async function recordFormSubmission(report) {
        if (!report || report.state !== "verification_pending" || report.delivery?.form_submitted !== true) {
            throw new Error("invalid_form_removal_report");
        }
        const profileId = safeProfileId(report.subject_ref);
        const brokerId = safeBrokerId(report.broker_id);
        const at = safeDate(report.generated_at, "form_removal_timestamp");
        const proof = safeStringArray(report.proof_references ?? [], SAFE_PROOF_REF, 12);
        const disclosures = safeStringArray(report.disclosures?.to_broker ?? [], /^[a-z_]{2,32}$/, 24);
        return withProfile(profileId, (profile) => {
            const brokerCase = profile.brokers[brokerId] ?? newBrokerCase(brokerId, at);
            if (brokerCase.state !== "submission_pending")
                throw new Error("submission_intent_required");
            transition(brokerCase, "submitted", at, "approved_browser_form_submission");
            transition(brokerCase, "verification_pending", at, "broker_email_control_required");
            brokerCase.submission_outcome = "form_success_evidence_observed";
            brokerCase.proof_references = [...new Set([...brokerCase.proof_references, ...proof])].slice(-24);
            brokerCase.disclosure_fields = disclosures;
            brokerCase.next_recheck_at = addDays(at, 1);
            profile.brokers[brokerId] = brokerCase;
        });
    }
    async function recordDirectRescan(report, rescanDays = DEFAULT_RESCAN_DAYS) {
        if (!report || !["direct_present", "direct_absent_known_listing_set", "inconclusive"].includes(report.observation)
            || report.removal_confirmation_scope !== "known_listing_set_only"
            || !Array.isArray(report.proof_references))
            throw new Error("invalid_direct_rescan_report");
        if (!Number.isInteger(rescanDays) || rescanDays < 1 || rescanDays > 365)
            throw new Error("invalid_rescan_window");
        const profileId = safeProfileId(report.subject_ref);
        const brokerId = safeBrokerId(report.broker_id);
        const at = safeDate(report.generated_at, "direct_rescan_timestamp");
        const proof = safeStringArray(report.proof_references, SAFE_PROOF_REF, 12);
        return withProfile(profileId, (profile) => {
            const brokerCase = profile.brokers[brokerId] ?? newBrokerCase(brokerId, at);
            brokerCase.last_observation = {
                at,
                kind: "publisher_direct_known_listing_set",
                state: report.observation,
                reason: report.removal_confirmation_scope,
            };
            brokerCase.proof_references = [...new Set([...brokerCase.proof_references, ...proof])].slice(-24);
            if (report.observation === "direct_present") {
                if (brokerCase.state === "confirmed_removed")
                    transition(brokerCase, "reappeared", at, "trusted_direct_rescan_present");
                else if (brokerCase.state !== "found")
                    transition(brokerCase, "found", at, "trusted_direct_rescan_present");
                brokerCase.next_recheck_at = null;
                brokerCase.removal_confirmation_scope = null;
                brokerCase.coverage_gap = null;
                brokerCase.direct_absence_observed_at = null;
                if (brokerCase.state !== "confirmed_removed")
                    brokerCase.removal_confirmed_at = null;
            }
            else if (report.observation === "direct_absent_known_listing_set") {
                brokerCase.removal_confirmation_scope = "known_listing_set_only";
                brokerCase.coverage_gap = "new_or_unindexed_listing_urls_not_checked";
                const stateBeforeAbsence = brokerCase.state;
                const removalInFlight = ["submitted", "verification_pending", "awaiting_processing"].includes(stateBeforeAbsence);
                const priorAbsence = typeof brokerCase.direct_absence_observed_at === "string"
                    ? brokerCase.direct_absence_observed_at
                    : null;
                if (removalInFlight && !priorAbsence) {
                    if (stateBeforeAbsence !== "awaiting_processing")
                        transition(brokerCase, "awaiting_processing", at, "first_trusted_direct_rescan_absent");
                    else
                        transition(brokerCase, "awaiting_processing", at, "first_trusted_direct_rescan_absent_after_processing_start");
                    brokerCase.direct_absence_observed_at = at;
                    if (!brokerCase.next_recheck_at || brokerCase.next_recheck_at <= at)
                        brokerCase.next_recheck_at = addDays(at, 7);
                }
                else if (removalInFlight && priorAbsence) {
                    if (at <= priorAbsence || !brokerCase.next_recheck_at || at < brokerCase.next_recheck_at) {
                        transition(brokerCase, "awaiting_processing", at, "repeat_trusted_direct_rescan_absent_before_due");
                    }
                    else {
                        transition(brokerCase, "confirmed_removed", at, "second_trusted_direct_rescan_absent_after_due");
                    }
                }
                else if (brokerCase.state !== "confirmed_removed") {
                    transition(brokerCase, "not_found", at, "trusted_direct_rescan_absent_known_listing_set_without_prior_removal");
                    brokerCase.direct_absence_observed_at = null;
                }
                if (brokerCase.state === "confirmed_removed") {
                    brokerCase.removal_confirmed_at = at;
                    brokerCase.next_recheck_at = addDays(at, rescanDays);
                }
            }
            else if (!["submitted", "verification_pending", "awaiting_processing", "confirmed_removed"].includes(brokerCase.state)) {
                transition(brokerCase, "inconclusive", at, "direct_rescan_inconclusive");
            }
            profile.brokers[brokerId] = brokerCase;
        });
    }
    async function reserveSubmission(profileId, brokerId, { channel, discoveryRequirement } = {}) {
        const cleanProfile = safeProfileId(profileId);
        const cleanBroker = safeBrokerId(brokerId);
        if (!["smtp_email", "browser_form"].includes(channel))
            throw new Error("invalid_submission_channel");
        if (!["prior_discovery_required", "not_required_for_data_subject_request"].includes(discoveryRequirement)) {
            throw new Error("invalid_discovery_requirement");
        }
        return withProfile(cleanProfile, (profile, at) => {
            const brokerCase = profile.brokers[cleanBroker] ?? newBrokerCase(cleanBroker, at);
            if (brokerCase.state === "new" && discoveryRequirement === "not_required_for_data_subject_request") {
                transition(brokerCase, "action_selected", at, "data_subject_request_selected");
            }
            if (!["found", "indirect_exposure", "action_selected", "reappeared", "partially_removed", "request_rejected"].includes(brokerCase.state)) {
                throw new Error("rightout_submission_not_ready");
            }
            transition(brokerCase, "submission_pending", at, "durable_provider_write_intent");
            brokerCase.submission_channel = channel;
            brokerCase.submission_started_at = at;
            brokerCase.submission_outcome = "pending";
            const proof = opaqueEvidence("intent", [cleanProfile, cleanBroker, channel, at]);
            brokerCase.proof_references = [...new Set([...brokerCase.proof_references, proof])].slice(-24);
            profile.brokers[cleanBroker] = brokerCase;
            return { state: brokerCase.state, proof_reference: proof, started_at: at };
        });
    }
    async function releaseSubmission(profileId, brokerId, reason = "provider_write_not_started") {
        const cleanProfile = safeProfileId(profileId);
        const cleanBroker = safeBrokerId(brokerId);
        return withProfile(cleanProfile, (profile, at) => {
            const brokerCase = profile.brokers[cleanBroker];
            if (!brokerCase || brokerCase.state !== "submission_pending")
                throw new Error("rightout_submission_not_pending");
            transition(brokerCase, "action_selected", at, String(reason).slice(0, 80));
            brokerCase.submission_outcome = "not_started";
            brokerCase.submission_started_at = null;
            profile.brokers[cleanBroker] = brokerCase;
        });
    }
    async function recordSubmissionUncertain(profileId, brokerId, { channel, reason } = {}) {
        const cleanProfile = safeProfileId(profileId);
        const cleanBroker = safeBrokerId(brokerId);
        if (!["smtp_email", "browser_form"].includes(channel))
            throw new Error("invalid_submission_channel");
        return withProfile(cleanProfile, (profile, at) => {
            const brokerCase = profile.brokers[cleanBroker];
            if (!brokerCase || brokerCase.state !== "submission_pending" || brokerCase.submission_channel !== channel) {
                throw new Error("rightout_submission_not_pending");
            }
            transition(brokerCase, "submission_uncertain", at, "provider_write_outcome_ambiguous");
            brokerCase.submission_outcome = "uncertain";
            brokerCase.human_task_reason = String(reason ?? "reconcile_ambiguous_provider_write").slice(0, 80);
            brokerCase.next_recheck_at = null;
            profile.brokers[cleanBroker] = brokerCase;
        });
    }
    async function recordControllerOutcome(profileId, brokerId, outcome, broker) {
        const cleanProfile = safeProfileId(profileId);
        const cleanBroker = safeBrokerId(brokerId);
        const allowedOutcomes = new Set(["processing_acknowledged", "erasure_confirmed", "partial_erasure", "deletion_confirmed", "partial_deletion", "identity_required", "request_rejected"]);
        if (!allowedOutcomes.has(outcome))
            throw new Error("invalid_controller_outcome");
        if (!broker || broker.id !== cleanBroker || !["eu_controller_email_erasure", "us_data_broker_email_deletion"].includes(broker.process_class)
            || broker.removal?.confirmation_policy !== "submitted_until_controller_response")
            throw new Error("unsupported_controller_outcome_lane");
        const processingDays = broker.removal?.processing_days;
        if ((broker.process_class === "eu_controller_email_erasure" && processingDays !== 30)
            || (broker.process_class === "us_data_broker_email_deletion" && processingDays !== 45))
            throw new Error("unsupported_controller_outcome_lane");
        if ((broker.process_class === "eu_controller_email_erasure" && ["deletion_confirmed", "partial_deletion"].includes(outcome))
            || (broker.process_class === "us_data_broker_email_deletion" && ["erasure_confirmed", "partial_erasure"].includes(outcome)))
            throw new Error("unsupported_controller_outcome_lane");
        return withProfile(cleanProfile, (profile, at) => {
            const brokerCase = profile.brokers[cleanBroker];
            if (!brokerCase || !["submitted", "verification_pending", "awaiting_processing", "identity_verification_required", "partially_removed", "submission_uncertain"].includes(brokerCase.state)) {
                throw new Error("rightout_controller_outcome_not_ready");
            }
            const proof = opaqueEvidence("controller", [cleanProfile, cleanBroker, outcome, at]);
            if (brokerCase.state === "submission_uncertain") {
                transition(brokerCase, "submitted", at, "controller_response_proves_request_receipt");
            }
            const target = {
                processing_acknowledged: "awaiting_processing",
                erasure_confirmed: "confirmed_removed",
                partial_erasure: "partially_removed",
                deletion_confirmed: "confirmed_removed",
                partial_deletion: "partially_removed",
                identity_required: "identity_verification_required",
                request_rejected: "request_rejected",
            }[outcome];
            transition(brokerCase, target, at, `human_reviewed_controller_${outcome}`);
            brokerCase.proof_references = [...new Set([...brokerCase.proof_references, proof])].slice(-24);
            brokerCase.submission_outcome = outcome;
            brokerCase.human_task_reason = outcome === "identity_required"
                ? "proportionate_identity_review_required"
                : ["partial_erasure", "partial_deletion", "request_rejected"].includes(outcome)
                    ? "controller_outcome_review_required"
                    : null;
            if (target === "awaiting_processing")
                brokerCase.next_recheck_at = addDays(at, processingDays);
            if (target === "confirmed_removed") {
                brokerCase.removal_confirmed_at = at;
                brokerCase.removal_confirmation_scope = "controller_response_only";
                brokerCase.coverage_gap = "other_identifiers_or_controllers_not_checked";
                brokerCase.next_recheck_at = null;
            }
            profile.brokers[cleanBroker] = brokerCase;
            return { state: target, proof_reference: proof, confirmation_scope: brokerCase.removal_confirmation_scope };
        });
    }
    async function reconcileSubmission(profileId, brokerId, outcome, { processingDays = DEFAULT_PROCESSING_DAYS } = {}) {
        const cleanProfile = safeProfileId(profileId);
        const cleanBroker = safeBrokerId(brokerId);
        if (!['provider_write_not_started', 'provider_write_confirmed'].includes(outcome)) {
            throw new Error('invalid_submission_reconciliation');
        }
        if (!Number.isInteger(processingDays) || processingDays < 1 || processingDays > 365) {
            throw new Error('invalid_processing_window');
        }
        return withProfile(cleanProfile, (profile, at) => {
            const brokerCase = profile.brokers[cleanBroker];
            if (!brokerCase || !['submission_pending', 'submission_uncertain'].includes(brokerCase.state)) {
                throw new Error('rightout_submission_reconciliation_not_ready');
            }
            const channel = brokerCase.submission_channel;
            if (!['smtp_email', 'browser_form'].includes(channel))
                throw new Error('invalid_submission_channel');
            const proof = opaqueEvidence('reconcile', [cleanProfile, cleanBroker, channel, outcome, at]);
            brokerCase.proof_references = [...new Set([...brokerCase.proof_references, proof])].slice(-24);
            if (outcome === 'provider_write_not_started') {
                transition(brokerCase, 'action_selected', at, 'human_reviewed_provider_write_not_started');
                brokerCase.submission_outcome = 'human_reviewed_not_started';
                brokerCase.submission_started_at = null;
                brokerCase.next_recheck_at = null;
                brokerCase.human_task_reason = null;
            }
            else {
                transition(brokerCase, 'submitted', at, 'human_reviewed_provider_write_confirmed');
                brokerCase.submission_outcome = 'human_reviewed_provider_write_confirmed';
                brokerCase.human_task_reason = null;
                if (channel === 'browser_form') {
                    transition(brokerCase, 'verification_pending', at, 'human_reviewed_form_submission_confirmed');
                    brokerCase.next_recheck_at = addDays(at, 1);
                }
                else {
                    brokerCase.next_recheck_at = addDays(at, processingDays);
                }
            }
            profile.brokers[cleanBroker] = brokerCase;
            return { state: brokerCase.state, channel, proof_reference: proof };
        });
    }
    async function recordLifecycle(profileId, brokerId, state, options = {}) {
        const cleanProfile = safeProfileId(profileId);
        const cleanBroker = safeBrokerId(brokerId);
        const allowedEvidence = new Set(["broker_verification_link", "human_task"]);
        if (!allowedEvidence.has(options.evidenceKind))
            throw new Error("untrusted_lifecycle_evidence");
        if (state === "confirmed_removed" || state === "reappeared")
            throw new Error("trusted_rescan_or_controller_method_required");
        return withProfile(cleanProfile, (profile, at) => {
            const brokerCase = profile.brokers[cleanBroker] ?? newBrokerCase(cleanBroker, at);
            transition(brokerCase, state, at, options.evidenceKind);
            if (state === "verification_pending")
                brokerCase.next_recheck_at = addDays(at, 1);
            if (state === "awaiting_processing")
                brokerCase.next_recheck_at = addDays(at, options.processingDays ?? DEFAULT_PROCESSING_DAYS);
            if (state === "human_task_queued")
                brokerCase.human_task_reason = String(options.reason ?? "manual_step_required").slice(0, 80);
            if (typeof options.proofReference === "string") {
                const proof = safeStringArray([options.proofReference], SAFE_PROOF_REF, 1);
                brokerCase.proof_references = [...new Set([...brokerCase.proof_references, ...proof])].slice(-24);
            }
            profile.brokers[cleanBroker] = brokerCase;
        });
    }
    async function removalContext(profileId, brokerId) {
        const profile = await load(profileId);
        const cleanBroker = safeBrokerId(brokerId);
        const brokerCase = profile.brokers[cleanBroker];
        if (brokerCase && ["submission_pending", "submission_uncertain", "submitted", "verification_pending", "awaiting_processing", "identity_verification_required"].includes(brokerCase.state)) {
            throw new Error("rightout_removal_already_in_flight");
        }
        if (brokerCase?.state === "confirmed_removed")
            throw new Error("rightout_removal_already_confirmed");
        if (!brokerCase || !["found", "indirect_exposure", "action_selected", "reappeared"].includes(brokerCase.state)) {
            throw new Error("rightout_discovery_required_before_removal");
        }
        const discoveryProof = [...brokerCase.proof_references].reverse().find((value) => /^(?:scan|direct)_/.test(value));
        if (!discoveryProof)
            throw new Error("rightout_discovery_required_before_removal");
        return { state: brokerCase.state, discovery_proof_reference: discoveryProof, observed_at: brokerCase.last_observation?.at ?? null };
    }
    async function verificationContext(profileId, brokerId, allowedStates = ["submitted", "verification_pending"]) {
        const profile = await load(profileId);
        const cleanBroker = safeBrokerId(brokerId);
        const brokerCase = profile.brokers[cleanBroker];
        if (!brokerCase || !allowedStates.includes(brokerCase.state))
            throw new Error("rightout_verification_case_not_ready");
        const submitted = [...brokerCase.history].reverse().find((entry) => entry.to === "submitted");
        const submissionProof = [...brokerCase.proof_references].reverse().find((value) => /^(?:smtp|form)_/.test(value));
        if (!submitted || !submissionProof)
            throw new Error("rightout_verification_case_not_ready");
        return {
            state: brokerCase.state,
            submitted_at: submitted.at,
            submission_proof_reference: submissionProof,
        };
    }
    async function plan(profileId, catalog) {
        const profile = await load(profileId);
        const generatedAt = now().toISOString();
        const rows = catalogRows(catalog).map((broker) => {
            const brokerCase = profile.brokers[broker.id] ?? newBrokerCase(broker.id, profile.updated_at);
            const lane = laneFor(broker);
            const cluster = broker.ownership_cluster;
            const officialActionUrl = safeOfficialActionUrl(broker);
            return {
                broker_id: broker.id,
                state: brokerCase.state,
                lane,
                tier: tierFor(broker, lane),
                next_action: nextActionFor(broker, brokerCase, generatedAt),
                human_only: broker.human_only === true,
                category: safeMetadataToken(broker.category, "unclassified"),
                process_class: safeMetadataToken(broker.process_class, "unclassified"),
                prerequisites: safeStringArray(broker.prerequisites ?? [], /^[a-z0-9_]{2,64}$/, 24),
                next_recheck_at: brokerCase.next_recheck_at,
                ...(SAFE_LISTING_HANDLE.test(brokerCase.listing_handle ?? "") ? { listing_handle: brokerCase.listing_handle } : {}),
                ...(officialActionUrl ? {
                    official_action_url: officialActionUrl,
                    ...(broker.eu_process && typeof broker.eu_process === "object" ? {
                        effect_scope: safeMetadataToken(broker.eu_process.effect_scope),
                        erasure_semantics: safeMetadataToken(broker.eu_process.erasure_semantics),
                        one_click_level: safeMetadataToken(broker.eu_process.one_click_level, "none"),
                    } : broker.us_process && typeof broker.us_process === "object" ? {
                        effect_scope: safeMetadataToken(broker.us_process.effect_scope),
                        deletion_semantics: safeMetadataToken(broker.us_process.deletion_semantics),
                        legal_scope: safeMetadataToken(broker.us_process.legal_scope),
                        one_click_level: safeMetadataToken(broker.us_process.one_click_level, "none"),
                    } : {}),
                } : {}),
                ...(cluster ? {
                    cluster_id: cluster.id,
                    parent_broker_id: cluster.parent_broker_id,
                    cluster_role: cluster.role,
                    cluster_coverage_policy: cluster.coverage_policy ?? null,
                } : {}),
            };
        });
        const byId = new Map(rows.map((row) => [row.broker_id, row]));
        for (const row of rows) {
            if (row.cluster_role !== "child"
                || row.cluster_coverage_policy !== "official_registry_claims_one_site_request_applies_across_cluster"
                || !["found", "indirect_exposure", "reappeared", "action_selected"].includes(row.state))
                continue;
            const parent = byId.get(row.parent_broker_id);
            if (parent && ["found", "indirect_exposure", "reappeared", "action_selected", "submitted", "verification_pending", "awaiting_processing", "confirmed_removed"].includes(parent.state)) {
                row.next_action = "wait_for_cluster_parent";
            }
        }
        const order = { reconcile_submission: 0, run_direct_rescan: 1, refresh_discovery_for_direct_handle: 2, refresh_catalog: 3, run_discovery: 4, poll_verification: 5, submit_email_removal: 6, submit_browser_form: 7, follow_up_controller_response_human: 8, review_provider_status_human: 9, queue_human_task: 10, complete_human_task: 11, complete_identity_verification_human_task: 12, review_partial_controller_outcome: 13, review_rejection_or_escalate: 14, retry_or_route_human: 15, wait_for_cluster_parent: 16, wait_for_processing_window: 17, wait_for_due_direct_rescan: 18, wait_for_controller_response: 19, wait_for_reappearance_recheck: 20 };
        rows.sort((a, b) => {
            const actionOrder = (order[a.next_action] ?? 99) - (order[b.next_action] ?? 99);
            if (actionOrder)
                return actionOrder;
            if (a.cluster_id && a.cluster_id === b.cluster_id) {
                const roleOrder = { parent: 0, child: 1, separate_optout_child: 2 };
                const clustered = (roleOrder[a.cluster_role] ?? 9) - (roleOrder[b.cluster_role] ?? 9);
                if (clustered)
                    return clustered;
            }
            return a.broker_id.localeCompare(b.broker_id);
        });
        const reconciliationRequired = rows.filter((row) => row.next_action === "reconcile_submission").length;
        const approvalGatedNow = rows.filter((row) => ["run_discovery", "run_direct_rescan", "submit_email_removal", "submit_browser_form", "poll_verification"].includes(row.next_action)).length;
        const operatorHandoffs = rows.filter((row) => row.human_only || row.next_action.endsWith("_human") || row.next_action.includes("human_task")).length;
        const executableWriteTargets = rows.filter((row) => ["email", "browser_form"].includes(row.lane)).length;
        const effectiveClusterChildren = rows.filter((row) => {
            if (row.cluster_role !== "child" || row.cluster_coverage_policy !== "official_registry_claims_one_site_request_applies_across_cluster")
                return false;
            return ["email", "browser_form"].includes(byId.get(row.parent_broker_id)?.lane);
        }).length;
        return {
            report_version: 1,
            subject_ref: profile.subject_ref,
            generated_at: generatedAt,
            actions: rows,
            summary: {
                total: rows.length,
                actionable_now: rows.filter((row) => !row.next_action.startsWith("wait_")).length,
                human_tasks: rows.filter((row) => ["queue_human_task", "complete_human_task", "retry_or_route_human"].includes(row.next_action)).length,
                eu_processes: rows.filter((row) => row.process_class.startsWith("eu_")).length,
                us_executable_processes: rows.filter((row) => row.process_class.startsWith("us_") && ["email", "browser_form"].includes(row.lane)).length,
                executable_write_targets: executableWriteTargets,
                effective_write_coverage_targets: executableWriteTargets + effectiveClusterChildren,
            },
            campaign: {
                resume_mode: reconciliationRequired > 0 ? "reconcile_before_external_writes" : approvalGatedNow > 0 ? "approval_gated_actions_available" : "waiting_or_human_handoff",
                reconciliation_required: reconciliationRequired,
                approval_gated_actions_now: approvalGatedNow,
                operator_handoffs: operatorHandoffs,
                autonomous_without_approval: false,
                autonomous_after_exact_approvals: reconciliationRequired === 0,
            },
            invariants: { raw_pii_in_report: false, provider_writes: 0 },
        };
    }
    async function due(profileId, at = now().toISOString()) {
        const when = safeDate(at, "due_timestamp");
        const profile = await load(profileId);
        const rows = Object.values(profile.brokers)
            .filter((item) => item.next_recheck_at && item.next_recheck_at <= when)
            .sort((a, b) => a.next_recheck_at.localeCompare(b.next_recheck_at))
            .map((item) => ({
            broker_id: item.broker_id,
            state: item.state,
            next_recheck_at: item.next_recheck_at,
            listing_handle: SAFE_LISTING_HANDLE.test(item.listing_handle ?? "") ? item.listing_handle : null,
            next_action: "call_rightout_next_actions_for_catalog_bound_resume",
        }));
        return { report_version: 1, subject_ref: profile.subject_ref, generated_at: when, due: rows, raw_pii_in_report: false };
    }
    async function status(profileId) {
        const profile = await load(profileId);
        const counts = Object.fromEntries(CASE_STATES.map((state) => [state, 0]));
        for (const brokerCase of Object.values(profile.brokers))
            counts[brokerCase.state] += 1;
        const cases = Object.values(profile.brokers).sort((a, b) => a.broker_id.localeCompare(b.broker_id)).map((item) => ({
            broker_id: item.broker_id,
            state: item.state,
            listing_handle: SAFE_LISTING_HANDLE.test(item.listing_handle ?? "") ? item.listing_handle : null,
            direct_absence_observed_at: item.direct_absence_observed_at ?? null,
            next_recheck_at: item.next_recheck_at,
            removal_confirmed_at: item.removal_confirmed_at,
            removal_confirmation_scope: item.removal_confirmation_scope ?? null,
            coverage_gap: item.coverage_gap ?? null,
            proof_references: item.proof_references,
            disclosure_fields: item.disclosure_fields,
            submission_channel: item.submission_channel ?? null,
            submission_started_at: item.submission_started_at ?? null,
            submission_outcome: item.submission_outcome ?? null,
            human_task_reason: item.human_task_reason,
        }));
        return {
            report_version: 1,
            subject_ref: profile.subject_ref,
            generated_at: now().toISOString(),
            counts,
            metrics: {
                confirmed_removed: counts.confirmed_removed,
                in_flight: counts.submitted + counts.verification_pending + counts.awaiting_processing,
                uncertain: counts.submission_pending + counts.submission_uncertain,
                needs_reconciliation: counts.submission_pending + counts.submission_uncertain,
                open: counts.found + counts.indirect_exposure + counts.reappeared + counts.action_selected,
                human_tasks: counts.human_task_queued,
                blocked: counts.blocked,
            },
            cases,
            invariants: { raw_pii_in_report: false },
        };
    }
    async function purge(profileId) {
        const key = safeProfileId(profileId);
        return store.delete(key);
    }
    return { load, ensure, reserveSubmission, releaseSubmission, recordSubmissionUncertain, reconcileSubmission, recordControllerOutcome, recordScan, recordRemoval, recordFormSubmission, recordDirectRescan, recordLifecycle, removalContext, verificationContext, purge, plan, due, status };
}
export const __test = { transition, laneFor, tierFor, nextActionFor, opaqueEvidence };
