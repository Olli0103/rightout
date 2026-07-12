import { createHash } from "node:crypto";

const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_PROOF_REF = /^(?:scan|smtp|form|mail|verify|direct)_[a-f0-9]{16,64}$/;
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
  "submitted",
  "verification_pending",
  "awaiting_processing",
  "confirmed_removed",
  "reappeared",
  "human_task_queued",
  "blocked",
]);

const TRANSITIONS = new Map([
  ["new", new Set(["searching", "inconclusive", "not_found", "found", "indirect_exposure", "human_task_queued", "blocked"])],
  ["searching", new Set(["inconclusive", "not_found", "found", "indirect_exposure", "human_task_queued", "blocked"])],
  ["inconclusive", new Set(["searching", "inconclusive", "not_found", "found", "indirect_exposure", "human_task_queued", "blocked"])],
  ["not_found", new Set(["searching", "inconclusive", "found", "indirect_exposure", "human_task_queued", "blocked"])],
  ["found", new Set(["action_selected", "submitted", "inconclusive", "not_found", "indirect_exposure", "human_task_queued", "blocked"])],
  ["indirect_exposure", new Set(["action_selected", "submitted", "inconclusive", "not_found", "found", "human_task_queued", "blocked"])],
  ["action_selected", new Set(["submitted", "inconclusive", "not_found", "found", "human_task_queued", "blocked"])],
  ["submitted", new Set(["verification_pending", "awaiting_processing", "found", "human_task_queued", "blocked"])],
  ["verification_pending", new Set(["awaiting_processing", "found", "human_task_queued", "blocked"])],
  ["awaiting_processing", new Set(["confirmed_removed", "found", "human_task_queued", "blocked"])],
  ["confirmed_removed", new Set(["confirmed_removed", "reappeared"])],
  ["reappeared", new Set(["found", "inconclusive", "not_found", "indirect_exposure", "action_selected", "submitted", "human_task_queued", "blocked"])],
  ["human_task_queued", new Set(["searching", "inconclusive", "not_found", "found", "indirect_exposure", "action_selected", "submitted", "verification_pending", "awaiting_processing", "confirmed_removed", "blocked"])],
  ["blocked", new Set(["searching", "inconclusive", "not_found", "found", "indirect_exposure", "action_selected", "human_task_queued"])],
]);

function safeProfileId(value) {
  if (typeof value !== "string" || !SAFE_PROFILE_ID.test(value)) throw new Error("invalid_profile_ref");
  return value;
}

function safeBrokerId(value) {
  if (typeof value !== "string" || !SAFE_BROKER_ID.test(value)) throw new Error("invalid_broker_id");
  return value;
}

function safeDate(value, label = "timestamp") {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw new Error(`invalid_${label}`);
  return new Date(value).toISOString();
}

function safeStringArray(values, pattern, max = 24) {
  if (!Array.isArray(values) || values.length > max) throw new Error("invalid_case_evidence");
  const out = [...new Set(values)];
  if (out.length !== values.length || !out.every((value) => typeof value === "string" && pattern.test(value))) {
    throw new Error("invalid_case_evidence");
  }
  return out.sort();
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
    proof_references: [],
    disclosure_fields: [],
    next_recheck_at: null,
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
  if (!CASE_STATES.includes(state)) throw new Error("invalid_case_state");
  const old = brokerCase.state;
  if (state !== old && !TRANSITIONS.get(old)?.has(state)) throw new Error("illegal_case_transition");
  brokerCase.state = state;
  brokerCase.updated_at = at;
  brokerCase.history = [...brokerCase.history, { at, from: old, to: state, reason }].slice(-MAX_HISTORY);
}

function sanitizeStoredProfile(value, profileId) {
  if (!value) return undefined;
  if (value.schema_version !== 1 || value.subject_ref !== profileId || !value.brokers || typeof value.brokers !== "object") {
    throw new Error("rightout_case_store_invalid");
  }
  return structuredClone(value);
}

function opaqueEvidence(prefix, parts) {
  return `${prefix}_${createHash("sha256").update(JSON.stringify(parts)).digest("hex").slice(0, 24)}`;
}

function catalogRows(catalog) {
  if (!catalog || !Array.isArray(catalog.brokers)) throw new Error("catalog_invalid");
  return catalog.brokers.filter((entry) => entry && typeof entry === "object" && SAFE_BROKER_ID.test(entry.id));
}

function laneFor(broker) {
  if (broker.removal?.supported === true && broker.removal?.channel === "email") return "email";
  if (broker.removal?.supported === true && broker.removal?.channel === "browser_form") return "browser_form";
  if (broker.lane === "registry") return "registry";
  if (broker.human_only === true || broker.lane === "human_task") return "human_task";
  if (broker.scan?.supported === true) return "scan_only";
  return "unsupported";
}

function tierFor(broker, lane) {
  if (lane === "email") return "T1";
  if (lane === "browser_form" && broker.removal?.requires?.captcha !== true) return "T1";
  if (lane === "browser_form") return "T2";
  if (lane === "scan_only") return "T2";
  return "T3";
}

function nextActionFor(broker, brokerCase) {
  if (brokerCase.state === "confirmed_removed") return "wait_for_reappearance_recheck";
  if (["submitted", "verification_pending"].includes(brokerCase.state)) return "poll_verification";
  if (brokerCase.state === "awaiting_processing") return "wait_for_due_direct_rescan";
  if (brokerCase.state === "human_task_queued") return "complete_human_task";
  if (brokerCase.state === "blocked") return "retry_or_route_human";
  if (["found", "indirect_exposure", "reappeared", "action_selected"].includes(brokerCase.state)) {
    const lane = laneFor(broker);
    if (lane === "email") return "submit_email_removal";
    if (lane === "browser_form") return "submit_browser_form";
    return "queue_human_task";
  }
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
    } finally {
      release();
      if (locks.get(key) === chain) locks.delete(key);
    }
  }

  async function load(profileId) {
    const key = safeProfileId(profileId);
    return sanitizeStoredProfile(await store.lookup(key), key) ?? newProfileCase(key, now().toISOString());
  }

  async function ensure(profileId, brokerIds = []) {
    const ids = safeStringArray(brokerIds, SAFE_BROKER_ID, 100);
    return withProfile(profileId, (profile, at) => {
      for (const brokerId of ids) profile.brokers[brokerId] ??= newBrokerCase(brokerId, at);
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
        if (!["indirect_exposure", "inconclusive"].includes(result?.state)) throw new Error("invalid_scan_report");
        const brokerCase = profile.brokers[brokerId] ?? newBrokerCase(brokerId, scanAt);
        brokerCase.last_observation = {
          at: scanAt,
          kind: "search_index",
          state: result.state,
          reason: String(result.reason).slice(0, 80),
        };
        const proofRef = opaqueEvidence("scan", [report.scan_id, brokerId, result.state, scanAt]);
        brokerCase.proof_references = [...new Set([...brokerCase.proof_references, proofRef])].slice(-24);
        if (brokerCase.state === "confirmed_removed") {
          // Search-index results can be stale and cannot prove reappearance.
          transition(brokerCase, "confirmed_removed", scanAt, "index_observation_did_not_change_confirmed_state");
        } else if (!["submitted", "verification_pending", "awaiting_processing"].includes(brokerCase.state)) {
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
    if (!Number.isInteger(processingDays) || processingDays < 1 || processingDays > 365) throw new Error("invalid_processing_window");
    return withProfile(profileId, (profile) => {
      const brokerCase = profile.brokers[brokerId] ?? newBrokerCase(brokerId, at);
      if (!["found", "indirect_exposure", "action_selected", "reappeared"].includes(brokerCase.state)) {
        throw new Error("illegal_case_transition");
      }
      transition(brokerCase, "submitted", at, "approved_email_submission");
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
      if (!["found", "indirect_exposure", "action_selected", "reappeared"].includes(brokerCase.state)) throw new Error("illegal_case_transition");
      transition(brokerCase, "submitted", at, "approved_browser_form_submission");
      transition(brokerCase, "verification_pending", at, "broker_email_control_required");
      brokerCase.proof_references = [...new Set([...brokerCase.proof_references, ...proof])].slice(-24);
      brokerCase.disclosure_fields = disclosures;
      brokerCase.next_recheck_at = addDays(at, 1);
      profile.brokers[brokerId] = brokerCase;
    });
  }

  async function recordDirectRescan(report, rescanDays = DEFAULT_RESCAN_DAYS) {
    if (
      !report || !["direct_present", "direct_absent_known_listing_set", "inconclusive"].includes(report.observation)
      || report.removal_confirmation_scope !== "known_listing_set_only"
      || !Array.isArray(report.proof_references)
    ) throw new Error("invalid_direct_rescan_report");
    if (!Number.isInteger(rescanDays) || rescanDays < 1 || rescanDays > 365) throw new Error("invalid_rescan_window");
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
        if (brokerCase.state === "confirmed_removed") transition(brokerCase, "reappeared", at, "trusted_direct_rescan_present");
        else if (brokerCase.state !== "found") transition(brokerCase, "found", at, "trusted_direct_rescan_present");
        brokerCase.next_recheck_at = null;
        brokerCase.removal_confirmation_scope = null;
        brokerCase.coverage_gap = null;
        if (brokerCase.state !== "confirmed_removed") brokerCase.removal_confirmed_at = null;
      } else if (report.observation === "direct_absent_known_listing_set") {
        brokerCase.removal_confirmation_scope = "known_listing_set_only";
        brokerCase.coverage_gap = "new_or_unindexed_listing_urls_not_checked";
        if (["submitted", "verification_pending"].includes(brokerCase.state)) {
          transition(brokerCase, "awaiting_processing", at, "trusted_direct_rescan_absent");
        }
        if (brokerCase.state === "awaiting_processing") transition(brokerCase, "confirmed_removed", at, "trusted_direct_rescan_absent");
        else if (brokerCase.state !== "confirmed_removed") transition(brokerCase, "not_found", at, "trusted_direct_rescan_absent_known_listing_set");
        if (brokerCase.state === "confirmed_removed") {
          brokerCase.removal_confirmed_at = at;
          brokerCase.next_recheck_at = addDays(at, rescanDays);
        }
      } else if (!["submitted", "verification_pending", "awaiting_processing", "confirmed_removed"].includes(brokerCase.state)) {
        transition(brokerCase, "inconclusive", at, "direct_rescan_inconclusive");
      }
      profile.brokers[brokerId] = brokerCase;
    });
  }

  async function recordLifecycle(profileId, brokerId, state, options = {}) {
    const cleanProfile = safeProfileId(profileId);
    const cleanBroker = safeBrokerId(brokerId);
    const allowedEvidence = new Set(["trusted_direct_rescan_absent", "trusted_direct_rescan_present", "broker_verification_link", "human_task"]);
    if (!allowedEvidence.has(options.evidenceKind)) throw new Error("untrusted_lifecycle_evidence");
    if (state === "confirmed_removed" && options.evidenceKind !== "trusted_direct_rescan_absent") {
      throw new Error("confirmed_removal_requires_direct_rescan");
    }
    if (state === "reappeared" && options.evidenceKind !== "trusted_direct_rescan_present") {
      throw new Error("reappearance_requires_direct_rescan");
    }
    return withProfile(cleanProfile, (profile, at) => {
      const brokerCase = profile.brokers[cleanBroker] ?? newBrokerCase(cleanBroker, at);
      transition(brokerCase, state, at, options.evidenceKind);
      if (state === "verification_pending") brokerCase.next_recheck_at = addDays(at, 1);
      if (state === "awaiting_processing") brokerCase.next_recheck_at = addDays(at, options.processingDays ?? DEFAULT_PROCESSING_DAYS);
      if (state === "confirmed_removed") {
        brokerCase.removal_confirmed_at = at;
        brokerCase.next_recheck_at = addDays(at, options.rescanDays ?? DEFAULT_RESCAN_DAYS);
      }
      if (state === "reappeared") brokerCase.next_recheck_at = null;
      if (state === "human_task_queued") brokerCase.human_task_reason = String(options.reason ?? "manual_step_required").slice(0, 80);
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
    if (brokerCase && ["submitted", "verification_pending", "awaiting_processing"].includes(brokerCase.state)) {
      throw new Error("rightout_removal_already_in_flight");
    }
    if (brokerCase?.state === "confirmed_removed") throw new Error("rightout_removal_already_confirmed");
    if (!brokerCase || !["found", "indirect_exposure", "action_selected", "reappeared"].includes(brokerCase.state)) {
      throw new Error("rightout_discovery_required_before_removal");
    }
    const discoveryProof = [...brokerCase.proof_references].reverse().find((value) => /^(?:scan|direct)_/.test(value));
    if (!discoveryProof) throw new Error("rightout_discovery_required_before_removal");
    return { state: brokerCase.state, discovery_proof_reference: discoveryProof, observed_at: brokerCase.last_observation?.at ?? null };
  }

  async function verificationContext(profileId, brokerId, allowedStates = ["submitted", "verification_pending"]) {
    const profile = await load(profileId);
    const cleanBroker = safeBrokerId(brokerId);
    const brokerCase = profile.brokers[cleanBroker];
    if (!brokerCase || !allowedStates.includes(brokerCase.state)) throw new Error("rightout_verification_case_not_ready");
    const submitted = [...brokerCase.history].reverse().find((entry) => entry.to === "submitted");
    const submissionProof = [...brokerCase.proof_references].reverse().find((value) => /^(?:smtp|form)_/.test(value));
    if (!submitted || !submissionProof) throw new Error("rightout_verification_case_not_ready");
    return {
      state: brokerCase.state,
      submitted_at: submitted.at,
      submission_proof_reference: submissionProof,
    };
  }

  async function plan(profileId, catalog) {
    const profile = await load(profileId);
    const rows = catalogRows(catalog).map((broker) => {
      const brokerCase = profile.brokers[broker.id] ?? newBrokerCase(broker.id, profile.updated_at);
      const lane = laneFor(broker);
      const cluster = broker.ownership_cluster;
      return {
        broker_id: broker.id,
        state: brokerCase.state,
        lane,
        tier: tierFor(broker, lane),
        next_action: nextActionFor(broker, brokerCase),
        human_only: broker.human_only === true,
        prerequisites: safeStringArray(broker.prerequisites ?? [], /^[a-z0-9_]{2,64}$/, 24),
        next_recheck_at: brokerCase.next_recheck_at,
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
      if (
        row.cluster_role !== "child"
        || row.cluster_coverage_policy !== "official_registry_claims_one_site_request_applies_across_cluster"
        || !["found", "indirect_exposure", "reappeared", "action_selected"].includes(row.state)
      ) continue;
      const parent = byId.get(row.parent_broker_id);
      if (parent && ["found", "indirect_exposure", "reappeared", "action_selected", "submitted", "verification_pending", "awaiting_processing", "confirmed_removed"].includes(parent.state)) {
        row.next_action = "wait_for_cluster_parent";
      }
    }
    const order = { refresh_catalog: 0, run_discovery: 1, poll_verification: 2, wait_for_due_direct_rescan: 3, submit_email_removal: 4, submit_browser_form: 5, queue_human_task: 6, complete_human_task: 7, retry_or_route_human: 8, wait_for_cluster_parent: 9, wait_for_reappearance_recheck: 10 };
    rows.sort((a, b) => {
      const actionOrder = (order[a.next_action] ?? 99) - (order[b.next_action] ?? 99);
      if (actionOrder) return actionOrder;
      if (a.cluster_id && a.cluster_id === b.cluster_id) {
        const roleOrder = { parent: 0, child: 1, separate_optout_child: 2 };
        const clustered = (roleOrder[a.cluster_role] ?? 9) - (roleOrder[b.cluster_role] ?? 9);
        if (clustered) return clustered;
      }
      return a.broker_id.localeCompare(b.broker_id);
    });
    return {
      report_version: 1,
      subject_ref: profile.subject_ref,
      generated_at: now().toISOString(),
      actions: rows,
      summary: {
        total: rows.length,
        actionable_now: rows.filter((row) => !row.next_action.startsWith("wait_")).length,
        human_tasks: rows.filter((row) => ["queue_human_task", "complete_human_task", "retry_or_route_human"].includes(row.next_action)).length,
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
      .map((item) => ({ broker_id: item.broker_id, state: item.state, next_recheck_at: item.next_recheck_at }));
    return { report_version: 1, subject_ref: profile.subject_ref, generated_at: when, due: rows, raw_pii_in_report: false };
  }

  async function status(profileId) {
    const profile = await load(profileId);
    const counts = Object.fromEntries(CASE_STATES.map((state) => [state, 0]));
    for (const brokerCase of Object.values(profile.brokers)) counts[brokerCase.state] += 1;
    const cases = Object.values(profile.brokers).sort((a, b) => a.broker_id.localeCompare(b.broker_id)).map((item) => ({
      broker_id: item.broker_id,
      state: item.state,
      next_recheck_at: item.next_recheck_at,
      removal_confirmed_at: item.removal_confirmed_at,
      removal_confirmation_scope: item.removal_confirmation_scope ?? null,
      coverage_gap: item.coverage_gap ?? null,
      proof_references: item.proof_references,
      disclosure_fields: item.disclosure_fields,
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

  return { load, ensure, recordScan, recordRemoval, recordFormSubmission, recordDirectRescan, recordLifecycle, removalContext, verificationContext, purge, plan, due, status };
}

export const __test = { transition, laneFor, tierFor, nextActionFor, opaqueEvidence };
