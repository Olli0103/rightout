import { createHash, randomBytes } from "node:crypto";

const SAFE_WORKER_ID = /^worker_[a-f0-9]{32}$/;
const SAFE_LEASE_ID = /^lease_[a-f0-9]{32}$/;
const SAFE_CAMPAIGN_ID = /^campaign_[a-f0-9]{32}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,80}$/;
const SAFE_LISTING_HANDLE = /^listing_[a-f0-9]{24}$/;
const SAFE_VERIFICATION_HANDLE = /^verify_[a-f0-9]{24}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const SAFE_RESULT_STATE = /^[a-z0-9_]{2,120}$/;

const TOOL_PARAMETER_KEYS = Object.freeze({
  rightout_live_scan: ["profileId", "brokerIds", "campaignId"],
  rightout_begin_discovery_session: ["profileId", "brokerId", "campaignId", "browserBackend"],
  rightout_submit_removal: ["profileId", "brokerId", "requestKind", "campaignId"],
  rightout_submit_parity_email: ["profileId", "brokerId", "campaignId", "listingHandle"],
  rightout_begin_webmail_session: ["profileId", "brokerId", "campaignId", "listingHandle"],
  rightout_begin_form_session: ["profileId", "brokerId", "campaignId", "listingHandle"],
  rightout_poll_verification: ["profileId", "brokerId", "campaignId"],
  rightout_begin_webmail_verification: ["profileId", "brokerId", "campaignId"],
  rightout_open_verification: ["profileId", "brokerId", "verificationHandle", "campaignId"],
  rightout_direct_rescan: ["profileId", "brokerId", "listingHandle", "campaignId"],
});

const TOOL_EFFECT = Object.freeze({
  rightout_live_scan: "discover",
  rightout_begin_discovery_session: "publisher_discover",
  rightout_submit_removal: "submit_email",
  rightout_submit_parity_email: "submit_email",
  rightout_begin_webmail_session: "submit_email",
  rightout_begin_form_session: "submit_form",
  rightout_poll_verification: "poll_verification",
  rightout_begin_webmail_verification: "poll_verification",
  rightout_open_verification: "open_verification",
  rightout_direct_rescan: "direct_recheck",
});

const REQUEST_KINDS = new Set(["delete_and_opt_out", "gdpr_erasure_objection"]);
const WORKER_STATES = new Set(["active", "paused", "human_gate", "done", "revoked"]);

function parseIso(value, error = "rightout_worker_state_invalid") {
  const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
  if (!Number.isFinite(parsed)) throw new Error(error);
  return parsed;
}

function validateCampaign(campaign) {
  if (
    !campaign || typeof campaign !== "object" || Array.isArray(campaign)
    || !SAFE_CAMPAIGN_ID.test(campaign.campaign_id ?? "")
    || !SAFE_PROFILE_ID.test(campaign.subject_ref ?? "")
    || !["active", "completed", "revoked"].includes(campaign.status)
    || !Array.isArray(campaign.broker_ids)
    || campaign.broker_ids.length < 1
    || campaign.broker_ids.some((id) => !SAFE_BROKER_ID.test(id))
    || !Array.isArray(campaign.effects)
  ) throw new Error("rightout_worker_campaign_invalid");
  return campaign;
}

function validateWorkerRecord(record) {
  if (
    !record || typeof record !== "object" || Array.isArray(record)
    || record.schemaVersion !== 1
    || !SAFE_WORKER_ID.test(record.workerId ?? "")
    || !SAFE_CAMPAIGN_ID.test(record.campaignId ?? "")
    || !SAFE_PROFILE_ID.test(record.profileId ?? "")
    || !Array.isArray(record.brokerIds) || record.brokerIds.length < 1
    || record.brokerIds.some((id) => !SAFE_BROKER_ID.test(id)) || new Set(record.brokerIds).size !== record.brokerIds.length
    || !Array.isArray(record.effects) || record.effects.length < 1
    || record.effects.some((effect) => typeof effect !== "string" || !/^[a-z_]{3,32}$/.test(effect))
    || !SAFE_SHA256.test(record.policyDigest ?? "")
    || !SAFE_SHA256.test(record.sessionBindingDigest ?? "")
    || !record.sessionRoute || typeof record.sessionRoute !== "object" || Array.isArray(record.sessionRoute)
    || workerSessionBindingDigest(record.sessionRoute) !== record.sessionBindingDigest
    || !WORKER_STATES.has(record.status)
    || !Number.isInteger(record.intervalMinutes) || record.intervalMinutes < 5 || record.intervalMinutes > 1_440
    || !Number.isInteger(record.maxConsecutiveFailures) || record.maxConsecutiveFailures < 1 || record.maxConsecutiveFailures > 10
    || !Number.isInteger(record.consecutiveFailures) || record.consecutiveFailures < 0
    || !Number.isInteger(record.actionsCompleted) || record.actionsCompleted < 0
  ) throw new Error("rightout_worker_state_invalid");
  parseIso(record.createdAt);
  parseIso(record.updatedAt);
  if (record.nextWakeAt !== null) parseIso(record.nextWakeAt);
  if (record.lease !== null) {
    if (
      typeof record.lease !== "object" || Array.isArray(record.lease)
      || !SAFE_LEASE_ID.test(record.lease.leaseId ?? "")
      || !Number.isFinite(record.lease.claimedAt)
      || !Number.isFinite(record.lease.expiresAt)
      || record.lease.expiresAt <= record.lease.claimedAt
    ) throw new Error("rightout_worker_state_invalid");
    if (record.lease.plan !== null) validateStoredPlan(record.lease.plan);
  }
  return record;
}

function validateStoredPlan(plan) {
  if (
    !plan || typeof plan !== "object" || Array.isArray(plan)
    || typeof plan.tool !== "string" || !TOOL_PARAMETER_KEYS[plan.tool]
    || !SAFE_SHA256.test(plan.commandDigest ?? "")
    || !SAFE_SHA256.test(plan.executionDigest ?? "")
    || typeof plan.reason !== "string" || !/^[a-z0-9_]{3,120}$/.test(plan.reason)
    || !Number.isFinite(plan.issuedAt)
    || !Number.isInteger(plan.campaignUsedEffectsBaseline) || plan.campaignUsedEffectsBaseline < 0
    || (plan.campaignLastEffectReferenceBaseline !== null
      && (typeof plan.campaignLastEffectReferenceBaseline !== "string" || !/^effect_[a-f0-9]{24}$/.test(plan.campaignLastEffectReferenceBaseline)))
  ) throw new Error("rightout_worker_state_invalid");
  if (plan.receipt !== null) {
    if (
      !plan.receipt || typeof plan.receipt !== "object" || Array.isArray(plan.receipt)
      || !["completed", "human_gate"].includes(plan.receipt.state)
      || plan.receipt.executionDigest !== plan.executionDigest
      || !SAFE_RESULT_STATE.test(plan.receipt.resultState ?? "")
      || !Number.isFinite(plan.receipt.observedAt)
    ) throw new Error("rightout_worker_state_invalid");
  }
}

function publicWorker(record) {
  const worker = validateWorkerRecord(record);
  return {
    worker_id: worker.workerId,
    campaign_id: worker.campaignId,
    subject_ref: worker.profileId,
    broker_ids: [...worker.brokerIds],
    effects: [...worker.effects],
    status: worker.status,
    interval_minutes: worker.intervalMinutes,
    next_wake_at: worker.nextWakeAt,
    consecutive_failures: worker.consecutiveFailures,
    max_consecutive_failures: worker.maxConsecutiveFailures,
    actions_completed: worker.actionsCompleted,
    lease_active: worker.lease !== null,
    unresolved_action: worker.lease?.plan !== null,
    last_reason: worker.lastReason ?? null,
    created_at: worker.createdAt,
    updated_at: worker.updatedAt,
    raw_pii_in_report: false,
  };
}

function cleanWorkerCreateInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_worker_input_invalid");
  const allowed = new Set(["campaignId", "intervalMinutes", "maxConsecutiveFailures"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error("rightout_worker_input_invalid");
  if (!SAFE_CAMPAIGN_ID.test(value.campaignId ?? "")) throw new Error("rightout_worker_input_invalid");
  if (!Number.isInteger(value.intervalMinutes) || value.intervalMinutes < 5 || value.intervalMinutes > 1_440) {
    throw new Error("rightout_worker_input_invalid");
  }
  if (!Number.isInteger(value.maxConsecutiveFailures) || value.maxConsecutiveFailures < 1 || value.maxConsecutiveFailures > 10) {
    throw new Error("rightout_worker_input_invalid");
  }
  return {
    campaignId: value.campaignId,
    intervalMinutes: value.intervalMinutes,
    maxConsecutiveFailures: value.maxConsecutiveFailures,
  };
}

export function workerSessionBindingDigest({ sessionKey, agentId }) {
  if (
    typeof sessionKey !== "string" || !/^[A-Za-z0-9._:@/-]{8,240}$/.test(sessionKey)
    || typeof agentId !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(agentId)
  ) throw new Error("rightout_worker_session_required");
  return createHash("sha256").update(JSON.stringify(["rightout-worker-session-v1", sessionKey, agentId])).digest("hex");
}

export function workerPolicyDigest({ catalogDigest, recipeDigest, runtimeScopeDigest }) {
  if (![catalogDigest, recipeDigest, runtimeScopeDigest].every((value) => typeof value === "string" && SAFE_SHA256.test(value))) {
    throw new Error("rightout_worker_policy_invalid");
  }
  return createHash("sha256").update(JSON.stringify([
    "rightout-worker-policy-v1", catalogDigest, recipeDigest, runtimeScopeDigest,
  ])).digest("hex");
}

function validateParameters(parameters, tool, worker) {
  if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) throw new Error("rightout_worker_command_invalid");
  const allowed = TOOL_PARAMETER_KEYS[tool];
  const keys = Object.keys(parameters).sort();
  if (keys.some((key) => !allowed.includes(key))) throw new Error("rightout_worker_command_invalid");
  const required = tool === "rightout_live_scan" ? ["profileId", "brokerIds", "campaignId"]
    : tool === "rightout_submit_removal" ? ["profileId", "brokerId", "requestKind", "campaignId"]
      : tool === "rightout_open_verification" ? ["profileId", "brokerId", "verificationHandle", "campaignId"]
        : tool === "rightout_direct_rescan" ? ["profileId", "brokerId", "listingHandle", "campaignId"]
          : ["profileId", "brokerId", "campaignId"];
  if (required.some((key) => !keys.includes(key))) throw new Error("rightout_worker_command_invalid");
  if (parameters.profileId !== worker.profileId || parameters.campaignId !== worker.campaignId) {
    throw new Error("rightout_worker_command_scope_mismatch");
  }
  if (parameters.brokerId !== undefined && !SAFE_BROKER_ID.test(parameters.brokerId)) throw new Error("rightout_worker_command_invalid");
  if (parameters.brokerIds !== undefined && (
    !Array.isArray(parameters.brokerIds) || parameters.brokerIds.length < 1 || parameters.brokerIds.length > 4
    || parameters.brokerIds.some((id) => !SAFE_BROKER_ID.test(id)) || new Set(parameters.brokerIds).size !== parameters.brokerIds.length
  )) throw new Error("rightout_worker_command_invalid");
  if (parameters.brokerId !== undefined && !worker.brokerIds.includes(parameters.brokerId)) throw new Error("rightout_worker_command_scope_mismatch");
  if (parameters.brokerIds !== undefined && parameters.brokerIds.some((id) => !worker.brokerIds.includes(id))) {
    throw new Error("rightout_worker_command_scope_mismatch");
  }
  if (!worker.effects.includes(TOOL_EFFECT[tool])) throw new Error("rightout_worker_command_scope_mismatch");
  if (parameters.browserBackend !== undefined && parameters.browserBackend !== "remote_cloud_cdp") throw new Error("rightout_worker_command_invalid");
  if (parameters.listingHandle !== undefined && !SAFE_LISTING_HANDLE.test(parameters.listingHandle)) throw new Error("rightout_worker_command_invalid");
  if (parameters.verificationHandle !== undefined && !SAFE_VERIFICATION_HANDLE.test(parameters.verificationHandle)) throw new Error("rightout_worker_command_invalid");
  if (parameters.requestKind !== undefined && !REQUEST_KINDS.has(parameters.requestKind)) throw new Error("rightout_worker_command_invalid");
  const serialized = JSON.stringify(parameters);
  if (serialized.length > 2_000 || /https?:|@|[\r\n]/iu.test(serialized)) throw new Error("rightout_worker_command_invalid");
  const cloned = JSON.parse(serialized);
  return Object.fromEntries(allowed.filter((key) => Object.hasOwn(cloned, key)).map((key) => [key, cloned[key]]));
}

export function validateWorkerCommand(command, workerRecord) {
  const worker = validateWorkerRecord(workerRecord);
  if (!command || typeof command !== "object" || Array.isArray(command)) throw new Error("rightout_worker_command_invalid");
  if (Object.keys(command).some((key) => !["kind", "tool", "parameters", "reason"].includes(key))) {
    throw new Error("rightout_worker_command_invalid");
  }
  if (command.kind !== "execute_tool" || typeof command.tool !== "string" || !TOOL_PARAMETER_KEYS[command.tool]) {
    throw new Error("rightout_worker_command_invalid");
  }
  if (typeof command.reason !== "string" || !/^[a-z0-9_]{3,120}$/.test(command.reason)) throw new Error("rightout_worker_command_invalid");
  const parameters = validateParameters(command.parameters, command.tool, worker);
  return { kind: "execute_tool", tool: command.tool, parameters, reason: command.reason };
}

function commandDigest(command) {
  return createHash("sha256").update(JSON.stringify(command)).digest("hex");
}

export function commandExecutionDigest(tool, parameters) {
  if (typeof tool !== "string" || !TOOL_PARAMETER_KEYS[tool] || !parameters || typeof parameters !== "object" || Array.isArray(parameters)) {
    throw new Error("rightout_worker_command_invalid");
  }
  return createHash("sha256").update(JSON.stringify(["rightout-worker-execution-v1", tool, parameters])).digest("hex");
}

export function classifyWorkerExecutionResult(toolName, result, error) {
  if (typeof error === "string" && error.length > 0) return { state: "human_gate", resultState: "tool_error" };
  const details = result && typeof result === "object" && !Array.isArray(result) ? result.details : undefined;
  if (!details || typeof details !== "object" || Array.isArray(details)) return { state: "human_gate", resultState: "missing_structured_result" };
  const resultState = typeof details.state === "string"
    ? details.state
    : typeof details.mode === "string" ? details.mode : "unclassified_result";
  if (!SAFE_RESULT_STATE.test(resultState)) return { state: "human_gate", resultState: "invalid_result_state" };
  if (
    details.retry_blocked === true || details.tracking?.durable_case_recorded === false
    || /(?:blocked|uncertain|human_gate|manual|failed|error|cancelled)/u.test(resultState)
  ) return { state: "human_gate", resultState };
  if (toolName === "rightout_live_scan") {
    return Array.isArray(details.results)
      ? { state: "completed", resultState }
      : { state: "human_gate", resultState: "live_scan_result_incomplete" };
  }
  if (toolName === "rightout_submit_removal" || toolName === "rightout_submit_parity_email") {
    return resultState === "submitted"
      ? { state: "completed", resultState }
      : { state: "human_gate", resultState };
  }
  if (toolName === "rightout_poll_verification") {
    return ["verification_pending", "verification_not_observed"].includes(resultState)
      ? { state: "completed", resultState }
      : { state: "human_gate", resultState };
  }
  if (toolName === "rightout_open_verification") {
    return resultState === "awaiting_processing"
      ? { state: "completed", resultState }
      : { state: "human_gate", resultState };
  }
  if (toolName === "rightout_direct_rescan") {
    return ["direct_present", "direct_absent_known_listing_set"].includes(details.observation)
      && details.tracking?.durable_case_recorded === true
      ? { state: "completed", resultState }
      : { state: "human_gate", resultState: "direct_rescan_inconclusive" };
  }
  return { state: "human_gate", resultState: "non_terminal_worker_tool" };
}

export function createAutonomyWorkerLedger(store, {
  now = () => Date.now(),
  randomWorkerId = (campaignId) => `worker_${createHash("sha256").update(JSON.stringify(["rightout-worker-v1", campaignId])).digest("hex").slice(0, 32)}`,
  randomLeaseId = () => `lease_${randomBytes(16).toString("hex")}`,
} = {}) {
  if (!store || typeof store.registerIfAbsent !== "function" || typeof store.lookup !== "function" || typeof store.update !== "function" || typeof store.entries !== "function") {
    throw new Error("rightout_worker_store_invalid");
  }

  async function create(input, { campaign, policyDigest, sessionBindingDigest, session }) {
    const clean = cleanWorkerCreateInput(input);
    const currentCampaign = validateCampaign(campaign);
    if (currentCampaign.campaign_id !== clean.campaignId || currentCampaign.status !== "active") throw new Error("rightout_worker_campaign_invalid");
    if (
      !SAFE_SHA256.test(policyDigest ?? "") || !SAFE_SHA256.test(sessionBindingDigest ?? "")
      || !session || workerSessionBindingDigest(session) !== sessionBindingDigest
    ) throw new Error("rightout_worker_policy_invalid");
    const workerId = randomWorkerId(clean.campaignId);
    if (!SAFE_WORKER_ID.test(workerId)) throw new Error("rightout_worker_state_invalid");
    const at = now();
    const record = {
      schemaVersion: 1,
      workerId,
      campaignId: currentCampaign.campaign_id,
      profileId: currentCampaign.subject_ref,
      brokerIds: [...currentCampaign.broker_ids],
      effects: [...currentCampaign.effects],
      policyDigest,
      sessionBindingDigest,
      sessionRoute: { sessionKey: session.sessionKey, agentId: session.agentId },
      status: "active",
      intervalMinutes: clean.intervalMinutes,
      maxConsecutiveFailures: clean.maxConsecutiveFailures,
      consecutiveFailures: 0,
      actionsCompleted: 0,
      nextWakeAt: new Date(at).toISOString(),
      lease: null,
      createdAt: new Date(at).toISOString(),
      updatedAt: new Date(at).toISOString(),
    };
    if (!await store.registerIfAbsent(workerId, record)) throw new Error("rightout_worker_state_invalid");
    return publicWorker(record);
  }

  async function status(workerId) {
    if (!SAFE_WORKER_ID.test(workerId ?? "")) throw new Error("rightout_worker_ref_invalid");
    const record = await store.lookup(workerId);
    if (!record) throw new Error("rightout_worker_not_found");
    return publicWorker(record);
  }

  async function claim(workerId, { campaign, policyDigest, sessionBindingDigest, leaseMs = 120_000 }) {
    if (!SAFE_WORKER_ID.test(workerId ?? "") || !Number.isInteger(leaseMs) || leaseMs < 30_000 || leaseMs > 300_000) {
      throw new Error("rightout_worker_ref_invalid");
    }
    const currentCampaign = validateCampaign(campaign);
    let result;
    await store.update(workerId, (value) => {
      const record = validateWorkerRecord(value);
      const at = now();
      if (record.campaignId !== currentCampaign.campaign_id || record.profileId !== currentCampaign.subject_ref) {
        throw new Error("rightout_worker_campaign_invalid");
      }
      if (record.policyDigest !== policyDigest || record.sessionBindingDigest !== sessionBindingDigest) {
        throw new Error("rightout_worker_policy_changed");
      }
      if (currentCampaign.status !== "active") {
        const next = { ...record, status: currentCampaign.status === "revoked" ? "revoked" : "done", lease: null, nextWakeAt: null, updatedAt: new Date(at).toISOString(), lastReason: `campaign_${currentCampaign.status}` };
        result = { state: next.status, worker: publicWorker(next) };
        return next;
      }
      if (record.status !== "active") throw new Error("rightout_worker_not_active");
      if (record.nextWakeAt !== null && parseIso(record.nextWakeAt) > at) {
        result = { state: "not_due", worker: publicWorker(record) };
        return record;
      }
      if (record.lease && record.lease.expiresAt > at) throw new Error("rightout_worker_lease_active");
      if (record.lease?.plan) {
        const next = { ...record, status: "human_gate", lease: record.lease, nextWakeAt: null, updatedAt: new Date(at).toISOString(), lastReason: "expired_lease_with_unresolved_action" };
        result = { state: "human_gate", worker: publicWorker(next) };
        return next;
      }
      const leaseId = randomLeaseId();
      if (!SAFE_LEASE_ID.test(leaseId)) throw new Error("rightout_worker_state_invalid");
      const next = {
        ...record,
        lease: { leaseId, claimedAt: at, expiresAt: at + leaseMs, plan: null },
        updatedAt: new Date(at).toISOString(),
      };
      result = { state: "claimed", lease_id: leaseId, lease_expires_at: new Date(at + leaseMs).toISOString(), worker: publicWorker(next) };
      return next;
    });
    return result;
  }

  async function issue(workerId, leaseId, command, evidenceBaseline = {}) {
    if (!SAFE_WORKER_ID.test(workerId ?? "") || !SAFE_LEASE_ID.test(leaseId ?? "")) throw new Error("rightout_worker_ref_invalid");
    let result;
    await store.update(workerId, (value) => {
      const record = validateWorkerRecord(value);
      const at = now();
      if (!record.lease || record.lease.leaseId !== leaseId || record.lease.expiresAt <= at) throw new Error("rightout_worker_lease_invalid");
      if (record.lease.plan) throw new Error("rightout_worker_action_unresolved");
      const clean = validateWorkerCommand(command, record);
      if (
        !evidenceBaseline || typeof evidenceBaseline !== "object" || Array.isArray(evidenceBaseline)
        || Object.keys(evidenceBaseline).some((key) => !["campaignUsedEffects", "campaignLastEffectReference"].includes(key))
        || !Number.isInteger(evidenceBaseline.campaignUsedEffects) || evidenceBaseline.campaignUsedEffects < 0
        || (evidenceBaseline.campaignLastEffectReference !== null
          && (typeof evidenceBaseline.campaignLastEffectReference !== "string" || !/^effect_[a-f0-9]{24}$/.test(evidenceBaseline.campaignLastEffectReference)))
      ) throw new Error("rightout_worker_evidence_invalid");
      const digest = commandDigest(clean);
      const plan = {
        tool: clean.tool,
        commandDigest: digest,
        executionDigest: commandExecutionDigest(clean.tool, clean.parameters),
        reason: clean.reason,
        issuedAt: at,
        campaignUsedEffectsBaseline: evidenceBaseline.campaignUsedEffects,
        campaignLastEffectReferenceBaseline: evidenceBaseline.campaignLastEffectReference,
        receipt: null,
      };
      const next = { ...record, lease: { ...record.lease, plan }, updatedAt: new Date(at).toISOString() };
      result = {
        state: "action_ready",
        worker_id: workerId,
        lease_id: leaseId,
        command_reference: `command_${digest.slice(0, 24)}`,
        command: clean,
        raw_pii_in_report: false,
      };
      return next;
    });
    return result;
  }

  async function pending(workerId, leaseId) {
    if (!SAFE_WORKER_ID.test(workerId ?? "") || !SAFE_LEASE_ID.test(leaseId ?? "")) throw new Error("rightout_worker_ref_invalid");
    const record = validateWorkerRecord(await store.lookup(workerId));
    if (!record.lease || record.lease.leaseId !== leaseId || !record.lease.plan) throw new Error("rightout_worker_action_missing");
    return {
      worker_id: workerId,
      campaign_id: record.campaignId,
      issued_at: new Date(record.lease.plan.issuedAt).toISOString(),
      campaign_used_effects_baseline: record.lease.plan.campaignUsedEffectsBaseline,
      campaign_last_effect_reference_baseline: record.lease.plan.campaignLastEffectReferenceBaseline,
      command_reference: `command_${record.lease.plan.commandDigest.slice(0, 24)}`,
      execution_digest: record.lease.plan.executionDigest,
      execution_receipt: record.lease.plan.receipt ? structuredClone(record.lease.plan.receipt) : null,
      raw_pii_in_report: false,
    };
  }

  async function matchExecution(tool, parameters, sessionBindingDigest) {
    if (!SAFE_SHA256.test(sessionBindingDigest ?? "")) throw new Error("rightout_worker_session_required");
    const matches = [];
    for (const entry of await store.entries()) {
      const record = validateWorkerRecord(entry.value);
      if (
        record.status !== "active" || record.sessionBindingDigest !== sessionBindingDigest
        || !record.lease?.plan || record.lease.plan.tool !== tool || record.lease.plan.receipt !== null
      ) continue;
      let clean;
      try { clean = validateParameters(parameters, tool, record); } catch { continue; }
      if (commandExecutionDigest(tool, clean) !== record.lease.plan.executionDigest) continue;
      matches.push({ worker_id: record.workerId, lease_id: record.lease.leaseId, execution_digest: record.lease.plan.executionDigest });
    }
    if (matches.length > 1) throw new Error("rightout_worker_execution_ambiguous");
    return matches[0];
  }

  async function recordExecutionResult(workerId, leaseId, value) {
    if (!SAFE_WORKER_ID.test(workerId ?? "") || !SAFE_LEASE_ID.test(leaseId ?? "")) throw new Error("rightout_worker_ref_invalid");
    if (
      !value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).some((key) => !["executionDigest", "state", "resultState"].includes(key))
      || !SAFE_SHA256.test(value.executionDigest ?? "") || !["completed", "human_gate"].includes(value.state)
      || !SAFE_RESULT_STATE.test(value.resultState ?? "")
    ) throw new Error("rightout_worker_receipt_invalid");
    let receipt;
    await store.update(workerId, (stored) => {
      const record = validateWorkerRecord(stored);
      if (
        !record.lease || record.lease.leaseId !== leaseId || !record.lease.plan
        || record.lease.plan.executionDigest !== value.executionDigest
      ) throw new Error("rightout_worker_action_missing");
      if (record.lease.plan.receipt) {
        if (
          record.lease.plan.receipt.state !== value.state
          || record.lease.plan.receipt.executionDigest !== value.executionDigest
          || record.lease.plan.receipt.resultState !== value.resultState
        ) throw new Error("rightout_worker_receipt_conflict");
        receipt = record.lease.plan.receipt;
        return record;
      }
      receipt = {
        state: value.state,
        executionDigest: value.executionDigest,
        resultState: value.resultState,
        observedAt: now(),
      };
      return {
        ...record,
        lease: { ...record.lease, plan: { ...record.lease.plan, receipt } },
        updatedAt: new Date(now()).toISOString(),
      };
    });
    return structuredClone(receipt);
  }

  async function recoverable() {
    const records = [];
    for (const entry of await store.entries()) {
      const record = validateWorkerRecord(entry.value);
      if (record.status !== "active") continue;
      records.push({
        worker_id: record.workerId,
        session_key: record.sessionRoute.sessionKey,
        agent_id: record.sessionRoute.agentId,
        next_wake_at: record.nextWakeAt,
        lease_expires_at: record.lease ? new Date(record.lease.expiresAt).toISOString() : null,
        unresolved_action: record.lease?.plan !== null,
      });
    }
    return records;
  }

  async function gateRecovery(workerId, reason = "scheduler_recovery_unavailable") {
    if (!SAFE_WORKER_ID.test(workerId ?? "") || typeof reason !== "string" || !/^[a-z0-9_]{3,120}$/.test(reason)) {
      throw new Error("rightout_worker_ref_invalid");
    }
    let result;
    await store.update(workerId, (stored) => {
      const record = validateWorkerRecord(stored);
      if (record.status !== "active") {
        result = publicWorker(record);
        return record;
      }
      const at = now();
      const next = {
        ...record,
        status: "human_gate",
        nextWakeAt: null,
        updatedAt: new Date(at).toISOString(),
        lastReason: reason,
      };
      result = publicWorker(next);
      return next;
    });
    return result;
  }

  async function complete(workerId, leaseId, value) {
    if (!SAFE_WORKER_ID.test(workerId ?? "") || !SAFE_LEASE_ID.test(leaseId ?? "")) throw new Error("rightout_worker_ref_invalid");
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_worker_completion_invalid");
    const allowed = new Set(["outcome", "nextWakeAt", "reason"]);
    if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error("rightout_worker_completion_invalid");
    if (!["action_succeeded", "done_for_now", "transient_failure", "human_gate"].includes(value.outcome)) {
      throw new Error("rightout_worker_completion_invalid");
    }
    if (value.reason !== undefined && (typeof value.reason !== "string" || !/^[a-z0-9_]{3,120}$/.test(value.reason))) {
      throw new Error("rightout_worker_completion_invalid");
    }
    if (value.nextWakeAt !== undefined && value.nextWakeAt !== null) parseIso(value.nextWakeAt, "rightout_worker_completion_invalid");
    let result;
    await store.update(workerId, (stored) => {
      const record = validateWorkerRecord(stored);
      const at = now();
      if (!record.lease || record.lease.leaseId !== leaseId || record.lease.expiresAt <= at) throw new Error("rightout_worker_lease_invalid");
      const requiresPlan = ["action_succeeded", "transient_failure"].includes(value.outcome);
      if (requiresPlan && !record.lease.plan) throw new Error("rightout_worker_action_missing");
      if (value.outcome === "action_succeeded" && record.lease.plan?.receipt?.state !== "completed") {
        throw new Error("rightout_worker_success_evidence_missing");
      }
      let next;
      if (value.outcome === "action_succeeded") {
        next = { ...record, lease: null, status: "active", nextWakeAt: new Date(at).toISOString(), consecutiveFailures: 0, actionsCompleted: record.actionsCompleted + 1, updatedAt: new Date(at).toISOString(), lastReason: value.reason ?? "action_succeeded" };
      } else if (value.outcome === "done_for_now") {
        const nextWakeAt = value.nextWakeAt ?? null;
        if (nextWakeAt !== null && parseIso(nextWakeAt) <= at) throw new Error("rightout_worker_completion_invalid");
        next = { ...record, lease: null, status: nextWakeAt === null ? "done" : "active", nextWakeAt, consecutiveFailures: 0, updatedAt: new Date(at).toISOString(), lastReason: value.reason ?? "done_for_now" };
      } else if (value.outcome === "human_gate") {
        next = { ...record, status: "human_gate", nextWakeAt: null, lease: record.lease, updatedAt: new Date(at).toISOString(), lastReason: value.reason ?? "human_gate" };
      } else {
        const failures = record.consecutiveFailures + 1;
        const terminal = failures >= record.maxConsecutiveFailures;
        const backoffMs = Math.min(24 * 60 * 60_000, 5 * 60_000 * (2 ** Math.min(8, failures - 1)));
        next = {
          ...record,
          lease: terminal ? record.lease : null,
          status: terminal ? "human_gate" : "active",
          nextWakeAt: terminal ? null : new Date(at + backoffMs).toISOString(),
          consecutiveFailures: failures,
          updatedAt: new Date(at).toISOString(),
          lastReason: terminal ? "failure_budget_exhausted" : value.reason ?? "transient_failure",
        };
      }
      result = { state: next.status, worker: publicWorker(next) };
      return next;
    });
    return result;
  }

  async function resume(workerId, { campaign, policyDigest, sessionBindingDigest }) {
    if (!SAFE_WORKER_ID.test(workerId ?? "")) throw new Error("rightout_worker_ref_invalid");
    const currentCampaign = validateCampaign(campaign);
    let result;
    await store.update(workerId, (value) => {
      const record = validateWorkerRecord(value);
      if (!new Set(["paused", "human_gate"]).has(record.status)) throw new Error("rightout_worker_resume_invalid");
      if (
        record.campaignId !== currentCampaign.campaign_id || currentCampaign.status !== "active"
        || record.policyDigest !== policyDigest || record.sessionBindingDigest !== sessionBindingDigest
      ) throw new Error("rightout_worker_policy_changed");
      const at = now();
      const next = { ...record, status: "active", lease: null, nextWakeAt: new Date(at).toISOString(), consecutiveFailures: 0, updatedAt: new Date(at).toISOString(), lastReason: "operator_resumed" };
      result = publicWorker(next);
      return next;
    });
    return result;
  }

  async function revoke(workerId) {
    if (!SAFE_WORKER_ID.test(workerId ?? "")) throw new Error("rightout_worker_ref_invalid");
    let result;
    await store.update(workerId, (value) => {
      const record = validateWorkerRecord(value);
      const at = now();
      const next = { ...record, status: "revoked", lease: null, nextWakeAt: null, updatedAt: new Date(at).toISOString(), lastReason: "operator_revoked" };
      result = publicWorker(next);
      return next;
    });
    return result;
  }

  return { create, status, claim, issue, pending, matchExecution, recordExecutionResult, recoverable, gateRecovery, complete, resume, revoke };
}

export const __test = {
  TOOL_PARAMETER_KEYS,
  TOOL_EFFECT,
  cleanWorkerCreateInput,
  commandDigest,
  commandExecutionDigest,
  classifyWorkerExecutionResult,
  publicWorker,
  validateWorkerRecord,
};
