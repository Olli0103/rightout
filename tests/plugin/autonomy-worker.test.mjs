import assert from "node:assert/strict";
import test from "node:test";

import {
  classifyWorkerExecutionResult,
  createAutonomyWorkerLedger,
  validateWorkerCommand,
  workerPolicyDigest,
  workerSessionBindingDigest,
} from "../../lib/autonomy-worker.mjs";

test("worker result receipts gate inconclusive direct rescans", () => {
  assert.deepEqual(classifyWorkerExecutionResult("rightout_direct_rescan", {
    details: { state: "submitted", observation: "inconclusive", tracking: { durable_case_recorded: true } },
  }), { state: "human_gate", resultState: "direct_rescan_inconclusive" });
  assert.deepEqual(classifyWorkerExecutionResult("rightout_direct_rescan", {
    details: { state: "submitted", observation: "direct_absent_known_listing_set", tracking: { durable_case_recorded: true } },
  }), { state: "completed", resultState: "submitted" });
  assert.deepEqual(classifyWorkerExecutionResult("rightout_direct_rescan", {
    details: { state: "submitted", observation: "direct_present", tracking: { durable_case_recorded: false } },
  }), { state: "human_gate", resultState: "submitted" });
});

function memoryStore() {
  const values = new Map();
  return {
    async registerIfAbsent(key, value) {
      if (values.has(key)) return false;
      values.set(key, structuredClone(value));
      return true;
    },
    async lookup(key) { return values.has(key) ? structuredClone(values.get(key)) : undefined; },
    async update(key, updater) {
      const next = updater(values.has(key) ? structuredClone(values.get(key)) : undefined);
      if (next === undefined) values.delete(key); else values.set(key, structuredClone(next));
      return true;
    },
    async entries() { return [...values].map(([key, value]) => ({ key, value: structuredClone(value) })); },
    values,
  };
}

const profileId = "profile_a1b2c3d4e5f60718";
const campaignId = "campaign_0123456789abcdef0123456789abcdef";
const workerId = "worker_0123456789abcdef0123456789abcdef";
const leaseIds = [
  "lease_0123456789abcdef0123456789abcdef",
  "lease_11111111111111111111111111111111",
  "lease_22222222222222222222222222222222",
  "lease_33333333333333333333333333333333",
];
const campaign = {
  campaign_id: campaignId,
  subject_ref: profileId,
  status: "active",
  broker_ids: ["spokeo"],
  effects: ["discover", "submit_email", "poll_verification"],
};
const effectBaseline = { campaignUsedEffects: 0, campaignLastEffectReference: null };
const digest = "a".repeat(64);
const sessionDigest = workerSessionBindingDigest({ sessionKey: "session:test:01234567", agentId: "main" });
const session = { sessionKey: "session:test:01234567", agentId: "main" };
const policyDigest = workerPolicyDigest({
  catalogDigest: digest,
  recipeDigest: "b".repeat(64),
  runtimeScopeDigest: "c".repeat(64),
  marketPolicyDigest: "d".repeat(64),
});

function fixture({ nowRef = { value: Date.parse("2026-07-14T15:00:00Z") } } = {}) {
  const store = memoryStore();
  let leaseIndex = 0;
  const ledger = createAutonomyWorkerLedger(store, {
    now: () => nowRef.value,
    randomWorkerId: () => workerId,
    randomLeaseId: () => leaseIds[leaseIndex++],
  });
  return { ledger, store, nowRef };
}

async function createWorker(ledger, overrides = {}) {
  return ledger.create({ campaignId, intervalMinutes: 15, maxConsecutiveFailures: 3, ...overrides }, {
    campaign,
    policyDigest,
    sessionBindingDigest: sessionDigest,
    session,
  });
}

test("durable worker claims, issues, and completes one exact allowlisted command", async () => {
  const { ledger } = fixture();
  const created = await createWorker(ledger);
  assert.equal(created.status, "active");
  assert.equal(created.raw_pii_in_report, false);

  const claim = await ledger.claim(workerId, { campaign, policyDigest, sessionBindingDigest: sessionDigest });
  assert.equal(claim.state, "claimed");
  const issued = await ledger.issue(workerId, claim.lease_id, {
    kind: "execute_tool",
    tool: "rightout_live_scan",
    parameters: { profileId, brokerIds: ["spokeo"], campaignId },
    reason: "discover_next_bounded_global_catalog_batch",
  }, effectBaseline);
  assert.equal(issued.command.tool, "rightout_live_scan");
  assert.match(issued.command_reference, /^command_[a-f0-9]{24}$/);
  const pending = await ledger.pending(workerId, claim.lease_id);
  assert.equal(pending.campaign_used_effects_baseline, 0);
  assert.equal(pending.command_reference, issued.command_reference);
  const matched = await ledger.matchExecution("rightout_live_scan", {
    campaignId: campaign.campaign_id,
    brokerIds: ["spokeo"],
    profileId,
  }, sessionDigest);
  assert.equal(matched.execution_digest, pending.execution_digest);
  await ledger.recordExecutionResult(workerId, claim.lease_id, {
    executionDigest: pending.execution_digest,
    state: "completed",
    resultState: "campaign_gated_live_scan",
  });
  const completed = await ledger.complete(workerId, claim.lease_id, { outcome: "action_succeeded" });
  assert.equal(completed.worker.actions_completed, 1);
  assert.equal(completed.worker.lease_active, false);
});

test("worker command grammar rejects foreign scope, URLs, invented tools, and oversized batches", async () => {
  const { ledger, store } = fixture();
  await createWorker(ledger);
  const record = store.values.get(workerId);
  for (const command of [
    { kind: "execute_tool", tool: "shell", parameters: { profileId, campaignId }, reason: "invented_tool" },
    { kind: "execute_tool", tool: "rightout_live_scan", parameters: { profileId: "profile_ffffffffffffffff", brokerIds: ["spokeo"], campaignId }, reason: "wrong_subject" },
    { kind: "execute_tool", tool: "rightout_poll_verification", parameters: { profileId, brokerId: "foreignbroker", campaignId }, reason: "foreign_broker" },
    { kind: "execute_tool", tool: "rightout_begin_form_session", parameters: { profileId, brokerId: "spokeo", campaignId }, reason: "unauthorized_effect" },
    { kind: "execute_tool", tool: "rightout_begin_discovery_session", parameters: { profileId, brokerId: "spokeo", campaignId, browserBackend: "foreign_backend" }, reason: "foreign_backend" },
    { kind: "execute_tool", tool: "rightout_begin_form_session", parameters: { profileId, brokerId: "spokeo", campaignId, listingHandle: "https://attacker.example/private" }, reason: "raw_url" },
    { kind: "execute_tool", tool: "rightout_live_scan", parameters: { profileId, brokerIds: ["a1", "a2", "a3", "a4", "a5"], campaignId }, reason: "oversized_batch" },
  ]) assert.throws(() => validateWorkerCommand(command, record), /rightout_worker_command/);
});

test("active leases exclude races and an issued expired lease becomes a human gate", async () => {
  const { ledger, nowRef } = fixture();
  await createWorker(ledger);
  const first = await ledger.claim(workerId, { campaign, policyDigest, sessionBindingDigest: sessionDigest, leaseMs: 30_000 });
  await assert.rejects(ledger.claim(workerId, { campaign, policyDigest, sessionBindingDigest: sessionDigest }), /rightout_worker_lease_active/);
  await ledger.issue(workerId, first.lease_id, {
    kind: "execute_tool", tool: "rightout_poll_verification",
    parameters: { profileId, brokerId: "spokeo", campaignId }, reason: "poll_due_verification",
  }, effectBaseline);
  const pending = await ledger.pending(workerId, first.lease_id);
  nowRef.value += 31_000;
  await assert.rejects(ledger.matchExecution("rightout_poll_verification", {
    profileId, brokerId: "spokeo", campaignId,
  }, sessionDigest), /rightout_worker_lease_expired/);
  await assert.rejects(ledger.recordExecutionResult(workerId, first.lease_id, {
    executionDigest: pending.execution_digest,
    state: "completed",
    resultState: "verification_pending",
  }), /rightout_worker_action_missing/);
  const recovered = await ledger.claim(workerId, { campaign, policyDigest, sessionBindingDigest: sessionDigest });
  assert.equal(recovered.state, "human_gate");
  assert.equal(recovered.worker.last_reason, "expired_lease_with_unresolved_action");
  assert.equal(recovered.worker.unresolved_action, true);
});

test("an expired pre-plan lease is safely reclaimed", async () => {
  const { ledger, nowRef } = fixture();
  await createWorker(ledger);
  await ledger.claim(workerId, { campaign, policyDigest, sessionBindingDigest: sessionDigest, leaseMs: 30_000 });
  nowRef.value += 31_000;
  const second = await ledger.claim(workerId, { campaign, policyDigest, sessionBindingDigest: sessionDigest });
  assert.equal(second.state, "claimed");
  assert.equal(second.lease_id, leaseIds[1]);
});

test("policy or trusted-session mutation fails before a worker plan is issued", async () => {
  const { ledger } = fixture();
  await createWorker(ledger);
  await assert.rejects(ledger.claim(workerId, {
    campaign,
    policyDigest: "d".repeat(64),
    sessionBindingDigest: sessionDigest,
  }), /rightout_worker_policy_changed/);
  await assert.rejects(ledger.claim(workerId, {
    campaign,
    policyDigest,
    sessionBindingDigest: "e".repeat(64),
  }), /rightout_worker_policy_changed/);
});

test("transient failures back off exponentially and stop at the configured human gate", async () => {
  const { ledger, nowRef } = fixture();
  await createWorker(ledger, { maxConsecutiveFailures: 2 });
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const claim = await ledger.claim(workerId, { campaign, policyDigest, sessionBindingDigest: sessionDigest });
    await ledger.issue(workerId, claim.lease_id, {
      kind: "execute_tool", tool: "rightout_poll_verification",
      parameters: { profileId, brokerId: "spokeo", campaignId }, reason: "poll_due_verification",
    }, effectBaseline);
    const completed = await ledger.complete(workerId, claim.lease_id, { outcome: "transient_failure", reason: "provider_temporarily_unavailable" });
    if (attempt === 0) {
      assert.equal(completed.state, "active");
      const wake = Date.parse(completed.worker.next_wake_at);
      assert.equal(wake - nowRef.value, 5 * 60_000);
      nowRef.value = wake;
    } else {
      assert.equal(completed.state, "human_gate");
      assert.equal(completed.worker.unresolved_action, true);
      assert.equal(completed.worker.last_reason, "failure_budget_exhausted");
    }
  }
});

test("campaign completion or revocation deterministically closes a worker", async () => {
  const { ledger } = fixture();
  await createWorker(ledger);
  const closed = await ledger.claim(workerId, {
    campaign: { ...campaign, status: "completed" }, policyDigest, sessionBindingDigest: sessionDigest,
  });
  assert.equal(closed.state, "done");

  const second = fixture();
  await createWorker(second.ledger);
  const revoked = await second.ledger.claim(workerId, {
    campaign: { ...campaign, status: "revoked" }, policyDigest, sessionBindingDigest: sessionDigest,
  });
  assert.equal(revoked.state, "revoked");
});
