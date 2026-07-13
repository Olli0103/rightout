import assert from "node:assert/strict";
import test from "node:test";

import { CASE_STATES, createCaseLedger } from "../../lib/cases.mjs";

const PROFILE = "profile_0123456789abcdef";

function memoryStore() {
  const values = new Map();
  return {
    async lookup(key) { return values.has(key) ? structuredClone(values.get(key)) : undefined; },
    async register(key, value) { values.set(key, structuredClone(value)); },
    async delete(key) { return values.delete(key); },
    values,
  };
}

async function recordDiscovery(ledger, brokerId = "beenverified", at = "2026-07-12T09:59:00Z") {
  await ledger.recordScan({
    mode: "approval_gated_live_scan",
    scan_id: "scan_0123456789abcdef",
    subject_ref: PROFILE,
    generated_at: at,
    results: [{ broker_id: brokerId, state: "indirect_exposure", reason: "search_index_candidate_observed" }],
  });
}

function clock(...values) {
  let index = 0;
  return () => new Date(values[Math.min(index++, values.length - 1)]);
}

const catalog = {
  brokers: [
    {
      id: "beenverified",
      lane: "email",
      human_only: false,
      prerequisites: ["subject_authorization"],
      scan: { supported: true },
      removal: { supported: true, channel: "email" },
    },
    {
      id: "truepeoplesearch",
      lane: "search_index",
      human_only: false,
      prerequisites: ["subject_authorization"],
      scan: { supported: true },
    },
    {
      id: "spokeo",
      official_url: "https://www.spokeo.com/optout",
      official_domains: ["spokeo.com"],
      lane: "human_task",
      human_only: true,
      prerequisites: ["manual_site_access_only"],
      scan: { supported: false },
    },
  ],
};

test("case state contract is complete and stable", () => {
  assert.deepEqual(CASE_STATES, [
    "new", "searching", "inconclusive", "not_found", "found", "indirect_exposure",
    "action_selected", "submission_pending", "submission_uncertain", "submitted", "verification_pending", "awaiting_processing",
    "identity_verification_required", "partially_removed", "request_rejected",
    "confirmed_removed", "reappeared", "human_task_queued", "blocked",
  ]);
});

test("scan observations persist without raw PII", async () => {
  const store = memoryStore();
  const ledger = createCaseLedger(store, { now: clock("2026-07-12T10:00:00Z", "2026-07-12T10:00:01Z") });
  await ledger.recordScan({
    mode: "approval_gated_live_scan",
    scan_id: "scan_0123456789abcdef",
    subject_ref: PROFILE,
    generated_at: "2026-07-12T10:00:00Z",
    results: [{ broker_id: "beenverified", state: "indirect_exposure", reason: "search_index_candidate_observed" }],
  });
  const status = await ledger.status(PROFILE);
  assert.equal(status.counts.indirect_exposure, 1);
  assert.match(status.cases[0].proof_references[0], /^scan_[a-f0-9]{24}$/);
  const serialized = JSON.stringify(store.values.get(PROFILE));
  assert.equal(serialized.includes("Alice"), false);
  assert.equal(serialized.includes("@example"), false);
});

test("opaque listing handles persist for later campaign resumption", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await ledger.recordScan({
    mode: "approval_gated_live_scan",
    scan_id: "scan_0123456789abcdef",
    subject_ref: PROFILE,
    generated_at: "2026-07-12T10:00:00Z",
    results: [{
      broker_id: "beenverified",
      state: "indirect_exposure",
      reason: "search_index_candidate_observed",
      listing_handle: "listing_0123456789abcdef01234567",
    }],
  });
  const plan = await ledger.plan(PROFILE, catalog);
  assert.equal(plan.actions.find((row) => row.broker_id === "beenverified").listing_handle, "listing_0123456789abcdef01234567");
  assert.equal(plan.campaign.resume_mode, "approval_gated_actions_available");
  assert.equal(plan.campaign.autonomous_without_approval, false);
  assert.equal(plan.campaign.autonomous_after_exact_approvals, true);
});

test("operator-authorized browser discovery records only an opaque candidate for later direct verification", async () => {
  const store = memoryStore();
  const ledger = createCaseLedger(store, { now: () => new Date("2026-07-13T10:00:00Z") });
  await ledger.recordBrowserDiscovery({
    mode: "operator_authorized_browser_discovery",
    subject_ref: PROFILE,
    broker_id: "familytreenow",
    state: "indirect_exposure",
    listing_handle: "listing_0123456789abcdef01234567",
    generated_at: "2026-07-13T10:00:00Z",
    proof_references: ["receipt_0123456789abcdef01234567"],
  });
  const status = await ledger.status(PROFILE);
  assert.equal(status.cases[0].state, "indirect_exposure");
  assert.equal(status.cases[0].listing_handle, "listing_0123456789abcdef01234567");
  assert.equal(JSON.stringify(store.values.get(PROFILE)).includes("https://"), false);
});

test("browser discovery evidence does not regress in-flight or terminal request states", async () => {
  for (const state of ["action_selected", "identity_verification_required", "partially_removed", "request_rejected"]) {
    const store = memoryStore();
    const ledger = createCaseLedger(store, { now: () => new Date("2026-07-13T10:00:00Z") });
    await recordDiscovery(ledger);
    store.values.get(PROFILE).brokers.beenverified.state = state;
    await ledger.recordBrowserDiscovery({
      mode: "operator_authorized_browser_discovery",
      subject_ref: PROFILE,
      broker_id: "beenverified",
      state: "indirect_exposure",
      listing_handle: "listing_0123456789abcdef01234567",
      generated_at: "2026-07-13T10:00:00Z",
      proof_references: ["receipt_0123456789abcdef01234567"],
    });
    const status = await ledger.status(PROFILE);
    assert.equal(status.cases[0].state, state);
    assert.equal(store.values.get(PROFILE).brokers.beenverified.last_observation.state, "indirect_exposure");
  }
});

test("approved removal records submission, field names, proof, and due date", async () => {
  const store = memoryStore();
  const ledger = createCaseLedger(store, { now: clock("2026-07-12T10:00:00Z", "2026-07-12T10:00:01Z") });
  await recordDiscovery(ledger);
  await ledger.reserveSubmission(PROFILE, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" });
  await ledger.recordRemoval({
    state: "submitted",
    subject_ref: PROFILE,
    broker_id: "beenverified",
    generated_at: "2026-07-12T10:00:00Z",
    delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"],
    disclosures: { to_broker: ["contact_email", "full_name"] },
  }, 10);
  const status = await ledger.status(PROFILE);
  assert.equal(status.counts.submitted, 1);
  assert.equal(status.cases[0].next_recheck_at, "2026-07-22T10:00:00.000Z");
  assert.deepEqual(status.cases[0].disclosure_fields, ["contact_email", "full_name"]);
});

test("confirmed removal cannot be caller-asserted without trusted direct rescan", async () => {
  const store = memoryStore();
  const ledger = createCaseLedger(store);
  await assert.rejects(
    ledger.recordLifecycle(PROFILE, "beenverified", "confirmed_removed", { evidenceKind: "human_task" }),
    /trusted_rescan_or_controller_method_required|untrusted_lifecycle_evidence/,
  );
});

test("browser form initiation records verification_pending without claiming removal", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await recordDiscovery(ledger, "intelius");
  await ledger.reserveSubmission(PROFILE, "intelius", { channel: "browser_form", discoveryRequirement: "prior_discovery_required" });
  await ledger.recordFormSubmission({
    state: "verification_pending", subject_ref: PROFILE, broker_id: "intelius",
    generated_at: "2026-07-12T10:00:00Z", delivery: { form_submitted: true },
    proof_references: ["form_0123456789abcdef01234567"], disclosures: { to_broker: ["contact_email"] },
  });
  const status = await ledger.status(PROFILE);
  assert.equal(status.counts.verification_pending, 1);
  assert.equal(status.metrics.confirmed_removed, 0);
  assert.deepEqual(status.cases[0].disclosure_fields, ["contact_email"]);
});

test("provider writes have a durable intent and ambiguous outcomes never auto-retry", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await recordDiscovery(ledger);
  const intent = await ledger.reserveSubmission(PROFILE, "beenverified", {
    channel: "smtp_email",
    discoveryRequirement: "prior_discovery_required",
  });
  assert.equal(intent.state, "submission_pending");
  assert.match(intent.proof_reference, /^intent_[a-f0-9]{24}$/);
  await ledger.recordSubmissionUncertain(PROFILE, "beenverified", {
    channel: "smtp_email",
    reason: "rightout_removal_transport_failed",
  });
  const status = await ledger.status(PROFILE);
  assert.equal(status.counts.submission_uncertain, 1);
  assert.equal(status.metrics.uncertain, 1);
  assert.equal(status.cases[0].submission_outcome, "uncertain");
  assert.equal(status.cases[0].human_task_reason, "rightout_removal_transport_failed");
  await assert.rejects(
    ledger.reserveSubmission(PROFILE, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" }),
    /rightout_submission_not_ready/,
  );
  const plan = await ledger.plan(PROFILE, catalog);
  assert.equal(plan.actions.find((row) => row.broker_id === "beenverified").next_action, "reconcile_submission");
});

test("ambiguous writes can resume only after operator-reviewed reconciliation", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await recordDiscovery(ledger);
  await ledger.reserveSubmission(PROFILE, "beenverified", {
    channel: "smtp_email",
    discoveryRequirement: "prior_discovery_required",
  });
  await ledger.recordSubmissionUncertain(PROFILE, "beenverified", {
    channel: "smtp_email",
    reason: "rightout_removal_transport_failed",
  });
  const reconciled = await ledger.reconcileSubmission(PROFILE, "beenverified", "provider_write_not_started");
  assert.equal(reconciled.state, "action_selected");
  assert.match(reconciled.proof_reference, /^reconcile_[a-f0-9]{24}$/);
  const retryable = await ledger.status(PROFILE);
  assert.equal(retryable.cases[0].submission_outcome, "human_reviewed_not_started");
  await ledger.reserveSubmission(PROFILE, "beenverified", {
    channel: "smtp_email",
    discoveryRequirement: "prior_discovery_required",
  });
  await ledger.recordSubmissionUncertain(PROFILE, "beenverified", {
    channel: "smtp_email",
    reason: "rightout_removal_transport_failed",
  });
  const confirmed = await ledger.reconcileSubmission(PROFILE, "beenverified", "provider_write_confirmed", { processingDays: 14 });
  assert.equal(confirmed.state, "submitted");
  const status = await ledger.status(PROFILE);
  assert.equal(status.cases[0].submission_outcome, "human_reviewed_provider_write_confirmed");
  assert.equal(status.cases[0].next_recheck_at, "2026-07-26T10:00:00.000Z");
});

test("human-reviewed EU and US controller outcomes are explicit and scoped", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await ledger.reserveSubmission(PROFILE, "fullenrich_eu", {
    channel: "smtp_email",
    discoveryRequirement: "not_required_for_data_subject_request",
  });
  await ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "fullenrich_eu",
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"], disclosures: { to_broker: ["contact_email"] },
  }, 30);
  const broker = {
    id: "fullenrich_eu",
    process_class: "eu_controller_email_erasure",
    removal: { confirmation_policy: "submitted_until_controller_response", processing_days: 30 },
  };
  const outcome = await ledger.recordControllerOutcome(PROFILE, "fullenrich_eu", "erasure_confirmed", broker);
  assert.equal(outcome.state, "confirmed_removed");
  assert.equal(outcome.confirmation_scope, "controller_response_only");
  const status = await ledger.status(PROFILE);
  assert.equal(status.counts.confirmed_removed, 1);
  assert.equal(status.cases[0].coverage_gap, "other_identifiers_or_controllers_not_checked");
  assert.match(status.cases[0].proof_references.at(-1), /^controller_[a-f0-9]{24}$/);
  await ledger.reserveSubmission(PROFILE, "amplemarket_us", {
    channel: "smtp_email",
    discoveryRequirement: "not_required_for_data_subject_request",
  });
  await ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "amplemarket_us",
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_1123456789abcdef01234567"], disclosures: { to_broker: ["full_name", "contact_email", "region", "country"] },
  }, 45);
  const usBroker = {
    id: "amplemarket_us",
    process_class: "us_data_broker_email_deletion",
    removal: { confirmation_policy: "submitted_until_controller_response", processing_days: 45 },
  };
  const usOutcome = await ledger.recordControllerOutcome(PROFILE, "amplemarket_us", "deletion_confirmed", usBroker);
  assert.equal(usOutcome.state, "confirmed_removed");
  assert.equal((await ledger.status(PROFILE)).counts.confirmed_removed, 2);
  await assert.rejects(
    ledger.recordControllerOutcome(PROFILE, "amplemarket_us", "erasure_confirmed", usBroker),
    /unsupported_controller_outcome_lane/,
  );
  await ledger.reserveSubmission(PROFILE, "wiza_us", {
    channel: "smtp_email",
    discoveryRequirement: "not_required_for_data_subject_request",
  });
  await ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "wiza_us",
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_2123456789abcdef01234567"], disclosures: { to_broker: ["full_name", "contact_email", "region", "country"] },
  }, 45);
  await ledger.recordControllerOutcome(PROFILE, "wiza_us", "processing_acknowledged", {
    id: "wiza_us",
    process_class: "us_data_broker_email_deletion",
    removal: { confirmation_policy: "submitted_until_controller_response", processing_days: 45 },
  });
  const wiza = (await ledger.status(PROFILE)).cases.find((item) => item.broker_id === "wiza_us");
  assert.equal(wiza.next_recheck_at, "2026-08-26T10:00:00.000Z");

  const partialBroker = {
    id: "partialcycle_us",
    process_class: "us_data_broker_email_deletion",
    removal: { confirmation_policy: "submitted_until_controller_response", processing_days: 45 },
  };
  await ledger.reserveSubmission(PROFILE, partialBroker.id, {
    channel: "smtp_email",
    discoveryRequirement: "not_required_for_data_subject_request",
  });
  await ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: partialBroker.id,
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_3123456789abcdef01234567"], disclosures: { to_broker: ["full_name", "contact_email", "region", "country"] },
  }, 45);
  assert.equal((await ledger.recordControllerOutcome(PROFILE, partialBroker.id, "partial_deletion", partialBroker)).state, "partially_removed");
  assert.equal((await ledger.recordControllerOutcome(PROFILE, partialBroker.id, "processing_acknowledged", partialBroker)).state, "awaiting_processing");
  assert.equal((await ledger.recordControllerOutcome(PROFILE, partialBroker.id, "partial_deletion", partialBroker)).state, "partially_removed");
  assert.equal((await ledger.recordControllerOutcome(PROFILE, partialBroker.id, "identity_required", partialBroker)).state, "identity_verification_required");
  assert.equal((await ledger.recordControllerOutcome(PROFILE, partialBroker.id, "partial_deletion", partialBroker)).state, "partially_removed");
  assert.equal((await ledger.recordControllerOutcome(PROFILE, partialBroker.id, "request_rejected", partialBroker)).state, "request_rejected");
  await assert.rejects(
    ledger.recordControllerOutcome(PROFILE, "fullenrich_eu", "erasure_confirmed", {
      ...broker, process_class: "eu_advertising_preference",
    }),
    /unsupported_controller_outcome_lane/,
  );
});

test("verification lifecycle reaches confirmed removal only after direct absence evidence", async () => {
  const store = memoryStore();
  const ledger = createCaseLedger(store, { now: clock(
    "2026-07-12T10:00:00Z", "2026-07-12T10:01:00Z", "2026-07-12T10:02:00Z",
    "2026-07-12T10:03:00Z", "2026-07-12T10:04:00Z", "2026-07-12T10:05:00Z",
  ) });
  await recordDiscovery(ledger);
  await ledger.reserveSubmission(PROFILE, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" });
  await ledger.recordRemoval({
    state: "submitted",
    subject_ref: PROFILE,
    broker_id: "beenverified",
    generated_at: "2026-07-12T10:00:00Z",
    delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"],
    disclosures: { to_broker: ["contact_email", "full_name"] },
  });
  await ledger.recordLifecycle(PROFILE, "beenverified", "verification_pending", { evidenceKind: "broker_verification_link" });
  await ledger.recordLifecycle(PROFILE, "beenverified", "awaiting_processing", { evidenceKind: "broker_verification_link" });
  await ledger.recordDirectRescan({
    subject_ref: PROFILE, broker_id: "beenverified", observation: "direct_absent_known_listing_set",
    removal_confirmation_scope: "known_listing_set_only", generated_at: "2026-08-01T10:00:00Z",
    proof_references: ["direct_0123456789abcdef01234567"],
  });
  assert.equal((await ledger.status(PROFILE)).counts.awaiting_processing, 1);
  await ledger.recordDirectRescan({
    subject_ref: PROFILE, broker_id: "beenverified", observation: "direct_absent_known_listing_set",
    removal_confirmation_scope: "known_listing_set_only", generated_at: "2026-08-08T10:00:00Z",
    proof_references: ["direct_fedcba9876543210fedcba98"],
  });
  const status = await ledger.status(PROFILE);
  assert.equal(status.metrics.confirmed_removed, 1);
  assert.ok(status.cases[0].removal_confirmed_at);
  assert.ok(status.cases[0].next_recheck_at);
});

test("direct-rescan report confirms a submitted known listing set and later detects reappearance", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await recordDiscovery(ledger);
  await ledger.reserveSubmission(PROFILE, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" });
  await ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "beenverified",
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: [], disclosures: { to_broker: [] },
  });
  await ledger.recordDirectRescan({
    subject_ref: PROFILE, broker_id: "beenverified", observation: "direct_absent_known_listing_set",
    removal_confirmation_scope: "known_listing_set_only", generated_at: "2026-07-20T10:00:00Z",
    proof_references: ["direct_0123456789abcdef01234567"],
  });
  assert.equal((await ledger.status(PROFILE)).counts.awaiting_processing, 1);
  assert.equal((await ledger.status(PROFILE)).counts.confirmed_removed, 0);
  await ledger.recordDirectRescan({
    subject_ref: PROFILE, broker_id: "beenverified", observation: "direct_absent_known_listing_set",
    removal_confirmation_scope: "known_listing_set_only", generated_at: "2026-07-27T10:00:00Z",
    proof_references: ["direct_fedcba9876543210fedcba98"],
  });
  assert.equal((await ledger.status(PROFILE)).counts.confirmed_removed, 1);
  const confirmed = await ledger.status(PROFILE);
  assert.equal(confirmed.cases[0].removal_confirmation_scope, "known_listing_set_only");
  assert.equal(confirmed.cases[0].coverage_gap, "new_or_unindexed_listing_urls_not_checked");
  await ledger.recordDirectRescan({
    subject_ref: PROFILE, broker_id: "beenverified", observation: "direct_present",
    removal_confirmation_scope: "known_listing_set_only", generated_at: "2026-11-20T10:00:00Z",
    proof_references: ["direct_89abcdef0123456789abcdef"],
  });
  assert.equal((await ledger.status(PROFILE)).counts.reappeared, 1);
});

test("an inconclusive direct recheck preserves evidence state and defers the next attempt", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-20T10:00:00Z") });
  await recordDiscovery(ledger);
  await ledger.reserveSubmission(PROFILE, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" });
  await ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "beenverified",
    generated_at: "2026-07-19T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"], disclosures: { to_broker: ["contact_email"] },
  });
  await ledger.recordDirectRescan({
    subject_ref: PROFILE, broker_id: "beenverified", observation: "inconclusive",
    removal_confirmation_scope: "known_listing_set_only", generated_at: "2026-07-20T10:00:00Z",
    proof_references: ["direct_0123456789abcdef01234567"],
  });
  const status = await ledger.status(PROFILE);
  assert.equal(status.cases[0].state, "submitted");
  assert.equal(status.cases[0].next_recheck_at, "2026-07-21T10:00:00.000Z");
  const stored = (await ledger.load(PROFILE)).brokers.beenverified;
  assert.equal(stored.last_observation.state, "inconclusive");
  assert.match(stored.history.at(-1).reason, /inconclusive_deferred/);
});

test("direct absence without a prior removal is not reported as confirmed removal", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await ledger.recordDirectRescan({
    subject_ref: PROFILE, broker_id: "truepeoplesearch", observation: "direct_absent_known_listing_set",
    removal_confirmation_scope: "known_listing_set_only", generated_at: "2026-07-12T10:00:00Z",
    proof_references: ["direct_0123456789abcdef01234567"],
  });
  const status = await ledger.status(PROFILE);
  assert.equal(status.counts.not_found, 1);
  assert.equal(status.counts.confirmed_removed, 0);
});

test("index observation never converts confirmed removal into reappeared", async () => {
  const store = memoryStore();
  const ledger = createCaseLedger(store, { now: () => new Date("2026-07-12T10:00:00Z") });
  await recordDiscovery(ledger);
  await ledger.reserveSubmission(PROFILE, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" });
  await ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "beenverified",
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"], disclosures: { to_broker: [] },
  });
  await ledger.recordLifecycle(PROFILE, "beenverified", "verification_pending", { evidenceKind: "broker_verification_link" });
  await ledger.recordLifecycle(PROFILE, "beenverified", "awaiting_processing", { evidenceKind: "broker_verification_link" });
  await ledger.recordDirectRescan({
    subject_ref: PROFILE, broker_id: "beenverified", observation: "direct_absent_known_listing_set",
    removal_confirmation_scope: "known_listing_set_only", generated_at: "2026-08-01T10:00:00Z",
    proof_references: ["direct_0123456789abcdef01234567"],
  });
  await ledger.recordDirectRescan({
    subject_ref: PROFILE, broker_id: "beenverified", observation: "direct_absent_known_listing_set",
    removal_confirmation_scope: "known_listing_set_only", generated_at: "2026-08-08T10:00:00Z",
    proof_references: ["direct_fedcba9876543210fedcba98"],
  });
  await ledger.recordScan({
    mode: "approval_gated_live_scan", scan_id: "scan_abcdef0123456789", subject_ref: PROFILE,
    generated_at: "2026-07-13T10:00:00Z",
    results: [{ broker_id: "beenverified", state: "indirect_exposure", reason: "search_index_candidate_observed" }],
  });
  assert.equal((await ledger.status(PROFILE)).counts.confirmed_removed, 1);
});

test("plan is deterministic and surfaces human work instead of dropping it", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  const plan = await ledger.plan(PROFILE, catalog);
  assert.deepEqual(plan.actions.map((row) => [row.broker_id, row.lane, row.next_action]), [
    ["beenverified", "email", "run_discovery"],
    ["truepeoplesearch", "scan_only", "run_discovery"],
    ["spokeo", "human_task", "queue_human_task"],
  ]);
  assert.equal(plan.summary.human_tasks, 1);
  assert.equal(plan.actions.find((row) => row.broker_id === "spokeo").official_action_url, "https://www.spokeo.com/optout");
  assert.equal(JSON.stringify(plan).includes("Alice"), false);
});

test("EU plan distinguishes controller erasure from browser-scoped preference control", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  const euCatalog = {
    brokers: [
      {
        id: "fullenrich_eu",
        official_url: "https://fullenrich.com/privacy-policy",
        official_domains: ["fullenrich.com"],
        lane: "email",
        human_only: false,
        process_class: "eu_controller_email_erasure",
        prerequisites: ["subject_authorization"],
        removal: {
          supported: true,
          channel: "email",
          discovery_requirement: "not_required_for_data_subject_request",
          confirmation_policy: "submitted_until_controller_response",
        },
        eu_process: {
          effect_scope: "controller_wide_request_subject_to_identification",
          erasure_semantics: "controller_erasure_request_not_yet_confirmed",
          one_click_level: "not_one_click_controller_email",
          official_action_url: "https://fullenrich.com/privacy-policy",
        },
      },
      {
        id: "edaa_yoc",
        official_url: "https://www.youronlinechoices.eu/",
        official_domains: ["youronlinechoices.eu"],
        lane: "guided_flow",
        human_only: true,
        process_class: "eu_advertising_preference",
        prerequisites: ["human_browser_action"],
        eu_process: {
          effect_scope: "participating_companies_current_browser",
          erasure_semantics: "preference_only_not_controller_erasure",
          one_click_level: "multi_company_one_stop_preference",
          official_action_url: "https://www.youronlinechoices.eu/",
        },
      },
    ],
  };
  const plan = await ledger.plan(PROFILE, euCatalog);
  assert.equal(plan.actions[0].broker_id, "fullenrich_eu");
  assert.equal(plan.actions[0].next_action, "submit_email_removal");
  assert.equal(plan.actions[0].erasure_semantics, "controller_erasure_request_not_yet_confirmed");
  assert.equal(plan.actions[1].next_action, "queue_human_task");
  assert.equal(plan.actions[1].erasure_semantics, "preference_only_not_controller_erasure");
  assert.equal(plan.summary.eu_processes, 2);

  for (const unsafeUrl of ["https://fullenrich.com/privacy-policy?next=evil", "https://fullenrich.com:444/privacy-policy"]) {
    const unsafeCatalog = structuredClone(euCatalog);
    unsafeCatalog.brokers[0].eu_process.official_action_url = unsafeUrl;
    const unsafePlan = await ledger.plan(PROFILE, unsafeCatalog);
    const unsafeFullenrich = unsafePlan.actions.find((row) => row.broker_id === "fullenrich_eu");
    assert.equal(Object.hasOwn(unsafeFullenrich, "official_action_url"), false);
    assert.equal(Object.hasOwn(unsafeFullenrich, "erasure_semantics"), false);
  }

  await ledger.reserveSubmission(PROFILE, "fullenrich_eu", { channel: "smtp_email", discoveryRequirement: "not_required_for_data_subject_request" });
  await ledger.recordRemoval({
    state: "submitted",
    subject_ref: PROFILE,
    broker_id: "fullenrich_eu",
    discovery_requirement: "not_required_for_data_subject_request",
    generated_at: "2026-07-12T10:00:00Z",
    delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"],
    disclosures: { to_broker: ["contact_email", "country"] },
  }, 30);
  const after = await ledger.plan(PROFILE, euCatalog);
  const fullenrichAfter = after.actions.find((row) => row.broker_id === "fullenrich_eu");
  assert.equal(fullenrichAfter.state, "submitted");
  assert.equal(fullenrichAfter.next_action, "wait_for_controller_response");
  assert.equal(fullenrichAfter.next_recheck_at, "2026-08-11T10:00:00.000Z");
});

test("due returns only elapsed rechecks", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await recordDiscovery(ledger);
  await ledger.reserveSubmission(PROFILE, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" });
  await ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "beenverified",
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: [], disclosures: { to_broker: [] },
  }, 2);
  assert.equal((await ledger.due(PROFILE, "2026-07-13T10:00:00Z")).due.length, 0);
  assert.equal((await ledger.due(PROFILE, "2026-07-14T10:00:00Z")).due.length, 1);
});

test("human-verified California DROP filing becomes one durable registry-wide case", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-13T10:00:00Z") });
  const filed = await ledger.recordDropFiled(PROFILE, { registryCount: 545, processingStart: "2026-08-01T00:00:00Z" });
  assert.equal(filed.state, "awaiting_processing");
  assert.match(filed.proof_reference, /^drop_[a-f0-9]{24}$/);
  assert.equal(filed.next_recheck_at, "2026-08-01T00:00:00.000Z");
  const status = await ledger.status(PROFILE);
  const drop = status.cases.find((item) => item.broker_id === "ca_drop");
  assert.equal(drop.submission_channel, "california_drop_human_portal");
  assert.equal(drop.coverage_gap, "nonregistered_brokers_and_fcra_exceptions_not_covered");
  await assert.rejects(ledger.recordDropFiled(PROFILE, { registryCount: 545, processingStart: "2026-08-01T00:00:00Z" }), /already_recorded/);
});

test("removal and form submission require prior discovery evidence", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await assert.rejects(ledger.removalContext(PROFILE, "beenverified"), /rightout_discovery_required_before_removal/);
  await assert.rejects(ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "beenverified",
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"], disclosures: { to_broker: [] },
  }), /submission_intent_required/);
  await assert.rejects(ledger.recordFormSubmission({
    state: "verification_pending", subject_ref: PROFILE, broker_id: "intelius",
    generated_at: "2026-07-12T10:00:00Z", delivery: { form_submitted: true },
    proof_references: ["form_0123456789abcdef01234567"], disclosures: { to_broker: [] },
  }), /submission_intent_required/);
});

test("concurrent updates retain both broker cases", async () => {
  const store = memoryStore();
  const ledger = createCaseLedger(store, { now: () => new Date("2026-07-12T10:00:00Z") });
  await Promise.all([
    ledger.ensure(PROFILE, ["beenverified"]),
    ledger.ensure(PROFILE, ["truepeoplesearch"]),
  ]);
  assert.deepEqual(Object.keys((await ledger.load(PROFILE)).brokers).sort(), ["beenverified", "truepeoplesearch"]);
});

test("v0.5 schema-v1 cases remain readable with v0.6 optional fields", async () => {
  const store = memoryStore();
  await store.register(PROFILE, {
    schema_version: 1,
    subject_ref: PROFILE,
    created_at: "2026-07-11T10:00:00.000Z",
    updated_at: "2026-07-11T10:00:00.000Z",
    brokers: {
      beenverified: {
        broker_id: "beenverified",
        state: "submitted",
        last_observation: null,
        proof_references: ["smtp_0123456789abcdef01234567"],
        disclosure_fields: ["contact_email"],
        submission_channel: "smtp_email",
        submission_started_at: "2026-07-11T10:00:00.000Z",
        submission_outcome: "accepted_by_outbound_smtp",
        next_recheck_at: "2026-07-25T10:00:00.000Z",
        removal_confirmed_at: null,
        removal_confirmation_scope: null,
        coverage_gap: null,
        human_task_reason: null,
        updated_at: "2026-07-11T10:00:00.000Z",
        history: [],
      },
    },
  });
  const ledger = createCaseLedger(store, { now: () => new Date("2026-07-12T10:00:00Z") });
  const status = await ledger.status(PROFILE);
  assert.equal(status.counts.submitted, 1);
  assert.equal(status.cases[0].listing_handle, null);
  assert.equal(status.cases[0].direct_absence_observed_at, null);
  assert.equal((await ledger.plan(PROFILE, catalog)).actions.find((row) => row.broker_id === "beenverified").state, "submitted");
});

test("ownership-cluster reduction orders the parent and suppresses redundant child writes", async () => {
  const store = memoryStore();
  const ledger = createCaseLedger(store, { now: () => new Date("2026-07-12T10:00:00Z") });
  const clustered = {
    brokers: [
      {
        id: "clusterparent", lane: "search_index", human_only: false,
        prerequisites: ["subject_authorization"], scan: { supported: true },
        ownership_cluster: { id: "cluster", parent_broker_id: "clusterparent", role: "parent", coverage_policy: "official_registry_claims_one_site_request_applies_across_cluster" },
      },
      {
        id: "clusterchild", lane: "search_index", human_only: false,
        prerequisites: ["subject_authorization"], scan: { supported: true },
        ownership_cluster: { id: "cluster", parent_broker_id: "clusterparent", role: "child", coverage_policy: "official_registry_claims_one_site_request_applies_across_cluster" },
      },
    ],
  };
  await ledger.recordScan({
    mode: "approval_gated_live_scan", scan_id: "scan_0123456789abcdef", subject_ref: PROFILE,
    generated_at: "2026-07-12T10:00:00Z",
    results: [
      { broker_id: "clusterparent", state: "indirect_exposure", reason: "search_index_candidate_observed" },
      { broker_id: "clusterchild", state: "indirect_exposure", reason: "search_index_candidate_observed" },
    ],
  });
  const plan = await ledger.plan(PROFILE, clustered);
  assert.equal(plan.actions[0].broker_id, "clusterparent");
  assert.equal(plan.actions[0].next_action, "queue_human_task");
  assert.equal(plan.actions[1].broker_id, "clusterchild");
  assert.equal(plan.actions[1].next_action, "wait_for_cluster_parent");
});
