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
    "action_selected", "submitted", "verification_pending", "awaiting_processing",
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

test("approved removal records submission, field names, proof, and due date", async () => {
  const store = memoryStore();
  const ledger = createCaseLedger(store, { now: clock("2026-07-12T10:00:00Z", "2026-07-12T10:00:01Z") });
  await recordDiscovery(ledger);
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
    /confirmed_removal_requires_direct_rescan/,
  );
});

test("browser form initiation records verification_pending without claiming removal", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await recordDiscovery(ledger, "intelius");
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

test("verification lifecycle reaches confirmed removal only after direct absence evidence", async () => {
  const store = memoryStore();
  const ledger = createCaseLedger(store, { now: clock(
    "2026-07-12T10:00:00Z", "2026-07-12T10:01:00Z", "2026-07-12T10:02:00Z",
    "2026-07-12T10:03:00Z", "2026-07-12T10:04:00Z", "2026-07-12T10:05:00Z",
  ) });
  await recordDiscovery(ledger);
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
  await ledger.recordLifecycle(PROFILE, "beenverified", "confirmed_removed", {
    evidenceKind: "trusted_direct_rescan_absent",
    proofReference: "direct_0123456789abcdef01234567",
  });
  const status = await ledger.status(PROFILE);
  assert.equal(status.metrics.confirmed_removed, 1);
  assert.ok(status.cases[0].removal_confirmed_at);
  assert.ok(status.cases[0].next_recheck_at);
});

test("direct-rescan report confirms a submitted known listing set and later detects reappearance", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await recordDiscovery(ledger);
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
  await ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "beenverified",
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"], disclosures: { to_broker: [] },
  });
  await ledger.recordLifecycle(PROFILE, "beenverified", "verification_pending", { evidenceKind: "broker_verification_link" });
  await ledger.recordLifecycle(PROFILE, "beenverified", "awaiting_processing", { evidenceKind: "broker_verification_link" });
  await ledger.recordLifecycle(PROFILE, "beenverified", "confirmed_removed", { evidenceKind: "trusted_direct_rescan_absent" });
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
  assert.equal(JSON.stringify(plan).includes("Alice"), false);
});

test("EU plan distinguishes controller erasure from browser-scoped preference control", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  const euCatalog = {
    brokers: [
      {
        id: "adsquare_eu",
        official_url: "https://adsquare.com/privacy",
        official_domains: ["adsquare.com"],
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
          effect_scope: "controller_wide_for_identified_mobile_advertising_id",
          erasure_semantics: "controller_erasure_request_not_yet_confirmed",
          one_click_level: "not_one_click_controller_email",
          official_action_url: "https://adsquare.com/privacy",
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
  assert.equal(plan.actions[0].broker_id, "adsquare_eu");
  assert.equal(plan.actions[0].next_action, "submit_email_removal");
  assert.equal(plan.actions[0].erasure_semantics, "controller_erasure_request_not_yet_confirmed");
  assert.equal(plan.actions[1].next_action, "queue_human_task");
  assert.equal(plan.actions[1].erasure_semantics, "preference_only_not_controller_erasure");
  assert.equal(plan.summary.eu_processes, 2);

  for (const unsafeUrl of ["https://adsquare.com/privacy?next=evil", "https://adsquare.com:444/privacy"]) {
    const unsafeCatalog = structuredClone(euCatalog);
    unsafeCatalog.brokers[0].eu_process.official_action_url = unsafeUrl;
    const unsafePlan = await ledger.plan(PROFILE, unsafeCatalog);
    const unsafeAdsquare = unsafePlan.actions.find((row) => row.broker_id === "adsquare_eu");
    assert.equal(Object.hasOwn(unsafeAdsquare, "official_action_url"), false);
    assert.equal(Object.hasOwn(unsafeAdsquare, "erasure_semantics"), false);
  }

  await ledger.recordRemoval({
    state: "submitted",
    subject_ref: PROFILE,
    broker_id: "adsquare_eu",
    discovery_requirement: "not_required_for_data_subject_request",
    generated_at: "2026-07-12T10:00:00Z",
    delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"],
    disclosures: { to_broker: ["contact_email", "mobile_advertising_id", "country"] },
  }, 30);
  const after = await ledger.plan(PROFILE, euCatalog);
  const adsquareAfter = after.actions.find((row) => row.broker_id === "adsquare_eu");
  assert.equal(adsquareAfter.state, "submitted");
  assert.equal(adsquareAfter.next_action, "wait_for_controller_response");
  assert.equal(adsquareAfter.next_recheck_at, "2026-08-11T10:00:00.000Z");
});

test("due returns only elapsed rechecks", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await recordDiscovery(ledger);
  await ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "beenverified",
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: [], disclosures: { to_broker: [] },
  }, 2);
  assert.equal((await ledger.due(PROFILE, "2026-07-13T10:00:00Z")).due.length, 0);
  assert.equal((await ledger.due(PROFILE, "2026-07-14T10:00:00Z")).due.length, 1);
});

test("removal and form submission require prior discovery evidence", async () => {
  const ledger = createCaseLedger(memoryStore(), { now: () => new Date("2026-07-12T10:00:00Z") });
  await assert.rejects(ledger.removalContext(PROFILE, "beenverified"), /rightout_discovery_required_before_removal/);
  await assert.rejects(ledger.recordRemoval({
    state: "submitted", subject_ref: PROFILE, broker_id: "beenverified",
    generated_at: "2026-07-12T10:00:00Z", delivery: { accepted_by_outbound_smtp: true },
    proof_references: ["smtp_0123456789abcdef01234567"], disclosures: { to_broker: [] },
  }), /illegal_case_transition/);
  await assert.rejects(ledger.recordFormSubmission({
    state: "verification_pending", subject_ref: PROFILE, broker_id: "intelius",
    generated_at: "2026-07-12T10:00:00Z", delivery: { form_submitted: true },
    proof_references: ["form_0123456789abcdef01234567"], disclosures: { to_broker: [] },
  }), /illegal_case_transition/);
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
