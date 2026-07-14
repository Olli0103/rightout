import assert from "node:assert/strict";
import test from "node:test";

import { planGlobalScanCampaignNext, planParityCampaignNext } from "../../lib/parity-autopilot.mjs";

const campaign = {
  campaign_id: `campaign_${"a".repeat(32)}`,
  subject_ref: "profile_0123456789abcdef",
  status: "active",
  broker_ids: ["familytreenow", "mylife", "spokeo"],
  effects: ["discover", "submit_email", "submit_form", "poll_verification", "direct_recheck"],
};

const parityCatalog = { brokers: [
  { id: "familytreenow", method: "web_form", source_status: "observed_403_antibot", verification: "on_site" },
  { id: "mylife", method: "phone", source_status: "observed_403_antibot", verification: "phone_or_identity", rescue_email: "membersupport@mylife.com", rescue_disclosure_fields: ["full_name", "contact_email", "listing_url"] },
  { id: "spokeo", method: "web_form", source_status: "observed_200_terms_restrict_automation", verification: "email", rescue_email: "legal@spokeo.com", rescue_disclosure_fields: ["full_name", "contact_email", "listing_url"] },
] };

test("autopilot scans every unresolved broker in one bounded batch", () => {
  const next = planParityCampaignNext({ campaign, caseStatus: { cases: [] }, parityCatalog });
  assert.equal(next.command.tool, "rightout_live_scan");
  assert.deepEqual(next.command.parameters.brokerIds, campaign.broker_ids);
  assert.equal(next.command.parameters.campaignId, campaign.campaign_id);
});

test("global autonomous discovery advances every eligible broker in deterministic four-route batches", () => {
  const brokerIds = Array.from({ length: 9 }, (_, index) => `global_${index}`);
  const scanCampaign = { ...campaign, broker_ids: brokerIds, effects: ["discover"] };
  const scanCatalog = { brokers: brokerIds.map((id) => ({
    id, category: id.endsWith("0") ? "people_search" : "data_broker",
    scan: { supported: true, automated_access_policy: "search_index_only_no_publisher_access" },
  })) };
  const first = planGlobalScanCampaignNext({ campaign: scanCampaign, caseStatus: { cases: [] }, scanCatalog });
  assert.deepEqual(first.command.parameters.brokerIds, brokerIds.slice(0, 4));
  assert.equal(first.remaining_unscanned_brokers, 9);
  const second = planGlobalScanCampaignNext({
    campaign: scanCampaign,
    caseStatus: { cases: brokerIds.slice(0, 4).map((broker_id) => ({ broker_id, state: "inconclusive" })) },
    scanCatalog,
  });
  assert.deepEqual(second.command.parameters.brokerIds, brokerIds.slice(4, 8));
  const final = planGlobalScanCampaignNext({
    campaign: scanCampaign,
    caseStatus: { cases: brokerIds.map((broker_id) => ({ broker_id, state: "indirect_exposure" })) },
    scanCatalog,
  });
  assert.equal(final.state, "done_for_now");
});

test("an inconclusive Brave scan never loops and blind opt-out proceeds only when the official route needs no listing URL", () => {
  const blindCampaign = { ...campaign, broker_ids: ["familytreenow"] };
  const blindCatalog = { brokers: [{
    id: "familytreenow", method: "web_form", source_status: "observed_403_antibot",
    disclosure_fields: ["full_name"], verification: "on_site",
  }] };
  const blind = planParityCampaignNext({
    campaign: blindCampaign,
    caseStatus: { cases: [{ broker_id: "familytreenow", state: "inconclusive" }] },
    parityCatalog: blindCatalog,
  });
  assert.equal(blind.command.tool, "rightout_begin_form_session");
  assert.equal(blind.command.parameters.listingHandle, undefined);

  const listingCampaign = { ...campaign, broker_ids: ["spokeo"] };
  const listingCatalog = { brokers: [{
    id: "spokeo", method: "web_form", source_status: "observed_200_terms_restrict_automation",
    disclosure_fields: ["listing_url", "contact_email"], verification: "email", rescue_email: "legal@spokeo.com",
    rescue_disclosure_fields: ["full_name", "contact_email", "listing_url"],
  }] };
  const gated = planParityCampaignNext({
    campaign: listingCampaign,
    caseStatus: { cases: [{ broker_id: "spokeo", state: "inconclusive" }] },
    parityCatalog: listingCatalog,
  });
  assert.equal(gated.state, "done_for_now");
  assert.equal(gated.consolidated_digest.human_gates, 1);
  assert.match(gated.consolidated_digest.deferred_human_gates[0].reason, /requires_listing_url/);

  const writtenPermissionRoute = planParityCampaignNext({
    campaign: listingCampaign,
    caseStatus: { cases: [{ broker_id: "spokeo", state: "found", listing_handle: `listing_${"c".repeat(24)}` }] },
    parityCatalog: listingCatalog,
  });
  assert.equal(writtenPermissionRoute.command.tool, "rightout_begin_form_session");
  assert.equal(writtenPermissionRoute.command.parameters.brokerId, "spokeo");

  const browserCampaign = { ...campaign, broker_ids: ["clustal"], effects: [...campaign.effects, "publisher_discover"] };
  const browserCatalog = { brokers: [{
    id: "clustal", method: "web_form", source_status: "observed_403_antibot",
    disclosure_fields: ["listing_url", "contact_email"], verification: "email",
  }] };
  const browser = planParityCampaignNext({
    campaign: browserCampaign,
    caseStatus: { cases: [{ broker_id: "clustal", state: "inconclusive" }] },
    parityCatalog: browserCatalog,
  });
  assert.equal(browser.command.tool, "rightout_begin_discovery_session");
  assert.equal(browser.command.parameters.brokerId, "clustal");
});

test("autopilot selects a generic form and improves the reference phone lane with official email", () => {
  const cases = campaign.broker_ids.map((broker_id) => ({ broker_id, state: "indirect_exposure", listing_handle: `listing_${"b".repeat(24)}` }));
  let next = planParityCampaignNext({ campaign, caseStatus: { cases }, parityCatalog });
  assert.equal(next.command.tool, "rightout_direct_rescan");
  assert.match(next.command.reason, /parent_reverifies/);
  cases[0].state = "found";
  next = planParityCampaignNext({ campaign, caseStatus: { cases }, parityCatalog });
  assert.equal(next.command.tool, "rightout_begin_form_session");
  assert.equal(next.command.parameters.brokerId, "familytreenow");
  cases[0].state = "verification_pending";
  cases[1].state = "found";
  next = planParityCampaignNext({ campaign, caseStatus: { cases }, parityCatalog });
  assert.equal(next.command.tool, "rightout_submit_parity_email");
  assert.equal(next.command.parameters.brokerId, "mylife");
  assert.match(next.command.reason, /improves_on_reference_phone/);
});

test("autopilot uses an independently sourced rescue email while the reference form host is unavailable", () => {
  const next = planParityCampaignNext({
    campaign: { ...campaign, broker_ids: ["peekyou"] },
    caseStatus: { cases: [{ broker_id: "peekyou", state: "inconclusive" }] },
    parityCatalog: { brokers: [{
      id: "peekyou", method: "web_form", source_status: "observed_official_archive_external_unavailable", verification: "email",
      disclosure_fields: ["full_name", "contact_email", "listing_url"], rescue_email: "ccpa@peekyou.com",
      rescue_disclosure_fields: ["full_name", "contact_email"],
    }] },
  });
  assert.equal(next.state, "action_ready");
  assert.equal(next.command.tool, "rightout_submit_parity_email");
  assert.equal(next.command.parameters.listingHandle, undefined);
  assert.equal(next.command.reason, "autonomous_official_rescue_for_external_unavailable_reference_route");
});

test("autopilot selects privacy-redacted webmail when SMTP is not configured", () => {
  const next = planParityCampaignNext({
    campaign: { ...campaign, broker_ids: ["peekyou"] },
    caseStatus: { cases: [{ broker_id: "peekyou", state: "inconclusive" }] },
    parityCatalog: { brokers: [{
      id: "peekyou", method: "web_form", source_status: "observed_official_archive_external_unavailable",
      disclosure_fields: ["full_name", "contact_email", "listing_url"], rescue_email: "ccpa@peekyou.com",
      rescue_disclosure_fields: ["full_name", "contact_email"],
    }] },
    emailMode: "webmail",
  });
  assert.equal(next.command.tool, "rightout_begin_webmail_session");
  assert.equal(next.command.parameters.brokerId, "peekyou");
});

test("autopilot routes due browser-mail verification through the bound logged-in profile", () => {
  const next = planParityCampaignNext({
    campaign: { ...campaign, broker_ids: ["spokeo"], effects: [...campaign.effects, "open_verification"] },
    caseStatus: { cases: [{
      broker_id: "spokeo", state: "verification_pending", next_recheck_at: "2026-01-01T00:00:00.000Z",
    }] },
    parityCatalog: { brokers: [{ id: "spokeo", method: "web_form", source_status: "observed_403_antibot", verification: "email" }] },
    verificationMode: "browser_webmail",
    now: Date.parse("2026-07-13T00:00:00.000Z"),
  });
  assert.equal(next.command.tool, "rightout_begin_webmail_verification");
  assert.equal(next.command.parameters.brokerId, "spokeo");
  assert.equal(next.command.parameters.campaignId, campaign.campaign_id);
});

test("a blocked route retries through the configured remote cloud browser before becoming human work", () => {
  const next = planParityCampaignNext({
    campaign: { ...campaign, broker_ids: ["familytreenow"], effects: [...campaign.effects, "publisher_discover"] },
    caseStatus: { cases: [{ broker_id: "familytreenow", state: "blocked" }] },
    parityCatalog: { brokers: [{ id: "familytreenow", method: "web_form", source_status: "observed_403_antibot" }] },
    browserMode: "managed_openclaw",
    remoteCloudRetryAvailable: true,
  });
  assert.equal(next.command.tool, "rightout_begin_discovery_session");
  assert.equal(next.command.parameters.browserBackend, "remote_cloud_cdp");
  assert.equal(next.command.reason, "stealth_or_cloud_browser_retry_after_blocked_primary_browser");
});

test("ambiguous provider writes take precedence over every browser retry", () => {
  const next = planParityCampaignNext({
    campaign: { ...campaign, broker_ids: ["familytreenow", "spokeo"], effects: [...campaign.effects, "publisher_discover"] },
    caseStatus: { cases: [
      { broker_id: "familytreenow", state: "blocked" },
      { broker_id: "spokeo", state: "submission_uncertain" },
    ] },
    parityCatalog,
    browserMode: "managed_openclaw",
    remoteCloudRetryAvailable: true,
  });
  assert.equal(next.state, "human_gate");
  assert.equal(next.next_tool, "rightout_reconcile_submission");
});

test("an unavailable route without a verified listing does not block the rest of the autonomous queue", () => {
  const degradedCampaign = { ...campaign, broker_ids: ["clustrmaps", "peekyou"] };
  const degradedCatalog = { brokers: [
    {
      id: "clustrmaps", method: "web_form", source_status: "observed_official_archive_external_unavailable", verification: "email",
      disclosure_fields: ["contact_email", "listing_url"], rescue_email: "support@clustrmaps.com",
      rescue_disclosure_fields: ["full_name", "contact_email", "listing_url"],
    },
    {
      id: "peekyou", method: "web_form", source_status: "observed_official_archive_external_unavailable", verification: "email",
      disclosure_fields: ["full_name", "contact_email", "listing_url"], rescue_email: "ccpa@peekyou.com",
      rescue_disclosure_fields: ["full_name", "contact_email"],
    },
  ] };
  const cases = [
    { broker_id: "clustrmaps", state: "inconclusive" },
    { broker_id: "peekyou", state: "inconclusive" },
  ];
  const next = planParityCampaignNext({ campaign: degradedCampaign, caseStatus: { cases }, parityCatalog: degradedCatalog });
  assert.equal(next.command.parameters.brokerId, "peekyou");
  cases[1].state = "submitted";
  const done = planParityCampaignNext({ campaign: degradedCampaign, caseStatus: { cases }, parityCatalog: degradedCatalog });
  assert.equal(done.state, "done_for_now");
  assert.deepEqual(done.consolidated_digest.external_degradations.map((item) => item.broker_id), ["clustrmaps"]);
});

test("source and human gates are consolidated instead of blocking a later autonomous effect", () => {
  const mixedCampaign = { ...campaign, broker_ids: ["aaa_unknown", "familytreenow"] };
  const mixedCatalog = { brokers: [
    { id: "aaa_unknown", method: "phone", source_status: "needs_evidence", disclosure_fields: ["full_name"] },
    { id: "familytreenow", method: "web_form", source_status: "observed_403_antibot", disclosure_fields: ["full_name"] },
  ] };
  const cases = [
    { broker_id: "aaa_unknown", state: "inconclusive" },
    { broker_id: "familytreenow", state: "inconclusive" },
  ];
  const next = planParityCampaignNext({ campaign: mixedCampaign, caseStatus: { cases }, parityCatalog: mixedCatalog });
  assert.equal(next.command.parameters.brokerId, "familytreenow");
  cases[1].state = "verification_pending";
  const done = planParityCampaignNext({ campaign: mixedCampaign, caseStatus: { cases }, parityCatalog: mixedCatalog });
  assert.equal(done.state, "done_for_now");
  assert.deepEqual(done.consolidated_digest.deferred_human_gates.map((item) => item.broker_id), ["aaa_unknown"]);
});

test("DOB form recipes remain autonomous after the form tool's explicit host-only gate", () => {
  const next = planParityCampaignNext({
    campaign: { ...campaign, broker_ids: ["intelius"] },
    caseStatus: { cases: [{ broker_id: "intelius", state: "inconclusive" }] },
    parityCatalog: { brokers: [{
      id: "intelius", method: "web_form", source_status: "observed_200",
      disclosure_fields: ["contact_email", "full_name", "date_of_birth"],
    }] },
  });
  assert.equal(next.state, "action_ready");
  assert.equal(next.command.tool, "rightout_begin_form_session");
  assert.equal(next.command.parameters.brokerId, "intelius");
});

test("official ownership coverage submits the parent before skipping redundant cluster children", () => {
  const clusteredCampaign = { ...campaign, broker_ids: ["familytreenow", "mylife"] };
  const clusteredCatalog = { brokers: [
    { id: "familytreenow", ownership_cluster: { id: "c", parent_broker_id: "familytreenow", role: "parent", coverage_policy: "official_registry_claims_one_site_request_applies_across_cluster" } },
    { id: "mylife", ownership_cluster: { id: "c", parent_broker_id: "familytreenow", role: "child", coverage_policy: "official_registry_claims_one_site_request_applies_across_cluster" } },
  ] };
  const cases = [
    { broker_id: "familytreenow", state: "found" },
    { broker_id: "mylife", state: "indirect_exposure" },
  ];
  const parent = planParityCampaignNext({ campaign: clusteredCampaign, caseStatus: { cases }, parityCatalog, coreCatalog: clusteredCatalog });
  assert.equal(parent.command.parameters.brokerId, "familytreenow");
  cases[0].state = "submitted";
  const skipped = planParityCampaignNext({ campaign: clusteredCampaign, caseStatus: { cases }, parityCatalog, coreCatalog: clusteredCatalog });
  assert.equal(skipped.state, "done_for_now");
});

test("ambiguous writes hard-stop autonomy and a waiting campaign emits one digest", () => {
  const uncertain = planParityCampaignNext({
    campaign,
    parityCatalog,
    caseStatus: { cases: [{ broker_id: "spokeo", state: "submission_uncertain" }] },
  });
  assert.equal(uncertain.state, "human_gate");
  assert.equal(uncertain.next_tool, "rightout_reconcile_submission");

  const waitingCases = campaign.broker_ids.map((broker_id) => ({
    broker_id,
    state: "awaiting_processing",
    next_recheck_at: "2099-01-01T00:00:00.000Z",
  }));
  const waiting = planParityCampaignNext({ campaign, parityCatalog, caseStatus: { cases: waitingCases }, now: 0 });
  assert.equal(waiting.state, "done_for_now");
  assert.equal(waiting.next_wake_at, "2099-01-01T00:00:00.000Z");
  assert.equal(waiting.consolidated_digest.in_flight, 3);
});
