import { isBraveScanLane } from "./scan-catalog.mjs";

const SAFE_CAMPAIGN_ID = /^campaign_[a-f0-9]{32}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,80}$/;
const EXTERNAL_UNAVAILABLE_STATUS = "observed_official_archive_external_unavailable";
const ACTIVE_SUBMISSION_STATES = new Set([
  "inconclusive", "not_found", "found", "indirect_exposure", "action_selected", "reappeared",
  "submission_pending", "submission_uncertain", "submitted", "verification_pending",
  "awaiting_processing", "identity_verification_required", "partially_removed",
  "request_rejected", "confirmed_removed", "human_task_queued", "blocked",
]);
export const LIVE_SCAN_CAMPAIGN_BATCH_SIZE = 4;

function assertPublicCampaign(value) {
  if (
    !value || typeof value !== "object" || value.status !== "active"
    || !SAFE_CAMPAIGN_ID.test(value.campaign_id ?? "")
    || !SAFE_PROFILE_ID.test(value.subject_ref ?? "")
    || !Array.isArray(value.broker_ids) || value.broker_ids.length < 1
    || value.broker_ids.some((id) => !SAFE_BROKER_ID.test(id))
    || !Array.isArray(value.effects)
  ) throw new Error("rightout_campaign_not_active");
}

function assertCaseStatus(value) {
  if (!value || typeof value !== "object" || !Array.isArray(value.cases)) throw new Error("rightout_autopilot_state_invalid");
}

function safeWake(cases, now) {
  return cases
    .map((item) => item?.next_recheck_at)
    .filter((value) => typeof value === "string" && Number.isFinite(Date.parse(value)) && Date.parse(value) > now)
    .sort()[0] ?? null;
}

function command(tool, parameters, reason) {
  return { kind: "execute_tool", tool, parameters, reason };
}

export function planGlobalScanCampaignNext({ campaign, caseStatus, scanCatalog }) {
  assertPublicCampaign(campaign);
  assertCaseStatus(caseStatus);
  if (campaign.effects.length !== 1 || campaign.effects[0] !== "discover") {
    throw new Error("rightout_autopilot_scope_invalid");
  }
  const rows = Array.isArray(scanCatalog?.brokers) ? scanCatalog.brokers : [];
  const eligible = new Set(rows.filter(isBraveScanLane).map((row) => row.id));
  if (campaign.broker_ids.some((id) => !eligible.has(id))) throw new Error("rightout_autopilot_catalog_invalid");
  const caseById = new Map(caseStatus.cases.map((item) => [item.broker_id, item]));
  const unresolved = campaign.broker_ids
    .filter((id) => !ACTIVE_SUBMISSION_STATES.has(caseById.get(id)?.state ?? "new"))
    .sort();
  if (unresolved.length) {
    return {
      state: "action_ready",
      command: command("rightout_live_scan", {
        profileId: campaign.subject_ref,
        brokerIds: unresolved.slice(0, LIVE_SCAN_CAMPAIGN_BATCH_SIZE),
        campaignId: campaign.campaign_id,
      }, "discover_next_bounded_global_catalog_batch"),
      remaining_unscanned_brokers: unresolved.length,
      batch_size: Math.min(LIVE_SCAN_CAMPAIGN_BATCH_SIZE, unresolved.length),
    };
  }
  return {
    state: "done_for_now",
    reason: "global_catalog_scan_scope_complete",
    next_wake_at: null,
    autonomous_effects_executed: 0,
  };
}

/**
 * Produce one deterministic next command for a bounded campaign. The caller executes
 * the returned RightOut tool and calls this function again until done_for_now.
 */
export function planParityCampaignNext({
  campaign, caseStatus, parityCatalog, coreCatalog,
  emailMode = "smtp", verificationMode = "imap", browserMode = "managed_openclaw",
  remoteCloudRetryAvailable = false, now = Date.now(),
}) {
  assertPublicCampaign(campaign);
  assertCaseStatus(caseStatus);
  if (!parityCatalog || !Array.isArray(parityCatalog.brokers)) throw new Error("rightout_autopilot_catalog_invalid");
  if (!["smtp", "webmail", "unavailable"].includes(emailMode)) throw new Error("rightout_autopilot_transport_invalid");
  if (!["imap", "browser_webmail", "unavailable"].includes(verificationMode)) throw new Error("rightout_autopilot_transport_invalid");
  if (!["managed_openclaw", "remote_cloud_cdp", "existing_logged_in_cdp", "named_profile_unspecified", "unavailable"].includes(browserMode)) {
    throw new Error("rightout_autopilot_transport_invalid");
  }

  const routeById = new Map(parityCatalog.brokers.map((route) => [route.id, route]));
  const coreById = new Map((Array.isArray(coreCatalog?.brokers) ? coreCatalog.brokers : []).map((route) => [route.id, route]));
  const caseById = new Map(caseStatus.cases.map((item) => [item.broker_id, item]));
  const scopedRoutes = campaign.broker_ids.map((id) => routeById.get(id)).filter(Boolean);
  if (scopedRoutes.length !== campaign.broker_ids.length) throw new Error("rightout_autopilot_catalog_invalid");
  const effects = new Set(campaign.effects);

  const uncertain = campaign.broker_ids
    .map((id) => caseById.get(id))
    .filter((item) => ["submission_pending", "submission_uncertain"].includes(item?.state))
    .sort((a, b) => a.broker_id.localeCompare(b.broker_id));
  if (uncertain.length) {
    return {
      state: "human_gate",
      reason: "ambiguous_provider_write_requires_operator_reconciliation",
      broker_id: uncertain[0].broker_id,
      next_tool: "rightout_reconcile_submission",
      autonomous_effects_executed: 0,
    };
  }

  const blockedRetry = scopedRoutes
    .map((route) => ({ route, item: caseById.get(route.id) }))
    .filter(({ route, item }) => item?.state === "blocked"
      && remoteCloudRetryAvailable && browserMode !== "remote_cloud_cdp" && effects.has("publisher_discover")
      && !["needs_evidence", EXTERNAL_UNAVAILABLE_STATUS].includes(route.source_status))
    .sort((a, b) => a.route.id.localeCompare(b.route.id))[0];
  if (blockedRetry) {
    return {
      state: "action_ready",
      command: command("rightout_begin_discovery_session", {
        profileId: campaign.subject_ref,
        brokerId: blockedRetry.route.id,
        campaignId: campaign.campaign_id,
        browserBackend: "remote_cloud_cdp",
      }, "stealth_or_cloud_browser_retry_after_blocked_primary_browser"),
    };
  }

  const undiscoveredRoutes = scopedRoutes
    .filter((route) => !ACTIVE_SUBMISSION_STATES.has(caseById.get(route.id)?.state ?? "new"));
  const scanRestricted = undiscoveredRoutes.filter((route) => {
    const core = coreById.get(route.id);
    return core?.human_only === true || core?.scan?.manual_only === true
      || core?.scan?.automated_access_policy === "prohibited_by_published_terms";
  });
  const undiscovered = undiscoveredRoutes
    .filter((route) => !scanRestricted.includes(route))
    .map((route) => route.id)
    .sort();
  if (undiscovered.length && effects.has("discover")) {
    return {
      state: "action_ready",
      command: command("rightout_live_scan", {
        profileId: campaign.subject_ref,
        brokerIds: undiscovered.slice(0, LIVE_SCAN_CAMPAIGN_BATCH_SIZE),
        campaignId: campaign.campaign_id,
      }, "discover_next_bounded_scoped_broker_batch"),
    };
  }

  const actionable = scopedRoutes
    .map((route) => ({ route, item: caseById.get(route.id) }))
    .filter(({ item }) => ["inconclusive", "not_found", "found", "indirect_exposure", "action_selected", "reappeared"].includes(item?.state))
    .sort((a, b) => {
      const role = (route) => coreById.get(route.id)?.ownership_cluster?.role === "parent" ? 0 : 1;
      return role(a.route) - role(b.route) || a.route.id.localeCompare(b.route.id);
    });
  const externalDegradations = [];
  const deferredHumanGates = scanRestricted.map((route) => ({
    broker_id: route.id,
    reason: "published_terms_require_human_only_discovery",
    next_action: "operator_locates_and_verifies_the_listing_outside_plugin_automation",
  }));
  for (const { route, item } of actionable) {
    const cluster = coreById.get(route.id)?.ownership_cluster;
    if (
      cluster?.role === "child"
      && cluster.coverage_policy === "official_registry_claims_one_site_request_applies_across_cluster"
      && campaign.broker_ids.includes(cluster.parent_broker_id)
    ) {
      const parentState = caseById.get(cluster.parent_broker_id)?.state ?? "new";
      if (["found", "indirect_exposure", "action_selected", "reappeared", "submission_pending", "submission_uncertain", "submitted", "verification_pending", "awaiting_processing", "confirmed_removed"].includes(parentState)) continue;
    }
    const useEmail = route.method === "email" || route.method === "phone"
      || route.source_status === EXTERNAL_UNAVAILABLE_STATUS
      || String(route.source_status).startsWith("needs_evidence");
    const rescueNeedsListing = route.rescue_disclosure_fields?.includes("listing_url");
    if (useEmail && route.rescue_email && effects.has("submit_email") && emailMode !== "unavailable" && (!rescueNeedsListing || item.listing_handle)) {
      return {
        state: "action_ready",
        command: command(emailMode === "webmail" ? "rightout_begin_webmail_session" : "rightout_submit_parity_email", {
          profileId: campaign.subject_ref,
          brokerId: route.id,
          campaignId: campaign.campaign_id,
          ...(item.listing_handle ? { listingHandle: item.listing_handle } : {}),
        }, route.source_status === EXTERNAL_UNAVAILABLE_STATUS
          ? "autonomous_official_rescue_for_external_unavailable_reference_route"
          : String(route.source_status).startsWith("needs_evidence")
          ? "official_rescue_channel_used_while_form_route_fails_closed"
          : route.method === "phone"
            ? "autonomous_official_email_rescue_improves_on_reference_phone_handoff"
            : "official_email_lane"),
      };
    }
    if (route.source_status === EXTERNAL_UNAVAILABLE_STATUS) {
      externalDegradations.push({
        broker_id: route.id,
        reason: rescueNeedsListing && !item.listing_handle
          ? "external_route_unavailable_and_rescue_requires_verified_listing"
          : "external_route_unavailable_and_rescue_effect_not_authorized",
        retry_when: "official_route_recovers_or_a_verified_listing_enables_the_rescue_lane",
      });
      continue;
    }
    if (String(route.source_status).startsWith("needs_evidence")) {
      deferredHumanGates.push({
        broker_id: route.id,
        reason: "official_route_needs_evidence",
        next_action: "refresh_clean_room_official_source_before_provider_io",
      });
      continue;
    }
    if (item.state === "indirect_exposure" && item.listing_handle && effects.has("direct_recheck")) {
      return {
        state: "action_ready",
        command: command("rightout_direct_rescan", {
          profileId: campaign.subject_ref,
          brokerId: route.id,
          listingHandle: item.listing_handle,
          campaignId: campaign.campaign_id,
        }, "parent_reverifies_search_index_candidate_before_provider_write"),
      };
    }
    if (route.disclosure_fields?.includes("listing_url") && !item.listing_handle) {
      if (effects.has("publisher_discover")) {
        return {
          state: "action_ready",
          command: command("rightout_begin_discovery_session", {
            profileId: campaign.subject_ref,
            brokerId: route.id,
            campaignId: campaign.campaign_id,
          }, "brave_was_inconclusive_open_separately_authorized_official_domain_discovery"),
        };
      }
      deferredHumanGates.push({
        broker_id: route.id,
        reason: "official_route_requires_listing_url_but_live_index_found_no_candidate",
        next_action: "locate_and_verify_the_subject_listing_in_an_operator_controlled_browser_then_resume",
      });
      continue;
    }
    if (route.method === "phone") {
      deferredHumanGates.push({ broker_id: route.id, reason: "reference_phone_lane_requires_human" });
      continue;
    }
    if (route.method === "web_form" && effects.has("submit_form")) {
      return {
        state: "action_ready",
        command: command("rightout_begin_form_session", {
          profileId: campaign.subject_ref,
          brokerId: route.id,
          campaignId: campaign.campaign_id,
          ...(item.listing_handle ? { listingHandle: item.listing_handle } : {}),
        }, "open_catalog_bound_browser_form_session"),
      };
    }
  }

  const due = scopedRoutes
    .map((route) => ({ route, item: caseById.get(route.id) }))
    .filter(({ item }) => item?.next_recheck_at && Date.parse(item.next_recheck_at) <= now)
    .sort((a, b) => a.item.next_recheck_at.localeCompare(b.item.next_recheck_at) || a.route.id.localeCompare(b.route.id));
  for (const { route, item } of due) {
    const providerIoRestricted = route.source_status === EXTERNAL_UNAVAILABLE_STATUS
      || String(route.source_status).startsWith("needs_evidence");
    if (item.listing_handle && effects.has("direct_recheck") && !providerIoRestricted) {
      return {
        state: "action_ready",
        command: command("rightout_direct_rescan", {
          profileId: campaign.subject_ref,
          brokerId: route.id,
          listingHandle: item.listing_handle,
          campaignId: campaign.campaign_id,
        }, "due_exact_known_listing_recheck"),
      };
    }
    if (route.verification === "email" && effects.has("poll_verification")) {
      if (verificationMode === "imap") {
        return {
          state: "action_ready",
          command: command("rightout_poll_verification", {
            profileId: campaign.subject_ref,
            brokerId: route.id,
            campaignId: campaign.campaign_id,
          }, "due_broker_receiver_authenticated_email_verification_poll"),
        };
      }
      if (verificationMode === "browser_webmail" && effects.has("open_verification")) {
        return {
          state: "action_ready",
          command: command("rightout_begin_webmail_verification", {
            profileId: campaign.subject_ref,
            brokerId: route.id,
            campaignId: campaign.campaign_id,
          }, "due_recipient_and_sender_bound_browser_webmail_verification"),
        };
      }
      deferredHumanGates.push({
        broker_id: route.id,
        reason: "verification_transport_not_configured",
        next_action: verificationMode === "browser_webmail"
          ? "add_open_verification_to_the_finite_campaign_or_complete_verification_manually"
          : "configure_receiver_authenticated_imap_or_browser_webmail_or_complete_verification_manually",
      });
    }
    if (providerIoRestricted) {
      deferredHumanGates.push({
        broker_id: route.id,
        reason: route.source_status === EXTERNAL_UNAVAILABLE_STATUS
          ? "provider_recheck_route_externally_unavailable"
          : "provider_recheck_requires_human_only_access",
        next_action: "operator_checks_the_official_provider_without_plugin_automation",
      });
    }
  }

  const cases = campaign.broker_ids.map((id) => caseById.get(id)).filter(Boolean);
  return {
    state: "done_for_now",
    next_wake_at: safeWake(cases, now),
    consolidated_digest: {
      scoped_brokers: campaign.broker_ids.length,
      observed_cases: cases.length,
      confirmed_removed: cases.filter((item) => item.state === "confirmed_removed").length,
      in_flight: cases.filter((item) => ["submitted", "verification_pending", "awaiting_processing"].includes(item.state)).length,
      human_gates: cases.filter((item) => ["identity_verification_required", "human_task_queued", "blocked"].includes(item.state)).length + deferredHumanGates.length,
      deferred_human_gates: deferredHumanGates,
      external_degradations: externalDegradations,
    },
  };
}
