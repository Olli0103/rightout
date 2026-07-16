import { createHash } from "node:crypto";

const DAY_MS = 24 * 60 * 60 * 1_000;
const REVIEWED_AT = "2026-07-16";
const SAFE_MARKET_ID = /^[a-z][a-z0-9_]{1,40}$/;
const SAFE_JURISDICTION = /^(?:EU|EEA|UK|[A-Z]{2}(?:-[A-Z0-9]{2,3})?)$/;

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

const MARKET_POLICIES = deepFreeze([
  {
    market_id: "eu_eea",
    coverage_class: "core",
    evidence_status: "evidenced",
    next_review_at: "2026-10-14",
    rights_basis: "gdpr_data_subject_rights",
    source_urls: [
      "https://www.edpb.europa.eu/topics/key-gdpr-concepts/data-subject-rights_en",
      "https://www.edpb.europa.eu/sme/be-compliant/respect-individuals-rights_en",
    ],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "catalog_limited_18_email_routes",
      provider_delete_opt_out: "unsupported_without_market_specific_route",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "not_evidenced",
      gpc_preference: "unsupported_or_not_evidenced",
    },
    safe_default: "catalog_bound_or_human_gate",
    open_requirements: [
      "no_pan_eu_broker_registry_evidenced",
      "real_world_effectiveness_needs_evidence",
    ],
  },
  {
    market_id: "uk",
    coverage_class: "core",
    evidence_status: "evidenced",
    next_review_at: "2026-09-17",
    rights_basis: "uk_gdpr_and_duaa_2025",
    source_urls: [
      "https://ico.org.uk/about-the-ico/what-we-do/legislation-we-cover/data-use-and-access-act-2025/the-data-use-and-access-act-2025-duaa-summary-of-the-changes/",
      "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/",
      "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-object/",
    ],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "catalog_limited_1_uk_email_route",
      provider_delete_opt_out: "human_only_market_route_not_implemented",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "not_evidenced",
      gpc_preference: "unsupported_or_not_evidenced",
    },
    safe_default: "dedicated_uk_contract_or_human_gate",
    open_requirements: [
      "only_cognism_uk_email_route_is_currently_evidenced",
      "additional_uk_provider_route_inventory_needs_evidence",
    ],
  },
  {
    market_id: "us_california",
    coverage_class: "core",
    evidence_status: "evidenced",
    next_review_at: "2026-08-01",
    rights_basis: "ccpa_cpra_and_delete_act",
    source_urls: [
      "https://privacy.ca.gov/drop/",
      "https://cppa.ca.gov/data_brokers/index.html",
      "https://oag.ca.gov/privacy/ccpa",
    ],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "catalog_limited_email_routes",
      provider_delete_opt_out: "parity_catalog_limited_provider_routes",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "human_verified_drop_filing_record_only",
      gpc_preference: "human_verified_signal_record_only",
    },
    safe_default: "drop_identity_and_submission_human_only",
    open_requirements: [
      "drop_processing_begins_2026_08_01",
      "nonregistered_brokers_and_fcra_exceptions_remain_gaps",
      "gpc_provider_compliance_requires_site_specific_evidence",
    ],
  },
  {
    market_id: "us_other",
    coverage_class: "extended",
    evidence_status: "needs_evidence",
    next_review_at: "2026-09-30",
    rights_basis: "state_specific_privacy_laws",
    source_urls: [
      "https://globalprivacycontrol.org/",
      "https://consumer.ftc.gov/articles/what-know-about-people-search-sites-sell-your-information",
    ],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "human_only_state_specific_review",
      provider_delete_opt_out: "parity_catalog_limited_provider_routes",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "not_evidenced",
      gpc_preference: "human_verified_signal_legal_effect_needs_market_evidence",
    },
    safe_default: "human_gate_until_state_right_and_eligibility_are_evidenced",
    open_requirements: [
      "state_by_state_rights_and_authorized_agent_rules_need_evidence",
      "vermont_oregon_texas_are_registry_routing_only",
    ],
  },
  {
    market_id: "canada",
    coverage_class: "extended",
    evidence_status: "partially_evidenced",
    next_review_at: "2026-10-14",
    rights_basis: "pipeda_and_provincial_law",
    source_urls: [
      "https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/p_principle/",
      "https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/p_principle/principles/p_consent/",
    ],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "human_only_rights_pack_not_implemented",
      provider_delete_opt_out: "human_only_market_route_not_implemented",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "not_evidenced",
      gpc_preference: "unsupported_or_not_evidenced",
    },
    safe_default: "human_gate_for_federal_and_provincial_scope",
    open_requirements: [
      "general_erasure_scope_must_not_be_inferred",
      "provincial_variants_need_evidence",
    ],
  },
  {
    market_id: "brazil",
    coverage_class: "extended",
    evidence_status: "partially_evidenced",
    next_review_at: "2026-10-14",
    rights_basis: "lgpd",
    source_urls: [
      "https://www.gov.br/anpd/pt-br/assuntos/titular-de-dados-1/direito-dos-titulares",
      "https://www.gov.br/anpd/pt-br/canais_atendimento/cidadao-titular-de-dados/denuncia-peticao-de-titular-referente-lgpd",
    ],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "human_only_rights_pack_not_implemented",
      provider_delete_opt_out: "human_only_market_route_not_implemented",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "not_evidenced",
      gpc_preference: "unsupported_or_not_evidenced",
    },
    safe_default: "human_gate_for_legal_basis_and_exceptions",
    open_requirements: [
      "controller_directory_and_request_contract_not_implemented",
      "deletion_exceptions_and_legal_basis_require_review",
    ],
  },
  {
    market_id: "australia",
    coverage_class: "extended",
    evidence_status: "partially_evidenced",
    next_review_at: "2026-10-14",
    rights_basis: "privacy_act_and_australian_privacy_principles",
    source_urls: [
      "https://www.oaic.gov.au/privacy/australian-privacy-principles/read-the-australian-privacy-principles",
      "https://www.oaic.gov.au/privacy/your-privacy-rights/your-personal-information/correct-your-personal-information",
    ],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "human_only_rights_pack_not_implemented",
      provider_delete_opt_out: "human_only_market_route_not_implemented",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "not_evidenced",
      gpc_preference: "unsupported_or_not_evidenced",
    },
    safe_default: "human_gate_do_not_claim_general_erasure_right",
    open_requirements: [
      "access_correction_and_retention_are_not_universal_erasure",
      "market_specific_broker_inventory_needs_evidence",
    ],
  },
  {
    market_id: "japan",
    coverage_class: "extended",
    evidence_status: "partially_evidenced",
    next_review_at: "2026-10-14",
    rights_basis: "appi",
    source_urls: [
      "https://www.ppc.go.jp/files/pdf/APPI_english.pdf",
      "https://www.ppc.go.jp/personalinfo/faq/APPI_QA/",
    ],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "human_only_rights_pack_not_implemented",
      provider_delete_opt_out: "human_only_market_route_not_implemented",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "not_evidenced",
      gpc_preference: "unsupported_or_not_evidenced",
    },
    safe_default: "human_gate_for_conditional_cease_use_or_erasure",
    open_requirements: [
      "request_conditions_and_identity_process_need_local_review",
      "market_specific_broker_inventory_needs_evidence",
    ],
  },
  {
    market_id: "singapore",
    coverage_class: "extended",
    evidence_status: "partially_evidenced",
    next_review_at: "2026-10-14",
    rights_basis: "pdpa",
    source_urls: [
      "https://www.pdpc.gov.sg/overview-of-pdpa/data-protection/individual/individuals-overview",
    ],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "human_only_rights_pack_not_implemented",
      provider_delete_opt_out: "human_only_market_route_not_implemented",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "not_evidenced",
      gpc_preference: "unsupported_or_not_evidenced",
    },
    safe_default: "human_gate_do_not_claim_general_erasure_right",
    open_requirements: [
      "withdrawal_access_and_correction_do_not_equal_universal_erasure",
      "market_specific_broker_inventory_needs_evidence",
    ],
  },
  {
    market_id: "india",
    coverage_class: "extended",
    evidence_status: "needs_evidence",
    next_review_at: "2026-08-14",
    rights_basis: "dpdp_act_2023_and_rules_2025",
    source_urls: [
      "https://www.meity.gov.in/documents/act-and-policies/digital-personal-data-protection-rules-2025-gDOxUjMtQWa",
      "https://www.meity.gov.in/writereaddata/files/Digital%20Personal%20Data%20Protection%20Act%202023.pdf",
    ],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "human_only_rights_pack_not_implemented",
      provider_delete_opt_out: "human_only_market_route_not_implemented",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "not_evidenced",
      gpc_preference: "unsupported_or_not_evidenced",
    },
    safe_default: "human_gate_until_phased_enforcement_and_route_scope_are_evidenced",
    open_requirements: [
      "phased_enforcement_status_requires_refresh",
      "controller_directory_and_request_contract_not_implemented",
    ],
  },
  {
    market_id: "other",
    coverage_class: "unknown",
    evidence_status: "needs_evidence",
    next_review_at: "2026-08-15",
    rights_basis: "market_specific_review_required",
    source_urls: [],
    rightout_support: {
      public_index_discovery: "bounded_autonomous_index_only",
      controller_request: "unsupported_without_market_evidence",
      provider_delete_opt_out: "unsupported_without_market_evidence",
      publisher_browser_or_form: "current_written_provider_authorization_required",
      universal_broker_request: "not_evidenced",
      gpc_preference: "unsupported_or_not_evidenced",
    },
    safe_default: "discovery_only_then_human_market_review",
    open_requirements: [
      "applicable_rights_identity_authority_deadlines_and_exceptions_need_evidence",
      "provider_and_transfer_requirements_need_evidence",
    ],
  },
]);

function parseDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error("rightout_market_policy_invalid");
  }
  const at = Date.parse(`${value}T00:00:00.000Z`);
  if (!Number.isFinite(at) || new Date(at).toISOString().slice(0, 10) !== value) {
    throw new Error("rightout_market_policy_invalid");
  }
  return at;
}

function reviewStatus(nextReviewAt, now) {
  const reviewAt = parseDate(nextReviewAt);
  if (now < reviewAt) return "current";
  if (now < reviewAt + 30 * DAY_MS) return "review_due";
  return "stale";
}

function californiaDropPhase(now) {
  const launch = Date.parse("2026-01-01T00:00:00.000Z");
  const processing = Date.parse("2026-08-01T00:00:00.000Z");
  if (now < launch) return "not_launched";
  if (now < processing) return "consumer_requests_open_broker_processing_not_started";
  return "broker_processing_required";
}

function validatePolicy(policy) {
  if (
    !policy || typeof policy !== "object" || !SAFE_MARKET_ID.test(policy.market_id)
    || !["core", "extended", "unknown"].includes(policy.coverage_class)
    || !["evidenced", "partially_evidenced", "needs_evidence"].includes(policy.evidence_status)
    || !Array.isArray(policy.source_urls)
    || policy.source_urls.some((url) => typeof url !== "string" || !url.startsWith("https://"))
    || !policy.rightout_support || typeof policy.rightout_support !== "object"
    || ![
      "human_verified_signal_record_only",
      "human_verified_signal_legal_effect_needs_market_evidence",
      "unsupported_or_not_evidenced",
    ].includes(policy.rightout_support.gpc_preference)
    || !Array.isArray(policy.open_requirements) || policy.open_requirements.length < 1
  ) throw new Error("rightout_market_policy_invalid");
  parseDate(policy.next_review_at);
  return policy;
}

export function marketPolicyHealth({ now = Date.now() } = {}) {
  if (!Number.isFinite(now)) throw new Error("rightout_market_policy_invalid");
  const markets = MARKET_POLICIES.map((raw) => {
    const policy = validatePolicy(raw);
    const source_status = reviewStatus(policy.next_review_at, now);
    return {
      ...structuredClone(policy),
      source_status,
      ...(policy.market_id === "us_california" ? { drop_phase: californiaDropPhase(now) } : {}),
      operational_authority: "diagnostic_only_not_authorization",
    };
  });
  const count = (status) => markets.filter((market) => market.source_status === status).length;
  const earliestReview = Math.min(...markets.map((market) => parseDate(market.next_review_at)));
  const summary = {
    current: count("current"),
    review_due: count("review_due"),
    stale: count("stale"),
    rights_execution_core_markets: markets.filter((market) => (
      ["catalog_limited_18_email_routes", "catalog_limited_1_uk_email_route", "catalog_limited_email_routes"]
        .includes(market.rightout_support.controller_request)
    )).length,
    human_or_unsupported_markets: markets.filter((market) => (
      !["catalog_limited_18_email_routes", "catalog_limited_1_uk_email_route", "catalog_limited_email_routes"]
        .includes(market.rightout_support.controller_request)
    )).length,
  };
  if (Object.keys(summary).some((key) => key.includes("pii"))) throw new Error("rightout_market_policy_invalid");
  return {
    report_version: 1,
    reviewed_at: REVIEWED_AT,
    generated_at: new Date(now).toISOString(),
    network_requests: 0,
    market_count: markets.length,
    summary,
    next_review_at: new Date(earliestReview).toISOString(),
    markets,
    cross_market_rules: [
      "technical_discovery_support_is_not_legal_or_provider_authorization",
      "publisher_automation_requires_current_written_provider_authorization_in_every_market",
      "provider_specific_route_eligibility_does_not_create_a_universal_privacy_right",
      "unsupported_or_uncertain_rights_execution_stops_at_a_human_gate",
      "no_market_claims_universal_or_permanent_deletion",
      "preference_signal_is_not_deletion_request_or_deletion_proof",
    ],
  };
}

export function marketPolicyOperatorHealth({ now = Date.now() } = {}) {
  const health = marketPolicyHealth({ now });
  const core_markets = health.markets
    .filter((market) => market.coverage_class === "core")
    .map((market) => ({
      market_id: market.market_id,
      evidence_status: market.evidence_status,
      next_review_at: market.next_review_at,
      source_status: market.source_status,
      controller_request: market.rightout_support.controller_request,
      safe_default: market.safe_default,
    }));
  const source_warnings = core_markets
    .filter((market) => market.source_status !== "current")
    .map((market) => `market_policy_source_${market.source_status}:${market.market_id}:${market.next_review_at}`);
  return {
    report_version: 1,
    reviewed_at: health.reviewed_at,
    generated_at: health.generated_at,
    next_review_at: health.next_review_at,
    market_count: health.market_count,
    summary: health.summary,
    core_markets,
    all_core_sources_current: source_warnings.length === 0,
    source_warnings,
    operational_authority: "diagnostic_only_not_authorization",
    full_policy_tool: "rightout_catalog_health",
  };
}

export function marketPolicyDigest({ now = Date.now() } = {}) {
  const health = marketPolicyHealth({ now });
  const contract = {
    policy_digest_version: 1,
    reviewed_at: health.reviewed_at,
    markets: health.markets,
    cross_market_rules: health.cross_market_rules,
  };
  return createHash("sha256").update(JSON.stringify(contract)).digest("hex");
}

export function marketIdsForJurisdictions(jurisdictions) {
  if (
    !Array.isArray(jurisdictions) || jurisdictions.length < 1 || jurisdictions.length > 20
    || jurisdictions.some((value) => typeof value !== "string" || !SAFE_JURISDICTION.test(value))
  ) throw new Error("rightout_market_jurisdiction_invalid");
  const ids = new Set();
  for (const jurisdiction of jurisdictions) {
    if (["EU", "EEA"].includes(jurisdiction)) ids.add("eu_eea");
    else if (["UK", "GB"].includes(jurisdiction)) ids.add("uk");
    else if (jurisdiction === "US-CA") ids.add("us_california");
    else if (jurisdiction === "US") ids.add("us_other");
    else if (jurisdiction === "CA") ids.add("canada");
    else if (jurisdiction === "BR") ids.add("brazil");
    else if (jurisdiction === "AU") ids.add("australia");
    else if (jurisdiction === "JP") ids.add("japan");
    else if (jurisdiction === "SG") ids.add("singapore");
    else if (jurisdiction === "IN") ids.add("india");
  }
  return [...ids].sort();
}

/**
 * @param {{jurisdictions?: string[], executionClass?: "controller_request" | "provider_delete_opt_out" | "publisher_browser_or_form", now?: number}} options
 */
export function assertMarketRightsExecution({ jurisdictions = [], executionClass = "controller_request", now = Date.now() } = {}) {
  if (!["controller_request", "provider_delete_opt_out", "publisher_browser_or_form"].includes(executionClass)) {
    throw new Error("rightout_market_execution_invalid");
  }
  const health = marketPolicyHealth({ now });
  const marketIds = marketIdsForJurisdictions(jurisdictions);
  if (marketIds.length !== 1) throw new Error("rightout_market_execution_unsupported");
  const market = health.markets.find((entry) => entry.market_id === marketIds[0]);
  if (!market) throw new Error("rightout_market_execution_unsupported");
  if (market.source_status !== "current") throw new Error("rightout_market_policy_source_not_current");
  if (
    executionClass === "controller_request"
    && !["catalog_limited_18_email_routes", "catalog_limited_1_uk_email_route", "catalog_limited_email_routes"]
      .includes(market.rightout_support.controller_request)
  ) throw new Error("rightout_market_execution_unsupported");
  if (
    executionClass === "provider_delete_opt_out"
    && market.rightout_support.provider_delete_opt_out !== "parity_catalog_limited_provider_routes"
  ) throw new Error("rightout_market_execution_unsupported");
  if (
    executionClass === "publisher_browser_or_form"
    && market.rightout_support.publisher_browser_or_form !== "current_written_provider_authorization_required"
  ) throw new Error("rightout_market_execution_unsupported");
  return {
    market_id: market.market_id,
    execution_class: executionClass,
    evidence_status: market.evidence_status,
    source_status: market.source_status,
    next_review_at: market.next_review_at,
    safe_default: market.safe_default,
    market_policy_digest: marketPolicyDigest({ now }),
    operational_authority: "market_contract_only_provider_and_subject_authority_still_required",
  };
}

/**
 * Validate one catalog-declared provider route before reading a subject profile
 * or contacting a provider. Every declared market must be current because the
 * route contract is shared by profiles that may qualify for any of them.
 *
 * @param {{jurisdictions?: string[], marketIds?: string[], executionClass?: "provider_delete_opt_out" | "publisher_browser_or_form", now?: number}} options
 */
export function assertMarketRouteExecution({
  jurisdictions = [],
  marketIds = [],
  executionClass = "provider_delete_opt_out",
  now = Date.now(),
} = {}) {
  if (!["provider_delete_opt_out", "publisher_browser_or_form"].includes(executionClass)) {
    throw new Error("rightout_market_execution_invalid");
  }
  const mapped = marketIdsForJurisdictions(jurisdictions);
  if (
    !Array.isArray(marketIds) || marketIds.length < 1 || marketIds.length > 11
    || marketIds.some((value) => typeof value !== "string" || !SAFE_MARKET_ID.test(value))
    || new Set(marketIds).size !== marketIds.length
    || JSON.stringify([...marketIds].sort()) !== JSON.stringify(mapped)
  ) throw new Error("rightout_market_route_contract_invalid");
  const health = marketPolicyHealth({ now });
  const markets = [...marketIds].sort().map((marketId) => {
    const market = health.markets.find((entry) => entry.market_id === marketId);
    if (!market) throw new Error("rightout_market_route_contract_invalid");
    if (market.source_status !== "current") throw new Error("rightout_market_policy_source_not_current");
    if (
      executionClass === "provider_delete_opt_out"
      && market.rightout_support.provider_delete_opt_out !== "parity_catalog_limited_provider_routes"
    ) throw new Error("rightout_market_execution_unsupported");
    if (
      executionClass === "publisher_browser_or_form"
      && market.rightout_support.publisher_browser_or_form !== "current_written_provider_authorization_required"
    ) throw new Error("rightout_market_execution_unsupported");
    return market;
  });
  return {
    execution_class: executionClass,
    jurisdictions: [...jurisdictions].sort(),
    market_ids: markets.map((market) => market.market_id),
    next_review_at: markets.map((market) => market.next_review_at).sort()[0],
    market_policy_digest: marketPolicyDigest({ now }),
    operational_authority: "market_route_contract_only_provider_and_subject_authority_still_required",
  };
}

export function assertProfileEligibleForMarketRoute({ routeJurisdictions = [], profileJurisdictions = [] } = {}) {
  const route = new Set(routeJurisdictions);
  marketIdsForJurisdictions(routeJurisdictions);
  marketIdsForJurisdictions(profileJurisdictions);
  const matched = [...new Set(profileJurisdictions.filter((jurisdiction) => route.has(jurisdiction)))].sort();
  if (!matched.length) throw new Error("rightout_market_profile_ineligible");
  return { matched_jurisdictions: matched, raw_pii_in_report: false };
}

export const __test = { californiaDropPhase, reviewStatus, validatePolicy };
