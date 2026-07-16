const EXPECTED_IDS = Object.freeze([
    "addresses", "advancedbackgroundchecks", "beenverified", "clustal", "clustrmaps",
    "cyberbackgroundchecks", "familytreenow", "fastpeoplesearch", "intelius", "mylife",
    "nuwber", "peekyou", "peoplefinders", "radaris", "rehold", "searchpeoplefree",
    "socialcatfish", "spokeo", "thatsthem", "truepeoplesearch", "usphonebook", "whitepages",
]);
const SAFE_ID = /^[a-z0-9_]{2,80}$/;
const SAFE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SAFE_JURISDICTION = /^(?:EU|EEA|UK|[A-Z]{2}(?:-[A-Z0-9]{2,3})?)$/;
const SAFE_MARKET_ID = /^[a-z][a-z0-9_]{1,40}$/;
const SAFE_FIELDS = new Set([
    "full_name", "contact_email", "listing_url", "date_of_birth", "street", "city", "region", "postal", "phone",
]);
const SAFE_STATUS = new Set([
    "observed_200", "observed_403_antibot", "observed_200_terms_restrict_automation", "needs_evidence",
    "observed_official_archive_external_unavailable",
]);
const EXTERNAL_UNAVAILABLE_STATUS = new Set([
    "observed_official_archive_external_unavailable",
]);
const SAFE_RESCUE_STATUS = new Set([
    "observed_official_registry", "observed_official_archive_with_current_mx",
]);
const SAFE_RESCUE_FIELDS = new Set(["full_name", "contact_email", "listing_url"]);
function validCatalogDate(value) {
    if (typeof value !== "string" || !/^2026-\d{2}-\d{2}$/.test(value))
        return false;
    const parsed = Date.parse(`${value}T00:00:00Z`);
    return Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 10) === value;
}
function exactKeys(value, allowed, error) {
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => !allowed.has(key))) {
        throw new Error(error);
    }
}
function uniqueStrings(values, pattern, { min = 1, max = 20 } = {}) {
    if (!Array.isArray(values) || values.length < min || values.length > max)
        throw new Error("rightout_parity_catalog_invalid");
    if (values.some((value) => typeof value !== "string" || !pattern.test(value)))
        throw new Error("rightout_parity_catalog_invalid");
    if (new Set(values).size !== values.length)
        throw new Error("rightout_parity_catalog_invalid");
    return [...values];
}
function cleanRoute(value) {
    exactKeys(value, new Set([
        "id", "name", "method", "action_url", "official_domains", "disclosure_fields", "verification",
        "challenge_policy", "source_url", "source_status", "last_checked", "cluster_parent",
        "execution_jurisdictions", "execution_market_ids", "provider_request_contract",
        "reference_contract", "current_contract",
        "source_evidence_url", "source_evidence_captured_at",
        "rescue_email", "rescue_source_url", "rescue_disclosure_fields", "rescue_last_checked", "rescue_source_status",
    ]), "rightout_parity_catalog_invalid");
    if (!SAFE_ID.test(value.id) || typeof value.name !== "string" || value.name.length < 2 || value.name.length > 100) {
        throw new Error("rightout_parity_catalog_invalid");
    }
    if (!new Set(["web_form", "email", "phone"]).has(value.method))
        throw new Error("rightout_parity_catalog_invalid");
    exactKeys(value.reference_contract, new Set([
        "method", "action_url", "inputs", "email_verification", "requires_dob", "requires_captcha",
    ]), "rightout_parity_catalog_invalid");
    const reference = value.reference_contract;
    if (!new Set(["web_form", "email", "phone"]).has(reference.method)
        || reference.method !== value.method
        || typeof reference.email_verification !== "boolean"
        || typeof reference.requires_dob !== "boolean"
        || typeof reference.requires_captcha !== "boolean")
        throw new Error("rightout_parity_catalog_invalid");
    const referenceInputs = uniqueStrings(reference.inputs, /^[a-z_]{2,32}$/, { max: 12 });
    const domains = uniqueStrings(value.official_domains, SAFE_DOMAIN, { max: 8 });
    const fields = uniqueStrings(value.disclosure_fields, /^[a-z_]{2,32}$/, { max: 12 });
    const executionJurisdictions = uniqueStrings(value.execution_jurisdictions, SAFE_JURISDICTION, { max: 12 });
    const executionMarketIds = uniqueStrings(value.execution_market_ids, SAFE_MARKET_ID, { max: 11 });
    if (JSON.stringify(executionJurisdictions) !== JSON.stringify(["US", "US-CA"])
        || JSON.stringify(executionMarketIds) !== JSON.stringify(["us_california", "us_other"])
        || value.provider_request_contract !== "us_provider_delete_opt_out_v1")
        throw new Error("rightout_parity_catalog_invalid");
    if (fields.some((field) => !SAFE_FIELDS.has(field)))
        throw new Error("rightout_parity_catalog_invalid");
    let actionUrl;
    let sourceUrl;
    try {
        actionUrl = new URL(value.action_url);
        sourceUrl = new URL(value.source_url);
    }
    catch {
        throw new Error("rightout_parity_catalog_invalid");
    }
    for (const url of [actionUrl, sourceUrl]) {
        if (url.protocol !== "https:" || url.username || url.password || !domains.some((domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`))) {
            throw new Error("rightout_parity_catalog_invalid");
        }
    }
    let referenceUrl;
    try {
        referenceUrl = new URL(reference.action_url);
    }
    catch {
        throw new Error("rightout_parity_catalog_invalid");
    }
    if (referenceUrl.protocol !== "https:" || referenceUrl.username || referenceUrl.password
        || !domains.some((domain) => referenceUrl.hostname === domain || referenceUrl.hostname.endsWith(`.${domain}`)))
        throw new Error("rightout_parity_catalog_invalid");
    const referenceFieldMap = { profile_url: "listing_url", state: "region" };
    const mappedReferenceInputs = referenceInputs.map((field) => referenceFieldMap[field] ?? field);
    if (mappedReferenceInputs.some((field) => !fields.includes(field)))
        throw new Error("rightout_parity_catalog_invalid");
    if (value.id === "rehold") {
        exactKeys(value.current_contract, new Set([
            "method", "action_url", "inputs", "verification", "evidence", "supersedes_reference_reason",
        ]), "rightout_parity_catalog_invalid");
        const current = value.current_contract;
        const currentInputs = uniqueStrings(current.inputs, /^[a-z_]{2,32}$/, { max: 12 });
        if (current.method !== value.method || current.action_url !== value.action_url
            || JSON.stringify(currentInputs) !== JSON.stringify(fields)
            || current.verification !== value.verification
            || current.supersedes_reference_reason !== "pinned_optout_route_now_404_official_information_control_route_requires_exact_listing_and_email"
            || !Array.isArray(current.evidence) || current.evidence.length !== 2)
            throw new Error("rightout_parity_catalog_invalid");
        const expectedEvidence = new Map([
            ["https://rehold.com/", "official_homepage_current_information_control_link"],
            ["https://rehold.com/page/privacy", "official_privacy_policy_exact_listing_and_email_requirements"],
        ]);
        for (const evidence of current.evidence) {
            exactKeys(evidence, new Set(["url", "fact_scope", "last_verified"]), "rightout_parity_catalog_invalid");
            if (expectedEvidence.get(evidence.url) !== evidence.fact_scope || evidence.last_verified !== value.last_checked) {
                throw new Error("rightout_parity_catalog_invalid");
            }
            expectedEvidence.delete(evidence.url);
        }
        if (expectedEvidence.size !== 0)
            throw new Error("rightout_parity_catalog_invalid");
    }
    else if (value.current_contract !== undefined)
        throw new Error("rightout_parity_catalog_invalid");
    if (!SAFE_STATUS.has(value.source_status) || !validCatalogDate(value.last_checked)) {
        throw new Error("rightout_parity_catalog_invalid");
    }
    if (EXTERNAL_UNAVAILABLE_STATUS.has(value.source_status)) {
        let sourceEvidence;
        try {
            sourceEvidence = new URL(value.source_evidence_url);
        }
        catch {
            throw new Error("rightout_parity_catalog_invalid");
        }
        const archivedClustrMaps = value.id === "clustrmaps"
            && sourceEvidence.hostname === "web.archive.org"
            && /^\/web\/\d{14}id_\/https:\/\/clustrmaps\.com\/bl\/opt-out$/.test(sourceEvidence.pathname);
        const archivedPeekYou = value.id === "peekyou"
            && sourceEvidence.hostname === "web.archive.org"
            && /^\/web\/\d{14}id_\/https:\/\/www\.peekyou\.com\/about\/contact\/optout\/$/.test(sourceEvidence.pathname);
        if (sourceEvidence.protocol !== "https:" || sourceEvidence.username || sourceEvidence.password
            || (!archivedClustrMaps && !archivedPeekYou)
            || !/^20\d{2}-\d{2}-\d{2}$/.test(value.source_evidence_captured_at))
            throw new Error("rightout_parity_catalog_invalid");
    }
    else if (value.source_evidence_url !== undefined || value.source_evidence_captured_at !== undefined) {
        throw new Error("rightout_parity_catalog_invalid");
    }
    if (value.cluster_parent !== undefined && !SAFE_ID.test(value.cluster_parent))
        throw new Error("rightout_parity_catalog_invalid");
    if (value.rescue_email !== undefined) {
        if (typeof value.rescue_email !== "string" || !/^[^@\s]{1,64}@[a-z0-9.-]{3,253}$/.test(value.rescue_email)) {
            throw new Error("rightout_parity_catalog_invalid");
        }
        let rescueSource;
        try {
            rescueSource = new URL(value.rescue_source_url);
        }
        catch {
            throw new Error("rightout_parity_catalog_invalid");
        }
        const officialRegistry = (rescueSource.hostname === "cppa.ca.gov" && /^\/data_broker_registry\/registry\d{4}\.csv$/.test(rescueSource.pathname)) || (rescueSource.hostname === "oag.ca.gov" && rescueSource.pathname === "/node/550652");
        const officialArchive = rescueSource.hostname === "web.archive.org"
            && /^\/web\/\d{14}id_\/https:\/\/clustrmaps\.com\/bl\/opt-out$/.test(rescueSource.pathname);
        if (rescueSource.protocol !== "https:" || rescueSource.username || rescueSource.password || (!officialRegistry && !officialArchive)) {
            throw new Error("rightout_parity_catalog_invalid");
        }
        const rescueFields = uniqueStrings(value.rescue_disclosure_fields, /^[a-z_]{2,32}$/, { max: 8 });
        if (rescueFields.some((field) => !SAFE_RESCUE_FIELDS.has(field)) || !rescueFields.includes("full_name") || !rescueFields.includes("contact_email")) {
            throw new Error("rightout_parity_catalog_invalid");
        }
        if (!validCatalogDate(value.rescue_last_checked) || !SAFE_RESCUE_STATUS.has(value.rescue_source_status)) {
            throw new Error("rightout_parity_catalog_invalid");
        }
        if ((value.rescue_source_status === "observed_official_registry" && !officialRegistry)
            || (value.rescue_source_status === "observed_official_archive_with_current_mx" && !officialArchive))
            throw new Error("rightout_parity_catalog_invalid");
    }
    else if ([
        value.rescue_source_url, value.rescue_disclosure_fields, value.rescue_last_checked, value.rescue_source_status,
    ].some((item) => item !== undefined))
        throw new Error("rightout_parity_catalog_invalid");
    if (EXTERNAL_UNAVAILABLE_STATUS.has(value.source_status) && value.rescue_email === undefined) {
        throw new Error("rightout_parity_catalog_invalid");
    }
    return {
        ...value,
        official_domains: domains,
        disclosure_fields: fields,
        execution_jurisdictions: executionJurisdictions,
        execution_market_ids: executionMarketIds,
    };
}
export function validateParityCatalog(value) {
    exactKeys(value, new Set(["schema_version", "reviewed_at", "reference_commit", "policy", "brokers", "health"]), "rightout_parity_catalog_invalid");
    if (value.schema_version !== 2 || !validCatalogDate(value.reviewed_at) || !/^[a-f0-9]{40}$/.test(value.reference_commit)) {
        throw new Error("rightout_parity_catalog_invalid");
    }
    exactKeys(value.policy, new Set([
        "clean_room", "all_routes_required", "unverified_routes_block_release", "profile_urls_use_encrypted_listing_handles", "hard_challenges_are_human_only",
    ]), "rightout_parity_catalog_invalid");
    if (Object.values(value.policy).some((item) => item !== true))
        throw new Error("rightout_parity_catalog_invalid");
    if (!Array.isArray(value.brokers))
        throw new Error("rightout_parity_catalog_invalid");
    const brokers = value.brokers.map(cleanRoute);
    const ids = brokers.map((broker) => broker.id).sort();
    if (JSON.stringify(ids) !== JSON.stringify([...EXPECTED_IDS].sort()))
        throw new Error("rightout_parity_catalog_invalid");
    const methods = Object.fromEntries(["web_form", "email", "phone"].map((method) => [method, brokers.filter((broker) => broker.method === method).length]));
    if (methods.web_form !== 20 || methods.email !== 1 || methods.phone !== 1)
        throw new Error("rightout_parity_catalog_invalid");
    const blockers = brokers.filter((broker) => broker.source_status === "needs_evidence").map((broker) => broker.id);
    const degraded = brokers.filter((broker) => EXTERNAL_UNAVAILABLE_STATUS.has(broker.source_status)).map((broker) => broker.id);
    const outcomeGaps = brokers.filter((broker) => {
        const providerIo = broker.source_status !== "needs_evidence"
            && !EXTERNAL_UNAVAILABLE_STATUS.has(broker.source_status);
        const independentlySourcedRescue = typeof broker.rescue_email === "string";
        const correctlyHumanGated = broker.method === "phone" || broker.disclosure_fields.includes("date_of_birth");
        return !providerIo && !independentlySourcedRescue && !correctlyHumanGated;
    }).map((broker) => broker.id);
    return {
        ...value,
        brokers,
        health: {
            broker_count: brokers.length,
            methods,
            source_blockers: blockers,
            externally_unavailable_routes: degraded,
            equivalent_outcome_gaps: outcomeGaps,
            release_ready: blockers.length === 0 && outcomeGaps.length === 0,
        },
    };
}
export function parityCatalogHealth(catalog, { now = Date.now(), maxAgeDays = 180 } = {}) {
    if (!Number.isFinite(now) || !Number.isInteger(maxAgeDays) || maxAgeDays < 1 || maxAgeDays > 365) {
        throw new Error("rightout_catalog_lane_stale");
    }
    const clean = validateParityCatalog(catalog);
    const staleRoutes = clean.brokers.filter((broker) => {
        const checked = Date.parse(`${broker.last_checked}T00:00:00Z`);
        return !Number.isFinite(checked) || checked > now || now - checked > maxAgeDays * 24 * 60 * 60_000;
    }).map((broker) => broker.id);
    const releaseReady = clean.health.release_ready && staleRoutes.length === 0;
    return {
        schema_version: 2,
        reference_commit: clean.reference_commit,
        reviewed_at: clean.reviewed_at,
        broker_count: clean.health.broker_count,
        broker_ids: clean.brokers.map((broker) => broker.id),
        broker_routes: clean.brokers.map((broker) => {
            const providerIoExecutable = broker.source_status !== "needs_evidence"
                && !EXTERNAL_UNAVAILABLE_STATUS.has(broker.source_status);
            return {
                broker_id: broker.id,
                method: broker.method,
                execution_jurisdictions: [...broker.execution_jurisdictions],
                execution_market_ids: [...broker.execution_market_ids],
                provider_request_contract: broker.provider_request_contract,
                source_state: broker.source_status,
                normalized_contract_evidence_complete: broker.source_status !== "needs_evidence",
                route_technically_addressable_from_catalog: providerIoExecutable,
                primary_route_available: !EXTERNAL_UNAVAILABLE_STATUS.has(broker.source_status),
                autonomous_rescue_available: typeof broker.rescue_email === "string",
                explicit_human_only_gate: broker.method === "phone" || broker.disclosure_fields.includes("date_of_birth"),
                equivalent_outcome_available: !clean.health.equivalent_outcome_gaps.includes(broker.id),
            };
        }),
        methods: clean.health.methods,
        source_blockers: clean.health.source_blockers,
        externally_unavailable_routes: clean.health.externally_unavailable_routes,
        equivalent_outcome_gaps: clean.health.equivalent_outcome_gaps,
        stale_routes: staleRoutes,
        freshness_max_age_days: maxAgeDays,
        release_ready: releaseReady,
        next_action: releaseReady ? "run_normalized_contract_e2e" : staleRoutes.length
            ? "refresh_every_stale_parity_route_before_live_provider_io"
            : "resolve_every_needs_evidence_official_route",
    };
}
export function assertParityCatalogFresh(catalog, { now = Date.now(), maxAgeDays = 180 } = {}) {
    const health = parityCatalogHealth(catalog, { now, maxAgeDays });
    if (!health.release_ready)
        throw new Error("rightout_catalog_lane_stale");
    return validateParityCatalog(catalog);
}
export function assertParityCatalogRouteFresh(catalog, brokerId, { now = Date.now(), maxAgeDays = 180 } = {}) {
    if (!Number.isFinite(now) || !Number.isInteger(maxAgeDays) || maxAgeDays < 1 || maxAgeDays > 365) {
        throw new Error("rightout_catalog_lane_stale");
    }
    const clean = assertParityCatalogFresh(catalog, { now, maxAgeDays });
    const route = clean.brokers.find((row) => row.id === brokerId);
    const checked = Date.parse(`${route?.last_checked ?? ""}T00:00:00Z`);
    if (!route
        || String(route.source_status).startsWith("needs_evidence")
        || !Number.isFinite(checked)
        || checked > now
        || now - checked > maxAgeDays * 24 * 60 * 60_000)
        throw new Error("rightout_catalog_lane_stale");
    return route;
}
export function resolveParityBroker(catalog, brokerId) {
    if (typeof brokerId !== "string" || !SAFE_ID.test(brokerId))
        throw new Error("rightout_parity_broker_invalid");
    const clean = validateParityCatalog(catalog);
    const broker = clean.brokers.find((row) => row.id === brokerId);
    if (!broker)
        throw new Error("rightout_parity_broker_invalid");
    return broker;
}
export const __test = { EXPECTED_IDS, cleanRoute };
