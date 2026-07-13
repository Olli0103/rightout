const SCANNABLE_CATEGORIES = new Set(["people_search", "data_broker"]);
const SEARCH_INDEX_POLICY = "search_index_only_no_publisher_access";
function rows(value) {
    return Array.isArray(value?.brokers) ? value.brokers : [];
}
function hasFailClosedScanGate(entry) {
    return entry?.human_only === true
        || entry?.scan?.manual_only === true
        || entry?.scan?.automated_access_policy === "prohibited_by_published_terms";
}
function searchIndexScanContract(extra = {}) {
    return {
        supported: true,
        automated_access_policy: SEARCH_INDEX_POLICY,
        provider: "brave_search_api",
        ...extra,
    };
}
export function isBraveScanLane(entry) {
    return Boolean(entry
        && SCANNABLE_CATEGORIES.has(entry.category)
        && entry.scan?.supported === true
        && entry.scan?.automated_access_policy === SEARCH_INDEX_POLICY);
}
/**
 * Build the exact runtime catalog used by both campaign planning and live-scan
 * execution. Public-index discovery is a read-only domain signal; enabling it
 * here never enables publisher access or a removal effect.
 */
export function buildCombinedScanCatalog(coreCatalog, parityCatalog) {
    const combined = new Map();
    for (const entry of rows(coreCatalog)) {
        if (!entry || typeof entry !== "object" || Array.isArray(entry) || typeof entry.id !== "string")
            continue;
        if (entry.category === "data_broker"
            && entry.scan?.supported !== true
            && !hasFailClosedScanGate(entry)) {
            combined.set(entry.id, {
                ...entry,
                scan: searchIndexScanContract({
                    visibility_semantics: "public_index_signal_only_not_controller_inventory",
                }),
            });
        }
        else
            combined.set(entry.id, entry);
    }
    for (const route of rows(parityCatalog)) {
        if (!route || typeof route !== "object" || Array.isArray(route) || typeof route.id !== "string")
            continue;
        const existing = combined.get(route.id);
        if (hasFailClosedScanGate(route)) {
            if (existing) {
                combined.set(route.id, {
                    ...existing,
                    ...(route.human_only === true ? { human_only: true } : {}),
                    scan: {
                        ...(existing.scan ?? {}),
                        ...(route.scan ?? {}),
                        supported: false,
                    },
                });
            }
            continue;
        }
        if (existing?.scan?.supported === true || hasFailClosedScanGate(existing))
            continue;
        combined.set(route.id, {
            id: route.id,
            name: route.name,
            category: "people_search",
            official_domains: route.official_domains,
            scan: searchIndexScanContract({
                visibility_semantics: "public_index_signal_only_not_identity_or_private_inventory_proof",
            }),
        });
    }
    return { schema_version: 1, brokers: [...combined.values()] };
}
export function scanCoverage(catalog) {
    const eligible = rows(catalog).filter(isBraveScanLane);
    return {
        runtime_combined_entries: rows(catalog).length,
        code_enforced_brave_scan_lanes: eligible.length,
        people_search_brave_scan_lanes: eligible.filter((entry) => entry.category === "people_search").length,
        controller_b2b_brave_scan_lanes: eligible.filter((entry) => entry.category === "data_broker").length,
        human_only_controller_portal_lanes: rows(catalog).filter((entry) => (entry?.category === "data_broker"
            && entry.human_only === true
            && entry.process_class === "eu_controller_portal_erasure")).length,
    };
}
