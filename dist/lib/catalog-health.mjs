const SAFE_CATALOG_BROKER_ID = /^[a-z0-9_]{2,80}$/;
const SAFE_LIVE_BROKER_ID = /^[a-z0-9_]{2,24}$/;
const DAY_MS = 24 * 60 * 60 * 1_000;
function parseReviewDate(value) {
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
        throw new Error("rightout_catalog_freshness_invalid");
    }
    const at = Date.parse(`${value}T00:00:00.000Z`);
    if (!Number.isFinite(at) || new Date(at).toISOString().slice(0, 10) !== value) {
        throw new Error("rightout_catalog_freshness_invalid");
    }
    return at;
}
function catalogRows(catalog) {
    if (!catalog || !Array.isArray(catalog.brokers))
        throw new Error("rightout_catalog_invalid");
    return catalog.brokers;
}
function healthForEntry(entry, nowMs, warningDays) {
    if (!entry || typeof entry !== "object" || !SAFE_CATALOG_BROKER_ID.test(entry.id)) {
        throw new Error("rightout_catalog_freshness_invalid");
    }
    const freshnessDays = entry.freshness_days;
    if (!Number.isInteger(freshnessDays) || freshnessDays < 1 || freshnessDays > 365) {
        throw new Error("rightout_catalog_freshness_invalid");
    }
    const reviewedAt = parseReviewDate(entry.last_verified);
    const expiresAt = reviewedAt + freshnessDays * DAY_MS;
    const remainingDays = Math.floor((expiresAt - nowMs) / DAY_MS);
    const status = nowMs >= expiresAt ? "stale" : remainingDays <= warningDays ? "expiring" : "fresh";
    return {
        broker_id: entry.id,
        status,
        last_verified: entry.last_verified,
        freshness_days: freshnessDays,
        expires_at: new Date(expiresAt).toISOString(),
        remaining_days: Math.max(remainingDays, 0),
    };
}
export function catalogPolicyHealth(catalog, { now = Date.now(), warningDays = 30 } = {}) {
    if (!Number.isFinite(now) || !Number.isInteger(warningDays) || warningDays < 1 || warningDays > 90) {
        throw new Error("rightout_catalog_freshness_invalid");
    }
    const entries = catalogRows(catalog).map((entry) => healthForEntry(entry, now, warningDays));
    const count = (status) => entries.filter((entry) => entry.status === status).length;
    return {
        report_version: 1,
        generated_at: new Date(now).toISOString(),
        network_requests: 0,
        catalog_entries: entries.length,
        summary: { fresh: count("fresh"), expiring: count("expiring"), stale: count("stale") },
        expiring: entries.filter((entry) => entry.status === "expiring"),
        stale: entries.filter((entry) => entry.status === "stale"),
        live_provider_io_allowed: count("stale") === 0,
        next_action: count("stale") === 0 ? "none" : "refresh_official_source_facts_before_live_provider_io",
    };
}
export function assertFreshCatalogEntries(catalog, brokerIds, { now = Date.now() } = {}) {
    if (!Array.isArray(brokerIds) || brokerIds.length < 1 || brokerIds.some((id) => !SAFE_LIVE_BROKER_ID.test(id))) {
        throw new Error("rightout_catalog_freshness_invalid");
    }
    const rows = catalogRows(catalog);
    const health = catalogPolicyHealth(catalog, { now });
    if (!health.live_provider_io_allowed)
        throw new Error("rightout_catalog_lane_stale");
    for (const brokerId of brokerIds) {
        const entry = rows.find((row) => row?.id === brokerId);
        if (!entry)
            throw new Error("rightout_catalog_lane_stale");
    }
}
