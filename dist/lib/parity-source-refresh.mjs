const MAX_ROUTES = 50;
const EXTERNAL_UNAVAILABLE_STATUS = "observed_official_archive_external_unavailable";
async function mapBounded(values, limit, worker) {
    const output = new Array(values.length);
    let cursor = 0;
    async function run() {
        while (true) {
            const index = cursor++;
            if (index >= values.length)
                return;
            output[index] = await worker(values[index]);
        }
    }
    await Promise.all(Array.from({ length: Math.min(limit, values.length) }, () => run()));
    return output;
}
function classify(route, status) {
    if (route.source_status === "needs_evidence")
        return "needs_human_route_review";
    if (route.source_status === EXTERNAL_UNAVAILABLE_STATUS) {
        if (status === 404 || status === 410 || status >= 500)
            return "external_unavailable_reconfirmed";
        return "external_route_recovered_needs_catalog_review";
    }
    if (status >= 200 && status < 300)
        return "official_endpoint_observed";
    if ([401, 403, 405, 429].includes(status))
        return "official_endpoint_access_control_observed";
    if (status >= 300 && status < 400)
        return "redirect_quarantined";
    return "unexpected_status_needs_review";
}
export async function refreshParitySources({ catalog, guardedFetch, permissionForRoute, signal, now = () => new Date() }) {
    if (!catalog || !Array.isArray(catalog.brokers) || catalog.brokers.length < 1 || catalog.brokers.length > MAX_ROUTES) {
        throw new Error("rightout_parity_source_catalog_invalid");
    }
    if (typeof guardedFetch !== "function")
        throw new Error("rightout_parity_source_refresh_unavailable");
    if (typeof permissionForRoute !== "function")
        throw new Error("rightout_parity_source_permission_contract_required");
    const routes = [...catalog.brokers].sort((a, b) => a.id.localeCompare(b.id));
    const results = await mapBounded(routes, 4, async (route) => {
        if (signal?.aborted)
            throw new Error("rightout_parity_source_refresh_cancelled");
        let permission;
        try {
            permission = permissionForRoute(route);
        }
        catch {
            permission = null;
        }
        if (!permission)
            return { broker_id: route.id, state: "not_probed_permission_required", network_requests: 0 };
        let request;
        try {
            request = await guardedFetch({
                url: route.source_url,
                allowedHosts: route.official_domains,
                timeoutMs: 20_000,
                maxRedirects: 0,
                signal,
                init: { method: "GET", redirect: "manual", headers: { Accept: "text/html,application/xhtml+xml" } },
            });
            const status = request?.response?.status;
            if (!Number.isInteger(status) || status < 100 || status > 599)
                throw new Error("invalid_status");
            return { broker_id: route.id, state: classify(route, status), observed_status: status, network_requests: 1 };
        }
        catch (error) {
            if (signal?.aborted)
                throw new Error("rightout_parity_source_refresh_cancelled");
            return {
                broker_id: route.id,
                state: route.source_status === EXTERNAL_UNAVAILABLE_STATUS ? "external_unavailable_reconfirmed" : "unreachable_needs_review",
                network_requests: 1,
            };
        }
        finally {
            await request?.release?.();
        }
    });
    const reviewStates = new Set([
        "needs_human_route_review", "redirect_quarantined", "unexpected_status_needs_review", "unreachable_needs_review",
        "external_route_recovered_needs_catalog_review", "not_probed_permission_required",
    ]);
    const needsReview = results.filter((item) => reviewStates.has(item.state)).map((item) => item.broker_id);
    return {
        report_version: 1,
        generated_at: now().toISOString(),
        reference_commit: catalog.reference_commit,
        evaluated_routes: results.length,
        probed_routes: results.filter((item) => item.network_requests > 0).length,
        skipped_permission_required: results.filter((item) => item.state === "not_probed_permission_required").length,
        provider_reads: results.filter((item) => Number.isInteger(item.observed_status)).length,
        provider_read_attempts: results.reduce((sum, item) => sum + item.network_requests, 0),
        provider_writes: 0,
        route_parallelism: Math.min(4, routes.length),
        results,
        needs_review: needsReview,
        permission_required: results.filter((item) => item.state === "not_probed_permission_required").map((item) => item.broker_id),
        source_blockers: [...catalog.health.source_blockers],
        release_ready: needsReview.length === 0 && catalog.health.source_blockers.length === 0,
        raw_response_content_in_report: false,
        raw_pii_in_report: false,
        automatic_catalog_mutation: false,
    };
}
export const __test = { classify, mapBounded };
