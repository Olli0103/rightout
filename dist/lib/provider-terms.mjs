import { createHash } from "node:crypto";
const EXPECTED_IDS = Object.freeze([
    "addresses", "advancedbackgroundchecks", "beenverified", "clustal", "clustrmaps",
    "cyberbackgroundchecks", "familytreenow", "fastpeoplesearch", "intelius", "mylife",
    "nuwber", "peekyou", "peoplefinders", "radaris", "rehold", "searchpeoplefree",
    "socialcatfish", "spokeo", "thatsthem", "truepeoplesearch", "usphonebook", "whitepages",
]);
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const MAX_PERMISSION_DURATION_MS = 365 * 24 * 60 * 60_000;
export const PROVIDER_AUTOMATION_EFFECTS = Object.freeze([
    "source_refresh", "publisher_discover", "direct_recheck", "submit_form", "open_verification",
]);
export const PROVIDER_BROWSER_BACKENDS = Object.freeze([
    "managed_openclaw", "remote_cloud_cdp", "existing_logged_in_cdp",
]);
function canonical(value) {
    if (Array.isArray(value))
        return `[${value.map(canonical).join(",")}]`;
    if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}
function exactKeys(value, keys) {
    return value && typeof value === "object" && !Array.isArray(value)
        && Object.keys(value).length === keys.length && Object.keys(value).every((key) => keys.includes(key));
}
function safeHttps(value) {
    try {
        const url = new URL(value);
        return url.protocol === "https:" && !url.username && !url.password;
    }
    catch {
        return false;
    }
}
export function providerTermsContractDigest(contract) {
    return createHash("sha256").update(canonical(contract), "utf8").digest("hex");
}
export function validateProviderTermsCatalog(value) {
    if (!exactKeys(value, ["schema_version", "reviewed_at", "policy", "brokers"]) || value.schema_version !== 1 || value.reviewed_at !== "2026-07-13") {
        throw new Error("rightout_provider_terms_catalog_invalid");
    }
    if (!exactKeys(value.policy, ["default_publisher_automation", "permission_requirement", "operator_attestation_alone_is_insufficient"])
        || value.policy.default_publisher_automation !== "deny"
        || value.policy.permission_requirement !== "current_written_provider_authorization"
        || value.policy.operator_attestation_alone_is_insufficient !== true
        || !Array.isArray(value.brokers))
        throw new Error("rightout_provider_terms_catalog_invalid");
    const brokers = value.brokers.map((entry) => {
        const baseKeys = ["id", "status", "terms_url", "privacy_url", "action_url", "last_checked"];
        if (!(exactKeys(entry, baseKeys) || exactKeys(entry, [...baseKeys, "contract_digest"]))
            || !EXPECTED_IDS.includes(entry.id)
            || !["explicit_automation_prohibition", "needs_evidence"].includes(entry.status)
            || ![entry.terms_url, entry.privacy_url, entry.action_url].every(safeHttps)
            || entry.last_checked !== value.reviewed_at)
            throw new Error("rightout_provider_terms_catalog_invalid");
        const base = Object.fromEntries(baseKeys.map((key) => [key, entry[key]]));
        const digest = providerTermsContractDigest(base);
        if (entry.contract_digest !== undefined && entry.contract_digest !== digest)
            throw new Error("rightout_provider_terms_catalog_invalid");
        return { ...base, contract_digest: digest };
    });
    if (new Set(brokers.map((entry) => entry.id)).size !== EXPECTED_IDS.length
        || JSON.stringify(brokers.map((entry) => entry.id).sort()) !== JSON.stringify([...EXPECTED_IDS].sort())) {
        throw new Error("rightout_provider_terms_catalog_invalid");
    }
    return { ...value, brokers };
}
/**
 * @param {unknown} config
 * @param {Record<string, any>} broker
 * @param {unknown} catalog
 * @param {string} effect
 * @param {{browserBackend?:"managed_openclaw"|"remote_cloud_cdp"|"existing_logged_in_cdp", now?:number}} [options]
 */
export function assertPublisherAutomationPermission(config, broker, catalog, effect, { browserBackend, now = Date.now() } = {}) {
    const cleanCatalog = validateProviderTermsCatalog(catalog);
    const contract = cleanCatalog.brokers.find((entry) => entry.id === broker.id);
    if (!contract)
        throw new Error("rightout_publisher_automation_not_authorized");
    const permission = config?.publisherAutomationPermissions?.[broker.id];
    if (!exactKeys(permission, ["authorizationReferenceSha256", "termsContractDigest", "reviewedAt", "validUntil", "allowedEffects", "allowedBrowserBackends"])
        || !SAFE_SHA256.test(permission.authorizationReferenceSha256)
        || permission.termsContractDigest !== contract.contract_digest) {
        throw new Error("rightout_publisher_automation_not_authorized");
    }
    const allowedEffects = Array.isArray(permission.allowedEffects) ? [...permission.allowedEffects].sort() : [];
    const allowedBrowserBackends = Array.isArray(permission.allowedBrowserBackends) ? [...permission.allowedBrowserBackends].sort() : [];
    if (!PROVIDER_AUTOMATION_EFFECTS.includes(effect)
        || allowedEffects.length < 1 || allowedEffects.length !== new Set(allowedEffects).size
        || allowedEffects.some((item) => !PROVIDER_AUTOMATION_EFFECTS.includes(item))
        || allowedBrowserBackends.length !== new Set(allowedBrowserBackends).size
        || allowedBrowserBackends.some((item) => !PROVIDER_BROWSER_BACKENDS.includes(item))
        || !allowedEffects.includes(effect)
        || (browserBackend !== undefined && (!PROVIDER_BROWSER_BACKENDS.includes(browserBackend) || !allowedBrowserBackends.includes(browserBackend))))
        throw new Error("rightout_publisher_automation_not_authorized");
    const reviewedAt = Date.parse(permission.reviewedAt);
    const validUntil = Date.parse(permission.validUntil);
    if (!Number.isFinite(reviewedAt) || !Number.isFinite(validUntil) || reviewedAt > now + 300_000
        || validUntil <= now || validUntil <= reviewedAt || validUntil - reviewedAt > MAX_PERMISSION_DURATION_MS) {
        throw new Error("rightout_publisher_automation_not_authorized");
    }
    return {
        broker_id: broker.id,
        provider_terms_status: contract.status,
        terms_contract_digest: contract.contract_digest,
        authorization_reference_sha256: permission.authorizationReferenceSha256,
        allowed_effect: effect,
        allowed_browser_backend: browserBackend ?? null,
        valid_until: new Date(validUntil).toISOString(),
    };
}
export function providerTermsHealth(catalog) {
    const clean = validateProviderTermsCatalog(catalog);
    return {
        reviewed_at: clean.reviewed_at,
        broker_count: clean.brokers.length,
        explicit_automation_prohibitions: clean.brokers.filter((entry) => entry.status === "explicit_automation_prohibition").map((entry) => entry.id),
        needs_evidence: clean.brokers.filter((entry) => entry.status === "needs_evidence").map((entry) => entry.id),
        explicitly_permitted: [],
        default_publisher_automation: "deny",
        contracts: clean.brokers.map((entry) => ({
            broker_id: entry.id,
            status: entry.status,
            terms_url: entry.terms_url,
            contract_digest: entry.contract_digest,
        })),
    };
}
