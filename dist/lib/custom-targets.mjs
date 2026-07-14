import { isIP } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { recipeDigest, verifyExternalRecipePack } from "./recipes.mjs";
const SAFE_HANDLE = /^custom_[a-f0-9]{24}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const METHODS = new Set(["web_form", "email"]);
function cleanDomain(value) {
    if (typeof value !== "string")
        throw new Error("rightout_custom_target_invalid");
    const domain = value.trim().toLowerCase().replace(/^www\./u, "");
    if (!SAFE_DOMAIN.test(domain) || domain.includes("xn--") || isIP(domain) !== 0 || domain.endsWith(".local")) {
        throw new Error("rightout_custom_target_invalid");
    }
    return domain;
}
function cleanUrl(value, domain) {
    let url;
    try {
        url = new URL(value);
    }
    catch {
        throw new Error("rightout_custom_target_invalid");
    }
    const host = url.hostname.toLowerCase().replace(/^www\./u, "");
    if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443")
        || isIP(url.hostname) !== 0 || url.hostname.includes("xn--") || url.hash
        || (host !== domain && !host.endsWith(`.${domain}`)))
        throw new Error("rightout_custom_target_invalid");
    return url.toString();
}
function validateStored(record, handle) {
    if (!record || typeof record !== "object" || Array.isArray(record) || record.schemaVersion !== 1
        || record.handle !== handle || !SAFE_HANDLE.test(handle) || !SAFE_PROFILE_ID.test(record.profileId ?? "")
        || !METHODS.has(record.method) || !SAFE_DOMAIN.test(record.officialDomain ?? "")
        || typeof record.actionUrl !== "string" || typeof record.sourceUrl !== "string"
        || typeof record.createdAt !== "string" || !Number.isFinite(Date.parse(record.createdAt)))
        throw new Error("rightout_custom_target_state_invalid");
    if (cleanUrl(record.actionUrl, record.officialDomain) !== record.actionUrl || cleanUrl(record.sourceUrl, record.officialDomain) !== record.sourceUrl) {
        throw new Error("rightout_custom_target_state_invalid");
    }
    return structuredClone(record);
}
function cleanPermission(value, handle, recipe, now) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("rightout_custom_target_permission_required");
    const allowed = new Set([
        "schemaVersion", "customTargetHandle", "recipeDigest", "authorizationReferenceSha256",
        "officialDomainsDigest", "reviewedAt", "validUntil", "allowedEffects",
    ]);
    if (Object.keys(value).some((key) => !allowed.has(key)) || value.schemaVersion !== 1
        || value.customTargetHandle !== handle || value.recipeDigest !== recipeDigest(recipe)
        || !SAFE_SHA256.test(value.authorizationReferenceSha256 ?? "") || !SAFE_SHA256.test(value.officialDomainsDigest ?? "")
        || value.officialDomainsDigest !== recipeDigest(recipe.official_domains)
        || !Array.isArray(value.allowedEffects) || value.allowedEffects.length !== 1
        || value.allowedEffects[0] !== (recipe.method === "web_form" ? "submit_form" : "submit_email"))
        throw new Error("rightout_custom_target_permission_required");
    const reviewedAt = Date.parse(value.reviewedAt);
    const validUntil = Date.parse(value.validUntil);
    if (!Number.isFinite(reviewedAt) || !Number.isFinite(validUntil) || reviewedAt > now
        || validUntil <= now || validUntil <= reviewedAt || validUntil - reviewedAt > 366 * 24 * 60 * 60_000)
        throw new Error("rightout_custom_target_permission_expired");
    return structuredClone(value);
}
export function createCustomTargetVault(store, { now = () => Date.now(), randomHandle = () => `custom_${randomBytes(12).toString("hex")}` } = {}) {
    if (!store || typeof store.registerIfAbsent !== "function" || typeof store.lookup !== "function")
        throw new Error("rightout_custom_target_store_invalid");
    async function intake({ profileId, actionUrl, sourceUrl, officialDomain, method }) {
        if (!SAFE_PROFILE_ID.test(profileId ?? "") || !METHODS.has(method))
            throw new Error("rightout_custom_target_invalid");
        const domain = cleanDomain(officialDomain);
        const cleanActionUrl = cleanUrl(actionUrl, domain);
        const cleanSourceUrl = cleanUrl(sourceUrl, domain);
        for (let attempt = 0; attempt < 4; attempt += 1) {
            const handle = randomHandle();
            if (!SAFE_HANDLE.test(handle))
                throw new Error("rightout_custom_target_handle_invalid");
            const record = {
                schemaVersion: 1,
                handle,
                profileId,
                actionUrl: cleanActionUrl,
                sourceUrl: cleanSourceUrl,
                officialDomain: domain,
                method,
                createdAt: new Date(now()).toISOString(),
                state: "quarantined_unsigned",
            };
            if (await store.registerIfAbsent(handle, record, { ttlMs: 365 * 24 * 60 * 60_000 })) {
                return { custom_target_handle: handle, subject_ref: profileId, state: record.state, raw_target_in_report: false };
            }
        }
        throw new Error("rightout_custom_target_handle_collision");
    }
    async function metadata(handle, profileId) {
        if (!SAFE_HANDLE.test(handle ?? "") || !SAFE_PROFILE_ID.test(profileId ?? ""))
            throw new Error("rightout_custom_target_ref_invalid");
        const record = validateStored(await store.lookup(handle), handle);
        if (record.profileId !== profileId)
            throw new Error("rightout_custom_target_scope_mismatch");
        return {
            custom_target_handle: handle,
            subject_ref: profileId,
            method: record.method,
            state: record.state,
            created_at: record.createdAt,
            raw_target_in_report: false,
        };
    }
    async function resolveAuthorized(handle, profileId, { recipePacks, trustedKeys, permission }) {
        const meta = await metadata(handle, profileId);
        const record = validateStored(await store.lookup(handle), handle);
        if (!Array.isArray(recipePacks) || recipePacks.length < 1 || recipePacks.length > 20)
            throw new Error("rightout_custom_target_recipe_required");
        const recipes = recipePacks.flatMap((pack) => verifyExternalRecipePack(pack, trustedKeys, { now: now() }).recipes);
        const matches = recipes.filter((recipe) => (recipe.method === record.method
            && recipe.action_url === record.actionUrl
            && recipe.source_url === record.sourceUrl
            && recipe.official_domains.includes(record.officialDomain)));
        if (matches.length !== 1)
            throw new Error("rightout_custom_target_recipe_required");
        const recipe = matches[0];
        const clean = cleanPermission(permission, handle, recipe, now());
        return {
            metadata: { ...meta, state: "authorized_recipe_and_permission_bound", recipe_id: recipe.recipe_id, recipe_digest: recipeDigest(recipe) },
            record,
            recipe,
            permission: clean,
        };
    }
    return { intake, metadata, resolveAuthorized };
}
export const __test = { cleanDomain, cleanUrl, validateStored, cleanPermission };
