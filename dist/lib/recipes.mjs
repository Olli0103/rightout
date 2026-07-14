import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
const SAFE_BROKER_ID = /^[a-z0-9_]{2,80}$/;
const SAFE_PACK_ID = /^[a-z][a-z0-9._-]{2,80}$/;
const SAFE_KEY_ID = /^[A-Za-z0-9._-]{3,80}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const SAFE_FIELD = /^[a-z][a-z0-9_]{1,48}$/;
const METHODS = new Set(["web_form", "email", "phone"]);
const CHALLENGES = new Set([
    "ordinary_browser",
    "soft_managed_browser_then_human_hard",
    "ordinary_email_rescue_lane",
    "human_phone_or_identity_only",
]);
const FIELD_GROUPS = Object.freeze({
    contact_email: [["email field"], ["confirmation email field"]],
    full_name: [["legal name field"], ["first name field", "last name field"]],
    first_name: [["first name field"]],
    last_name: [["last name field"]],
    date_of_birth: [["date of birth field"]],
    listing_url: [["listing url field"]],
    listing_id: [["listing id field"]],
    street: [["address field"]],
    city: [["city field"]],
    region: [["region field"]],
    postal: [["postal field"]],
    phone: [["phone field"]],
});
const DISCLOSURE_FIELDS = new Set(Object.keys(FIELD_GROUPS));
function stableValue(value) {
    if (Array.isArray(value))
        return value.map(stableValue);
    if (value && typeof value === "object") {
        return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
    }
    return value;
}
export function canonicalRecipeJson(value) {
    let text;
    try {
        text = JSON.stringify(stableValue(value));
    }
    catch {
        throw new Error("rightout_recipe_invalid");
    }
    if (text === undefined || Buffer.byteLength(text) > 2_000_000)
        throw new Error("rightout_recipe_invalid");
    return text;
}
export function recipeDigest(value) {
    return createHash("sha256").update(canonicalRecipeJson(value)).digest("hex");
}
function cleanDomains(values) {
    if (!Array.isArray(values) || values.length < 1 || values.length > 12)
        throw new Error("rightout_recipe_invalid");
    const domains = values.map((value) => {
        if (typeof value !== "string" || value.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u.test(value)) {
            throw new Error("rightout_recipe_invalid");
        }
        return value;
    });
    if (new Set(domains).size !== domains.length)
        throw new Error("rightout_recipe_invalid");
    return [...domains].sort();
}
function cleanFields(values) {
    if (!Array.isArray(values) || values.length > 20
        || values.some((value) => typeof value !== "string" || !SAFE_FIELD.test(value) || !DISCLOSURE_FIELDS.has(value))) {
        throw new Error("rightout_recipe_invalid");
    }
    if (new Set(values).size !== values.length)
        throw new Error("rightout_recipe_invalid");
    return [...values];
}
function safeHttpsUrl(value, domains) {
    let url;
    try {
        url = new URL(value);
    }
    catch {
        throw new Error("rightout_recipe_invalid");
    }
    if (url.protocol !== "https:" || url.username || url.password || url.port
        || !domains.some((domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`)))
        throw new Error("rightout_recipe_invalid");
    return url.toString();
}
function cleanSteps(steps, method) {
    if (!Array.isArray(steps) || steps.length < 1 || steps.length > 16)
        throw new Error("rightout_recipe_invalid");
    const allowedKinds = method === "web_form"
        ? new Set(["open", "fill", "submit", "verify_email", "human_gate"])
        : method === "email" ? new Set(["send_email", "await_reply"])
            : new Set(["human_phone_handoff"]);
    const ids = new Set();
    return steps.map((step) => {
        if (!step || typeof step !== "object" || Array.isArray(step))
            throw new Error("rightout_recipe_invalid");
        if (Object.keys(step).some((key) => !["id", "kind", "required_fields", "success_markers"].includes(key)))
            throw new Error("rightout_recipe_invalid");
        if (typeof step.id !== "string" || !/^[a-z][a-z0-9_]{2,80}$/.test(step.id) || ids.has(step.id))
            throw new Error("rightout_recipe_invalid");
        ids.add(step.id);
        if (!allowedKinds.has(step.kind))
            throw new Error("rightout_recipe_invalid");
        const requiredFields = cleanFields(step.required_fields ?? []);
        const successMarkers = step.success_markers ?? [];
        if (!Array.isArray(successMarkers) || successMarkers.length > 12 || successMarkers.some((value) => typeof value !== "string" || !/^[a-z0-9_]{3,80}$/.test(value))) {
            throw new Error("rightout_recipe_invalid");
        }
        return { id: step.id, kind: step.kind, required_fields: requiredFields, success_markers: [...successMarkers] };
    });
}
export function validateRecipe(recipe) {
    if (!recipe || typeof recipe !== "object" || Array.isArray(recipe))
        throw new Error("rightout_recipe_invalid");
    const allowed = new Set([
        "schema_version", "recipe_id", "broker_id", "method", "action_url", "official_domains",
        "disclosure_fields", "verification", "challenge_policy", "source_url", "source_status",
        "reviewed_at", "expires_at", "steps", "source_contract_digest",
    ]);
    if (Object.keys(recipe).some((key) => !allowed.has(key)) || recipe.schema_version !== 1)
        throw new Error("rightout_recipe_invalid");
    if (typeof recipe.recipe_id !== "string" || !/^recipe_[a-z0-9_]{2,80}_v[1-9][0-9]*$/.test(recipe.recipe_id)
        || !SAFE_BROKER_ID.test(recipe.broker_id ?? "")
        || !recipe.recipe_id.startsWith(`recipe_${recipe.broker_id}_v`)
        || !METHODS.has(recipe.method)
        || typeof recipe.verification !== "string" || !/^[a-z0-9_]{2,48}$/.test(recipe.verification)
        || !CHALLENGES.has(recipe.challenge_policy)
        || typeof recipe.source_status !== "string" || !/^[a-z0-9_]{3,100}$/.test(recipe.source_status)
        || !SAFE_SHA256.test(recipe.source_contract_digest ?? ""))
        throw new Error("rightout_recipe_invalid");
    const domains = cleanDomains(recipe.official_domains);
    const actionUrl = safeHttpsUrl(recipe.action_url, domains);
    const sourceUrl = safeHttpsUrl(recipe.source_url, domains);
    const reviewedAt = Date.parse(`${recipe.reviewed_at}T00:00:00Z`);
    const expiresAt = Date.parse(`${recipe.expires_at}T00:00:00Z`);
    if (!Number.isFinite(reviewedAt) || !Number.isFinite(expiresAt) || expiresAt <= reviewedAt)
        throw new Error("rightout_recipe_invalid");
    const disclosureFields = cleanFields(recipe.disclosure_fields);
    const steps = cleanSteps(recipe.steps, recipe.method);
    return {
        schema_version: 1,
        recipe_id: recipe.recipe_id,
        broker_id: recipe.broker_id,
        method: recipe.method,
        action_url: actionUrl,
        official_domains: domains,
        disclosure_fields: disclosureFields,
        verification: recipe.verification,
        challenge_policy: recipe.challenge_policy,
        source_url: sourceUrl,
        source_status: recipe.source_status,
        reviewed_at: recipe.reviewed_at,
        expires_at: recipe.expires_at,
        steps,
        source_contract_digest: recipe.source_contract_digest,
    };
}
function recipeSteps(row) {
    if (row.method === "email")
        return [
            { id: "send_official_email", kind: "send_email", required_fields: row.disclosure_fields, success_markers: ["message_sent_observed"] },
            { id: "await_controller_reply", kind: "await_reply", required_fields: [], success_markers: ["authenticated_controller_reply"] },
        ];
    if (row.method === "phone")
        return [
            { id: "human_phone_handoff", kind: "human_phone_handoff", required_fields: [], success_markers: [] },
        ];
    return [
        { id: "open_official_route", kind: "open", required_fields: [], success_markers: [] },
        { id: "fill_minimum_fields", kind: "fill", required_fields: row.disclosure_fields, success_markers: [] },
        { id: "submit_request", kind: "submit", required_fields: [], success_markers: ["submission_success_observed", "verification_email_requested_observed"] },
        ...(row.verification === "email" ? [{ id: "verify_email", kind: "verify_email", required_fields: [], success_markers: ["verification_destination_opened_observed"] }] : []),
    ];
}
export function buildBuiltinRecipes(catalog, { expiresAt = "2027-07-14" } = {}) {
    if (!catalog || typeof catalog !== "object" || !Array.isArray(catalog.brokers) || catalog.brokers.length < 1)
        throw new Error("rightout_recipe_catalog_invalid");
    const recipes = catalog.brokers.map((row) => {
        if (!row || !SAFE_BROKER_ID.test(row.id ?? "") || !METHODS.has(row.method)
            || typeof row.action_url !== "string" || typeof row.source_url !== "string"
            || typeof row.last_checked !== "string" || !Array.isArray(row.official_domains)
            || !Array.isArray(row.disclosure_fields))
            throw new Error("rightout_recipe_catalog_invalid");
        const sourceContractDigest = recipeDigest({
            broker_id: row.id,
            method: row.method,
            action_url: row.action_url,
            official_domains: row.official_domains,
            disclosure_fields: row.disclosure_fields,
            verification: row.verification,
            challenge_policy: row.challenge_policy,
            source_url: row.source_url,
            source_status: row.source_status,
            reviewed_at: row.last_checked,
            reference_contract: row.reference_contract,
        });
        return validateRecipe({
            schema_version: 1,
            recipe_id: `recipe_${row.id}_v1`,
            broker_id: row.id,
            method: row.method,
            action_url: row.action_url,
            official_domains: row.official_domains,
            disclosure_fields: row.disclosure_fields,
            verification: row.verification,
            challenge_policy: row.challenge_policy,
            source_url: row.source_url,
            source_status: row.source_status,
            reviewed_at: row.last_checked,
            expires_at: expiresAt,
            steps: recipeSteps(row),
            source_contract_digest: sourceContractDigest,
        });
    }).sort((a, b) => a.broker_id.localeCompare(b.broker_id));
    if (new Set(recipes.map((recipe) => recipe.broker_id)).size !== recipes.length)
        throw new Error("rightout_recipe_catalog_invalid");
    return recipes;
}
export function compileBuiltinRecipePack(catalog, manifest, { sourceSha256 = "", now = Date.now() } = {}) {
    const allowed = new Set([
        "schema_version", "pack_id", "trust", "source_path", "source_sha256", "compiled_recipes_sha256", "expires_at",
    ]);
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)
        || Object.keys(manifest).some((key) => !allowed.has(key))
        || manifest.schema_version !== 1 || manifest.trust !== "release_attested_builtin"
        || !SAFE_PACK_ID.test(manifest.pack_id ?? "")
        || manifest.source_path !== "skills/data-broker-removal/references/brokers/unbroker-parity.json"
        || !SAFE_SHA256.test(manifest.source_sha256 ?? "")
        || !SAFE_SHA256.test(manifest.compiled_recipes_sha256 ?? "")
        || sourceSha256 !== manifest.source_sha256)
        throw new Error("rightout_recipe_pack_invalid");
    const expires = Date.parse(`${manifest.expires_at}T00:00:00Z`);
    if (!Number.isFinite(expires) || expires <= now)
        throw new Error("rightout_recipe_pack_expired");
    const recipes = buildBuiltinRecipes(catalog, { expiresAt: manifest.expires_at });
    if (recipeDigest(recipes) !== manifest.compiled_recipes_sha256)
        throw new Error("rightout_recipe_pack_integrity_failed");
    return {
        schema_version: 1,
        pack_id: manifest.pack_id,
        trust: manifest.trust,
        expires_at: manifest.expires_at,
        recipes,
        recipe_digest: manifest.compiled_recipes_sha256,
    };
}
export function verifyExternalRecipePack(pack, trustedKeys, { now = Date.now() } = {}) {
    if (!pack || typeof pack !== "object" || Array.isArray(pack))
        throw new Error("rightout_recipe_pack_invalid");
    const allowed = new Set(["schema_version", "pack_id", "trust", "key_id", "issued_at", "expires_at", "recipes", "signature"]);
    if (Object.keys(pack).some((key) => !allowed.has(key)) || pack.schema_version !== 1 || pack.trust !== "external_ed25519"
        || !SAFE_PACK_ID.test(pack.pack_id ?? "") || !SAFE_KEY_ID.test(pack.key_id ?? "")
        || typeof pack.signature !== "string" || !/^[A-Za-z0-9_-]{80,120}$/.test(pack.signature)
        || !trustedKeys || typeof trustedKeys !== "object" || Array.isArray(trustedKeys)
        || typeof trustedKeys[pack.key_id] !== "string")
        throw new Error("rightout_recipe_pack_invalid");
    const issued = Date.parse(pack.issued_at);
    const expires = Date.parse(pack.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now || expires <= now || expires - issued > 366 * 24 * 60 * 60_000) {
        throw new Error("rightout_recipe_pack_expired");
    }
    if (!Array.isArray(pack.recipes) || pack.recipes.length < 1 || pack.recipes.length > 500)
        throw new Error("rightout_recipe_pack_invalid");
    const recipes = pack.recipes.map(validateRecipe);
    if (new Set(recipes.map((row) => row.broker_id)).size !== recipes.length)
        throw new Error("rightout_recipe_pack_invalid");
    if (recipes.some((recipe) => {
        const reviewed = Date.parse(`${recipe.reviewed_at}T00:00:00Z`);
        const recipeExpires = Date.parse(`${recipe.expires_at}T00:00:00Z`);
        return reviewed > now || recipeExpires <= now || recipeExpires > expires;
    }))
        throw new Error("rightout_recipe_pack_expired");
    const unsigned = { ...pack };
    delete unsigned.signature;
    let key;
    try {
        key = createPublicKey(trustedKeys[pack.key_id]);
    }
    catch {
        throw new Error("rightout_recipe_pack_key_invalid");
    }
    let signature;
    try {
        signature = Buffer.from(pack.signature, "base64url");
    }
    catch {
        throw new Error("rightout_recipe_pack_signature_invalid");
    }
    if (!verifySignature(null, Buffer.from(canonicalRecipeJson(unsigned)), key, signature))
        throw new Error("rightout_recipe_pack_signature_invalid");
    return {
        schema_version: 1,
        pack_id: pack.pack_id,
        trust: pack.trust,
        key_id: pack.key_id,
        issued_at: pack.issued_at,
        expires_at: pack.expires_at,
        recipes,
        recipe_digest: recipeDigest(recipes),
    };
}
export function assessRecipeSnapshot(recipeInput, snapshot) {
    const recipe = validateRecipe(recipeInput);
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot) || snapshot.raw_pii_in_snapshot !== false) {
        throw new Error("rightout_recipe_snapshot_invalid");
    }
    const pageDomain = snapshot.page_domain;
    if (typeof pageDomain !== "string" || !recipe.official_domains.some((domain) => pageDomain === domain || pageDomain.endsWith(`.${domain}`))) {
        return { state: "quarantined", reason: "recipe_domain_drift", recipe_id: recipe.recipe_id };
    }
    if (["hard_human_gate", "access_blocked"].includes(snapshot.challenge)) {
        return { state: "human_gate", reason: `recipe_${snapshot.challenge}`, recipe_id: recipe.recipe_id };
    }
    const refs = Array.isArray(snapshot.refs) ? snapshot.refs : [];
    const names = refs.map((item) => String(item?.name ?? "").toLowerCase());
    if (names.some((name) => /\b(?:payment|credit card|government id|passport|create account|security question|otp)\b/u.test(name))) {
        return { state: "human_gate", reason: "recipe_unexpected_sensitive_control", recipe_id: recipe.recipe_id };
    }
    const success = typeof snapshot.snapshot === "string" && /(?:submission_success_observed|verification_email_requested_observed|verification_destination_opened_observed|suppression_success_observed)/u.test(snapshot.snapshot);
    const expectedFieldGroups = recipe.disclosure_fields.flatMap((field) => FIELD_GROUPS[field] ?? []);
    const hasExpectedField = expectedFieldGroups.some((group) => group.every((label) => names.includes(label)));
    const hasKnownAction = names.some((name) => (/\b(?:search|continue|submission|confirmation|suppression|consent|send) action\b/u.test(name)
        || name === "corroborated subject record"));
    const hasBoundedStaticChallenge = ["static_challenge_visible", "static_text_challenge_visible"].includes(snapshot.challenge)
        && names.some((name) => ["arithmetic answer", "static text challenge answer"].includes(name));
    if (!success && refs.length > 0 && !hasExpectedField && !hasKnownAction && !hasBoundedStaticChallenge) {
        return { state: "quarantined", reason: "recipe_semantic_drift", recipe_id: recipe.recipe_id };
    }
    return {
        state: "compatible",
        recipe_id: recipe.recipe_id,
        recipe_digest: recipeDigest(recipe),
        observed_expected_field: hasExpectedField,
        observed_known_action: hasKnownAction,
        observed_bounded_static_challenge: hasBoundedStaticChallenge,
        success_marker_observed: success,
    };
}
export const __test = { FIELD_GROUPS, cleanDomains, cleanSteps, stableValue };
