import { createHash } from "node:crypto";
const MAX_JSON_BYTES = 1_000_000;
const SAFE_TARGET = /^[A-Za-z0-9._:-]{1,160}$/;
const SAFE_REF = /^[A-Za-z0-9._:-]{1,160}$/;
function safeBridgeUrl(value) {
    if (typeof value !== "string" || value.length > 2_048)
        throw new Error("rightout_browser_bridge_unavailable");
    let url;
    try {
        url = new URL(value);
    }
    catch {
        throw new Error("rightout_browser_bridge_unavailable");
    }
    if (!(["http:", "https:"].includes(url.protocol)) || url.username || url.password || url.search || url.hash) {
        throw new Error("rightout_browser_bridge_unavailable");
    }
    return url.toString().replace(/\/$/, "");
}
async function boundedJson(response) {
    const declared = Number(response.headers.get("content-length") || "0");
    if (declared > MAX_JSON_BYTES)
        throw new Error("rightout_browser_response_invalid");
    const reader = response.body?.getReader();
    if (!reader)
        throw new Error("rightout_browser_response_invalid");
    const chunks = [];
    let size = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            size += value.byteLength;
            if (size > MAX_JSON_BYTES)
                throw new Error("rightout_browser_response_invalid");
            chunks.push(value);
        }
    }
    finally {
        reader.releaseLock();
    }
    const body = Buffer.concat(chunks.map((value) => Buffer.from(value))).toString("utf8");
    try {
        return JSON.parse(body);
    }
    catch {
        throw new Error("rightout_browser_response_invalid");
    }
}
function withPath(base, path) {
    const url = new URL(base);
    const relative = new URL(path, "http://rightout.local");
    url.pathname = `${url.pathname.replace(/\/$/, "")}${relative.pathname}`;
    url.search = relative.search;
    url.hash = "";
    return url.toString();
}
async function bridgeRequest(fetchImpl, base, path, { method = "GET", body, signal } = {}) {
    let response;
    try {
        response = await fetchImpl(withPath(base, path), {
            method,
            redirect: "error",
            headers: body === undefined ? { Accept: "application/json" } : { Accept: "application/json", "Content-Type": "application/json" },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
            signal,
        });
    }
    catch {
        if (signal?.aborted)
            throw new Error("rightout_form_cancelled");
        throw new Error("rightout_browser_bridge_failed");
    }
    if (!response.ok)
        throw new Error("rightout_browser_bridge_failed");
    return boundedJson(response);
}
function normalizeRefs(snapshot) {
    if (!snapshot || snapshot.ok !== true || snapshot.format !== "ai" || !snapshot.refs || typeof snapshot.refs !== "object") {
        throw new Error("rightout_browser_snapshot_invalid");
    }
    const refs = [];
    for (const [ref, value] of Object.entries(snapshot.refs)) {
        if (!SAFE_REF.test(ref) || !value || typeof value !== "object")
            continue;
        refs.push({ ref, role: String(value.role ?? "").toLowerCase(), name: String(value.name ?? "").toLowerCase() });
    }
    return refs;
}
function findRef(refs, spec) {
    const roles = new Set(spec.roles);
    const candidates = refs.filter((item) => roles.has(item.role) && spec.name_contains.some((fragment) => item.name.includes(fragment)));
    if (candidates.length !== 1)
        throw new Error("rightout_form_contract_mismatch");
    return candidates[0].ref;
}
function assertNoHumanGate(snapshot) {
    const text = String(snapshot.snapshot ?? "").toLowerCase();
    if (/\b(?:captcha|recaptcha|hcaptcha|government id|identity document|upload id)\b/u.test(text)) {
        throw new Error("rightout_form_human_gate_required");
    }
}
function assertSuccess(snapshot, phrases) {
    const text = String(snapshot.snapshot ?? "").toLowerCase();
    if (!phrases.some((phrase) => text.includes(phrase)))
        throw new Error("rightout_form_submission_unconfirmed");
}
export function createBrowserFormSubmitter({ fetchImpl = globalThis.fetch, now = () => new Date() } = {}) {
    if (typeof fetchImpl !== "function")
        throw new Error("rightout_browser_bridge_unavailable");
    return async function submitBrowserForm({ bridgeUrl, formUrl, recipe, values, signal }) {
        const base = safeBridgeUrl(bridgeUrl);
        if (signal?.aborted)
            throw new Error("rightout_form_cancelled");
        let targetId;
        try {
            const opened = await bridgeRequest(fetchImpl, base, "/tabs/open", { method: "POST", body: { url: formUrl, label: "rightout-removal" }, signal });
            if (!opened || opened.ok !== true || typeof opened.targetId !== "string" || !SAFE_TARGET.test(opened.targetId)) {
                throw new Error("rightout_browser_bridge_failed");
            }
            targetId = opened.targetId;
            const snapshot = await bridgeRequest(fetchImpl, base, `/snapshot?format=ai&refs=aria&interactive=true&compact=true&targetId=${encodeURIComponent(targetId)}&maxChars=100000&timeoutMs=20000`, { signal });
            assertNoHumanGate(snapshot);
            const refs = normalizeRefs(snapshot);
            const fields = recipe.fields.map((spec) => {
                const value = values[spec.profile_field];
                if (typeof value !== "string" || !value)
                    throw new Error("rightout_form_profile_field_missing");
                return { ref: findRef(refs, spec), type: spec.type, value };
            });
            await bridgeRequest(fetchImpl, base, "/act", { method: "POST", body: { kind: "fill", fields, targetId }, signal });
            for (const spec of recipe.checkboxes ?? []) {
                await bridgeRequest(fetchImpl, base, "/act", { method: "POST", body: { kind: "click", ref: findRef(refs, spec), targetId }, signal });
            }
            await bridgeRequest(fetchImpl, base, "/act", { method: "POST", body: { kind: "click", ref: findRef(refs, recipe.submit), targetId }, signal });
            const after = await bridgeRequest(fetchImpl, base, `/snapshot?format=ai&refs=aria&compact=true&targetId=${encodeURIComponent(targetId)}&maxChars=100000&timeoutMs=20000`, { signal });
            assertNoHumanGate(after);
            assertSuccess(after, recipe.success_phrases);
            const at = now().toISOString();
            return {
                submitted: true,
                submitted_at: at,
                proof_reference: `form_${createHash("sha256").update(JSON.stringify([formUrl, at, targetId])).digest("hex").slice(0, 24)}`,
            };
        }
        finally {
            if (targetId) {
                try {
                    await bridgeRequest(fetchImpl, base, `/tabs/${encodeURIComponent(targetId)}`, { method: "DELETE", signal: undefined });
                }
                catch { /* tab cleanup is best effort and never changes submission truth */ }
            }
        }
    };
}
export const __test = { safeBridgeUrl, normalizeRefs, findRef, assertNoHumanGate, assertSuccess, boundedJson };
