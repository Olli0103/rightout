import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readdir, realpath, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { createHash, randomBytes } from "node:crypto";
const SAFE_EVIDENCE_REF = /^evidence_[a-f0-9]{64}$/;
const SAFE_EXPORT_KEY = /^export_[a-f0-9]{64}$/;
const SAFE_EXPORT_NAME = /^evidence_[a-f0-9]{64}\.(?:json|md)$/;
const SAFE_EXPORT_TEMP_NAME = /^\.evidence_[a-f0-9]{64}\.[a-f0-9]{16}\.tmp$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,80}$/;
const SAFE_KIND = /^(?:case_transition|controller_candidate|route_health)_snapshot$/;
const FORBIDDEN_KEY = /(?:name|email|phone|address|url|uri|token|secret|password|payload|body|html|text|image|screenshot)/iu;
const FORBIDDEN_VALUE = /(?:https?:\/\/|[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,63}|\b(?:bearer|ya29\.)\b|(?:^|[\s"'])\/[A-Za-z0-9._/-]{2,})/iu;
const MAX_CONTENT_BYTES = 32 * 1024;
const MAX_RETENTION_DAYS = 730;
const RETENTION_DAY_MS = 24 * 60 * 60_000;
const MAX_TIMER_DELAY_MS = 2_147_000_000;
function stable(value) {
    if (Array.isArray(value))
        return value.map(stable);
    if (value && typeof value === "object")
        return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
    return value;
}
function canonical(value) {
    let text;
    try {
        text = JSON.stringify(stable(value));
    }
    catch {
        throw new Error("rightout_evidence_content_invalid");
    }
    if (text === undefined || Buffer.byteLength(text) > MAX_CONTENT_BYTES)
        throw new Error("rightout_evidence_content_invalid");
    return text;
}
function sanitized(value, depth = 0) {
    if (depth > 10)
        throw new Error("rightout_evidence_content_invalid");
    if (value === null || typeof value === "boolean")
        return value;
    if (typeof value === "number") {
        if (!Number.isFinite(value))
            throw new Error("rightout_evidence_content_invalid");
        return value;
    }
    if (typeof value === "string") {
        if (value.length > 1_024 || /[\u0000-\u001f\u007f]/u.test(value) || FORBIDDEN_VALUE.test(value))
            throw new Error("rightout_evidence_contains_sensitive_data");
        return value;
    }
    if (Array.isArray(value)) {
        if (value.length > 100)
            throw new Error("rightout_evidence_content_invalid");
        return value.map((item) => sanitized(item, depth + 1));
    }
    if (!value || typeof value !== "object")
        throw new Error("rightout_evidence_content_invalid");
    const keys = Object.keys(value);
    if (keys.length > 100 || keys.some((key) => !/^[a-z][a-z0-9_]{0,63}$/.test(key) || FORBIDDEN_KEY.test(key))) {
        throw new Error("rightout_evidence_contains_sensitive_data");
    }
    return Object.fromEntries(keys.map((key) => [key, sanitized(value[key], depth + 1)]));
}
function cleanScope({ profileId, brokerId, kind, retentionDays }) {
    if (!SAFE_PROFILE_ID.test(profileId ?? "") || !SAFE_BROKER_ID.test(brokerId ?? "") || !SAFE_KIND.test(kind ?? "")) {
        throw new Error("rightout_evidence_scope_invalid");
    }
    if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > MAX_RETENTION_DAYS)
        throw new Error("rightout_evidence_retention_invalid");
    return { profileId, brokerId, kind, retentionDays };
}
function validateRecord(record, ref) {
    if (!record || typeof record !== "object" || Array.isArray(record) || record.schemaVersion !== 1
        || record.ref !== ref || !SAFE_EVIDENCE_REF.test(ref) || !SAFE_PROFILE_ID.test(record.profileId ?? "")
        || !SAFE_BROKER_ID.test(record.brokerId ?? "") || !SAFE_KIND.test(record.kind ?? "")
        || typeof record.createdAt !== "string" || !Number.isFinite(Date.parse(record.createdAt))
        || typeof record.expiresAt !== "string" || !Number.isFinite(Date.parse(record.expiresAt))
        || Date.parse(record.expiresAt) <= Date.parse(record.createdAt)
        || !Number.isInteger(record.retentionDays) || record.retentionDays < 1 || record.retentionDays > MAX_RETENTION_DAYS
        || Date.parse(record.expiresAt) > Date.parse(record.createdAt) + record.retentionDays * RETENTION_DAY_MS
        || typeof record.contentDigest !== "string" || !/^[a-f0-9]{64}$/.test(record.contentDigest))
        throw new Error("rightout_evidence_record_invalid");
    const content = sanitized(record.content);
    if (createHash("sha256").update(canonical(content)).digest("hex") !== record.contentDigest)
        throw new Error("rightout_evidence_tampered");
    return { ...record, content };
}
function exportKey(ref, format) {
    return `export_${createHash("sha256").update(canonical(["rightout-evidence-export-v1", ref, format])).digest("hex")}`;
}
function validateExportRecord(record, key) {
    if (!record || typeof record !== "object" || Array.isArray(record) || record.schemaVersion !== 1
        || !SAFE_EXPORT_KEY.test(key ?? "") || record.key !== key || !SAFE_EVIDENCE_REF.test(record.evidenceRef ?? "")
        || !SAFE_PROFILE_ID.test(record.profileId ?? "") || !["json", "markdown"].includes(record.format)
        || !SAFE_EXPORT_NAME.test(record.artifactName ?? "")
        || typeof record.createdAt !== "string" || !Number.isFinite(Date.parse(record.createdAt))
        || typeof record.expiresAt !== "string" || !Number.isFinite(Date.parse(record.expiresAt))
        || Date.parse(record.expiresAt) <= Date.parse(record.createdAt))
        throw new Error("rightout_evidence_export_record_invalid");
    const extension = record.format === "json" ? "json" : "md";
    if (record.artifactName !== `${record.evidenceRef}.${extension}` || key !== exportKey(record.evidenceRef, record.format)) {
        throw new Error("rightout_evidence_export_record_invalid");
    }
    return structuredClone(record);
}
async function privateExportDirectory(root) {
    const base = await realpath(root).catch(() => { throw new Error("rightout_evidence_export_root_invalid"); });
    const directory = resolve(base, "rightout-evidence-exports-v1");
    const rel = relative(base, directory);
    if (!rel || rel.startsWith("..") || isAbsolute(rel))
        throw new Error("rightout_evidence_export_path_invalid");
    try {
        await mkdir(directory, { mode: 0o700 });
    }
    catch (error) {
        if (error?.code !== "EEXIST")
            throw new Error("rightout_evidence_export_failed");
    }
    const metadata = await lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink())
        throw new Error("rightout_evidence_export_path_invalid");
    await chmod(directory, 0o700);
    if (await realpath(directory) !== directory || dirname(directory) !== base)
        throw new Error("rightout_evidence_export_path_invalid");
    return directory;
}
async function unlinkManagedArtifact(path, errorCode) {
    try {
        await unlink(path);
        return true;
    }
    catch (error) {
        if (error?.code === "ENOENT")
            return false;
        throw new Error(errorCode);
    }
}
/**
 * @param {any} store
 * @param {{ now?: () => Date, exportStore?: any, exportRoot?: string, setTimer?: typeof setTimeout, clearTimer?: typeof clearTimeout, onCleanupError?: (error: unknown) => void }} [options]
 */
export function createEvidenceVault(store, options = {}) {
    const { now = () => new Date(), exportStore, exportRoot, setTimer = setTimeout, clearTimer = clearTimeout, onCleanupError = () => undefined, } = options;
    if (!store || typeof store.registerIfAbsent !== "function" || typeof store.lookup !== "function"
        || typeof store.update !== "function" || typeof store.delete !== "function" || typeof store.entries !== "function"
        || typeof store.reencrypt !== "function")
        throw new Error("rightout_evidence_store_invalid");
    if ((exportStore === undefined) !== (exportRoot === undefined))
        throw new Error("rightout_evidence_export_store_invalid");
    if (exportStore && (typeof exportStore.register !== "function" || typeof exportStore.lookup !== "function"
        || typeof exportStore.entries !== "function" || typeof exportStore.update !== "function"
        || typeof exportStore.delete !== "function" || typeof exportStore.reencrypt !== "function"))
        throw new Error("rightout_evidence_export_store_invalid");
    if (typeof setTimer !== "function" || typeof clearTimer !== "function" || typeof onCleanupError !== "function") {
        throw new Error("rightout_evidence_cleanup_scheduler_invalid");
    }
    let cleanupTimer;
    let vaultTail = Promise.resolve();
    /** @template T @param {() => Promise<T> | T} operation @returns {Promise<T>} */
    function serialized(operation) {
        const run = vaultTail.then(operation, operation);
        vaultTail = run.then(() => undefined, () => undefined);
        return run;
    }
    function armCleanupTimer(delay) {
        cleanupTimer = setTimer(async () => {
            cleanupTimer = undefined;
            try {
                await serialized(cleanupExpiredEvidenceInternal);
            }
            catch (error) {
                onCleanupError(error);
                armCleanupTimer(60_000);
            }
        }, delay);
        cleanupTimer?.unref?.();
    }
    async function scheduleNextCleanup() {
        if (cleanupTimer !== undefined) {
            clearTimer(cleanupTimer);
            cleanupTimer = undefined;
        }
        let nextExpiry = Number.POSITIVE_INFINITY;
        for (const entry of await store.entries()) {
            const record = validateRecord(entry.value, entry.key);
            nextExpiry = Math.min(nextExpiry, Date.parse(record.expiresAt));
        }
        if (exportStore) {
            for (const entry of await exportStore.entries()) {
                const record = validateExportRecord(entry.value, entry.key);
                nextExpiry = Math.min(nextExpiry, Date.parse(record.expiresAt));
            }
        }
        if (!Number.isFinite(nextExpiry))
            return;
        const delay = Math.max(1, Math.min(MAX_TIMER_DELAY_MS, nextExpiry - now().getTime()));
        armCleanupTimer(delay);
    }
    async function tightenExportExpiry(ref, expiresAt) {
        if (!exportStore)
            return;
        for (const entry of await exportStore.entries()) {
            const record = validateExportRecord(entry.value, entry.key);
            if (record.evidenceRef !== ref || Date.parse(record.expiresAt) <= Date.parse(expiresAt))
                continue;
            await exportStore.update(entry.key, (value) => {
                const current = validateExportRecord(value, entry.key);
                return { ...current, expiresAt };
            });
        }
    }
    async function cleanupExpiredExportsInternal() {
        if (!exportStore || exportRoot === undefined)
            return { deleted: 0, orphaned: 0 };
        const directory = await privateExportDirectory(exportRoot);
        const current = now().getTime();
        const liveNames = new Set();
        let deleted = 0;
        for (const entry of await exportStore.entries()) {
            const record = validateExportRecord(entry.value, entry.key);
            if (Date.parse(record.expiresAt) <= current) {
                if (await unlinkManagedArtifact(join(directory, record.artifactName), "rightout_evidence_export_cleanup_failed"))
                    deleted += 1;
                await exportStore.delete(entry.key);
            }
            else {
                liveNames.add(record.artifactName);
            }
        }
        let orphaned = 0;
        for (const entry of await readdir(directory, { withFileTypes: true })) {
            if (SAFE_EXPORT_TEMP_NAME.test(entry.name)) {
                if (await unlinkManagedArtifact(join(directory, entry.name), "rightout_evidence_export_cleanup_failed"))
                    orphaned += 1;
                continue;
            }
            if (!SAFE_EXPORT_NAME.test(entry.name) || liveNames.has(entry.name))
                continue;
            if (await unlinkManagedArtifact(join(directory, entry.name), "rightout_evidence_export_cleanup_failed"))
                orphaned += 1;
        }
        return { deleted, orphaned };
    }
    async function cleanupExpiredEvidenceInternal() {
        const current = now().getTime();
        let deleted = 0;
        for (const entry of await store.entries()) {
            const record = validateRecord(entry.value, entry.key);
            if (Date.parse(record.expiresAt) <= current) {
                await store.delete(entry.key);
                deleted += 1;
            }
        }
        await cleanupExpiredExportsInternal();
        await scheduleNextCleanup();
        return deleted;
    }
    async function liveRecord(ref) {
        const record = validateRecord(await store.lookup(ref), ref);
        if (Date.parse(record.expiresAt) <= now().getTime()) {
            await store.delete(ref);
            await cleanupExpiredExportsInternal();
            throw new Error("rightout_evidence_expired");
        }
        return record;
    }
    async function putInternal({ profileId, brokerId, kind, retentionDays = 365, content }) {
        await cleanupExpiredEvidenceInternal();
        const scope = cleanScope({ profileId, brokerId, kind, retentionDays });
        const cleanContent = sanitized(content);
        const contentText = canonical(cleanContent);
        const contentDigest = createHash("sha256").update(contentText).digest("hex");
        const ref = `evidence_${createHash("sha256").update(canonical(["rightout-evidence-v1", scope.profileId, scope.brokerId, scope.kind, contentDigest])).digest("hex")}`;
        const at = now();
        const createdAt = at.toISOString();
        const expiresAt = new Date(at.getTime() + retentionDays * RETENTION_DAY_MS).toISOString();
        const record = { schemaVersion: 1, ref, ...scope, contentDigest, content: cleanContent, createdAt, expiresAt };
        if (!await store.registerIfAbsent(ref, record)) {
            await store.update(ref, (value) => {
                const existing = validateRecord(value, ref);
                const stricterPolicyExpiry = Date.parse(existing.createdAt) + retentionDays * RETENTION_DAY_MS;
                const nextExpiry = Math.min(Date.parse(existing.expiresAt), stricterPolicyExpiry);
                return {
                    ...existing,
                    retentionDays: Math.min(existing.retentionDays, retentionDays),
                    expiresAt: new Date(nextExpiry).toISOString(),
                };
            });
        }
        const retained = validateRecord(await store.lookup(ref), ref);
        await tightenExportExpiry(ref, retained.expiresAt);
        const persisted = await liveRecord(ref);
        await scheduleNextCleanup();
        return {
            evidence_ref: ref,
            subject_ref: persisted.profileId,
            broker_id: persisted.brokerId,
            kind: persisted.kind,
            content_sha256: persisted.contentDigest,
            created_at: persisted.createdAt,
            expires_at: persisted.expiresAt,
            retention_days: persisted.retentionDays,
            encrypted_at_rest: true,
            raw_content_in_report: false,
        };
    }
    async function metadataInternal(ref, profileId) {
        if (!SAFE_EVIDENCE_REF.test(ref ?? "") || !SAFE_PROFILE_ID.test(profileId ?? ""))
            throw new Error("rightout_evidence_ref_invalid");
        await cleanupExpiredEvidenceInternal();
        const record = await liveRecord(ref);
        if (record.profileId !== profileId)
            throw new Error("rightout_evidence_scope_mismatch");
        return {
            evidence_ref: ref,
            subject_ref: record.profileId,
            broker_id: record.brokerId,
            kind: record.kind,
            content_sha256: record.contentDigest,
            created_at: record.createdAt,
            expires_at: record.expiresAt,
            retention_days: record.retentionDays,
            encrypted_at_rest: true,
            raw_content_in_report: false,
        };
    }
    async function exportRedactedInternal(ref, profileId, root, format = "json") {
        if (exportRoot !== undefined && root !== exportRoot)
            throw new Error("rightout_evidence_export_root_invalid");
        if (!new Set(["json", "markdown"]).has(format))
            throw new Error("rightout_evidence_export_format_invalid");
        const meta = await metadataInternal(ref, profileId);
        const record = await liveRecord(ref);
        const artifact = format === "json"
            ? `${JSON.stringify({ schema_version: 1, ...meta, content: record.content }, null, 2)}\n`
            : [
                "# RightOut redacted evidence export", "", `- Evidence: \`${ref}\``, `- Subject: \`${profileId}\``,
                `- Broker: \`${record.brokerId}\``, `- Kind: \`${record.kind}\``, `- Created: ${record.createdAt}`, "",
                "```json", JSON.stringify(record.content, null, 2), "```", "",
            ].join("\n");
        sanitized(record.content);
        if (FORBIDDEN_VALUE.test(artifact))
            throw new Error("rightout_evidence_export_redaction_failed");
        const directory = await privateExportDirectory(root);
        const extension = format === "json" ? "json" : "md";
        const file = join(directory, `${ref}.${extension}`);
        const temp = join(directory, `.${ref}.${randomBytes(8).toString("hex")}.tmp`);
        let handle;
        try {
            handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
            await handle.writeFile(artifact, "utf8");
            await handle.sync();
            await handle.close();
            handle = undefined;
            await rename(temp, file);
            await chmod(file, 0o600);
        }
        catch {
            throw new Error("rightout_evidence_export_failed");
        }
        finally {
            await handle?.close().catch(() => undefined);
            await unlink(temp).catch(() => undefined);
        }
        if (exportStore) {
            const key = exportKey(ref, format);
            const exportRecord = {
                schemaVersion: 1,
                key,
                profileId,
                evidenceRef: ref,
                format,
                artifactName: `${ref}.${extension}`,
                createdAt: now().toISOString(),
                expiresAt: record.expiresAt,
            };
            try {
                await exportStore.register(key, exportRecord);
            }
            catch {
                await unlink(file).catch(() => undefined);
                throw new Error("rightout_evidence_export_failed");
            }
            await scheduleNextCleanup();
        }
        return { ...meta, state: "redacted_evidence_exported", format, artifact_path: file, export_approved_required: true };
    }
    async function purgeExportsInternal(profileId) {
        if (!SAFE_PROFILE_ID.test(profileId ?? "") || !exportStore || exportRoot === undefined)
            return 0;
        const directory = await privateExportDirectory(exportRoot);
        let deleted = 0;
        for (const entry of await exportStore.entries()) {
            const record = validateExportRecord(entry.value, entry.key);
            if (record.profileId !== profileId)
                continue;
            await unlinkManagedArtifact(join(directory, record.artifactName), "rightout_evidence_export_purge_failed");
            await exportStore.delete(entry.key);
            deleted += 1;
        }
        await scheduleNextCleanup();
        return deleted;
    }
    async function purgeSubjectInternal(profileId) {
        if (!SAFE_PROFILE_ID.test(profileId ?? ""))
            throw new Error("rightout_evidence_scope_invalid");
        const evidenceExports = await purgeExportsInternal(profileId);
        let evidenceEntries = 0;
        for (const entry of await store.entries()) {
            const record = validateRecord(entry.value, entry.key);
            if (record.profileId !== profileId)
                continue;
            await store.delete(entry.key);
            evidenceEntries += 1;
        }
        await scheduleNextCleanup();
        return { evidence_exports: evidenceExports, evidence_entries: evidenceEntries };
    }
    async function reencryptInternal() {
        const [evidenceEntries, evidenceExportEntries] = await Promise.all([
            store.reencrypt(),
            exportStore ? exportStore.reencrypt() : Promise.resolve(0),
        ]);
        return { evidence_entries: evidenceEntries, evidence_export_entries: evidenceExportEntries };
    }
    return {
        put: (input) => serialized(() => putInternal(input)),
        metadata: (ref, profileId) => serialized(() => metadataInternal(ref, profileId)),
        exportRedacted: (ref, profileId, root, format) => serialized(() => exportRedactedInternal(ref, profileId, root, format)),
        purgeExports: (profileId) => serialized(() => purgeExportsInternal(profileId)),
        purgeSubject: (profileId) => serialized(() => purgeSubjectInternal(profileId)),
        cleanupExpiredEvidence: () => serialized(cleanupExpiredEvidenceInternal),
        cleanupExpiredExports: () => serialized(cleanupExpiredExportsInternal),
        reencrypt: () => serialized(reencryptInternal),
    };
}
export const __test = { canonical, sanitized, cleanScope, validateRecord, validateExportRecord, exportKey, privateExportDirectory };
