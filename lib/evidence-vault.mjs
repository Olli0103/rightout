import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, realpath, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { createHash, randomBytes } from "node:crypto";

const SAFE_EVIDENCE_REF = /^evidence_[a-f0-9]{64}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,80}$/;
const SAFE_KIND = /^(?:case_transition|controller_candidate|route_health)_snapshot$/;
const FORBIDDEN_KEY = /(?:name|email|phone|address|url|uri|token|secret|password|payload|body|html|text|image|screenshot)/iu;
const FORBIDDEN_VALUE = /(?:https?:\/\/|[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,63}|\b(?:bearer|ya29\.)\b|(?:^|[\s"'])\/[A-Za-z0-9._/-]{2,})/iu;
const MAX_CONTENT_BYTES = 32 * 1024;
const MAX_RETENTION_DAYS = 730;

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  return value;
}

function canonical(value) {
  let text;
  try { text = JSON.stringify(stable(value)); } catch { throw new Error("rightout_evidence_content_invalid"); }
  if (text === undefined || Buffer.byteLength(text) > MAX_CONTENT_BYTES) throw new Error("rightout_evidence_content_invalid");
  return text;
}

function sanitized(value, depth = 0) {
  if (depth > 10) throw new Error("rightout_evidence_content_invalid");
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("rightout_evidence_content_invalid");
    return value;
  }
  if (typeof value === "string") {
    if (value.length > 1_024 || /[\u0000-\u001f\u007f]/u.test(value) || FORBIDDEN_VALUE.test(value)) throw new Error("rightout_evidence_contains_sensitive_data");
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 100) throw new Error("rightout_evidence_content_invalid");
    return value.map((item) => sanitized(item, depth + 1));
  }
  if (!value || typeof value !== "object") throw new Error("rightout_evidence_content_invalid");
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
  if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > MAX_RETENTION_DAYS) throw new Error("rightout_evidence_retention_invalid");
  return { profileId, brokerId, kind, retentionDays };
}

function validateRecord(record, ref) {
  if (
    !record || typeof record !== "object" || Array.isArray(record) || record.schemaVersion !== 1
    || record.ref !== ref || !SAFE_EVIDENCE_REF.test(ref) || !SAFE_PROFILE_ID.test(record.profileId ?? "")
    || !SAFE_BROKER_ID.test(record.brokerId ?? "") || !SAFE_KIND.test(record.kind ?? "")
    || typeof record.createdAt !== "string" || !Number.isFinite(Date.parse(record.createdAt))
    || typeof record.contentDigest !== "string" || !/^[a-f0-9]{64}$/.test(record.contentDigest)
  ) throw new Error("rightout_evidence_record_invalid");
  const content = sanitized(record.content);
  if (createHash("sha256").update(canonical(content)).digest("hex") !== record.contentDigest) throw new Error("rightout_evidence_tampered");
  return { ...record, content };
}

async function privateExportDirectory(root) {
  const base = await realpath(root).catch(() => { throw new Error("rightout_evidence_export_root_invalid"); });
  const directory = resolve(base, "rightout-evidence-exports-v1");
  const rel = relative(base, directory);
  if (!rel || rel.startsWith("..") || isAbsolute(rel)) throw new Error("rightout_evidence_export_path_invalid");
  try { await mkdir(directory, { mode: 0o700 }); }
  catch (error) { if (error?.code !== "EEXIST") throw new Error("rightout_evidence_export_failed"); }
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("rightout_evidence_export_path_invalid");
  await chmod(directory, 0o700);
  if (await realpath(directory) !== directory || dirname(directory) !== base) throw new Error("rightout_evidence_export_path_invalid");
  return directory;
}

export function createEvidenceVault(store, { now = () => new Date() } = {}) {
  if (!store || typeof store.registerIfAbsent !== "function" || typeof store.lookup !== "function") throw new Error("rightout_evidence_store_invalid");

  async function put({ profileId, brokerId, kind, retentionDays = 365, content }) {
    const scope = cleanScope({ profileId, brokerId, kind, retentionDays });
    const cleanContent = sanitized(content);
    const contentText = canonical(cleanContent);
    const contentDigest = createHash("sha256").update(contentText).digest("hex");
    const ref = `evidence_${createHash("sha256").update(canonical(["rightout-evidence-v1", scope.profileId, scope.brokerId, scope.kind, contentDigest])).digest("hex")}`;
    const createdAt = now().toISOString();
    const record = { schemaVersion: 1, ref, ...scope, contentDigest, content: cleanContent, createdAt };
    await store.registerIfAbsent(ref, record, { ttlMs: retentionDays * 24 * 60 * 60_000 });
    const persisted = validateRecord(await store.lookup(ref), ref);
    return {
      evidence_ref: ref,
      subject_ref: persisted.profileId,
      broker_id: persisted.brokerId,
      kind: persisted.kind,
      content_sha256: persisted.contentDigest,
      created_at: persisted.createdAt,
      retention_days: persisted.retentionDays,
      encrypted_at_rest: true,
      raw_content_in_report: false,
    };
  }

  async function metadata(ref, profileId) {
    if (!SAFE_EVIDENCE_REF.test(ref ?? "") || !SAFE_PROFILE_ID.test(profileId ?? "")) throw new Error("rightout_evidence_ref_invalid");
    const record = validateRecord(await store.lookup(ref), ref);
    if (record.profileId !== profileId) throw new Error("rightout_evidence_scope_mismatch");
    return {
      evidence_ref: ref,
      subject_ref: record.profileId,
      broker_id: record.brokerId,
      kind: record.kind,
      content_sha256: record.contentDigest,
      created_at: record.createdAt,
      retention_days: record.retentionDays,
      encrypted_at_rest: true,
      raw_content_in_report: false,
    };
  }

  async function exportRedacted(ref, profileId, root, format = "json") {
    if (!new Set(["json", "markdown"]).has(format)) throw new Error("rightout_evidence_export_format_invalid");
    const meta = await metadata(ref, profileId);
    const record = validateRecord(await store.lookup(ref), ref);
    const artifact = format === "json"
      ? `${JSON.stringify({ schema_version: 1, ...meta, content: record.content }, null, 2)}\n`
      : [
        "# RightOut redacted evidence export", "", `- Evidence: \`${ref}\``, `- Subject: \`${profileId}\``,
        `- Broker: \`${record.brokerId}\``, `- Kind: \`${record.kind}\``, `- Created: ${record.createdAt}`, "",
        "```json", JSON.stringify(record.content, null, 2), "```", "",
      ].join("\n");
    sanitized(record.content);
    if (FORBIDDEN_VALUE.test(artifact)) throw new Error("rightout_evidence_export_redaction_failed");
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
    } catch { throw new Error("rightout_evidence_export_failed"); }
    finally { await handle?.close().catch(() => undefined); await unlink(temp).catch(() => undefined); }
    return { ...meta, state: "redacted_evidence_exported", format, artifact_path: file, export_approved_required: true };
  }

  return { put, metadata, exportRedacted };
}

export const __test = { canonical, sanitized, cleanScope, validateRecord, privateExportDirectory };
