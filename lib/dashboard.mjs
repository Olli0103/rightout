import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, realpath, rename, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { createHash, randomBytes } from "node:crypto";

const FORBIDDEN = /(?:https?:\/\/|[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,63}|\b(?:bearer|ya29\.)\b)/iu;

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value) ?? "null";
}

function assertSanitized(model) {
  let text;
  try { text = JSON.stringify(model); } catch { throw new Error("rightout_dashboard_invalid"); }
  if (Buffer.byteLength(text) > 2_000_000 || FORBIDDEN.test(text) || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(text)) {
    throw new Error("rightout_dashboard_sensitive_data");
  }
  return JSON.parse(text);
}

function escapeHtml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function htmlArtifact(model) {
  const rows = model.profiles.flatMap((profile) => profile.cases.map((item) => [
    profile.subject_ref, item.broker_id, item.state, item.next_recheck_at ?? "-",
  ]));
  return [
    "<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src \'none\'; connect-src \'none\'; frame-src \'none\';">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    "<title>RightOut local privacy dashboard</title>",
    "<style>body{font:15px system-ui;margin:2rem;max-width:1100px;color:#16202a;background:#f6f7f9}h1{margin-bottom:.25rem}.card{background:white;border:1px solid #d9dee5;border-radius:12px;padding:1rem;margin:1rem 0}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.55rem;border-bottom:1px solid #e6e9ee}code{font-size:.85em}.muted{color:#5d6977}</style>",
    "</head><body><h1>RightOut local privacy dashboard</h1>",
    `<p class="muted">Generated ${escapeHtml(model.generated_at)} · ${escapeHtml(model.member.role)} · ${model.profiles.length} subject scope(s)</p>`,
    `<div class="card"><strong>Operational effectiveness:</strong> ${escapeHtml(model.operational_effectiveness)}<br><strong>Due now:</strong> ${model.due_now}<br><strong>Encrypted evidence refs:</strong> ${model.evidence_reference_count}</div>`,
    '<div class="card"><table><thead><tr><th>Subject</th><th>Broker</th><th>State</th><th>Next recheck</th></tr></thead><tbody>',
    ...rows.map((row) => `<tr>${row.map((cell) => `<td><code>${escapeHtml(cell)}</code></td>`).join("")}</tr>`),
    "</tbody></table></div>",
    '<p class="muted">Static local artifact. No scripts, remote assets, forms, or network connections.</p>',
    "</body></html>\n",
  ].join("");
}

async function privateDirectory(root) {
  const base = await realpath(root).catch(() => { throw new Error("rightout_dashboard_root_invalid"); });
  const directory = resolve(base, "rightout-dashboard-exports-v1");
  const rel = relative(base, directory);
  if (!rel || rel.startsWith("..") || isAbsolute(rel)) throw new Error("rightout_dashboard_path_invalid");
  try { await mkdir(directory, { mode: 0o700 }); }
  catch (error) { if (error?.code !== "EEXIST") throw new Error("rightout_dashboard_export_failed"); }
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("rightout_dashboard_path_invalid");
  await chmod(directory, 0o700);
  if (await realpath(directory) !== directory || dirname(directory) !== base) throw new Error("rightout_dashboard_path_invalid");
  return directory;
}

export async function exportLocalDashboard(modelInput, root, format = "html") {
  if (!new Set(["html", "json"]).has(format)) throw new Error("rightout_dashboard_format_invalid");
  const model = assertSanitized(modelInput);
  const digest = createHash("sha256").update(canonical(model)).digest("hex");
  const artifact = format === "json" ? `${JSON.stringify(model, null, 2)}\n` : htmlArtifact(model);
  if (FORBIDDEN.test(artifact) || (format === "html" && /<script\b|<[^>]*\son[a-z]+\s*=|<form\b|<iframe\b/iu.test(artifact))) {
    throw new Error("rightout_dashboard_sensitive_data");
  }
  const directory = await privateDirectory(root);
  const file = join(directory, `rightout-dashboard-${digest}.${format}`);
  const temp = join(directory, `.dashboard-${randomBytes(8).toString("hex")}.tmp`);
  let handle;
  try {
    handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await handle.writeFile(artifact, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temp, file);
    await chmod(file, 0o600);
  } catch { throw new Error("rightout_dashboard_export_failed"); }
  finally { await handle?.close().catch(() => undefined); await unlink(temp).catch(() => undefined); }
  return { state: "local_dashboard_exported", artifact_name: basename(file), format, content_sha256: digest, network_service_started: false, raw_pii_in_report: false };
}

export const __test = { canonical, assertSanitized, escapeHtml, htmlArtifact, privateDirectory };
