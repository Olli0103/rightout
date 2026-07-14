import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { exportLocalDashboard } from "../../lib/dashboard.mjs";

const model = {
  dashboard_version: 1,
  generated_at: "2026-07-14T12:00:00.000Z",
  member: { member_id: "member_0123456789abcdef", role: "manager", authorized_profile_count: 1 },
  profiles: [{
    subject_ref: "profile_0123456789abcdef",
    counts: { confirmed_removed: 1 },
    cases: [{ broker_id: "fullenrich_eu", state: "confirmed_removed", next_recheck_at: null }],
  }],
  effectiveness: [{ subject_ref: "profile_0123456789abcdef", operational_effectiveness: "needs_evidence" }],
  operational_effectiveness: "needs_evidence",
  due_now: 0,
  evidence_reference_count: 1,
  route_health: { summary: { fresh: 5, expiring: 0, stale: 0 }, live_provider_io_allowed: true, next_action: "none" },
  invariants: { raw_pii_in_report: false, network_requests: 0, browser_service_started: false },
};

test("dashboard export is static, private, content-addressed, and network inert", async () => {
  const root = mkdtempSync(join(tmpdir(), "rightout-dashboard-"));
  const html = await exportLocalDashboard(model, root, "html");
  assert.equal(html.network_service_started, false);
  assert.match(html.artifact_name, /^rightout-dashboard-[a-f0-9]{64}\.html$/);
  const directory = join(root, "rightout-dashboard-exports-v1");
  const htmlPath = join(directory, html.artifact_name);
  const artifact = readFileSync(htmlPath, "utf8");
  assert.match(artifact, /Content-Security-Policy/);
  assert.match(artifact, /default-src 'none'/);
  assert.doesNotMatch(artifact, /<script\b|<form\b|<iframe\b|<[^>]*\son[a-z]+\s*=|https?:\/\//iu);
  assert.equal(statSync(directory).mode & 0o777, 0o700);
  assert.equal(statSync(htmlPath).mode & 0o777, 0o600);

  const json = await exportLocalDashboard(model, root, "json");
  assert.equal(json.content_sha256, html.content_sha256);
  assert.deepEqual(JSON.parse(readFileSync(join(directory, json.artifact_name), "utf8")), model);
});

test("dashboard export rejects sensitive models and symlinked export directories", async () => {
  const root = mkdtempSync(join(tmpdir(), "rightout-dashboard-sensitive-"));
  await assert.rejects(exportLocalDashboard({ ...model, contact: "subject@example.invalid" }, root, "json"), /sensitive_data/);
  await assert.rejects(exportLocalDashboard({ ...model, source: "https://controller.example" }, root, "html"), /sensitive_data/);

  const unsafe = mkdtempSync(join(tmpdir(), "rightout-dashboard-symlink-"));
  symlinkSync(tmpdir(), join(unsafe, "rightout-dashboard-exports-v1"));
  await assert.rejects(exportLocalDashboard(model, unsafe, "html"), /path_invalid/);
});
