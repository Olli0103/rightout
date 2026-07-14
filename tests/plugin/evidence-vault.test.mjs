import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createEvidenceVault } from "../../lib/evidence-vault.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";

const profileId = "profile_0123456789abcdef";
const brokerId = "fullenrich_eu";
const stateKey = "dummy-evidence-key-with-more-than-32-characters";

function fixture({ mutableNow } = {}) {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-evidence-vault-"));
  const store = createEncryptedFileKeyedStore({
    stateDir, namespace: "rightout-evidence-vault-v1", maxEntries: 500,
    getSecret: () => stateKey, ...(mutableNow ? { now: () => mutableNow.value } : {}),
  });
  const exportStore = createEncryptedFileKeyedStore({
    stateDir, namespace: "rightout-evidence-export-index-v1", maxEntries: 1_000,
    getSecret: () => stateKey, ...(mutableNow ? { now: () => mutableNow.value } : {}),
  });
  return {
    stateDir,
    store,
    exportStore,
    vault: createEvidenceVault(store, {
      now: () => new Date(mutableNow?.value ?? Date.now()), exportStore, exportRoot: stateDir,
    }),
  };
}

const content = {
  state: "submitted",
  proof_references: ["smtp_0123456789abcdef01234567"],
  submission_channel: "smtp_email",
  next_recheck_at: "2026-08-13T10:00:00.000Z",
  raw_pii_in_snapshot: false,
};

test("evidence is content-addressed, encrypted, deduplicated, and metadata-only by default", async () => {
  const { stateDir, vault } = fixture();
  const first = await vault.put({ profileId, brokerId, kind: "case_transition_snapshot", retentionDays: 30, content });
  const second = await vault.put({ profileId, brokerId, kind: "case_transition_snapshot", retentionDays: 30, content });
  assert.equal(first.evidence_ref, second.evidence_ref);
  assert.match(first.evidence_ref, /^evidence_[a-f0-9]{64}$/);
  assert.equal(first.raw_content_in_report, false);
  assert.equal("content" in first, false);
  const meta = await vault.metadata(first.evidence_ref, profileId);
  assert.equal(meta.content_sha256, first.content_sha256);
  assert.equal("content" in meta, false);
  const encrypted = readFileSync(join(stateDir, "rightout-plugin-state-v1", "rightout-evidence-vault-v1.json.enc"), "utf8");
  assert.doesNotMatch(encrypted, /submitted|smtp_012345|profile_0123|fullenrich/);
  await assert.rejects(vault.metadata(first.evidence_ref, "profile_ffffffffffffffff"), /scope_mismatch/);
});

test("evidence rejects sensitive values, suspicious keys, tampering, and expires with its retention", async () => {
  const mutableNow = { value: Date.parse("2026-07-14T10:00:00Z") };
  const { store, vault } = fixture({ mutableNow });
  await assert.rejects(vault.put({ profileId, brokerId, kind: "case_transition_snapshot", retentionDays: 30, content: { email: "subject@example.invalid" } }), /sensitive_data/);
  await assert.rejects(vault.put({ profileId, brokerId, kind: "case_transition_snapshot", retentionDays: 30, content: { route: "https://controller.example/path" } }), /sensitive_data/);
  const saved = await vault.put({ profileId, brokerId, kind: "case_transition_snapshot", retentionDays: 1, content });
  await store.update(saved.evidence_ref, (record) => ({ ...record, content: { ...record.content, state: "confirmed_removed" } }));
  await assert.rejects(vault.metadata(saved.evidence_ref, profileId), /tampered/);

  const expiringFixture = fixture({ mutableNow });
  const fresh = await expiringFixture.vault.put({ profileId, brokerId, kind: "route_health_snapshot", retentionDays: 1, content: { state: "fresh", raw_pii_in_snapshot: false } });
  mutableNow.value += 25 * 60 * 60_000;
  await assert.rejects(expiringFixture.vault.metadata(fresh.evidence_ref, profileId), /record_invalid/);
});

test("evidence dedupe atomically keeps the stricter retention", async () => {
  const mutableNow = { value: Date.parse("2026-07-14T10:00:00Z") };
  const { stateDir, vault } = fixture({ mutableNow });
  const first = await vault.put({ profileId, brokerId, kind: "case_transition_snapshot", retentionDays: 365, content });
  const exported = await vault.exportRedacted(first.evidence_ref, profileId, stateDir, "json");
  mutableNow.value += 60_000;
  const stricter = await vault.put({ profileId, brokerId, kind: "case_transition_snapshot", retentionDays: 30, content });
  const attemptedExtension = await vault.put({ profileId, brokerId, kind: "case_transition_snapshot", retentionDays: 365, content });
  assert.equal(first.evidence_ref, stricter.evidence_ref);
  assert.equal(stricter.retention_days, 30);
  assert.equal(attemptedExtension.retention_days, 30);
  assert.equal(attemptedExtension.expires_at, stricter.expires_at);
  mutableNow.value += 31 * 24 * 60 * 60_000;
  await vault.cleanupExpiredEvidence();
  assert.equal(existsSync(exported.artifact_path), false);
});

test("redacted export is separately invoked, private, contained, and rejects a symlink directory", async () => {
  const { stateDir, store, exportStore, vault } = fixture();
  const saved = await vault.put({ profileId, brokerId, kind: "case_transition_snapshot", retentionDays: 30, content });
  const exported = await vault.exportRedacted(saved.evidence_ref, profileId, stateDir, "json");
  assert.equal(exported.state, "redacted_evidence_exported");
  assert.ok(exported.artifact_path.startsWith(`${realpathSync(stateDir)}/rightout-evidence-exports-v1/`));
  const artifact = readFileSync(exported.artifact_path, "utf8");
  assert.match(artifact, /smtp_0123456789abcdef01234567/);
  assert.doesNotMatch(artifact, /@|https?:\/\//);

  const unsafeRoot = mkdtempSync(join(tmpdir(), "rightout-evidence-export-symlink-"));
  symlinkSync(tmpdir(), join(unsafeRoot, "rightout-evidence-exports-v1"));
  const unsafeVault = createEvidenceVault(store, { exportStore, exportRoot: unsafeRoot });
  await assert.rejects(unsafeVault.exportRedacted(saved.evidence_ref, profileId, unsafeRoot, "markdown"), /export_path_invalid/);
});

test("managed evidence exports are deleted on subject purge and retention expiry", async () => {
  const mutableNow = { value: Date.parse("2026-07-14T10:00:00Z") };
  const { stateDir, vault } = fixture({ mutableNow });
  const first = await vault.put({ profileId, brokerId, kind: "case_transition_snapshot", retentionDays: 30, content });
  const purged = await vault.exportRedacted(first.evidence_ref, profileId, stateDir, "json");
  assert.equal(existsSync(purged.artifact_path), true);
  assert.equal(await vault.purgeExports(profileId), 1);
  assert.equal(existsSync(purged.artifact_path), false);

  const expiring = await vault.put({ profileId, brokerId, kind: "route_health_snapshot", retentionDays: 1, content: { state: "fresh", raw_pii_in_snapshot: false } });
  const expiredExport = await vault.exportRedacted(expiring.evidence_ref, profileId, stateDir, "json");
  const staleTemp = join(stateDir, "rightout-evidence-exports-v1", `.${expiring.evidence_ref}.0123456789abcdef.tmp`);
  writeFileSync(staleTemp, "interrupted export", { mode: 0o600 });
  mutableNow.value += 25 * 60 * 60_000;
  await vault.cleanupExpiredEvidence();
  assert.equal(existsSync(expiredExport.artifact_path), false);
  assert.equal(existsSync(staleTemp), false);
  await assert.rejects(vault.metadata(expiring.evidence_ref, profileId), /record_invalid|expired/);
});
