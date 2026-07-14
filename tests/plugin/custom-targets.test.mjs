import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createCustomTargetVault } from "../../lib/custom-targets.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { canonicalRecipeJson, recipeDigest } from "../../lib/recipes.mjs";

const now = Date.parse("2026-07-14T12:00:00Z");
const profileId = "profile_0123456789abcdef";
const stateKey = "dummy-custom-target-key-with-more-than-32-characters";
const target = {
  profileId,
  actionUrl: "https://privacy.controller.example/remove",
  sourceUrl: "https://controller.example/privacy",
  officialDomain: "controller.example",
  method: "web_form",
};

function fixture() {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-custom-target-"));
  const store = createEncryptedFileKeyedStore({
    stateDir, namespace: "rightout-custom-targets-v1", maxEntries: 500, getSecret: () => stateKey, now: () => now,
  });
  let sequence = 0;
  const vault = createCustomTargetVault(store, { now: () => now, randomHandle: () => `custom_${String(++sequence).padStart(24, "0")}` });
  return { stateDir, store, vault };
}

function signedPack() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const recipe = {
    schema_version: 1,
    recipe_id: "recipe_custombroker_v1",
    broker_id: "custombroker",
    method: "web_form",
    action_url: target.actionUrl,
    official_domains: [target.officialDomain],
    disclosure_fields: ["contact_email"],
    verification: "none",
    challenge_policy: "ordinary_browser",
    source_url: target.sourceUrl,
    source_status: "operator_verified_official_route",
    reviewed_at: "2026-07-14",
    expires_at: "2027-01-01",
    steps: [
      { id: "open_official_route", kind: "open", required_fields: [], success_markers: [] },
      { id: "fill_minimum_fields", kind: "fill", required_fields: ["contact_email"], success_markers: [] },
      { id: "submit_request", kind: "submit", required_fields: [], success_markers: ["submission_success_observed"] },
    ],
    source_contract_digest: createHash("sha256").update("synthetic-source-contract").digest("hex"),
  };
  const unsigned = {
    schema_version: 1, pack_id: "custom_target_test_v1", trust: "external_ed25519", key_id: "custom-test-key",
    issued_at: "2026-07-14T10:00:00Z", expires_at: "2027-01-01T00:00:00Z", recipes: [recipe],
  };
  return {
    recipe,
    pack: { ...unsigned, signature: sign(null, Buffer.from(canonicalRecipeJson(unsigned)), privateKey).toString("base64url") },
    trustedKeys: { "custom-test-key": publicKey.export({ type: "spki", format: "pem" }).toString() },
  };
}

test("custom intake stores target facts encrypted and returns only an opaque quarantine handle", async () => {
  const { stateDir, vault } = fixture();
  const result = await vault.intake(target);
  assert.deepEqual(result, {
    custom_target_handle: "custom_000000000000000000000001",
    subject_ref: profileId,
    state: "quarantined_unsigned",
    raw_target_in_report: false,
  });
  const metadata = await vault.metadata(result.custom_target_handle, profileId);
  assert.equal(metadata.state, "quarantined_unsigned");
  assert.equal("actionUrl" in metadata, false);
  const encrypted = readFileSync(join(stateDir, "rightout-plugin-state-v1", "rightout-custom-targets-v1.json.enc"), "utf8");
  assert.doesNotMatch(encrypted, /controller\.example|privacy|remove/);
  await assert.rejects(vault.metadata(result.custom_target_handle, "profile_ffffffffffffffff"), /scope_mismatch/);
});

test("custom intake rejects SSRF-shaped, Unicode-confusable, credential, and domain-confusion targets", async () => {
  const { vault } = fixture();
  for (const mutation of [
    { actionUrl: "http://controller.example/remove" },
    { actionUrl: "https://127.0.0.1/remove" },
    { actionUrl: "https://controller.example.attacker.invalid/remove" },
    { actionUrl: "https://user:pass@controller.example/remove" },
    { officialDomain: "xn--controller-9za.example", actionUrl: "https://xn--controller-9za.example/remove", sourceUrl: "https://xn--controller-9za.example/privacy" },
  ]) await assert.rejects(vault.intake({ ...target, ...mutation }), /custom_target_invalid/);
});

test("a custom target becomes internally resolvable only with an exact signed recipe and current permission", async () => {
  const { vault } = fixture();
  const intake = await vault.intake(target);
  const signed = signedPack();
  const permission = {
    schemaVersion: 1,
    customTargetHandle: intake.custom_target_handle,
    recipeDigest: recipeDigest(signed.recipe),
    authorizationReferenceSha256: "a".repeat(64),
    officialDomainsDigest: recipeDigest(signed.recipe.official_domains),
    reviewedAt: "2026-07-14T11:00:00Z",
    validUntil: "2026-12-31T00:00:00Z",
    allowedEffects: ["submit_form"],
  };
  const ready = await vault.resolveAuthorized(intake.custom_target_handle, profileId, {
    recipePacks: [signed.pack], trustedKeys: signed.trustedKeys, permission,
  });
  assert.equal(ready.metadata.state, "authorized_recipe_and_permission_bound");
  assert.equal(ready.recipe.action_url, target.actionUrl);
  assert.equal(ready.record.actionUrl, target.actionUrl);

  await assert.rejects(vault.resolveAuthorized(intake.custom_target_handle, profileId, {
    recipePacks: [{ ...signed.pack, pack_id: "tampered_pack" }], trustedKeys: signed.trustedKeys, permission,
  }), /signature_invalid/);
  await assert.rejects(vault.resolveAuthorized(intake.custom_target_handle, profileId, {
    recipePacks: [signed.pack], trustedKeys: signed.trustedKeys, permission: { ...permission, authorizationReferenceSha256: "bad" },
  }), /permission_required/);
  await assert.rejects(vault.resolveAuthorized(intake.custom_target_handle, "profile_ffffffffffffffff", {
    recipePacks: [signed.pack], trustedKeys: signed.trustedKeys, permission,
  }), /scope_mismatch/);
});
