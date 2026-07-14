import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  assessRecipeSnapshot,
  buildBuiltinRecipes,
  canonicalRecipeJson,
  compileBuiltinRecipePack,
  recipeDigest,
  validateRecipe,
  verifyExternalRecipePack,
} from "../../lib/recipes.mjs";

const catalogPath = new URL("../../skills/data-broker-removal/references/brokers/unbroker-parity.json", import.meta.url);
const manifestPath = new URL("../../skills/data-broker-removal/references/brokers/recipe-pack.json", import.meta.url);
const catalogBytes = await readFile(catalogPath);
const catalog = JSON.parse(catalogBytes);
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const sourceSha256 = createHash("sha256").update(catalogBytes).digest("hex");
const now = Date.parse("2026-07-14T12:00:00Z");

function builtins() {
  return buildBuiltinRecipes(catalog, { expiresAt: manifest.expires_at });
}

function signedPack(overrides = {}) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const unsigned = {
    schema_version: 1,
    pack_id: "community_test_v1",
    trust: "external_ed25519",
    key_id: "publisher-test-key",
    issued_at: "2026-07-14T10:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    recipes: builtins().map((recipe) => ({ ...recipe, expires_at: "2027-01-01" })),
    ...overrides,
  };
  return {
    pack: {
      ...unsigned,
      signature: sign(null, Buffer.from(canonicalRecipeJson(unsigned)), privateKey).toString("base64url"),
    },
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

test("release-attested built-in recipe pack covers every broker exactly and verifies both digests", () => {
  const pack = compileBuiltinRecipePack(catalog, manifest, { sourceSha256, now });
  assert.equal(pack.recipes.length, 22);
  assert.equal(new Set(pack.recipes.map((recipe) => recipe.broker_id)).size, 22);
  assert.equal(pack.recipe_digest, manifest.compiled_recipes_sha256);
  assert.equal(recipeDigest(pack.recipes), manifest.compiled_recipes_sha256);
  assert.deepEqual(pack.recipes.map((recipe) => recipe.broker_id), catalog.brokers.map((row) => row.id).sort());
});

test("built-in manifest fails closed on source, compiled, path, expiry, or catalog duplication", () => {
  assert.throws(() => compileBuiltinRecipePack(catalog, manifest, { sourceSha256: "0".repeat(64), now }), /rightout_recipe_pack_invalid/);
  assert.throws(() => compileBuiltinRecipePack(catalog, { ...manifest, compiled_recipes_sha256: "0".repeat(64) }, { sourceSha256, now }), /integrity_failed/);
  assert.throws(() => compileBuiltinRecipePack(catalog, { ...manifest, source_path: "foreign.json" }, { sourceSha256, now }), /pack_invalid/);
  assert.throws(() => compileBuiltinRecipePack(catalog, manifest, { sourceSha256, now: Date.parse("2027-07-14T00:00:00Z") }), /pack_expired/);
  assert.throws(() => buildBuiltinRecipes({ brokers: [...catalog.brokers, catalog.brokers[0]] }), /catalog_invalid/);
});

test("external recipe packs require an exact trusted Ed25519 signature and bounded lifetime", () => {
  const { pack, publicKey } = signedPack();
  const verified = verifyExternalRecipePack(pack, { "publisher-test-key": publicKey }, { now });
  assert.equal(verified.recipes.length, 22);
  assert.equal(verified.key_id, "publisher-test-key");

  assert.throws(() => verifyExternalRecipePack({ ...pack, pack_id: "tampered_v1" }, { "publisher-test-key": publicKey }, { now }), /signature_invalid/);
  const other = signedPack();
  assert.throws(() => verifyExternalRecipePack(pack, { "publisher-test-key": other.publicKey }, { now }), /signature_invalid/);
  assert.throws(() => verifyExternalRecipePack(pack, { "publisher-test-key": publicKey }, { now: Date.parse("2027-01-01T00:00:00Z") }), /pack_expired/);
  const long = signedPack({ expires_at: "2028-07-14T10:00:00Z" });
  assert.throws(() => verifyExternalRecipePack(long.pack, { "publisher-test-key": long.publicKey }, { now }), /pack_expired/);

  const unsigned = { ...pack };
  delete unsigned.signature;
  for (const [type, options] of [
    ["ec", { namedCurve: "P-256" }],
    ["rsa", { modulusLength: 512 }],
  ]) {
    const foreign = generateKeyPairSync(type, options);
    const foreignPack = {
      ...unsigned,
      signature: sign(null, Buffer.from(canonicalRecipeJson(unsigned)), foreign.privateKey).toString("base64url"),
    };
    const foreignPublic = foreign.publicKey.export({ type: "spki", format: "pem" }).toString();
    assert.throws(() => verifyExternalRecipePack(foreignPack, { "publisher-test-key": foreignPublic }, { now }), /key_invalid/);
  }
});

test("recipe validation binds recipe identity, official domains, and fixed fields", () => {
  const recipe = builtins().find((item) => item.broker_id === "spokeo");
  assert.equal(validateRecipe(recipe).recipe_id, "recipe_spokeo_v1");
  assert.throws(() => validateRecipe({ ...recipe, recipe_id: "recipe_other_v1" }), /recipe_invalid/);
  assert.throws(() => validateRecipe({ ...recipe, action_url: "https://attacker.example/collect" }), /recipe_invalid/);
  assert.throws(() => validateRecipe({ ...recipe, disclosure_fields: [...recipe.disclosure_fields, "government_id"] }), /recipe_invalid/);
});

test("drift assessment quarantines foreign or semantically unknown pages without exposing raw content", () => {
  const recipe = builtins().find((item) => item.broker_id === "spokeo");
  const foreign = assessRecipeSnapshot(recipe, {
    raw_pii_in_snapshot: false, page_domain: "attacker.example", challenge: "none", refs: [], snapshot: "generic_form_content_redacted",
  });
  assert.deepEqual(foreign, { state: "quarantined", reason: "recipe_domain_drift", recipe_id: "recipe_spokeo_v1" });

  const semantic = assessRecipeSnapshot(recipe, {
    raw_pii_in_snapshot: false,
    page_domain: "www.spokeo.com",
    challenge: "none",
    refs: [{ ref: "x1", role: "link", name: "unrecognized navigation" }],
    snapshot: "generic_form_content_redacted",
  });
  assert.equal(semantic.state, "quarantined");
  assert.equal(semantic.reason, "recipe_semantic_drift");
  assert.doesNotMatch(JSON.stringify(semantic), /unrecognized navigation|attacker\.example/);
});

test("drift assessment allows expected redacted controls and gates sensitive or hard challenges", () => {
  const recipe = builtins().find((item) => item.broker_id === "spokeo");
  const compatible = assessRecipeSnapshot(recipe, {
    raw_pii_in_snapshot: false,
    page_domain: "www.spokeo.com",
    challenge: "none",
    refs: [
      { ref: "u1", role: "textbox", name: "listing url field" },
      { ref: "e1", role: "textbox", name: "email field" },
      { ref: "s1", role: "button", name: "submission action" },
    ],
    snapshot: "generic_form_content_redacted",
  });
  assert.equal(compatible.state, "compatible");
  assert.equal(compatible.observed_expected_field, true);
  assert.equal(compatible.observed_known_action, true);

  for (const input of [
    { challenge: "hard_human_gate", refs: [] },
    { challenge: "none", refs: [{ name: "credit card field" }] },
  ]) {
    const gated = assessRecipeSnapshot(recipe, {
      raw_pii_in_snapshot: false, page_domain: "spokeo.com", snapshot: "generic_form_content_redacted", ...input,
    });
    assert.equal(gated.state, "human_gate");
  }
});
