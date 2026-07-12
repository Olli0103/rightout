import assert from "node:assert/strict";
import test from "node:test";

import { createListingTokenVault } from "../../lib/listing-tokens.mjs";

function storeFixture() {
  const values = new Map();
  return {
    values,
    async register(key, value) { values.set(key, structuredClone(value)); },
    async lookup(key) { return values.has(key) ? structuredClone(values.get(key)) : undefined; },
  };
}

const candidate = {
  profileId: "profile_a1b2c3d4e5f60718",
  brokerId: "truepeoplesearch",
  urls: ["https://www.truepeoplesearch.com/find/person/private-record"],
  officialDomains: ["truepeoplesearch.com"],
  observedAt: "2026-07-12T12:00:00.000Z",
};

test("listing URLs are encrypted at rest and recover only in exact scope", async () => {
  const store = storeFixture();
  const vault = createListingTokenVault(store, "dummy-encryption-key-with-more-than-32-characters");
  const handle = await vault.storeCandidate(candidate);
  assert.match(handle, /^listing_[a-f0-9]{24}$/);
  const serializedEnvelope = JSON.stringify(store.values.get(handle));
  assert.equal(serializedEnvelope.includes("private-record"), false);
  assert.equal(serializedEnvelope.includes("https://"), false);
  assert.deepEqual(await vault.lookup(handle, candidate.profileId, candidate.brokerId), candidate);
  await assert.rejects(vault.lookup(handle, candidate.profileId, "beenverified"), /expired/);
});

test("listing vault rejects weak keys and off-domain candidate URLs", async () => {
  assert.throws(() => createListingTokenVault(storeFixture(), "weak"), /key_required/);
  const vault = createListingTokenVault(storeFixture(), "dummy-encryption-key-with-more-than-32-characters");
  await assert.rejects(vault.storeCandidate({ ...candidate, urls: ["https://evil.invalid/person"] }), /invalid_listing_candidate/);
});
