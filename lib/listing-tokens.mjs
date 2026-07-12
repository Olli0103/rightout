import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

const SAFE_HANDLE = /^listing_[a-f0-9]{24}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function encryptionKey(secret) {
  if (typeof secret !== "string" || secret.length < 32 || secret.length > 4_096) {
    throw new Error("rightout_listing_token_key_required");
  }
  return createHash("sha256").update(secret, "utf8").digest();
}

function cleanCandidate(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_listing_candidate");
  if (!SAFE_PROFILE_ID.test(value.profileId) || !SAFE_BROKER_ID.test(value.brokerId)) throw new Error("invalid_listing_candidate");
  if (!Array.isArray(value.officialDomains) || value.officialDomains.length < 1 || value.officialDomains.length > 5) {
    throw new Error("invalid_listing_candidate");
  }
  const officialDomains = [...new Set(value.officialDomains.map((item) => String(item).toLowerCase()))];
  if (officialDomains.length !== value.officialDomains.length || !officialDomains.every((item) => SAFE_DOMAIN.test(item))) {
    throw new Error("invalid_listing_candidate");
  }
  if (!Array.isArray(value.urls) || value.urls.length < 1 || value.urls.length > 10) throw new Error("invalid_listing_candidate");
  const urls = [...new Set(value.urls.map((item) => {
    const parsed = new URL(item);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password) throw new Error("invalid_listing_candidate");
    const host = parsed.hostname.toLowerCase();
    if (!officialDomains.some((domain) => host === domain || host.endsWith(`.${domain}`))) throw new Error("invalid_listing_candidate");
    return parsed.toString();
  }))];
  if (urls.length !== value.urls.length) throw new Error("invalid_listing_candidate");
  const observedAt = new Date(value.observedAt);
  if (!Number.isFinite(observedAt.valueOf())) throw new Error("invalid_listing_candidate");
  return { profileId: value.profileId, brokerId: value.brokerId, urls, officialDomains, observedAt: observedAt.toISOString() };
}

function aad(profileId, brokerId) {
  return Buffer.from(JSON.stringify(["rightout-listing-token-v1", profileId, brokerId]), "utf8");
}

export function createListingTokenVault(store, secret) {
  if (!store || typeof store.register !== "function" || typeof store.lookup !== "function") {
    throw new Error("rightout_listing_store_unavailable");
  }
  const key = encryptionKey(secret);

  async function storeCandidate(candidate) {
    const clean = cleanCandidate(candidate);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(aad(clean.profileId, clean.brokerId));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(clean), "utf8"), cipher.final()]);
    const handle = `listing_${randomBytes(12).toString("hex")}`;
    await store.register(handle, {
      schemaVersion: 1,
      profileId: clean.profileId,
      brokerId: clean.brokerId,
      iv: iv.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
    });
    return handle;
  }

  async function lookup(handle, profileId, brokerId) {
    if (!SAFE_HANDLE.test(handle) || !SAFE_PROFILE_ID.test(profileId) || !SAFE_BROKER_ID.test(brokerId)) {
      throw new Error("invalid_listing_handle");
    }
    const envelope = await store.lookup(handle);
    if (!envelope || envelope.schemaVersion !== 1 || envelope.profileId !== profileId || envelope.brokerId !== brokerId) {
      throw new Error("rightout_listing_handle_expired");
    }
    try {
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64url"));
      decipher.setAAD(aad(profileId, brokerId));
      decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
        decipher.final(),
      ]).toString("utf8");
      return cleanCandidate(JSON.parse(plaintext));
    } catch (error) {
      if (error instanceof Error && error.message === "invalid_listing_candidate") throw error;
      throw new Error("rightout_listing_token_decryption_failed");
    }
  }

  return { storeCandidate, lookup };
}

export const __test = { cleanCandidate, encryptionKey };
