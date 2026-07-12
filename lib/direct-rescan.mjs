import { createHash } from "node:crypto";

import { scanProfileDigest } from "./live-scan.mjs";

const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_HANDLE = /^listing_[a-f0-9]{24}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const MAX_RESPONSE_BYTES = 1_000_000;
export const RIGHTOUT_DIRECT_SCAN_POLICY_VERSION = "2026-07-12";

function cleanInput(input) {
  if (!SAFE_PROFILE_ID.test(input?.profileId)) throw new Error("invalid_profile_ref");
  if (!SAFE_BROKER_ID.test(input?.brokerId)) throw new Error("invalid_broker_id");
  if (!SAFE_HANDLE.test(input?.listingHandle)) throw new Error("invalid_listing_handle");
  return { profileId: input.profileId, brokerId: input.brokerId, listingHandle: input.listingHandle };
}

function cleanList(values, pattern, max) {
  if (!Array.isArray(values) || values.length < 1 || values.length > max) throw new Error("rightout_direct_scan_attestation_required");
  const out = [...new Set(values)].sort();
  if (out.length !== values.length || !out.every((item) => typeof item === "string" && pattern.test(item))) {
    throw new Error("rightout_direct_scan_attestation_required");
  }
  return out;
}

function cleanDigests(value, profiles) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_direct_scan_attestation_required");
  const keys = Object.keys(value).sort();
  if (keys.length !== profiles.length || keys.some((key, i) => key !== profiles[i]) || keys.some((key) => !SAFE_SHA256.test(value[key]))) {
    throw new Error("rightout_direct_scan_attestation_required");
  }
  return Object.fromEntries(keys.map((key) => [key, value[key]]));
}

export function validateDirectScanInput(input) {
  return cleanInput(input);
}

export function validateDirectScanAttestations(input, value) {
  const clean = cleanInput(input);
  const allowed = new Set([
    "rightoutDirectScanPolicyAccepted", "rightoutDirectScanPolicyVersion", "subjectConsentReviewed",
    "publisherAccessAuthorized", "publisherTermsReviewed", "authorizedProfileIds", "authorizedProfileDigests",
    "authorizedBrokerIds",
  ]);
  if (
    !value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).some((key) => !allowed.has(key))
    || value.rightoutDirectScanPolicyAccepted !== true
    || value.rightoutDirectScanPolicyVersion !== RIGHTOUT_DIRECT_SCAN_POLICY_VERSION
    || value.subjectConsentReviewed !== true
    || value.publisherAccessAuthorized !== true
    || value.publisherTermsReviewed !== true
  ) throw new Error("rightout_direct_scan_attestation_required");
  const authorizedProfileIds = cleanList(value.authorizedProfileIds, SAFE_PROFILE_ID, 20);
  const authorizedProfileDigests = cleanDigests(value.authorizedProfileDigests, authorizedProfileIds);
  const authorizedBrokerIds = cleanList(value.authorizedBrokerIds, SAFE_BROKER_ID, 50);
  if (!authorizedProfileIds.includes(clean.profileId) || !authorizedBrokerIds.includes(clean.brokerId)) {
    throw new Error("rightout_direct_scan_attestation_required");
  }
  return {
    rightoutDirectScanPolicyAccepted: true,
    rightoutDirectScanPolicyVersion: RIGHTOUT_DIRECT_SCAN_POLICY_VERSION,
    subjectConsentReviewed: true,
    publisherAccessAuthorized: true,
    publisherTermsReviewed: true,
    authorizedProfileIds,
    authorizedProfileDigests,
    authorizedBrokerIds,
  };
}

export function resolveDirectScanCatalogEntry(catalog, input) {
  const clean = cleanInput(input);
  const broker = Array.isArray(catalog?.brokers) ? catalog.brokers.find((item) => item?.id === clean.brokerId) : undefined;
  if (
    !broker || broker.category !== "people_search" || broker.direct_rescan?.supported !== true
    || broker.direct_rescan.strategy !== "exact_encrypted_index_candidate_urls"
    || broker.direct_rescan.publisher_terms_gate !== "operator_attestation_required"
  ) throw new Error("unsupported_direct_rescan_lane");
  return { id: broker.id, name: String(broker.name).slice(0, 80), raw: broker };
}

export function directScanScopeBinding(input, attestations, broker) {
  const clean = cleanInput(input);
  return JSON.stringify(["direct-rescan", clean, attestations, broker.id]);
}

export function directScanApprovalDescription(input, broker) {
  const clean = cleanInput(input);
  return `P ${clean.profileId}; B ${broker.id}; H ${clean.listingHandle}. Decrypt exact known listing URL(s) only after allow-once; publisher terms reviewed. No form/email/write.`;
}

function normalizedText(value) {
  return String(value ?? "").normalize("NFKC").toLowerCase().replace(/[^a-z0-9@.+]+/g, " ").replace(/\s+/g, " ").trim();
}

function subjectSignals(profilePayload) {
  let value;
  try { value = JSON.parse(profilePayload); } catch { throw new Error("profile_invalid"); }
  const name = normalizedText(value.fullName);
  if (name.length < 3) throw new Error("profile_invalid");
  const corroborators = [];
  const locations = [
    [value.city, value.region].filter(Boolean).join(" "),
    ...(Array.isArray(value.priorLocations) ? value.priorLocations.map((item) => [item?.city, item?.region].filter(Boolean).join(" ")) : []),
  ];
  for (const item of locations) if (normalizedText(item).length >= 3) corroborators.push({ kind: "location", value: normalizedText(item) });
  for (const item of [value.contactEmail, ...(Array.isArray(value.emails) ? value.emails : [])]) {
    if (normalizedText(item).includes("@")) corroborators.push({ kind: "email", value: normalizedText(item) });
  }
  for (const item of [value.address, ...(Array.isArray(value.priorAddresses) ? value.priorAddresses : [])]) {
    if (normalizedText(item).length >= 6) corroborators.push({ kind: "address", value: normalizedText(item) });
  }
  for (const item of Array.isArray(value.phones) ? value.phones : []) {
    const digits = String(item).replace(/\D/g, "");
    if (digits.length >= 7) corroborators.push({ kind: "phone", value: digits });
  }
  if (!corroborators.length) throw new Error("direct_rescan_corroborator_required");
  return { name, corroborators };
}

async function boundedText(response, signal) {
  const declared = Number(response.headers.get("content-length") || "0");
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) throw new Error("response_too_large");
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      if (signal?.aborted) throw new Error("rightout_direct_scan_cancelled");
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) throw new Error("response_too_large");
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return new TextDecoder().decode(Buffer.concat(chunks.map((item) => Buffer.from(item))));
}

function pageMatch(html, signals) {
  const text = normalizedText(html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " "));
  if (/captcha|verify you are human|access denied|unusual traffic/.test(text)) return { blocked: true };
  if (!text.includes(signals.name)) return { matched: false };
  for (const item of signals.corroborators) {
    const haystack = item.kind === "phone" ? text.replace(/\D/g, "") : text;
    if (haystack.includes(item.value)) return { matched: true, corroborator: item.kind };
  }
  return { matched: false };
}

export async function runDirectRescan({ input, catalog, profilePayload, attestations, token, guardedFetch, signal }) {
  const clean = cleanInput(input);
  const broker = resolveDirectScanCatalogEntry(catalog, clean);
  const checkedAttestations = validateDirectScanAttestations(clean, attestations);
  if (scanProfileDigest(profilePayload) !== checkedAttestations.authorizedProfileDigests[clean.profileId]) {
    throw new Error("rightout_direct_scan_profile_snapshot_changed");
  }
  if (!token || token.profileId !== clean.profileId || token.brokerId !== clean.brokerId || !Array.isArray(token.urls)) {
    throw new Error("rightout_listing_handle_scope_mismatch");
  }
  const signals = subjectSignals(profilePayload);
  const observations = [];
  let matchedCorroborator;
  for (const url of token.urls) {
    if (signal?.aborted) throw new Error("rightout_direct_scan_cancelled");
    let request;
    try {
      request = await guardedFetch({
        url, allowedHosts: token.officialDomains, timeoutMs: 20_000, maxRedirects: 0, signal,
        init: { method: "GET", redirect: "manual", headers: { Accept: "text/html,application/xhtml+xml" } },
      });
      if ([404, 410].includes(request.response.status)) observations.push("absent");
      else if (request.response.status === 200) {
        const match = pageMatch(await boundedText(request.response, signal), signals);
        if (match.blocked) observations.push("blocked");
        else if (match.matched) { observations.push("present"); matchedCorroborator = match.corroborator; }
        else observations.push("ambiguous");
      } else observations.push("ambiguous");
    } catch (error) {
      if (signal?.aborted || (error instanceof Error && error.message === "rightout_direct_scan_cancelled")) throw new Error("rightout_direct_scan_cancelled");
      observations.push("error");
    } finally { await request?.release?.(); }
  }
  const observation = observations.includes("present")
    ? "direct_present"
    : observations.length > 0 && observations.every((item) => item === "absent")
      ? "direct_absent_known_listing_set"
      : "inconclusive";
  const proofReference = `direct_${createHash("sha256").update(JSON.stringify([clean.listingHandle, observation, new Date().toISOString()])).digest("hex").slice(0, 24)}`;
  return {
    report_version: 1,
    subject_ref: clean.profileId,
    broker_id: clean.brokerId,
    observation,
    known_listing_count: token.urls.length,
    checked_listing_count: observations.length,
    ...(matchedCorroborator ? { match_basis: `full_name_plus_${matchedCorroborator}` } : {}),
    proof_references: [proofReference],
    generated_at: new Date().toISOString(),
    removal_confirmation_scope: "known_listing_set_only",
    coverage_gap: "new_or_unindexed_listing_urls_not_checked",
    invariants: { raw_url_in_report: false, raw_page_content_in_report: false, raw_pii_in_report: false, provider_writes: 0 },
  };
}

export const __test = { normalizedText, pageMatch, subjectSignals, boundedText };
