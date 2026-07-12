import { createHash, randomUUID } from "node:crypto";

const BRAVE_ENDPOINT = "https://api.search.brave.com/res/v1/web/search";
const MAX_RESPONSE_BYTES = 750_000;
const SAFE_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const BRAVE_TERMS_VERSION = "2026-02-11";
const SAFE_SHA256 = /^[a-f0-9]{64}$/;

function cleanInput(value, label, min, max) {
  if (typeof value !== "string") {
    throw new Error(`invalid_${label}`);
  }
  const clean = value.trim().replace(/\s+/g, " ");
  if (clean.length < min || clean.length > max || /[\u0000-\u001f\u007f]/.test(clean)) {
    throw new Error(`invalid_${label}`);
  }
  return clean;
}

function cleanScanConsent(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("subject_consent_required");
  const allowed = new Set(["authorized", "recordedAt", "scope"]);
  if (Object.keys(value).some((key) => !allowed.has(key)) || value.authorized !== true) {
    throw new Error("subject_consent_required");
  }
  const recordedAt = cleanInput(value.recordedAt, "consent", 20, 35);
  const timestamp = Date.parse(recordedAt);
  if (!Number.isFinite(timestamp) || timestamp > Date.now() + 300_000) throw new Error("subject_consent_required");
  if (!Array.isArray(value.scope) || value.scope.length < 1 || value.scope.length > 8) {
    throw new Error("subject_consent_required");
  }
  const scope = [...new Set(value.scope)];
  if (
    scope.length !== value.scope.length
    || !scope.every((item) => typeof item === "string" && /^[a-z_]{2,32}$/.test(item))
    || !scope.includes("scan")
  ) {
    throw new Error("subject_consent_required");
  }
  return { authorized: true, recordedAt: new Date(timestamp).toISOString(), scope: scope.sort() };
}

function cleanBrokerIds(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 2) {
    throw new Error("invalid_broker_ids");
  }
  const ids = [...new Set(values)];
  if (!ids.every((value) => typeof value === "string" && SAFE_ID.test(value))) {
    throw new Error("invalid_broker_ids");
  }
  return ids;
}

function cleanAuthorizedBrokerIds(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 20) {
    throw new Error("rightout_operator_attestation_required");
  }
  const ids = [...new Set(values)];
  if (ids.length !== values.length || !ids.every((value) => typeof value === "string" && SAFE_ID.test(value))) {
    throw new Error("rightout_operator_attestation_required");
  }
  return ids.sort();
}

function cleanAuthorizedProfileIds(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 20) {
    throw new Error("rightout_operator_attestation_required");
  }
  const ids = [...new Set(values)];
  if (ids.length !== values.length || !ids.every((value) => typeof value === "string" && SAFE_PROFILE_ID.test(value))) {
    throw new Error("rightout_operator_attestation_required");
  }
  return ids.sort();
}

function cleanProfileDigests(value, authorizedProfileIds) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("rightout_operator_attestation_required");
  }
  const keys = Object.keys(value).sort();
  if (
    keys.length !== authorizedProfileIds.length
    || keys.some((key, index) => key !== authorizedProfileIds[index])
    || keys.some((key) => typeof value[key] !== "string" || !SAFE_SHA256.test(value[key]))
  ) {
    throw new Error("rightout_operator_attestation_required");
  }
  return Object.fromEntries(keys.map((key) => [key, value[key]]));
}

function throwIfAborted(signal) {
  if (!signal?.aborted) {
    return;
  }
  const error = new Error("rightout_scan_cancelled");
  error.name = "AbortError";
  throw error;
}

function cleanProfileId(value) {
  if (typeof value !== "string" || !SAFE_PROFILE_ID.test(value)) {
    throw new Error("invalid_profile_ref");
  }
  return value;
}

function parseSubjectProfile(value) {
  if (typeof value !== "string" || value.length < 2 || value.length > 2_048) {
    throw new Error("profile_unavailable");
  }
  let profile;
  try {
    profile = JSON.parse(value);
  } catch {
    throw new Error("profile_invalid");
  }
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
    throw new Error("profile_invalid");
  }
  const allowedKeys = new Set(["fullName", "city", "region", "country", "contactEmail", "jurisdictions", "consent"]);
  if (Object.keys(profile).some((key) => !allowedKeys.has(key))) {
    throw new Error("profile_invalid");
  }
  const fullName = cleanInput(profile.fullName, "profile", 3, 120);
  const city = cleanInput(profile.city, "profile", 1, 80);
  const region = cleanInput(profile.region, "profile", 2, 40);
  const country = cleanInput(profile.country || "US", "profile", 2, 2).toUpperCase();
  if (country !== "US") {
    throw new Error("unsupported_country");
  }
  const consent = cleanScanConsent(profile.consent);
  return { fullName, city, region, country, consent };
}

function normalizedSubjectDigest(subject) {
  return createHash("sha256")
    .update(JSON.stringify([subject.fullName, subject.city, subject.region, subject.country, subject.consent]), "utf8")
    .digest("hex");
}

export function scanProfileDigest(profilePayload) {
  return normalizedSubjectDigest(parseSubjectProfile(profilePayload));
}

function normalizeHost(value) {
  return value.trim().toLowerCase().replace(/^\.+|\.+$/g, "");
}

function cleanOfficialDomains(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 5) {
    throw new Error("unsupported_broker");
  }
  const domains = [...new Set(values.map((value) => typeof value === "string" ? normalizeHost(value) : ""))];
  if (domains.length !== values.length || !domains.every((value) => SAFE_DOMAIN.test(value))) {
    throw new Error("unsupported_broker");
  }
  return domains;
}

function hostAllowed(host, domains) {
  const normalized = normalizeHost(host);
  return domains.some((domain) => normalized === domain || normalized.endsWith(`.${domain}`));
}

function hasIndexCandidate(payload, officialDomains) {
  const results = payload?.web?.results;
  if (!Array.isArray(results)) {
    return false;
  }
  for (const item of results) {
    if (typeof item?.url !== "string" || item.url.length > 2_048) {
      continue;
    }
    try {
      const parsed = new URL(item.url);
      if (
        parsed.protocol !== "https:"
        || parsed.username
        || parsed.password
        || !hostAllowed(parsed.hostname, officialDomains)
      ) {
        continue;
      }
      return true;
    } catch {
      continue;
    }
  }
  return false;
}

async function readBoundedText(response, maxBytes = MAX_RESPONSE_BYTES, signal) {
  throwIfAborted(signal);
  const length = Number(response.headers.get("content-length") || "0");
  if (Number.isFinite(length) && length > maxBytes) {
    throw new Error("response_too_large");
  }
  if (!response.body) {
    return "";
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      throwIfAborted(signal);
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maxBytes) {
        throw new Error("response_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(merged);
}

function safeFailureReason(error) {
  const code = error instanceof Error ? error.message : "unknown";
  const allowed = new Set([
    "provider_auth_failed",
    "provider_rate_limited",
    "provider_unavailable",
    "provider_response_invalid",
    "response_too_large",
  ]);
  return allowed.has(code) ? code : "network_or_policy_error";
}

async function guardedJsonPost(guardedFetch, url, body, apiKey, signal) {
  throwIfAborted(signal);
  const request = await guardedFetch({
    url,
    allowedHosts: ["api.search.brave.com"],
    timeoutMs: 15_000,
    maxRedirects: 0,
    signal,
    init: {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-Subscription-Token": apiKey,
      },
      body: JSON.stringify(body),
      redirect: "manual",
    },
  });
  try {
    if (request.response.status === 401 || request.response.status === 403) {
      throw new Error("provider_auth_failed");
    }
    if (request.response.status === 429) {
      throw new Error("provider_rate_limited");
    }
    if (!request.response.ok) {
      throw new Error("provider_unavailable");
    }
    const text = await readBoundedText(request.response, MAX_RESPONSE_BYTES, signal);
    try {
      return JSON.parse(text);
    } catch {
      throw new Error("provider_response_invalid");
    }
  } finally {
    await request.release();
  }
}

export function validatePublicToolInput(input) {
  return {
    profileId: cleanProfileId(input?.profileId),
    brokerIds: cleanBrokerIds(input?.brokerIds),
  };
}

export function validateLiveScanInput(input) {
  return {
    ...validatePublicToolInput(input),
    subject: parseSubjectProfile(input?.subject),
  };
}

export function validateOperatorAttestations(input, value) {
  const publicInput = validatePublicToolInput(input);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("rightout_operator_attestation_required");
  }
  const allowedKeys = new Set([
    "braveTermsAccepted",
    "braveTermsVersion",
    "braveCustomerResponsibilitiesAccepted",
    "subjectConsentReviewed",
    "authorizedProfileIds",
    "authorizedProfileDigests",
    "authorizedBrokerIds",
  ]);
  if (
    Object.keys(value).some((key) => !allowedKeys.has(key))
    || value.braveTermsAccepted !== true
    || value.braveTermsVersion !== BRAVE_TERMS_VERSION
    || value.braveCustomerResponsibilitiesAccepted !== true
    || value.subjectConsentReviewed !== true
  ) {
    throw new Error("rightout_operator_attestation_required");
  }
  const authorizedProfileIds = cleanAuthorizedProfileIds(value.authorizedProfileIds);
  const authorizedProfileDigests = cleanProfileDigests(value.authorizedProfileDigests, authorizedProfileIds);
  const authorizedBrokerIds = cleanAuthorizedBrokerIds(value.authorizedBrokerIds);
  if (
    !authorizedProfileIds.includes(publicInput.profileId)
    || publicInput.brokerIds.some((brokerId) => !authorizedBrokerIds.includes(brokerId))
  ) {
    throw new Error("rightout_operator_attestation_required");
  }
  return {
    braveTermsAccepted: true,
    braveTermsVersion: BRAVE_TERMS_VERSION,
    braveCustomerResponsibilitiesAccepted: true,
    subjectConsentReviewed: true,
    authorizedProfileIds,
    authorizedProfileDigests,
    authorizedBrokerIds,
  };
}

export function approvalDescription(input) {
  const validated = validatePublicToolInput(input);
  return `P ${validated.profileId}; B ${validated.brokerIds.join(",")}. Brave index (terms ${BRAVE_TERMS_VERSION}; consent+duties attested; logs <=90d/ZDR). Sends name+city+region+country. No broker request/write/email or RightOut storage.`;
}

export async function runLiveScan({ input, catalog, apiKey, guardedFetch, signal, operatorAttestations }) {
  throwIfAborted(signal);
  const validated = validateLiveScanInput(input);
  const attestations = validateOperatorAttestations(validated, operatorAttestations);
  const subject = validated.subject;
  if (normalizedSubjectDigest(subject) !== attestations.authorizedProfileDigests[validated.profileId]) {
    throw new Error("rightout_scan_profile_snapshot_changed");
  }
  if (typeof apiKey !== "string" || apiKey.length < 1) {
    throw new Error("missing_provider_secret");
  }
  const catalogEntries = Array.isArray(catalog?.brokers) ? catalog.brokers : [];
  const selected = validated.brokerIds.map((id) => catalogEntries.find((entry) => entry.id === id));
  if (selected.some((entry) => (
    !entry
    || entry.category !== "people_search"
    || entry.scan?.supported !== true
    || entry.scan?.automated_access_policy !== "search_index_only_no_publisher_access"
  ))) {
    throw new Error("unsupported_broker");
  }
  const results = [];
  const scanId = `scan_${randomUUID().replaceAll("-", "")}`;
  for (const broker of selected) {
      throwIfAborted(signal);
      const officialDomains = cleanOfficialDomains(broker.official_domains);
      const query = `site:${officialDomains[0]} "${subject.fullName}" "${subject.city}" "${subject.region}"`;
      try {
        const payload = await guardedJsonPost(
          guardedFetch,
          BRAVE_ENDPOINT,
          { q: query, country: "US", search_lang: "en", safesearch: "strict", count: 10 },
          apiKey,
          signal,
        );
        if (hasIndexCandidate(payload, officialDomains)) {
          results.push({
            broker_id: broker.id,
            state: "indirect_exposure",
            proof_references: [],
            reason: "search_index_candidate_observed",
          });
        } else {
          results.push({
            broker_id: broker.id,
            state: "inconclusive",
            proof_references: [],
            reason: "no_index_candidates_not_proof_of_absence",
          });
        }
      } catch (error) {
        throwIfAborted(signal);
        results.push({ broker_id: broker.id, state: "inconclusive", proof_references: [], reason: safeFailureReason(error) });
      }
  }
  return {
    report_version: 3,
    scan_id: scanId,
    subject_ref: validated.profileId,
    mode: "approval_gated_live_scan",
    approval_boundary: "openclaw_plugin_permission_allow_once",
    generated_at: new Date().toISOString(),
    provider: {
      name: "Brave Search API",
      endpoint_host: "api.search.brave.com",
      query_transport: "POST body",
      terms_version: BRAVE_TERMS_VERSION,
      query_log_retention: "up_to_90_days_standard_plan_unless_applicable_zdr_agreement",
      raw_provider_results_included: false,
    },
    disclosures: {
      to_search_provider: ["full_name", "city", "region", "country"],
      to_broker_pages: [],
      values_in_report: false,
    },
    results,
    summary: {
      checked: results.length,
      found: 0,
      indirect_exposure: results.filter((item) => item.state === "indirect_exposure").length,
      not_found: 0,
      inconclusive: results.filter((item) => item.state === "inconclusive").length,
      coverage_gaps: [
        "search_index_coverage_is_not_complete",
        "no_index_result_is_not_proof_of_absence",
        "search_index_candidates_are_indirect_signals_not_identity_proof",
        "publisher_pages_are_never_fetched",
        "only_catalog_brokers_with_supported_live_scan_policy_are_checked",
      ],
    },
    invariants: {
      operator_attestations_checked: true,
      submissions: 0,
      emails: 0,
      provider_writes: 0,
      publisher_requests: 0,
      local_pii_storage: 0,
      search_result_storage: 0,
      raw_pii_in_report: false,
      raw_response_content_in_report: false,
      candidate_urls_in_report: false,
    },
  };
}

export const __test = {
  hasIndexCandidate,
  cleanOfficialDomains,
  readBoundedText,
  throwIfAborted,
};

export { BRAVE_TERMS_VERSION };
