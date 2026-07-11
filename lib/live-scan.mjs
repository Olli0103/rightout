import { createHmac, randomBytes, randomUUID } from "node:crypto";

const BRAVE_ENDPOINT = "https://api.search.brave.com/res/v1/web/search";
const MAX_RESPONSE_BYTES = 750_000;
const SAFE_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;

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
  const allowedKeys = new Set(["fullName", "city", "region", "country"]);
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
  return { fullName, city, region, country };
}

function normalizeHost(value) {
  return value.trim().toLowerCase().replace(/^\.+|\.+$/g, "");
}

function hostAllowed(host, domains) {
  const normalized = normalizeHost(host);
  return domains.some((domain) => normalized === domain || normalized.endsWith(`.${domain}`));
}

function candidateUrls(payload, officialDomains, maxCandidates, candidatePathPattern) {
  const results = payload?.web?.results;
  if (!Array.isArray(results)) {
    return [];
  }
  const urls = [];
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
        || parsed.search
        || parsed.hash
        || !hostAllowed(parsed.hostname, officialDomains)
      ) {
        continue;
      }
      const pathPolicy = new RegExp(candidatePathPattern, "u");
      if (!pathPolicy.test(parsed.pathname)) {
        continue;
      }
      urls.push(parsed.toString());
    } catch {
      continue;
    }
    if (urls.length >= maxCandidates) {
      break;
    }
  }
  return [...new Set(urls)];
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

function normalizeIdentityText(value) {
  return typeof value === "string"
    ? value.trim().replace(/\s+/g, " ").toLocaleLowerCase("en-US")
    : "";
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function addressMatches(value, subject) {
  const city = normalizeIdentityText(subject.city);
  const region = normalizeIdentityText(subject.region);
  if (typeof value === "string") {
    const text = normalizeIdentityText(value);
    const gap = "[\\s,;|()\\-]{0,80}";
    const location = new RegExp(
      `(?:\\b${escapeRegExp(city)}\\b${gap}\\b${escapeRegExp(region)}\\b|\\b${escapeRegExp(region)}\\b${gap}\\b${escapeRegExp(city)}\\b)`,
      "u",
    );
    return location.test(text);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  return normalizeIdentityText(value.addressLocality) === city
    && normalizeIdentityText(value.addressRegion) === region;
}

function isPersonType(value) {
  return value === "Person" || (Array.isArray(value) && value.includes("Person"));
}

function personRecordMatches(value, subject) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !isPersonType(value["@type"])) {
    return false;
  }
  if (normalizeIdentityText(value.name) !== normalizeIdentityText(subject.fullName)) {
    return false;
  }
  const addresses = Array.isArray(value.address) ? value.address : [value.address];
  return addresses.some((address) => addressMatches(address, subject));
}

function jsonLdContainsMatchingPerson(value, subject, state = { nodes: 0 }, depth = 0) {
  if (depth > 20 || state.nodes++ > 2_000 || value === null || typeof value !== "object") {
    return false;
  }
  if (personRecordMatches(value, subject)) {
    return true;
  }
  const children = Array.isArray(value) ? value : Object.values(value);
  return children.some((child) => jsonLdContainsMatchingPerson(child, subject, state, depth + 1));
}

function directPageMatches(html, subject) {
  const scripts = html.matchAll(/<script\b[^>]*\btype\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi);
  for (const match of scripts) {
    let payload;
    try {
      payload = JSON.parse(match[1]);
    } catch {
      continue;
    }
    if (jsonLdContainsMatchingPerson(payload, subject)) {
      return true;
    }
  }
  return false;
}

function proofRef(brokerId, candidateUrl, scanSecret) {
  const digest = createHmac("sha256", scanSecret).update(`${brokerId}\u0000${candidateUrl}`).digest("hex").slice(0, 24);
  return `proof_${digest}`;
}

function safeFailureReason(error) {
  const code = error instanceof Error ? error.message : "unknown";
  const allowed = new Set([
    "provider_auth_failed",
    "provider_rate_limited",
    "provider_unavailable",
    "provider_response_invalid",
    "candidate_blocked",
    "candidate_unavailable",
    "candidate_response_invalid",
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

async function verifyCandidate(guardedFetch, candidateUrl, officialDomains, subject, signal) {
  throwIfAborted(signal);
  const request = await guardedFetch({
    url: candidateUrl,
    allowedHosts: officialDomains,
    timeoutMs: 12_000,
    maxRedirects: 2,
    signal,
    init: {
      method: "GET",
      headers: {
        Accept: "text/html,application/xhtml+xml",
        "Cache-Control": "no-store",
        "User-Agent": "RightOut/0.2 read-only approved privacy scan",
      },
      redirect: "follow",
    },
  });
  try {
    const finalHost = new URL(request.finalUrl).hostname;
    if (!hostAllowed(finalHost, officialDomains)) {
      throw new Error("candidate_blocked");
    }
    if (request.response.status === 401 || request.response.status === 403 || request.response.status === 429) {
      throw new Error("candidate_blocked");
    }
    if (request.response.status === 404 || request.response.status === 410) {
      return false;
    }
    if (!request.response.ok) {
      throw new Error("candidate_unavailable");
    }
    const contentType = request.response.headers.get("content-type") || "";
    if (!contentType.toLowerCase().includes("text/html")) {
      throw new Error("candidate_response_invalid");
    }
    return directPageMatches(await readBoundedText(request.response, MAX_RESPONSE_BYTES, signal), subject);
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
  const allowedKeys = new Set(["braveTermsAccepted", "authorizedProfileIds", "authorizedBrokerIds"]);
  if (
    Object.keys(value).some((key) => !allowedKeys.has(key))
    || value.braveTermsAccepted !== true
  ) {
    throw new Error("rightout_operator_attestation_required");
  }
  const authorizedProfileIds = cleanAuthorizedProfileIds(value.authorizedProfileIds);
  const authorizedBrokerIds = cleanAuthorizedBrokerIds(value.authorizedBrokerIds);
  if (
    !authorizedProfileIds.includes(publicInput.profileId)
    || publicInput.brokerIds.some((brokerId) => !authorizedBrokerIds.includes(brokerId))
  ) {
    throw new Error("rightout_operator_attestation_required");
  }
  return {
    braveTermsAccepted: true,
    authorizedProfileIds,
    authorizedBrokerIds,
  };
}

export function approvalDescription(input) {
  const validated = validatePublicToolInput(input);
  return `P ${validated.profileId}; B ${validated.brokerIds.join(",")}. Send name+city+region+country to Brave (logs <=90d unless ZDR). Fetch operator-attested pages; public permission unverified. RightOut: no writes/storage/email.`;
}

export async function runLiveScan({ input, catalog, apiKey, maxCandidatesPerBroker = 2, guardedFetch, signal, operatorAttestations }) {
  throwIfAborted(signal);
  const validated = validateLiveScanInput(input);
  validateOperatorAttestations(validated, operatorAttestations);
  const subject = validated.subject;
  if (typeof apiKey !== "string" || apiKey.length < 1) {
    throw new Error("missing_provider_secret");
  }
  const catalogEntries = Array.isArray(catalog?.brokers) ? catalog.brokers : [];
  const selected = validated.brokerIds.map((id) => catalogEntries.find((entry) => entry.id === id));
  if (selected.some((entry) => (
    !entry
    || entry.category !== "people_search"
    || entry.scan?.supported !== true
    || entry.scan?.automated_access_policy !== "operator_permission_required"
  ))) {
    throw new Error("unsupported_broker");
  }
  const candidateLimit = Math.min(Math.max(Number(maxCandidatesPerBroker) || 2, 1), 3);
  const results = [];
  const scanSecret = randomBytes(32);
  const scanId = `scan_${randomUUID().replaceAll("-", "")}`;
  try {
    for (const broker of selected) {
      throwIfAborted(signal);
      const officialDomains = broker.official_domains.map(normalizeHost);
      const query = `site:${officialDomains[0]} "${subject.fullName}" "${subject.city}" "${subject.region}"`;
      try {
        const payload = await guardedJsonPost(
          guardedFetch,
          BRAVE_ENDPOINT,
          { q: query, country: "US", search_lang: "en", safesearch: "strict", count: 10 },
          apiKey,
          signal,
        );
        const brokerCandidateLimit = Math.min(candidateLimit, Number(broker.scan.max_candidates) || 1);
        const candidates = candidateUrls(payload, officialDomains, brokerCandidateLimit, broker.scan.candidate_path_pattern);
        let foundRef = null;
        let verificationFailure = null;
        for (const candidate of candidates) {
          throwIfAborted(signal);
          try {
            if (await verifyCandidate(guardedFetch, candidate, officialDomains, subject, signal)) {
              foundRef = proofRef(broker.id, candidate, scanSecret);
              break;
            }
          } catch (error) {
            throwIfAborted(signal);
            verificationFailure = safeFailureReason(error);
          }
        }
        if (foundRef) {
          results.push({ broker_id: broker.id, state: "found", proof_references: [foundRef], reason: "structured_person_record_match" });
        } else {
          results.push({
            broker_id: broker.id,
            state: "inconclusive",
            proof_references: [],
            reason: verificationFailure || (candidates.length ? "candidate_not_verified" : "no_index_candidates_not_proof_of_absence"),
          });
        }
      } catch (error) {
        throwIfAborted(signal);
        results.push({ broker_id: broker.id, state: "inconclusive", proof_references: [], reason: safeFailureReason(error) });
      }
    }
  } finally {
    scanSecret.fill(0);
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
      query_log_retention: "up_to_90_days_standard_plan_unless_applicable_zdr_agreement",
      raw_provider_results_included: false,
    },
    disclosures: {
      to_search_provider: ["full_name", "city", "region", "country"],
      to_broker_pages: ["query_free_candidate_profile_page_request"],
      values_in_report: false,
    },
    results,
    summary: {
      checked: results.length,
      found: results.filter((item) => item.state === "found").length,
      not_found: 0,
      inconclusive: results.filter((item) => item.state === "inconclusive").length,
      coverage_gaps: [
        "search_index_coverage_is_not_complete",
        "no_index_result_is_not_proof_of_absence",
        "anti_bot_or_login_pages_remain_inconclusive",
        "only_catalog_brokers_with_supported_live_scan_policy_are_checked",
      ],
    },
    invariants: {
      operator_attestations_checked: true,
      submissions: 0,
      emails: 0,
      provider_writes: 0,
      local_pii_storage: 0,
      raw_pii_in_report: false,
      raw_response_content_in_report: false,
      candidate_urls_in_report: false,
    },
  };
}

export const __test = {
  candidateUrls,
  directPageMatches,
  proofRef,
  readBoundedText,
  throwIfAborted,
};
