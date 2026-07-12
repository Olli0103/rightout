import { createHash, randomUUID } from "node:crypto";

const SAFE_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_EMAIL = /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i;
const SAFE_JURISDICTION = /^(?:EU|EEA|[A-Z]{2}(?:-[A-Z0-9]{2,3})?)$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const SAFE_PHONE = /^\+?[0-9][0-9 .()-]{5,30}$/;
const REQUEST_KINDS = new Set(["delete_and_opt_out"]);
const RIGHTOUT_REMOVAL_POLICY_VERSION = "2026-07-12";
const ALLOWED_SMTP_ENDPOINTS = new Map([
  ["smtp.gmail.com", new Map([[465, true], [587, false]])],
  ["smtp.mail.yahoo.com", new Map([[465, true], [587, false]])],
  ["smtp.mail.me.com", new Map([[587, false]])],
  ["smtp.fastmail.com", new Map([[465, true], [587, false]])],
]);

function cleanString(value, label, min, max) {
  if (typeof value !== "string") throw new Error(`invalid_${label}`);
  const clean = value.trim().replace(/\s+/g, " ");
  if (clean.length < min || clean.length > max || /[\u0000-\u001f\u007f]/.test(clean)) {
    throw new Error(`invalid_${label}`);
  }
  return clean;
}

function cleanSecret(value, label, min, max) {
  if (typeof value !== "string" || value.length < min || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`invalid_${label}`);
  }
  return value;
}

function cleanProfileId(value) {
  if (typeof value !== "string" || !SAFE_PROFILE_ID.test(value)) throw new Error("invalid_profile_ref");
  return value;
}

function cleanBrokerId(value) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) throw new Error("invalid_broker_id");
  return value;
}

function cleanRequestKind(value) {
  if (typeof value !== "string" || !REQUEST_KINDS.has(value)) throw new Error("invalid_request_kind");
  return value;
}

function cleanEmail(value, label = "email") {
  const clean = cleanString(value, label, 3, 254).toLowerCase();
  if (!SAFE_EMAIL.test(clean)) throw new Error(`invalid_${label}`);
  return clean;
}

function cleanJurisdictions(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 12) throw new Error("profile_invalid");
  const normalized = [...new Set(values.map((value) => typeof value === "string" ? value.trim().toUpperCase() : ""))];
  if (normalized.length !== values.length || !normalized.every((value) => SAFE_JURISDICTION.test(value))) {
    throw new Error("profile_invalid");
  }
  return normalized.sort();
}

function cleanConsent(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("subject_consent_required");
  const allowed = new Set(["authorized", "recordedAt", "scope"]);
  if (Object.keys(value).some((key) => !allowed.has(key)) || value.authorized !== true) {
    throw new Error("subject_consent_required");
  }
  const recordedAt = cleanString(value.recordedAt, "consent", 20, 35);
  const timestamp = Date.parse(recordedAt);
  if (!Number.isFinite(timestamp) || timestamp > Date.now() + 300_000) throw new Error("subject_consent_required");
  if (!Array.isArray(value.scope) || value.scope.length < 1 || value.scope.length > 8) {
    throw new Error("subject_consent_required");
  }
  const scope = [...new Set(value.scope)];
  if (scope.length !== value.scope.length || !scope.every((item) => typeof item === "string" && /^[a-z_]{2,32}$/.test(item))) {
    throw new Error("subject_consent_required");
  }
  if (!scope.includes("broker_removal")) throw new Error("subject_consent_required");
  return { authorized: true, recordedAt: new Date(timestamp).toISOString(), scope: scope.sort() };
}

export function validateRemovalPublicToolInput(input) {
  return {
    profileId: cleanProfileId(input?.profileId),
    brokerId: cleanBrokerId(input?.brokerId),
    requestKind: cleanRequestKind(input?.requestKind),
  };
}

export function parseRemovalProfile(value) {
  if (typeof value !== "string" || value.length < 2 || value.length > 4_096) throw new Error("profile_unavailable");
  let profile;
  try {
    profile = JSON.parse(value);
  } catch {
    throw new Error("profile_invalid");
  }
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) throw new Error("profile_invalid");
  const allowed = new Set(["fullName", "city", "region", "country", "contactEmail", "jurisdictions", "alsoKnownAs", "emails", "phones", "priorLocations", "currentAddress", "priorAddresses", "consent"]);
  if (Object.keys(profile).some((key) => !allowed.has(key))) throw new Error("profile_invalid");
  const fullName = cleanString(profile.fullName, "profile", 3, 120);
  const city = cleanString(profile.city, "profile", 1, 80);
  const region = cleanString(profile.region, "profile", 2, 40).toUpperCase();
  const country = cleanString(profile.country, "profile", 2, 2).toUpperCase();
  if (!/^[A-Z0-9][A-Z0-9 .'-]{1,39}$/.test(region) || !/^[A-Z]{2}$/.test(country)) throw new Error("profile_invalid");
  const contactEmail = cleanEmail(profile.contactEmail, "contact_email");
  const jurisdictions = cleanJurisdictions(profile.jurisdictions);
  const alsoKnownAs = cleanOptionalStrings(profile.alsoKnownAs, "alias", 2, 120, 5);
  const emails = cleanOptionalStrings(profile.emails, "email", 3, 254, 5).map((email) => cleanEmail(email));
  const phones = cleanOptionalStrings(profile.phones, "phone", 7, 32, 5);
  if (!phones.every((phone) => SAFE_PHONE.test(phone))) throw new Error("profile_invalid");
  const priorLocations = cleanPriorLocations(profile.priorLocations);
  const currentAddress = profile.currentAddress === undefined ? undefined : cleanAddress(profile.currentAddress);
  const priorAddresses = cleanPriorAddresses(profile.priorAddresses);
  const consent = cleanConsent(profile.consent);
  return {
    fullName,
    city,
    region,
    country,
    contactEmail,
    jurisdictions,
    ...(alsoKnownAs.length ? { alsoKnownAs } : {}),
    ...(emails.length ? { emails } : {}),
    ...(phones.length ? { phones } : {}),
    ...(priorLocations.length ? { priorLocations } : {}),
    ...(currentAddress ? { currentAddress } : {}),
    ...(priorAddresses.length ? { priorAddresses } : {}),
    consent,
  };
}

function cleanOptionalStrings(values, label, min, max, maxItems) {
  if (values === undefined) return [];
  if (!Array.isArray(values) || values.length > maxItems) throw new Error("profile_invalid");
  const cleaned = values.map((value) => cleanString(value, label, min, max));
  if (new Set(cleaned.map((value) => value.toLowerCase())).size !== cleaned.length) throw new Error("profile_invalid");
  return cleaned;
}

function cleanPriorLocations(values) {
  if (values === undefined) return [];
  if (!Array.isArray(values) || values.length > 5) throw new Error("profile_invalid");
  const out = values.map((location) => {
    if (!location || typeof location !== "object" || Array.isArray(location)) throw new Error("profile_invalid");
    if (Object.keys(location).some((key) => !["city", "region", "country"].includes(key))) throw new Error("profile_invalid");
    const city = cleanString(location.city, "prior_city", 1, 80);
    const region = cleanString(location.region, "prior_region", 2, 40).toUpperCase();
    const country = cleanString(location.country ?? "US", "prior_country", 2, 2).toUpperCase();
    if (!/^[A-Z]{2}$/.test(country)) throw new Error("profile_invalid");
    return { city, region, country };
  });
  if (new Set(out.map((value) => JSON.stringify(value))).size !== out.length) throw new Error("profile_invalid");
  return out;
}

function cleanAddress(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("profile_invalid");
  if (Object.keys(value).some((key) => !["line1", "line2", "city", "region", "postal", "country"].includes(key))) throw new Error("profile_invalid");
  const line1 = cleanString(value.line1, "address_line1", 3, 120);
  const line2 = value.line2 === undefined ? undefined : cleanString(value.line2, "address_line2", 1, 80);
  const city = cleanString(value.city, "address_city", 1, 80);
  const region = cleanString(value.region, "address_region", 2, 40).toUpperCase();
  const postal = cleanString(value.postal, "address_postal", 3, 16);
  const country = cleanString(value.country ?? "US", "address_country", 2, 2).toUpperCase();
  if (!/^[A-Z]{2}$/.test(country)) throw new Error("profile_invalid");
  return { line1, ...(line2 ? { line2 } : {}), city, region, postal, country };
}

function cleanPriorAddresses(values) {
  if (values === undefined) return [];
  if (!Array.isArray(values) || values.length > 5) throw new Error("profile_invalid");
  const out = values.map(cleanAddress);
  if (new Set(out.map((value) => JSON.stringify(value))).size !== out.length) throw new Error("profile_invalid");
  return out;
}

function cleanStringArray(values, label, pattern, maxItems = 20) {
  if (!Array.isArray(values) || values.length < 1 || values.length > maxItems) {
    throw new Error("rightout_removal_attestation_required");
  }
  const clean = [...new Set(values)];
  if (clean.length !== values.length || !clean.every((item) => typeof item === "string" && pattern.test(item))) {
    throw new Error("rightout_removal_attestation_required");
  }
  return clean.sort();
}

function cleanProfileDigests(value, authorizedProfileIds) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("rightout_removal_attestation_required");
  }
  const keys = Object.keys(value).sort();
  if (
    keys.length !== authorizedProfileIds.length
    || keys.some((key, index) => key !== authorizedProfileIds[index])
    || keys.some((key) => typeof value[key] !== "string" || !SAFE_SHA256.test(value[key]))
  ) {
    throw new Error("rightout_removal_attestation_required");
  }
  return Object.fromEntries(keys.map((key) => [key, value[key]]));
}

function normalizedProfileDigest(profile) {
  return createHash("sha256")
    .update(JSON.stringify([
      profile.fullName,
      profile.city,
      profile.region,
      profile.country,
      profile.contactEmail,
      profile.jurisdictions,
      profile.alsoKnownAs ?? [],
      profile.emails ?? [],
      profile.phones ?? [],
      profile.priorLocations ?? [],
      profile.currentAddress ?? null,
      profile.priorAddresses ?? [],
      profile.consent,
    ]), "utf8")
    .digest("hex");
}

export function removalProfileDigest(profilePayload) {
  return normalizedProfileDigest(parseRemovalProfile(profilePayload));
}

export function removalSmtpDigest(smtp) {
  return createHash("sha256")
    .update(JSON.stringify([smtp.host, smtp.port, smtp.secure, smtp.username, smtp.password, smtp.fromAddress]), "utf8")
    .digest("hex");
}

export function validateRemovalOperatorAttestations(input, value) {
  const publicInput = validateRemovalPublicToolInput(input);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("rightout_removal_attestation_required");
  }
  const allowed = new Set([
    "rightoutRemovalPolicyAccepted",
    "rightoutRemovalPolicyVersion",
    "subjectConsentReviewed",
    "smtpAccountAuthorized",
    "minimumDisclosureAccepted",
    "authorizedProfileIds",
    "authorizedProfileDigests",
    "authorizedBrokerIds",
    "authorizedRequestKinds",
    "smtpTransportDigest",
  ]);
  if (
    Object.keys(value).some((key) => !allowed.has(key))
    || value.rightoutRemovalPolicyAccepted !== true
    || value.rightoutRemovalPolicyVersion !== RIGHTOUT_REMOVAL_POLICY_VERSION
    || value.subjectConsentReviewed !== true
    || value.smtpAccountAuthorized !== true
    || value.minimumDisclosureAccepted !== true
  ) {
    throw new Error("rightout_removal_attestation_required");
  }
  const authorizedProfileIds = cleanStringArray(value.authorizedProfileIds, "profile", SAFE_PROFILE_ID);
  const authorizedProfileDigests = cleanProfileDigests(value.authorizedProfileDigests, authorizedProfileIds);
  const authorizedBrokerIds = cleanStringArray(value.authorizedBrokerIds, "broker", SAFE_ID, 50);
  const authorizedRequestKinds = cleanStringArray(value.authorizedRequestKinds, "request_kind", /^[a-z_]{2,32}$/, 4);
  if (typeof value.smtpTransportDigest !== "string" || !SAFE_SHA256.test(value.smtpTransportDigest)) {
    throw new Error("rightout_removal_attestation_required");
  }
  if (
    !authorizedProfileIds.includes(publicInput.profileId)
    || !authorizedBrokerIds.includes(publicInput.brokerId)
    || !authorizedRequestKinds.includes(publicInput.requestKind)
  ) {
    throw new Error("rightout_removal_attestation_required");
  }
  return {
    rightoutRemovalPolicyAccepted: true,
    rightoutRemovalPolicyVersion: RIGHTOUT_REMOVAL_POLICY_VERSION,
    subjectConsentReviewed: true,
    smtpAccountAuthorized: true,
    minimumDisclosureAccepted: true,
    authorizedProfileIds,
    authorizedProfileDigests,
    authorizedBrokerIds,
    authorizedRequestKinds,
    smtpTransportDigest: value.smtpTransportDigest,
  };
}

function cleanRemovalEntry(catalog, input) {
  const brokers = Array.isArray(catalog?.brokers) ? catalog.brokers : [];
  const broker = brokers.find((entry) => entry?.id === input.brokerId);
  const removal = broker?.removal;
  if (
    !broker
    || broker.category !== "people_search"
    || broker.lane !== "email"
    || broker.approval_gate !== "send_request"
    || broker.human_only !== false
    || removal?.supported !== true
    || removal.channel !== "email"
    || !Array.isArray(removal.request_kinds)
    || !removal.request_kinds.includes(input.requestKind)
    || removal.confirmation_policy !== "submitted_until_later_rescan"
    || removal.identity_verification !== "broker_may_request_follow_up"
  ) {
    throw new Error("unsupported_removal_lane");
  }
  const recipient = cleanEmail(removal.recipient, "recipient");
  const recipientDomain = recipient.split("@")[1];
  if (recipientDomain !== removal.smtp_recipient_domain) throw new Error("unsupported_removal_lane");
  const disclosureFields = cleanStringArray(removal.disclosure_fields, "field", /^[a-z_]{2,32}$/, 12);
  if (disclosureFields.join(",") !== ["contact_email", "country", "full_name", "region"].join(",")) {
    throw new Error("unsupported_removal_lane");
  }
  const eligibleJurisdictions = cleanStringArray(removal.eligible_jurisdictions, "jurisdiction", SAFE_JURISDICTION, 12);
  return {
    id: broker.id,
    name: cleanString(broker.name, "broker_name", 2, 80),
    recipient,
    disclosureFields,
    eligibleJurisdictions,
    policyRevision: cleanString(removal.policy_revision, "policy_revision", 8, 32),
    lastVerified: cleanString(removal.last_verified, "last_verified", 10, 10),
  };
}

export function resolveRemovalCatalogEntry(catalog, input) {
  return cleanRemovalEntry(catalog, validateRemovalPublicToolInput(input));
}

export function validateSmtpConfig(value, profile) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_smtp_not_configured");
  const allowed = new Set(["host", "port", "secure", "username", "password", "fromAddress"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error("rightout_smtp_not_configured");
  const host = cleanString(value.host, "smtp_host", 4, 253).toLowerCase();
  const port = value.port;
  const secure = value.secure;
  const endpoint = ALLOWED_SMTP_ENDPOINTS.get(host);
  if (!Number.isInteger(port) || !endpoint || endpoint.get(port) !== secure) throw new Error("rightout_smtp_not_configured");
  const username = cleanSecret(value.username, "smtp_username", 1, 254);
  const password = cleanSecret(value.password, "smtp_password", 1, 1_024);
  const fromAddress = cleanEmail(value.fromAddress, "from_address");
  if (fromAddress !== profile.contactEmail) throw new Error("rightout_smtp_identity_mismatch");
  return { host, port, secure, username, password, fromAddress };
}

function assertEligible(profile, broker) {
  if (
    broker.eligibleJurisdictions.includes("US-CA")
    && (
      profile.country !== "US"
      || profile.region !== "CA"
      || !profile.jurisdictions.includes("US")
      || !profile.jurisdictions.includes("US-CA")
    )
  ) {
    throw new Error("profile_not_eligible_for_removal_lane");
  }
  if (!broker.eligibleJurisdictions.some((jurisdiction) => profile.jurisdictions.includes(jurisdiction))) {
    throw new Error("profile_not_eligible_for_removal_lane");
  }
}

export function validateRemovalPreflight({ input, catalog, profilePayload, smtpConfig, operatorAttestations }) {
  const publicInput = validateRemovalPublicToolInput(input);
  const broker = cleanRemovalEntry(catalog, publicInput);
  const attestations = validateRemovalOperatorAttestations(publicInput, operatorAttestations);
  const profile = parseRemovalProfile(profilePayload);
  if (normalizedProfileDigest(profile) !== attestations.authorizedProfileDigests[publicInput.profileId]) {
    throw new Error("rightout_removal_snapshot_changed");
  }
  const smtp = validateSmtpConfig(smtpConfig, profile);
  if (removalSmtpDigest(smtp) !== attestations.smtpTransportDigest) {
    throw new Error("rightout_removal_snapshot_changed");
  }
  assertEligible(profile, broker);
  return { input: publicInput, profile, broker, attestations, smtp };
}

function renderRequest(profile, broker) {
  return {
    subject: "Privacy request: delete and opt out",
    text: [
      `Hello ${broker.name} Privacy Team,`,
      "",
      "I am requesting deletion of personal information associated with me and an opt-out from sale or sharing. Please use the following information only to identify and process this request:",
      "",
      `Name: ${profile.fullName}`,
      `Email: ${profile.contactEmail}`,
      `Region: ${profile.region}`,
      `Country: ${profile.country}`,
      "",
      "Please confirm receipt and tell me if additional identity verification is required.",
      "",
      "Regards,",
      profile.fullName,
    ].join("\n"),
  };
}

function throwIfAborted(signal) {
  if (!signal?.aborted) return;
  const error = new Error("rightout_removal_cancelled");
  error.name = "AbortError";
  throw error;
}

function deterministicMessageId(input, profile, broker) {
  const digest = createHash("sha256")
    .update(JSON.stringify([input.profileId, broker.id, input.requestKind, profile.consent.recordedAt]))
    .digest("hex")
    .slice(0, 32);
  return `<rightout.${digest}@local.invalid>`;
}

function acceptedAddresses(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => {
    if (typeof item === "string") return item.toLowerCase();
    if (item && typeof item === "object" && typeof item.address === "string") return item.address.toLowerCase();
    return "";
  });
}

export function removalApprovalDescription(input, broker) {
  const publicInput = validateRemovalPublicToolInput(input);
  const cleanBroker = broker ?? { name: publicInput.brokerId, recipient: "catalog-locked", disclosureFields: [] };
  const text = `P ${publicInput.profileId}; ${cleanBroker.name} -> ${cleanBroker.recipient}. Send 1 delete+opt-out email with ${cleanBroker.disclosureFields.join(",")}. External write; may require verification; no form/CAPTCHA.`;
  if (text.length > 256) throw new Error("approval_description_too_long");
  return text;
}

export function removalScopeBinding(input, attestations, broker) {
  const publicInput = validateRemovalPublicToolInput(input);
  return JSON.stringify(["removal", publicInput, attestations, broker]);
}

export async function runRemovalSubmission({
  input,
  catalog,
  profilePayload,
  smtpConfig,
  operatorAttestations,
  sendMail,
  signal,
  now = () => new Date(),
}) {
  throwIfAborted(signal);
  const {
    input: publicInput,
    profile,
    broker,
    attestations,
    smtp,
  } = validateRemovalPreflight({ input, catalog, profilePayload, smtpConfig, operatorAttestations });
  if (typeof sendMail !== "function") throw new Error("rightout_removal_transport_unavailable");
  const rendered = renderRequest(profile, broker);
  const messageId = deterministicMessageId(publicInput, profile, broker);
  throwIfAborted(signal);
  let receipt;
  try {
    receipt = await sendMail({
      transport: smtp,
      message: {
        from: smtp.fromAddress,
        to: broker.recipient,
        replyTo: smtp.fromAddress,
        subject: rendered.subject,
        text: rendered.text,
        messageId,
        headers: {
          "X-RightOut-Request-Kind": publicInput.requestKind,
          "X-RightOut-Policy": attestations.rightoutRemovalPolicyVersion,
        },
      },
      signal,
    });
  } catch (error) {
    if (error instanceof Error && error.message === "rightout_removal_cancelled_before_transport") {
      throwIfAborted(signal);
    }
    throw new Error("rightout_removal_transport_failed");
  }
  if (!acceptedAddresses(receipt?.accepted).includes(broker.recipient) || acceptedAddresses(receipt?.rejected).includes(broker.recipient)) {
    throw new Error("rightout_removal_not_accepted");
  }
  const proofReference = `smtp_${createHash("sha256").update(messageId).digest("hex").slice(0, 24)}`;
  return {
    report_version: 4,
    removal_id: `removal_${randomUUID().replaceAll("-", "")}`,
    subject_ref: publicInput.profileId,
    broker_id: broker.id,
    request_kind: publicInput.requestKind,
    state: "submitted",
    generated_at: now().toISOString(),
    approval_boundary: "openclaw_plugin_permission_allow_once_separate_removal_tool",
    delivery: {
      channel: "smtp_email",
      recipient: broker.recipient,
      smtp_host: smtp.host,
      accepted_by_outbound_smtp: true,
      broker_receipt_confirmed: false,
      removal_confirmed: false,
      next_state: "awaiting_verification_or_processing",
    },
    disclosures: {
      to_broker: broker.disclosureFields,
      values_in_report: false,
      attachments: 0,
      identity_documents: 0,
    },
    proof_references: [proofReference],
    coverage_gaps: [
      "smtp_acceptance_is_not_broker_receipt",
      "submission_is_not_removal_confirmation",
      "broker_may_request_additional_identity_verification",
      "later_read_only_rescan_required_before_confirmed_removed",
    ],
    invariants: {
      operator_attestations_checked: true,
      subject_consent_checked: true,
      emails: 1,
      submissions: 1,
      provider_writes: 1,
      forms_submitted: 0,
      captcha_bypasses: 0,
      raw_pii_in_report: false,
      raw_message_in_report: false,
      local_pii_storage: 0,
    },
  };
}

export const __test = {
  cleanEmail,
  renderRequest,
  deterministicMessageId,
  acceptedAddresses,
};

export { RIGHTOUT_REMOVAL_POLICY_VERSION };
