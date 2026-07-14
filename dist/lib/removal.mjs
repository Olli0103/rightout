import { createHash, randomUUID, scryptSync } from "node:crypto";
import { ISO_COUNTRIES } from "./countries.mjs";
const SAFE_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_EMAIL = /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i;
const SAFE_JURISDICTION = /^(?:EU|EEA|[A-Z]{2}(?:-[A-Z0-9]{2,3})?)$/;
const MAX_CONSENT_DURATION_MS = 365 * 24 * 60 * 60_000;
const SAFE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const SAFE_PHONE = /^\+?[0-9][0-9 .()-]{5,30}$/;
const SAFE_MOBILE_ADVERTISING_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const REQUEST_KINDS = new Set(["delete_and_opt_out", "gdpr_erasure_objection"]);
const RIGHTOUT_REMOVAL_POLICY_VERSION = "2026-07-12-eu1";
const EU_EEA_COUNTRIES = new Set([
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE",
    "IS", "IT", "LV", "LI", "LT", "LU", "MT", "NL", "NO", "PL", "PT", "RO", "SK", "SI",
    "ES", "SE",
]);
const ALLOWED_SMTP_ENDPOINTS = new Map([
    ["smtp.gmail.com", new Map([[465, true], [587, false]])],
    ["smtp.mail.yahoo.com", new Map([[465, true], [587, false]])],
    ["smtp.mail.me.com", new Map([[587, false]])],
    ["smtp.fastmail.com", new Map([[465, true], [587, false]])],
]);
function cleanString(value, label, min, max) {
    if (typeof value !== "string")
        throw new Error(`invalid_${label}`);
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
    if (typeof value !== "string" || !SAFE_PROFILE_ID.test(value))
        throw new Error("invalid_profile_ref");
    return value;
}
function cleanBrokerId(value) {
    if (typeof value !== "string" || !SAFE_ID.test(value))
        throw new Error("invalid_broker_id");
    return value;
}
function cleanRequestKind(value) {
    if (typeof value !== "string" || !REQUEST_KINDS.has(value))
        throw new Error("invalid_request_kind");
    return value;
}
function cleanEmail(value, label = "email") {
    const clean = cleanString(value, label, 3, 254).toLowerCase();
    if (!SAFE_EMAIL.test(clean))
        throw new Error(`invalid_${label}`);
    return clean;
}
function cleanJurisdictions(values) {
    if (!Array.isArray(values) || values.length < 1 || values.length > 12)
        throw new Error("profile_invalid");
    const normalized = [...new Set(values.map((value) => typeof value === "string" ? value.trim().toUpperCase() : ""))];
    if (normalized.length !== values.length || !normalized.every((value) => SAFE_JURISDICTION.test(value))) {
        throw new Error("profile_invalid");
    }
    return normalized.sort();
}
function cleanConsent(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("subject_consent_required");
    const allowed = new Set(["authorized", "recordedAt", "validUntil", "scope", "method"]);
    if (Object.keys(value).some((key) => !allowed.has(key)) || value.authorized !== true) {
        throw new Error("subject_consent_required");
    }
    const recordedAt = cleanString(value.recordedAt, "consent", 20, 35);
    const timestamp = Date.parse(recordedAt);
    if (!Number.isFinite(timestamp) || timestamp > Date.now() + 300_000)
        throw new Error("subject_consent_required");
    const validUntil = cleanString(value.validUntil, "consent", 20, 35);
    const expiry = Date.parse(validUntil);
    if (!Number.isFinite(expiry) || expiry <= Date.now() || expiry <= timestamp || expiry - timestamp > MAX_CONSENT_DURATION_MS) {
        throw new Error("subject_consent_required");
    }
    if (!Array.isArray(value.scope) || value.scope.length < 1 || value.scope.length > 8) {
        throw new Error("subject_consent_required");
    }
    const scope = [...new Set(value.scope)];
    if (scope.length !== value.scope.length || !scope.every((item) => typeof item === "string" && /^[a-z_]{2,32}$/.test(item))) {
        throw new Error("subject_consent_required");
    }
    if (!scope.includes("broker_removal"))
        throw new Error("subject_consent_required");
    const method = value.method === undefined ? "self" : cleanString(value.method, "consent_method", 3, 24);
    if (!new Set(["self", "written_authorization", "poa"]).has(method))
        throw new Error("subject_consent_required");
    return { authorized: true, recordedAt: new Date(timestamp).toISOString(), validUntil: new Date(expiry).toISOString(), scope: scope.sort(), method };
}
export function validateRemovalPublicToolInput(input) {
    if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((key) => !["profileId", "brokerId", "requestKind"].includes(key))) {
        throw new Error("invalid_removal_input");
    }
    return {
        profileId: cleanProfileId(input?.profileId),
        brokerId: cleanBrokerId(input?.brokerId),
        requestKind: cleanRequestKind(input?.requestKind),
    };
}
export function parseRemovalProfile(value) {
    if (typeof value !== "string" || value.length < 2 || value.length > 4_096)
        throw new Error("profile_unavailable");
    let profile;
    try {
        profile = JSON.parse(value);
    }
    catch {
        throw new Error("profile_invalid");
    }
    if (!profile || typeof profile !== "object" || Array.isArray(profile))
        throw new Error("profile_invalid");
    const allowed = new Set(["fullName", "city", "region", "country", "contactEmail", "jurisdictions", "mobileAdvertisingId", "dateOfBirth", "alsoKnownAs", "emails", "phones", "priorLocations", "currentAddress", "priorAddresses", "consent"]);
    if (Object.keys(profile).some((key) => !allowed.has(key)))
        throw new Error("profile_invalid");
    const fullName = cleanString(profile.fullName, "profile", 3, 120);
    const city = cleanString(profile.city, "profile", 1, 80);
    const region = cleanString(profile.region, "profile", 2, 40).toUpperCase();
    const country = cleanString(profile.country, "profile", 2, 2).toUpperCase();
    if (!/^[A-Z0-9][A-Z0-9 .'-]{1,39}$/.test(region) || !ISO_COUNTRIES.has(country))
        throw new Error("profile_invalid");
    const contactEmail = cleanEmail(profile.contactEmail, "contact_email");
    const jurisdictions = cleanJurisdictions(profile.jurisdictions);
    const mobileAdvertisingId = profile.mobileAdvertisingId === undefined
        ? undefined
        : cleanString(profile.mobileAdvertisingId, "mobile_advertising_id", 36, 36).toLowerCase();
    if (mobileAdvertisingId !== undefined && !SAFE_MOBILE_ADVERTISING_ID.test(mobileAdvertisingId))
        throw new Error("profile_invalid");
    const dateOfBirth = profile.dateOfBirth === undefined ? undefined : cleanString(profile.dateOfBirth, "date_of_birth", 10, 10);
    if (dateOfBirth !== undefined) {
        const timestamp = Date.parse(`${dateOfBirth}T00:00:00Z`);
        if (!/^\d{4}-\d{2}-\d{2}$/.test(dateOfBirth) || !Number.isFinite(timestamp) || timestamp >= Date.now() || timestamp < Date.parse("1900-01-01T00:00:00Z")) {
            throw new Error("profile_invalid");
        }
    }
    const alsoKnownAs = cleanOptionalStrings(profile.alsoKnownAs, "alias", 2, 120, 5);
    const emails = cleanOptionalStrings(profile.emails, "email", 3, 254, 5).map((email) => cleanEmail(email));
    const phones = cleanOptionalStrings(profile.phones, "phone", 7, 32, 5);
    if (!phones.every((phone) => SAFE_PHONE.test(phone)))
        throw new Error("profile_invalid");
    const priorLocations = cleanPriorLocations(profile.priorLocations, country);
    const currentAddress = profile.currentAddress === undefined ? undefined : cleanAddress(profile.currentAddress, country);
    const priorAddresses = cleanPriorAddresses(profile.priorAddresses, country);
    const consent = cleanConsent(profile.consent);
    return {
        fullName,
        city,
        region,
        country,
        contactEmail,
        jurisdictions,
        ...(mobileAdvertisingId ? { mobileAdvertisingId } : {}),
        ...(dateOfBirth ? { dateOfBirth } : {}),
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
    if (values === undefined)
        return [];
    if (!Array.isArray(values) || values.length > maxItems)
        throw new Error("profile_invalid");
    const cleaned = values.map((value) => cleanString(value, label, min, max));
    if (new Set(cleaned.map((value) => value.toLowerCase())).size !== cleaned.length)
        throw new Error("profile_invalid");
    return cleaned;
}
function cleanPriorLocations(values, defaultCountry) {
    if (values === undefined)
        return [];
    if (!Array.isArray(values) || values.length > 5)
        throw new Error("profile_invalid");
    const out = values.map((location) => {
        if (!location || typeof location !== "object" || Array.isArray(location))
            throw new Error("profile_invalid");
        if (Object.keys(location).some((key) => !["city", "region", "country"].includes(key)))
            throw new Error("profile_invalid");
        const city = cleanString(location.city, "prior_city", 1, 80);
        const region = cleanString(location.region, "prior_region", 2, 40).toUpperCase();
        const country = cleanString(location.country ?? defaultCountry, "prior_country", 2, 2).toUpperCase();
        if (!ISO_COUNTRIES.has(country))
            throw new Error("profile_invalid");
        return { city, region, country };
    });
    if (new Set(out.map((value) => JSON.stringify(value))).size !== out.length)
        throw new Error("profile_invalid");
    return out;
}
function cleanAddress(value, defaultCountry) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("profile_invalid");
    if (Object.keys(value).some((key) => !["line1", "line2", "city", "region", "postal", "country"].includes(key)))
        throw new Error("profile_invalid");
    const line1 = cleanString(value.line1, "address_line1", 3, 120);
    const line2 = value.line2 === undefined ? undefined : cleanString(value.line2, "address_line2", 1, 80);
    const city = cleanString(value.city, "address_city", 1, 80);
    const region = cleanString(value.region, "address_region", 2, 40).toUpperCase();
    const postal = cleanString(value.postal, "address_postal", 3, 16);
    const country = cleanString(value.country ?? defaultCountry, "address_country", 2, 2).toUpperCase();
    if (!ISO_COUNTRIES.has(country))
        throw new Error("profile_invalid");
    return { line1, ...(line2 ? { line2 } : {}), city, region, postal, country };
}
function cleanPriorAddresses(values, defaultCountry) {
    if (values === undefined)
        return [];
    if (!Array.isArray(values) || values.length > 5)
        throw new Error("profile_invalid");
    const out = values.map((value) => cleanAddress(value, defaultCountry));
    if (new Set(out.map((value) => JSON.stringify(value))).size !== out.length)
        throw new Error("profile_invalid");
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
    if (keys.length !== authorizedProfileIds.length
        || keys.some((key, index) => key !== authorizedProfileIds[index])
        || keys.some((key) => typeof value[key] !== "string" || !SAFE_SHA256.test(value[key]))) {
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
        profile.mobileAdvertisingId ?? null,
        profile.dateOfBirth ?? null,
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
    const clean = validateSmtpConfig(smtp, { contactEmail: smtp?.fromAddress });
    if (clean.authMode === "oauth2") {
        const salt = JSON.stringify([
            "rightout-smtp-transport-oauth2-v1",
            clean.host,
            clean.port,
            clean.secure,
            clean.username,
            clean.fromAddress,
            clean.oauthExpiresAt,
        ]);
        return scryptSync(clean.oauthAccessToken, salt, 32).toString("hex");
    }
    const salt = JSON.stringify([
        "rightout-smtp-transport-v2",
        clean.host,
        clean.port,
        clean.secure,
        clean.username,
        clean.fromAddress,
    ]);
    return scryptSync(clean.password, salt, 32).toString("hex");
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
    if (Object.keys(value).some((key) => !allowed.has(key))
        || value.rightoutRemovalPolicyAccepted !== true
        || value.rightoutRemovalPolicyVersion !== RIGHTOUT_REMOVAL_POLICY_VERSION
        || value.subjectConsentReviewed !== true
        || value.smtpAccountAuthorized !== true
        || value.minimumDisclosureAccepted !== true) {
        throw new Error("rightout_removal_attestation_required");
    }
    const authorizedProfileIds = cleanStringArray(value.authorizedProfileIds, "profile", SAFE_PROFILE_ID);
    const authorizedProfileDigests = cleanProfileDigests(value.authorizedProfileDigests, authorizedProfileIds);
    const authorizedBrokerIds = cleanStringArray(value.authorizedBrokerIds, "broker", SAFE_ID, 50);
    const authorizedRequestKinds = cleanStringArray(value.authorizedRequestKinds, "request_kind", /^[a-z_]{2,32}$/, 4);
    if (typeof value.smtpTransportDigest !== "string" || !SAFE_SHA256.test(value.smtpTransportDigest)) {
        throw new Error("rightout_removal_attestation_required");
    }
    if (!authorizedProfileIds.includes(publicInput.profileId)
        || !authorizedBrokerIds.includes(publicInput.brokerId)
        || !authorizedRequestKinds.includes(publicInput.requestKind)) {
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
    if (!broker
        || !["people_search", "data_broker"].includes(broker.category)
        || broker.lane !== "email"
        || broker.approval_gate !== "send_request"
        || broker.human_only !== false
        || removal?.supported !== true
        || removal.channel !== "email"
        || !Array.isArray(removal.request_kinds)
        || !removal.request_kinds.includes(input.requestKind)
        || !["submitted_until_later_rescan", "submitted_until_controller_response"].includes(removal.confirmation_policy)
        || removal.identity_verification !== "broker_may_request_follow_up") {
        throw new Error("unsupported_removal_lane");
    }
    const recipient = cleanEmail(removal.recipient, "recipient");
    const recipientDomain = recipient.split("@")[1];
    if (recipientDomain !== removal.smtp_recipient_domain)
        throw new Error("unsupported_removal_lane");
    const officialDomains = cleanStringArray(broker.official_domains, "official_domain", SAFE_DOMAIN, 12);
    if (!officialDomains.some((domain) => recipientDomain === domain || recipientDomain.endsWith(`.${domain}`))) {
        throw new Error("unsupported_removal_lane");
    }
    const disclosureFields = cleanStringArray(removal.disclosure_fields, "field", /^[a-z_]{2,32}$/, 12);
    const allowedDisclosureSets = input.requestKind === "delete_and_opt_out"
        ? [["contact_email", "country", "full_name", "region"]]
        : [
            ["contact_email", "country"],
            ["contact_email", "country", "full_name"],
            ["contact_email", "country", "mobile_advertising_id"],
        ];
    if (!allowedDisclosureSets.some((fields) => disclosureFields.join(",") === fields.join(","))) {
        throw new Error("unsupported_removal_lane");
    }
    const templateId = cleanString(removal.template_id, "template_id", 8, 40);
    if ((input.requestKind === "delete_and_opt_out" && templateId !== "us_delete_opt_out_v1")
        || (input.requestKind === "gdpr_erasure_objection" && templateId !== "gdpr_erasure_objection_v1"))
        throw new Error("unsupported_removal_lane");
    const discoveryRequirement = cleanString(removal.discovery_requirement, "discovery_requirement", 8, 64);
    if (!["prior_discovery_required", "not_required_for_data_subject_request"].includes(discoveryRequirement)) {
        throw new Error("unsupported_removal_lane");
    }
    if ((broker.category === "people_search" && discoveryRequirement !== "prior_discovery_required")
        || (broker.category === "data_broker" && discoveryRequirement !== "not_required_for_data_subject_request"))
        throw new Error("unsupported_removal_lane");
    const isPeopleSearch = broker.category === "people_search";
    const isEuController = broker.category === "data_broker" && broker.process_class === "eu_controller_email_erasure";
    const isUsDataBroker = broker.category === "data_broker" && broker.process_class === "us_data_broker_email_deletion";
    if ((isPeopleSearch && (input.requestKind !== "delete_and_opt_out"
        || removal.confirmation_policy !== "submitted_until_later_rescan"
        || broker.process_class !== "us_people_search_removal"))
        || (isEuController && (input.requestKind !== "gdpr_erasure_objection"
            || removal.confirmation_policy !== "submitted_until_controller_response"))
        || (isUsDataBroker && (input.requestKind !== "delete_and_opt_out"
            || removal.confirmation_policy !== "submitted_until_controller_response"))
        || (!isPeopleSearch && !isEuController && !isUsDataBroker))
        throw new Error("unsupported_removal_lane");
    const processingDays = removal.processing_days;
    if (!Number.isInteger(processingDays)
        || (isPeopleSearch && processingDays !== 14)
        || (isEuController && processingDays !== 30)
        || (isUsDataBroker && processingDays !== 45))
        throw new Error("unsupported_removal_lane");
    const eligibleJurisdictions = cleanStringArray(removal.eligible_jurisdictions, "jurisdiction", SAFE_JURISDICTION, 12);
    if ((isPeopleSearch && eligibleJurisdictions.join(",") !== "US-CA")
        || (isEuController && eligibleJurisdictions.join(",") !== "EEA,EU")
        || (isUsDataBroker && eligibleJurisdictions.join(",") !== "US-CA"))
        throw new Error("unsupported_removal_lane");
    return {
        id: broker.id,
        name: cleanString(broker.name, "broker_name", 2, 80),
        recipient,
        disclosureFields,
        eligibleJurisdictions,
        requestKind: input.requestKind,
        templateId,
        discoveryRequirement,
        confirmationPolicy: removal.confirmation_policy,
        processClass: broker.process_class,
        processingDays,
        policyRevision: cleanString(removal.policy_revision, "policy_revision", 8, 32),
        lastVerified: cleanString(removal.last_verified, "last_verified", 10, 10),
    };
}
export function resolveRemovalCatalogEntry(catalog, input) {
    return cleanRemovalEntry(catalog, validateRemovalPublicToolInput(input));
}
export function validateSmtpConfig(value, profile) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("rightout_smtp_not_configured");
    const allowed = new Set(["host", "port", "secure", "username", "password", "fromAddress", "authMode", "oauthAccessToken", "oauthExpiresAt"]);
    if (Object.keys(value).some((key) => !allowed.has(key)))
        throw new Error("rightout_smtp_not_configured");
    const host = cleanString(value.host, "smtp_host", 4, 253).toLowerCase();
    const port = value.port;
    const secure = value.secure;
    const endpoint = ALLOWED_SMTP_ENDPOINTS.get(host);
    if (!Number.isInteger(port) || !endpoint || endpoint.get(port) !== secure)
        throw new Error("rightout_smtp_not_configured");
    const username = cleanSecret(value.username, "smtp_username", 1, 254);
    const fromAddress = cleanEmail(value.fromAddress, "from_address");
    if (fromAddress !== profile.contactEmail)
        throw new Error("rightout_smtp_identity_mismatch");
    const authMode = value.authMode ?? "password";
    if (authMode === "oauth2") {
        if (value.password !== undefined)
            throw new Error("rightout_smtp_not_configured");
        const oauthAccessToken = cleanSecret(value.oauthAccessToken, "smtp_oauth_access_token", 16, 8_192);
        const oauthExpiresAt = cleanOauthExpiry(value.oauthExpiresAt, "smtp");
        return { host, port, secure, username, authMode, oauthAccessToken, oauthExpiresAt, fromAddress };
    }
    if (authMode !== "password" || value.oauthAccessToken !== undefined || value.oauthExpiresAt !== undefined) {
        throw new Error("rightout_smtp_not_configured");
    }
    const password = cleanSecret(value.password, "smtp_password", 1, 1_024);
    if (value.authMode === "password")
        return { host, port, secure, username, authMode, password, fromAddress };
    return { host, port, secure, username, password, fromAddress };
}
function cleanOauthExpiry(value, protocol) {
    if (typeof value !== "string" || value.length < 20 || value.length > 35)
        throw new Error(`rightout_${protocol}_oauth_expired`);
    const expiresAt = Date.parse(value);
    const now = Date.now();
    if (!Number.isFinite(expiresAt) || expiresAt <= now + 60_000 || expiresAt > now + 24 * 60 * 60_000) {
        throw new Error(`rightout_${protocol}_oauth_expired`);
    }
    return new Date(expiresAt).toISOString();
}
function assertEligible(profile, broker) {
    if (broker.eligibleJurisdictions.includes("US-CA")
        && (profile.country !== "US"
            || profile.region !== "CA"
            || !profile.jurisdictions.includes("US")
            || !profile.jurisdictions.includes("US-CA"))) {
        throw new Error("profile_not_eligible_for_removal_lane");
    }
    if (broker.eligibleJurisdictions.some((jurisdiction) => jurisdiction === "EU" || jurisdiction === "EEA")
        && (!EU_EEA_COUNTRIES.has(profile.country)
            || !profile.jurisdictions.includes(profile.country)
            || !profile.jurisdictions.some((jurisdiction) => jurisdiction === "EU" || jurisdiction === "EEA"))) {
        throw new Error("profile_not_eligible_for_removal_lane");
    }
    if (!broker.eligibleJurisdictions.some((jurisdiction) => profile.jurisdictions.includes(jurisdiction))) {
        throw new Error("profile_not_eligible_for_removal_lane");
    }
    if (broker.disclosureFields.includes("mobile_advertising_id") && !profile.mobileAdvertisingId) {
        throw new Error("profile_missing_required_removal_identifier");
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
function disclosureLines(profile, broker) {
    const values = {
        full_name: ["Name", profile.fullName],
        contact_email: ["Email", profile.contactEmail],
        region: ["Region", profile.region],
        country: ["Country", profile.country],
        mobile_advertising_id: ["Mobile advertising ID", profile.mobileAdvertisingId],
    };
    return broker.disclosureFields.map((field) => {
        const [label, value] = values[field] ?? [];
        if (!label || !value)
            throw new Error("profile_missing_required_removal_identifier");
        return `${label}: ${value}`;
    });
}
function renderRequest(profile, broker) {
    const fields = disclosureLines(profile, broker);
    if (broker.templateId === "gdpr_erasure_objection_v1") {
        return {
            subject: "GDPR request: erasure and objection",
            text: [
                `Hello ${broker.name} Privacy Team,`,
                "",
                "I am exercising my data-protection rights. Where applicable, I request erasure of personal data concerning me under GDPR Article 17. I withdraw any consent under Article 7(3), and I object under Article 21(2) to processing for direct marketing, including related profiling.",
                "",
                "Please use only the following information to identify and process this request:",
                "",
                ...fields,
                "",
                "Please confirm receipt and the outcome. If any data cannot be erased, please state the applicable legal basis or exception. Where Article 19 applies, please notify recipients and tell me which recipients were notified.",
                "",
                "Regards,",
                broker.disclosureFields.includes("full_name") ? profile.fullName : "Data subject",
            ].join("\n"),
        };
    }
    return {
        subject: "Privacy request: delete and opt out",
        text: [
            `Hello ${broker.name} Privacy Team,`,
            "",
            "I am requesting deletion of personal information associated with me and an opt-out from sale or sharing. Please use the following information only to identify and process this request:",
            "",
            ...fields,
            "",
            "Please confirm receipt and tell me if additional identity verification is required.",
            "",
            "Regards,",
            profile.fullName,
        ].join("\n"),
    };
}
function throwIfAborted(signal) {
    if (!signal?.aborted)
        return;
    const error = new Error("rightout_removal_cancelled");
    error.name = "AbortError";
    throw error;
}
function deterministicMessageId(input, profile, broker) {
    const digest = createHash("sha256")
        .update(JSON.stringify([input.profileId, broker.id, input.requestKind, profile.consent.recordedAt, profile.consent.validUntil]))
        .digest("hex")
        .slice(0, 32);
    return `<rightout.${digest}@local.invalid>`;
}
export { deterministicMessageId as removalMessageId };
function acceptedAddresses(value) {
    if (!Array.isArray(value))
        return [];
    return value.map((item) => {
        if (typeof item === "string")
            return item.toLowerCase();
        if (item && typeof item === "object" && typeof item.address === "string")
            return item.address.toLowerCase();
        return "";
    });
}
export function removalApprovalDescription(input, broker) {
    const publicInput = validateRemovalPublicToolInput(input);
    const cleanBroker = broker ?? { name: publicInput.brokerId, recipient: "catalog-locked", disclosureFields: [] };
    const requestLabel = publicInput.requestKind === "gdpr_erasure_objection" ? "GDPR erasure+objection" : "delete+opt-out";
    const text = `P ${publicInput.profileId}; ${cleanBroker.name} -> ${cleanBroker.recipient}. Send 1 ${requestLabel} email with ${cleanBroker.disclosureFields.join(",")}. External write; may require verification; no form/CAPTCHA.`;
    if (text.length > 256)
        throw new Error("approval_description_too_long");
    return text;
}
export function removalScopeBinding(input, attestations, broker) {
    const publicInput = validateRemovalPublicToolInput(input);
    return JSON.stringify(["removal", publicInput, attestations, broker]);
}
export async function runRemovalSubmission({ input, catalog, profilePayload, smtpConfig, operatorAttestations, sendMail, signal, approvalBoundary = "assisted_allow_once", now = () => new Date(), }) {
    if (!["assisted_allow_once", "finite_campaign_grant"].includes(approvalBoundary))
        throw new Error("rightout_approval_boundary_invalid");
    throwIfAborted(signal);
    const { input: publicInput, profile, broker, attestations, smtp, } = validateRemovalPreflight({ input, catalog, profilePayload, smtpConfig, operatorAttestations });
    if (typeof sendMail !== "function")
        throw new Error("rightout_removal_transport_unavailable");
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
    }
    catch (error) {
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
        process_class: broker.processClass,
        discovery_requirement: broker.discoveryRequirement,
        state: "submitted",
        generated_at: now().toISOString(),
        approval_boundary: approvalBoundary,
        delivery: {
            channel: "smtp_email",
            recipient: broker.recipient,
            smtp_host: smtp.host,
            accepted_by_outbound_smtp: true,
            broker_receipt_confirmed: false,
            removal_confirmed: false,
            next_state: broker.confirmationPolicy === "submitted_until_controller_response"
                ? "awaiting_controller_response"
                : "awaiting_verification_or_processing",
        },
        disclosures: {
            to_broker: broker.disclosureFields,
            values_in_report: false,
            attachments: 0,
            identity_documents: 0,
        },
        proof_references: [proofReference],
        coverage_gaps: broker.processClass === "eu_controller_email_erasure"
            ? [
                "smtp_acceptance_is_not_controller_receipt",
                "submission_is_not_erasure_confirmation",
                "controller_may_request_proportionate_identity_verification",
                "controller_response_requires_human_review",
                "no_universal_eu_broker_erasure_registry",
            ]
            : broker.processClass === "us_data_broker_email_deletion"
                ? [
                    "smtp_acceptance_is_not_controller_receipt",
                    "submission_is_not_deletion_confirmation",
                    "controller_may_request_proportionate_identity_verification",
                    "controller_response_requires_human_review",
                    "california_drop_and_other_identifiers_not_checked",
                ]
                : [
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
