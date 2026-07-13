import { imapTransportDigest, validateImapConfig } from "./imap.mjs";
import { parseRemovalProfile, removalProfileDigest } from "./removal.mjs";
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_VERIFY_HANDLE = /^verify_[a-f0-9]{24}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const SAFE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
export const RIGHTOUT_VERIFICATION_POLICY_VERSION = "2026-07-12";
function cleanProfileId(value) {
    if (typeof value !== "string" || !SAFE_PROFILE_ID.test(value))
        throw new Error("invalid_profile_ref");
    return value;
}
function cleanBrokerId(value) {
    if (typeof value !== "string" || !SAFE_BROKER_ID.test(value))
        throw new Error("invalid_broker_id");
    return value;
}
function cleanVerificationHandle(value) {
    if (typeof value !== "string" || !SAFE_VERIFY_HANDLE.test(value))
        throw new Error("invalid_verification_handle");
    return value;
}
function cleanStringArray(values, pattern, max = 20) {
    if (!Array.isArray(values) || values.length < 1 || values.length > max)
        throw new Error("rightout_verification_attestation_required");
    const out = [...new Set(values)];
    if (out.length !== values.length || !out.every((value) => typeof value === "string" && pattern.test(value))) {
        throw new Error("rightout_verification_attestation_required");
    }
    return out.sort();
}
function cleanProfileDigests(value, profileIds) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("rightout_verification_attestation_required");
    const keys = Object.keys(value).sort();
    if (keys.length !== profileIds.length || keys.some((key, index) => key !== profileIds[index]) || keys.some((key) => !SAFE_SHA256.test(value[key]))) {
        throw new Error("rightout_verification_attestation_required");
    }
    return Object.fromEntries(keys.map((key) => [key, value[key]]));
}
function cleanDomains(values) {
    if (!Array.isArray(values) || values.length < 1 || values.length > 12)
        throw new Error("unsupported_verification_lane");
    const out = [...new Set(values)];
    if (out.length !== values.length || !out.every((value) => typeof value === "string" && SAFE_DOMAIN.test(value))) {
        throw new Error("unsupported_verification_lane");
    }
    return out.sort();
}
export function validateVerificationPollInput(input) {
    if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((key) => !["profileId", "brokerId"].includes(key))) {
        throw new Error("invalid_verification_input");
    }
    return { profileId: cleanProfileId(input?.profileId), brokerId: cleanBrokerId(input?.brokerId) };
}
export function validateVerificationOpenInput(input) {
    if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((key) => !["profileId", "brokerId", "verificationHandle"].includes(key))) {
        throw new Error("invalid_verification_input");
    }
    return {
        profileId: cleanProfileId(input.profileId),
        brokerId: cleanBrokerId(input.brokerId),
        verificationHandle: cleanVerificationHandle(input.verificationHandle),
    };
}
export function resolveVerificationCatalogEntry(catalog, input) {
    const isOpen = Boolean(input && typeof input === "object" && "verificationHandle" in input);
    const publicInput = isOpen
        ? validateVerificationOpenInput(input)
        : validateVerificationPollInput(input);
    const broker = Array.isArray(catalog?.brokers) ? catalog.brokers.find((entry) => entry?.id === publicInput.brokerId) : undefined;
    if (!broker
        || broker.category !== "people_search"
        || broker.verification?.supported !== true
        || broker.verification.channel !== "imap"
        || !["approval_gated_https_get", "browser_same_profile_required", "human_only"].includes(broker.verification.open_link)
        || (isOpen && !["approval_gated_https_get", "browser_same_profile_required"].includes(broker.verification.open_link))) {
        throw new Error("unsupported_verification_lane");
    }
    return {
        id: broker.id,
        name: String(broker.name).slice(0, 80),
        senderDomains: cleanDomains(broker.verification.sender_domains),
        linkDomains: cleanDomains(broker.verification.link_domains),
        processingDays: Number.isInteger(broker.verification.processing_days) ? broker.verification.processing_days : 14,
        openLinkMode: broker.verification.open_link,
        raw: broker,
    };
}
export function validateVerificationAttestations(input, value) {
    const publicInput = validateVerificationPollInput({ profileId: input?.profileId, brokerId: input?.brokerId });
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("rightout_verification_attestation_required");
    const allowed = new Set([
        "rightoutVerificationPolicyAccepted", "rightoutVerificationPolicyVersion", "subjectConsentReviewed",
        "inboxReadAuthorized", "verificationLinkOpenAuthorized", "authorizedProfileIds", "authorizedProfileDigests",
        "authorizedBrokerIds", "imapTransportDigest",
    ]);
    if (Object.keys(value).some((key) => !allowed.has(key))
        || value.rightoutVerificationPolicyAccepted !== true
        || value.rightoutVerificationPolicyVersion !== RIGHTOUT_VERIFICATION_POLICY_VERSION
        || value.subjectConsentReviewed !== true
        || value.inboxReadAuthorized !== true
        || value.verificationLinkOpenAuthorized !== true
        || typeof value.imapTransportDigest !== "string"
        || !SAFE_SHA256.test(value.imapTransportDigest)) {
        throw new Error("rightout_verification_attestation_required");
    }
    const authorizedProfileIds = cleanStringArray(value.authorizedProfileIds, SAFE_PROFILE_ID);
    const authorizedProfileDigests = cleanProfileDigests(value.authorizedProfileDigests, authorizedProfileIds);
    const authorizedBrokerIds = cleanStringArray(value.authorizedBrokerIds, SAFE_BROKER_ID, 50);
    if (!authorizedProfileIds.includes(publicInput.profileId) || !authorizedBrokerIds.includes(publicInput.brokerId)) {
        throw new Error("rightout_verification_attestation_required");
    }
    return {
        rightoutVerificationPolicyAccepted: true,
        rightoutVerificationPolicyVersion: RIGHTOUT_VERIFICATION_POLICY_VERSION,
        subjectConsentReviewed: true,
        inboxReadAuthorized: true,
        verificationLinkOpenAuthorized: true,
        authorizedProfileIds,
        authorizedProfileDigests,
        authorizedBrokerIds,
        imapTransportDigest: value.imapTransportDigest,
    };
}
export function validateVerificationPreflight({ input, catalog, profilePayload, imapTransport, attestations }) {
    const publicInput = validateVerificationPollInput({ profileId: input?.profileId, brokerId: input?.brokerId });
    const broker = resolveVerificationCatalogEntry(catalog, publicInput);
    const cleanAttestations = validateVerificationAttestations(publicInput, attestations);
    const profile = parseRemovalProfile(profilePayload);
    if (removalProfileDigest(profilePayload) !== cleanAttestations.authorizedProfileDigests[publicInput.profileId]) {
        throw new Error("rightout_verification_snapshot_changed");
    }
    const imap = validateImapConfig(imapTransport, profile.contactEmail);
    if (imapTransportDigest(imap) !== cleanAttestations.imapTransportDigest)
        throw new Error("rightout_verification_snapshot_changed");
    return { input: publicInput, broker, profile, imap, attestations: cleanAttestations };
}
export function verificationPollApprovalDescription(input, broker) {
    const publicInput = validateVerificationPollInput(input);
    const label = broker?.name ?? publicInput.brokerId;
    const text = `P ${publicInput.profileId}; ${label}. Read up to 30 post-submission inbox messages, require aligned DKIM+recipient+time, return no mail content or PII.`;
    if (text.length > 256)
        throw new Error("approval_description_too_long");
    return text;
}
export function verificationOpenApprovalDescription(input, broker) {
    const publicInput = validateVerificationOpenInput(input);
    const domains = broker?.linkDomains;
    if (!Array.isArray(domains) || domains.length < 1)
        throw new Error("unsupported_verification_lane");
    const text = `P ${publicInput.profileId}; ${publicInput.brokerId}; ${publicInput.verificationHandle}. Open one stored HTTPS confirmation link on ${domains.join(",")}; external broker write.`;
    if (text.length > 256)
        throw new Error("approval_description_too_long");
    return text;
}
export function verificationPollScopeBinding(input, attestations, broker) {
    return JSON.stringify(["verification_poll", validateVerificationPollInput(input), attestations, broker.id, broker.senderDomains, broker.linkDomains]);
}
export function verificationOpenScopeBinding(input, attestations, broker) {
    const publicInput = validateVerificationOpenInput(input);
    return JSON.stringify(["verification_open", publicInput, attestations, broker.id, broker.linkDomains]);
}
