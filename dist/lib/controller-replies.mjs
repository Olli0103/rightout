import { imapTransportDigest, validateImapConfig } from "./imap.mjs";
import { parseRemovalProfile, removalMessageId, removalProfileDigest } from "./removal.mjs";
export const RIGHTOUT_CONTROLLER_REPLY_POLICY_VERSION = "2026-07-14-eu1";
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const SAFE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
function publicInput(value) {
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => !["profileId", "brokerId"].includes(key))) {
        throw new Error("rightout_controller_reply_input_invalid");
    }
    if (!SAFE_PROFILE_ID.test(value.profileId ?? "") || !SAFE_BROKER_ID.test(value.brokerId ?? "")) {
        throw new Error("rightout_controller_reply_input_invalid");
    }
    return { profileId: value.profileId, brokerId: value.brokerId };
}
function exactStrings(values, pattern, max) {
    if (!Array.isArray(values) || values.length < 1 || values.length > max || values.some((value) => typeof value !== "string" || !pattern.test(value))) {
        throw new Error("rightout_controller_reply_attestation_required");
    }
    const out = [...new Set(values)].sort();
    if (out.length !== values.length)
        throw new Error("rightout_controller_reply_attestation_required");
    return out;
}
export function validateControllerReplyAttestations(input, value) {
    const cleanInput = publicInput(input);
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("rightout_controller_reply_attestation_required");
    const allowed = new Set([
        "rightoutControllerReplyPolicyAccepted", "rightoutControllerReplyPolicyVersion", "subjectConsentReviewed",
        "inboxReadAuthorized", "authorizedProfileIds", "authorizedProfileDigests", "authorizedBrokerIds", "imapTransportDigest",
    ]);
    if (Object.keys(value).some((key) => !allowed.has(key))
        || value.rightoutControllerReplyPolicyAccepted !== true
        || value.rightoutControllerReplyPolicyVersion !== RIGHTOUT_CONTROLLER_REPLY_POLICY_VERSION
        || value.subjectConsentReviewed !== true || value.inboxReadAuthorized !== true
        || typeof value.imapTransportDigest !== "string" || !SAFE_SHA256.test(value.imapTransportDigest))
        throw new Error("rightout_controller_reply_attestation_required");
    const authorizedProfileIds = exactStrings(value.authorizedProfileIds, SAFE_PROFILE_ID, 100);
    const authorizedBrokerIds = exactStrings(value.authorizedBrokerIds, SAFE_BROKER_ID, 100);
    if (!value.authorizedProfileDigests || typeof value.authorizedProfileDigests !== "object" || Array.isArray(value.authorizedProfileDigests)) {
        throw new Error("rightout_controller_reply_attestation_required");
    }
    const digestKeys = Object.keys(value.authorizedProfileDigests).sort();
    if (digestKeys.length !== authorizedProfileIds.length
        || digestKeys.some((key, index) => key !== authorizedProfileIds[index] || !SAFE_SHA256.test(value.authorizedProfileDigests[key]))
        || !authorizedProfileIds.includes(cleanInput.profileId) || !authorizedBrokerIds.includes(cleanInput.brokerId))
        throw new Error("rightout_controller_reply_attestation_required");
    return {
        rightoutControllerReplyPolicyAccepted: true,
        rightoutControllerReplyPolicyVersion: RIGHTOUT_CONTROLLER_REPLY_POLICY_VERSION,
        subjectConsentReviewed: true,
        inboxReadAuthorized: true,
        authorizedProfileIds,
        authorizedProfileDigests: Object.fromEntries(digestKeys.map((key) => [key, value.authorizedProfileDigests[key]])),
        authorizedBrokerIds,
        imapTransportDigest: value.imapTransportDigest,
    };
}
function controllerBroker(catalog, brokerId) {
    const broker = Array.isArray(catalog?.brokers) ? catalog.brokers.find((row) => row?.id === brokerId) : undefined;
    if (!broker || broker.removal?.supported !== true || broker.removal?.channel !== "email"
        || broker.removal?.confirmation_policy !== "submitted_until_controller_response"
        || !["eu_controller_email_erasure", "us_data_broker_email_deletion"].includes(broker.process_class)
        || !Array.isArray(broker.official_domains) || broker.official_domains.length < 1 || broker.official_domains.length > 12
        || broker.official_domains.some((domain) => typeof domain !== "string" || !SAFE_DOMAIN.test(domain)))
        throw new Error("rightout_controller_reply_lane_unsupported");
    const requestKind = broker.process_class === "eu_controller_email_erasure" ? "gdpr_erasure_objection" : "delete_and_opt_out";
    return {
        id: broker.id,
        processClass: broker.process_class,
        processingDays: broker.removal.processing_days,
        officialDomains: [...new Set(broker.official_domains)].sort(),
        requestKind,
        raw: broker,
    };
}
export function validateControllerReplyPreflight({ input, catalog, profilePayload, imapTransport, attestations }) {
    const cleanInput = publicInput(input);
    const cleanAttestations = validateControllerReplyAttestations(cleanInput, attestations);
    const profile = parseRemovalProfile(profilePayload);
    if (removalProfileDigest(profilePayload) !== cleanAttestations.authorizedProfileDigests[cleanInput.profileId]) {
        throw new Error("rightout_controller_reply_snapshot_changed");
    }
    const imap = validateImapConfig(imapTransport, profile.contactEmail);
    if (imapTransportDigest(imap) !== cleanAttestations.imapTransportDigest)
        throw new Error("rightout_controller_reply_snapshot_changed");
    const broker = controllerBroker(catalog, cleanInput.brokerId);
    const expectedMessageId = removalMessageId({ ...cleanInput, requestKind: broker.requestKind }, profile, broker.raw);
    return { input: cleanInput, attestations: cleanAttestations, profile, imap, broker, expectedMessageId };
}
function responseSegment(value) {
    const text = typeof value === "string" ? value.slice(0, 100_000) : "";
    return text
        .split(/\n(?:on .{0,300}wrote:|from:|-----original message-----|_{5,})/iu, 1)[0]
        .split("\n").filter((line) => !line.trimStart().startsWith(">")).join("\n")
        .replace(/\s+/gu, " ").trim().toLowerCase();
}
const SIGNALS = Object.freeze([
    ["partial", /\b(?:some|certain|part of|einige|bestimmte)\b.{0,80}\b(?:cannot|can't|unable|retain|retained|keep|löschen|gelöscht|aufbewahren|erased?|deleted?)\b/iu],
    ["identity", /\b(?:need|require|provide|submit|benötigen|brauchen|senden)\b.{0,80}\b(?:verify your identity|identity verification|proof of identity|identität verifizieren|identitätsnachweis)\b/iu],
    ["rejected", /\b(?:cannot|can't|unable to|decline|deny|reject|abgelehnt|nicht bearbeiten|nicht erfüllen)\b.{0,80}\b(?:request|anfrage|antrag)\b/iu],
    ["confirmed", /\b(?:we have|has been|successfully|wurde|wurden)\b.{0,80}\b(?:erased|deleted|removed|completed|gelöscht|entfernt|abgeschlossen)\b/iu],
    ["processing", /\b(?:we have received|we received|receipt of|being processed|processing your|eingegangen|erhalten|wird bearbeitet)\b.{0,80}\b(?:request|anfrage|antrag)?\b/iu],
]);
const QUALIFIED_COMPLETION = /(?:\b(?:not|never|cannot|can't|unable|except|however|but|retain|retained|nicht|nie|kein(?:e|en|er|es)?|außer|jedoch|aber|aufbewahr(?:t|en))\b.{0,100}\b(?:erased|deleted|removed|completed|gelöscht|entfernt|abgeschlossen)\b)|(?:\b(?:erased|deleted|removed|completed|gelöscht|entfernt|abgeschlossen)\b.{0,100}\b(?:not|never|except|however|but|retain|retained|nicht|nie|kein(?:e|en|er|es)?|außer|jedoch|aber|aufbewahr(?:t|en))\b)/iu;
export function classifyControllerReply({ text, processClass }) {
    if (!["eu_controller_email_erasure", "us_data_broker_email_deletion"].includes(processClass))
        throw new Error("rightout_controller_reply_lane_unsupported");
    const segment = responseSegment(text);
    if (QUALIFIED_COMPLETION.test(segment)) {
        return { outcome_candidate: "needs_manual_check", confidence: "none", evidence_signals: ["qualified_or_negated_completion"], terminal: false };
    }
    const matched = SIGNALS.filter(([, pattern]) => pattern.test(segment)).map(([signal]) => signal);
    if (matched.length !== 1) {
        return { outcome_candidate: "needs_manual_check", confidence: "none", evidence_signals: matched.sort(), terminal: false };
    }
    const signal = matched[0];
    const outcome = signal === "partial"
        ? processClass === "eu_controller_email_erasure" ? "partial_erasure" : "partial_deletion"
        : signal === "confirmed"
            ? processClass === "eu_controller_email_erasure" ? "erasure_confirmed" : "deletion_confirmed"
            : signal === "identity" ? "identity_required"
                : signal === "rejected" ? "request_rejected"
                    : "processing_acknowledged";
    return {
        outcome_candidate: outcome,
        confidence: "high",
        evidence_signals: [`literal_${signal}_phrase`],
        terminal: ["erasure_confirmed", "deletion_confirmed", "partial_erasure", "partial_deletion", "request_rejected"].includes(outcome),
    };
}
export function controllerReplyScopeBinding(input, attestations, broker) {
    return JSON.stringify(["controller-reply-poll-v1", publicInput(input), attestations, {
            id: broker.id, processClass: broker.processClass, officialDomains: broker.officialDomains,
        }]);
}
export const __test = { responseSegment, QUALIFIED_COMPLETION };
