import { randomUUID } from "node:crypto";

import { parseRemovalProfile, removalProfileDigest } from "./removal.mjs";

const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,24}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const SAFE_JURISDICTION = /^(?:EU|EEA|[A-Z]{2}(?:-[A-Z0-9]{2,3})?)$/;
const SAFE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
export const RIGHTOUT_FORM_POLICY_VERSION = "2026-07-12";

function cleanInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("invalid_form_removal_input");
  if (Object.keys(input).some((key) => !["profileId", "brokerId", "requestKind"].includes(key))) throw new Error("invalid_form_removal_input");
  if (typeof input.profileId !== "string" || !SAFE_PROFILE_ID.test(input.profileId)) throw new Error("invalid_profile_ref");
  if (typeof input.brokerId !== "string" || !SAFE_BROKER_ID.test(input.brokerId)) throw new Error("invalid_broker_id");
  if (input.requestKind !== "delete_and_opt_out") throw new Error("invalid_request_kind");
  return { profileId: input.profileId, brokerId: input.brokerId, requestKind: "delete_and_opt_out" };
}

function cleanArray(values, pattern, max = 20, error = "unsupported_form_lane") {
  if (!Array.isArray(values) || values.length < 1 || values.length > max) throw new Error(error);
  const out = [...new Set(values)];
  if (out.length !== values.length || !out.every((value) => typeof value === "string" && pattern.test(value))) throw new Error(error);
  return out.sort();
}

function cleanSpec(value, expectedRoles) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("unsupported_form_lane");
  const allowed = new Set(["profile_field", "type", "roles", "name_contains"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error("unsupported_form_lane");
  const roles = cleanArray(value.roles, /^[a-z]{2,20}$/, 4);
  if (expectedRoles && roles.some((role) => !expectedRoles.has(role))) throw new Error("unsupported_form_lane");
  const nameContains = cleanArray(value.name_contains, /^[a-z0-9 _-]{2,40}$/, 6);
  return {
    ...(value.profile_field ? { profile_field: value.profile_field } : {}),
    ...(value.type ? { type: value.type } : {}),
    roles,
    name_contains: nameContains,
  };
}

function cleanRecipe(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("unsupported_form_lane");
  const allowed = new Set(["recipe_version", "fields", "checkboxes", "submit", "success_phrases", "captcha_policy"]);
  if (Object.keys(value).some((key) => !allowed.has(key)) || value.recipe_version !== 1 || value.captcha_policy !== "fail_closed_human_task") {
    throw new Error("unsupported_form_lane");
  }
  if (!Array.isArray(value.fields) || value.fields.length !== 1) throw new Error("unsupported_form_lane");
  const fields = value.fields.map((field) => cleanSpec(field, new Set(["textbox"]))).map((field) => {
    if (field.profile_field !== "contact_email" || field.type !== "text") throw new Error("unsupported_form_lane");
    return field;
  });
  if (!Array.isArray(value.checkboxes) || value.checkboxes.length !== 1) throw new Error("unsupported_form_lane");
  const checkboxes = value.checkboxes.map((item) => cleanSpec(item, new Set(["checkbox"])));
  const submit = cleanSpec(value.submit, new Set(["button"]));
  const successPhrases = cleanArray(value.success_phrases, /^[a-z0-9 ._-]{4,80}$/, 6);
  return { recipe_version: 1, fields, checkboxes, submit, success_phrases: successPhrases, captcha_policy: value.captcha_policy };
}

function cleanDomains(values) {
  return cleanArray(values, SAFE_DOMAIN, 8);
}

export function validateFormRemovalInput(input) {
  return cleanInput(input);
}

export function resolveFormCatalogEntry(catalog, input) {
  const publicInput = cleanInput(input);
  const broker = Array.isArray(catalog?.brokers) ? catalog.brokers.find((entry) => entry?.id === publicInput.brokerId) : undefined;
  const removal = broker?.removal;
  if (
    !broker || broker.category !== "people_search" || broker.lane !== "browser_form"
    || broker.approval_gate !== "send_request" || broker.human_only !== false
    || removal?.supported !== true || removal.channel !== "browser_form"
    || !Array.isArray(removal.request_kinds) || !removal.request_kinds.includes(publicInput.requestKind)
    || removal.confirmation_policy !== "verification_pending_until_email_confirmed"
    || removal.identity_verification !== "email_control_then_subject_selection"
    || removal.discovery_requirement !== "prior_discovery_required"
  ) throw new Error("unsupported_form_lane");
  const allowedDomains = cleanDomains(removal.allowed_form_domains);
  let formUrl;
  try { formUrl = new URL(removal.form_url); } catch { throw new Error("unsupported_form_lane"); }
  if (formUrl.protocol !== "https:" || formUrl.username || formUrl.password || formUrl.search || formUrl.hash || !allowedDomains.some((domain) => formUrl.hostname === domain || formUrl.hostname.endsWith(`.${domain}`))) {
    throw new Error("unsupported_form_lane");
  }
  const eligibleJurisdictions = cleanArray(removal.eligible_jurisdictions, SAFE_JURISDICTION, 12);
  if (JSON.stringify(removal.disclosure_fields) !== JSON.stringify(["contact_email"])) throw new Error("unsupported_form_lane");
  return {
    id: broker.id,
    name: String(broker.name).slice(0, 80),
    formUrl: formUrl.toString(),
    allowedDomains,
    disclosureFields: ["contact_email"],
    eligibleJurisdictions,
    discoveryRequirement: "prior_discovery_required",
    recipe: cleanRecipe(removal.form_recipe),
  };
}

export function validateFormAttestations(input, value) {
  const publicInput = cleanInput(input);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_form_attestation_required");
  const allowed = new Set([
    "rightoutFormPolicyAccepted", "rightoutFormPolicyVersion", "subjectConsentReviewed",
    "browserFormAuthorized", "minimumDisclosureAccepted", "authorizedProfileIds",
    "authorizedProfileDigests", "authorizedBrokerIds",
  ]);
  if (
    Object.keys(value).some((key) => !allowed.has(key))
    || value.rightoutFormPolicyAccepted !== true
    || value.rightoutFormPolicyVersion !== RIGHTOUT_FORM_POLICY_VERSION
    || value.subjectConsentReviewed !== true
    || value.browserFormAuthorized !== true
    || value.minimumDisclosureAccepted !== true
  ) throw new Error("rightout_form_attestation_required");
  const profileIds = cleanArray(value.authorizedProfileIds, SAFE_PROFILE_ID, 20, "rightout_form_attestation_required");
  const brokerIds = cleanArray(value.authorizedBrokerIds, SAFE_BROKER_ID, 50, "rightout_form_attestation_required");
  if (!value.authorizedProfileDigests || typeof value.authorizedProfileDigests !== "object" || Array.isArray(value.authorizedProfileDigests)) {
    throw new Error("rightout_form_attestation_required");
  }
  const keys = Object.keys(value.authorizedProfileDigests).sort();
  if (keys.length !== profileIds.length || keys.some((key, index) => key !== profileIds[index]) || keys.some((key) => !SAFE_SHA256.test(value.authorizedProfileDigests[key]))) {
    throw new Error("rightout_form_attestation_required");
  }
  if (!profileIds.includes(publicInput.profileId) || !brokerIds.includes(publicInput.brokerId)) throw new Error("rightout_form_attestation_required");
  return {
    rightoutFormPolicyAccepted: true,
    rightoutFormPolicyVersion: RIGHTOUT_FORM_POLICY_VERSION,
    subjectConsentReviewed: true,
    browserFormAuthorized: true,
    minimumDisclosureAccepted: true,
    authorizedProfileIds: profileIds,
    authorizedProfileDigests: Object.fromEntries(keys.map((key) => [key, value.authorizedProfileDigests[key]])),
    authorizedBrokerIds: brokerIds,
  };
}

export function validateFormPreflight({ input, catalog, profilePayload, attestations }) {
  const publicInput = cleanInput(input);
  const broker = resolveFormCatalogEntry(catalog, publicInput);
  const cleanAttestations = validateFormAttestations(publicInput, attestations);
  const profile = parseRemovalProfile(profilePayload);
  if (removalProfileDigest(profilePayload) !== cleanAttestations.authorizedProfileDigests[publicInput.profileId]) throw new Error("rightout_form_snapshot_changed");
  if (!broker.eligibleJurisdictions.some((jurisdiction) => profile.jurisdictions.includes(jurisdiction))) throw new Error("profile_not_eligible_for_form_lane");
  return { input: publicInput, broker, profile, attestations: cleanAttestations };
}

export function formApprovalDescription(input, broker) {
  const publicInput = cleanInput(input);
  const cleanBroker = broker ?? { name: publicInput.brokerId, disclosureFields: ["contact_email"], allowedDomains: [] };
  const text = `P ${publicInput.profileId}; ${cleanBroker.name}. Fill ${cleanBroker.disclosureFields.join(",")} at ${cleanBroker.allowedDomains.join(",")}; accept site terms and submit suppression initiation. External write; CAPTCHA/ID fails closed.`;
  if (text.length > 256) throw new Error("approval_description_too_long");
  return text;
}

export function formScopeBinding(input, attestations, broker) {
  return JSON.stringify(["browser_form_removal", cleanInput(input), attestations, broker]);
}

export async function runFormRemoval({ input, catalog, profilePayload, attestations, bridgeUrl, submitForm, signal, now = () => new Date() }) {
  const preflight = validateFormPreflight({ input, catalog, profilePayload, attestations });
  if (typeof submitForm !== "function" || typeof bridgeUrl !== "string") throw new Error("rightout_browser_bridge_unavailable");
  const result = await submitForm({
    bridgeUrl,
    formUrl: preflight.broker.formUrl,
    recipe: preflight.broker.recipe,
    values: { contact_email: preflight.profile.contactEmail },
    signal,
  });
  if (result?.submitted !== true || typeof result.proof_reference !== "string") throw new Error("rightout_form_submission_unconfirmed");
  return {
    report_version: 1,
    removal_id: `removal_${randomUUID().replaceAll("-", "")}`,
    subject_ref: preflight.input.profileId,
    broker_id: preflight.input.brokerId,
    request_kind: preflight.input.requestKind,
    state: "verification_pending",
    generated_at: now().toISOString(),
    approval_boundary: "openclaw_plugin_permission_allow_once_separate_browser_form_tool",
    delivery: {
      channel: "openclaw_sandbox_browser_form",
      form_domain: preflight.broker.allowedDomains[0],
      form_submitted: true,
      removal_confirmed: false,
      next_state: "verification_pending",
    },
    disclosures: { to_broker: preflight.broker.disclosureFields, values_in_report: false, identity_documents: 0 },
    proof_references: [result.proof_reference],
    coverage_gaps: ["form_submission_initiates_suppression_flow", "email_verification_and_subject_selection_remain", "later_direct_rescan_required"],
    invariants: { subject_consent_checked: true, forms_submitted: 1, provider_writes: 1, captcha_bypasses: 0, raw_pii_in_report: false },
  };
}
