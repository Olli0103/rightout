import assert from "node:assert/strict";
import test from "node:test";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

import { removalProfileDigest } from "../../lib/removal.mjs";
import {
  formApprovalDescription,
  formScopeBinding,
  resolveFormCatalogEntry,
  runFormRemoval,
  validateFormPreflight,
  validateFormRemovalInput,
} from "../../lib/form-removal.mjs";

const profileId = "profile_0123456789abcdef";
const input = { profileId, brokerId: "intelius", requestKind: "delete_and_opt_out" };
const profile = {
  fullName: "Avery Example", city: "Exampleville", region: "CA", country: "US",
  contactEmail: "avery@example.invalid", jurisdictions: ["US", "US-CA"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["scan", "broker_removal"] },
};
const payload = JSON.stringify(profile);
const browserScope = {
  browserBackendMode: "managed_openclaw",
  browserControlTransport: "openclaw_sandbox_browser_bridge",
  remoteCloudFallback: false,
  routingDigest: "d".repeat(64),
};
const catalog = { brokers: [{
  id: "intelius", name: "Intelius", category: "people_search", lane: "browser_form",
  approval_gate: "send_request", human_only: false,
  removal: {
    supported: true, channel: "browser_form", request_kinds: ["delete_and_opt_out"],
    form_url: "https://suppression.peopleconnect.us/", allowed_form_domains: ["peopleconnect.us"],
    disclosure_fields: ["contact_email"], eligible_jurisdictions: ["US"],
    identity_verification: "email_control_then_subject_selection",
    confirmation_policy: "verification_pending_until_email_confirmed",
    discovery_requirement: "prior_discovery_required",
    form_recipe: {
      recipe_version: 1,
      fields: [{ profile_field: "contact_email", type: "text", roles: ["textbox"], name_contains: ["email"] }],
      checkboxes: [{ roles: ["checkbox"], name_contains: ["agree", "terms"] }],
      submit: { roles: ["button"], name_contains: ["continue"] },
      success_phrases: ["check your email", "verification email"],
      captcha_policy: "fail_closed_human_task",
    },
  },
}] };
const attestations = {
  rightoutFormPolicyAccepted: true,
  rightoutFormPolicyVersion: "2026-07-12",
  subjectConsentReviewed: true,
  browserFormAuthorized: true,
  minimumDisclosureAccepted: true,
  authorizedProfileIds: [profileId],
  authorizedProfileDigests: { [profileId]: removalProfileDigest(payload) },
  authorizedBrokerIds: ["intelius"],
};

test("form public input is opaque and fixed-purpose", () => {
  assert.deepEqual(validateFormRemovalInput(input), input);
  assert.throws(() => validateFormRemovalInput({ ...input, profileId: "Avery Example" }), /invalid_profile_ref/);
  assert.throws(() => validateFormRemovalInput({ ...input, requestKind: "custom" }), /invalid_request_kind/);
});

test("catalog recipe is closed, domain-pinned, and minimum-disclosure", () => {
  const broker = resolveFormCatalogEntry(catalog, input);
  assert.equal(broker.formUrl, "https://suppression.peopleconnect.us/");
  assert.deepEqual(broker.disclosureFields, ["contact_email"]);
  const dangerous = structuredClone(catalog);
  dangerous.brokers[0].removal.form_recipe.fields[0].selector = "body *";
  assert.throws(() => resolveFormCatalogEntry(dangerous, input), /unsupported_form_lane/);
  const crossDomain = structuredClone(catalog);
  crossDomain.brokers[0].removal.form_url = "https://attacker.invalid/form";
  assert.throws(() => resolveFormCatalogEntry(crossDomain, input), /unsupported_form_lane/);
});

test("preflight binds consented profile snapshot and eligible jurisdiction", () => {
  assert.equal(validateFormPreflight({ input, catalog, profilePayload: payload, attestations }).profile.contactEmail, profile.contactEmail);
  assert.throws(() => validateFormPreflight({
    input, catalog, profilePayload: JSON.stringify({ ...profile, fullName: "Changed Example" }), attestations,
  }), /rightout_form_snapshot_changed/);
  const euPayload = JSON.stringify({ ...profile, country: "DE", region: "BE", jurisdictions: ["DE", "EU"] });
  const euAttestations = { ...attestations, authorizedProfileDigests: { [profileId]: removalProfileDigest(euPayload) } };
  assert.throws(() => validateFormPreflight({ input, catalog, profilePayload: euPayload, attestations: euAttestations }), /profile_not_eligible_for_form_lane/);
});

test("form approval is exact and PII-free", () => {
  const broker = resolveFormCatalogEntry(catalog, input);
  const text = formApprovalDescription(input, broker, browserScope);
  assert.match(text, /browser=managed\/sandbox/);
  assert.match(text, /embedded processors may receive requests/);
  assert.match(text, /CAPTCHA\/ID fail closed/);
  assert.doesNotMatch(text, /Avery|avery@example/);
  assert.ok(text.length <= 256);
  assert.notEqual(formScopeBinding(input, attestations, broker, browserScope), formScopeBinding({ ...input, brokerId: "otherbroker" }, attestations, broker, browserScope));
  assert.notEqual(formScopeBinding(input, attestations, broker, browserScope), formScopeBinding(input, attestations, broker, { ...browserScope, routingDigest: "e".repeat(64) }));
});

test("successful browser initiation is reported only as verification_pending", async () => {
  let received;
  const report = await runFormRemoval({
    input, catalog, profilePayload: payload, attestations, bridgeUrl: "http://127.0.0.1:3000/browser",
    browserBackend: "managed_openclaw", browserControlTransport: "openclaw_sandbox_browser_bridge",
    async submitForm(args) {
      received = args;
      return { submitted: true, proof_reference: "form_0123456789abcdef01234567" };
    },
    now: () => new Date("2026-07-12T12:00:00Z"),
  });
  assert.equal(received.values.contact_email, profile.contactEmail);
  assert.equal(report.state, "verification_pending");
  assert.equal(report.delivery.removal_confirmed, false);
  assert.equal(report.delivery.browser_backend, "managed_openclaw");
  assert.equal(report.delivery.browser_control_transport, "openclaw_sandbox_browser_bridge");
  assert.equal(report.delivery.subresource_egress_isolation, false);
  assert.equal(report.invariants.provider_writes, 1);
  assert.equal(JSON.stringify(report).includes(profile.contactEmail), false);
});

test("missing browser bridge and unconfirmed submission fail closed", async () => {
  await assert.rejects(runFormRemoval({ input, catalog, profilePayload: payload, attestations, browserBackend: "managed_openclaw", browserControlTransport: "openclaw_sandbox_browser_bridge", submitForm() {} }), /rightout_browser_bridge_unavailable/);
  await assert.rejects(runFormRemoval({
    input, catalog, profilePayload: payload, attestations, bridgeUrl: "http://127.0.0.1:3000",
    browserBackend: "managed_openclaw", browserControlTransport: "openclaw_sandbox_browser_bridge",
    async submitForm() { return { submitted: false }; },
  }), /rightout_form_submission_unconfirmed/);
});
