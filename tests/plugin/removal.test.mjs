import assert from "node:assert/strict";
import test from "node:test";
import { inspect } from "node:util";

import { scanProfileDigest } from "../../lib/live-scan.mjs";

import {
  __test,
  parseRemovalProfile,
  removalApprovalDescription,
  removalProfileDigest,
  removalSmtpDigest,
  runRemovalSubmission,
  validateRemovalOperatorAttestations,
  validateRemovalPublicToolInput,
  validateSmtpConfig,
} from "../../lib/removal.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const toolInput = { profileId, brokerId: "beenverified", requestKind: "delete_and_opt_out" };
const privateProfile = {
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  contactEmail: "avery@example.invalid",
  jurisdictions: ["US", "US-CA"],
  consent: {
    authorized: true,
    recordedAt: "2026-07-12T08:00:00.000Z",
    scope: ["scan", "broker_removal"],
  },
};
const smtpConfig = {
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  username: "smtp-user",
  password: "smtp-app-password",
  fromAddress: privateProfile.contactEmail,
};
const profilePayload = JSON.stringify(privateProfile);
const removalAttestations = {
  rightoutRemovalPolicyAccepted: true,
  rightoutRemovalPolicyVersion: "2026-07-12",
  subjectConsentReviewed: true,
  smtpAccountAuthorized: true,
  minimumDisclosureAccepted: true,
  authorizedProfileIds: [profileId],
  authorizedProfileDigests: { [profileId]: removalProfileDigest(profilePayload) },
  authorizedBrokerIds: ["beenverified"],
  authorizedRequestKinds: ["delete_and_opt_out"],
  smtpTransportDigest: removalSmtpDigest(smtpConfig),
};
const broker = {
  id: "beenverified",
  name: "BeenVerified",
  category: "people_search",
  lane: "email",
  approval_gate: "send_request",
  human_only: false,
  removal: {
    supported: true,
    channel: "email",
    request_kinds: ["delete_and_opt_out"],
    recipient: "privacy@beenverified.com",
    smtp_recipient_domain: "beenverified.com",
    disclosure_fields: ["full_name", "contact_email", "region", "country"],
    eligible_jurisdictions: ["US-CA"],
    identity_verification: "broker_may_request_follow_up",
    confirmation_policy: "submitted_until_later_rescan",
    policy_revision: "2025-10-21",
    last_verified: "2026-07-12",
  },
};
const catalog = { schema_version: 3, brokers: [broker] };

test("removal approval names the exact write without exposing PII values", () => {
  const text = removalApprovalDescription(toolInput, {
    name: broker.name,
    recipient: broker.removal.recipient,
    disclosureFields: [...broker.removal.disclosure_fields].sort(),
  });
  assert.match(text, /BeenVerified -> privacy@beenverified\.com/);
  assert.match(text, /External write/);
  assert.match(text, /no form\/CAPTCHA/);
  assert.doesNotMatch(text, /Avery|Exampleville|avery@example/);
  assert.ok(text.length <= 256, text);
});

test("public input is opaque and the private profile requires recorded removal consent", () => {
  assert.deepEqual(validateRemovalPublicToolInput(toolInput), toolInput);
  assert.throws(() => validateRemovalPublicToolInput({ ...toolInput, profileId: "Avery Example" }), /invalid_profile_ref/);
  assert.throws(() => validateRemovalPublicToolInput({ ...toolInput, brokerId: "../escape" }), /invalid_broker_id/);
  assert.throws(() => validateRemovalPublicToolInput({ ...toolInput, requestKind: "send_any_email" }), /invalid_request_kind/);

  const parsed = parseRemovalProfile(JSON.stringify(privateProfile));
  assert.equal(parsed.contactEmail, privateProfile.contactEmail);
  assert.ok(parsed.consent.scope.includes("broker_removal"));
  assert.throws(
    () => parseRemovalProfile(JSON.stringify({ ...privateProfile, consent: { ...privateProfile.consent, authorized: false } })),
    /subject_consent_required/,
  );
  assert.throws(
    () => parseRemovalProfile(JSON.stringify({ ...privateProfile, dateOfBirth: "2000-01-01" })),
    /profile_invalid/,
  );
});

test("SMTP is restricted to pinned TLS endpoints and the subject sender address", () => {
  const profile = parseRemovalProfile(JSON.stringify(privateProfile));
  assert.deepEqual(validateSmtpConfig(smtpConfig, profile), smtpConfig);
  assert.throws(() => validateSmtpConfig({ ...smtpConfig, host: "127.0.0.1" }, profile), /rightout_smtp_not_configured/);
  assert.throws(() => validateSmtpConfig({ ...smtpConfig, port: 25 }, profile), /rightout_smtp_not_configured/);
  assert.throws(() => validateSmtpConfig({ ...smtpConfig, secure: false }, profile), /rightout_smtp_not_configured/);
  assert.throws(() => validateSmtpConfig({ ...smtpConfig, fromAddress: "other@example.invalid" }, profile), /rightout_smtp_identity_mismatch/);
  assert.equal(validateSmtpConfig({ ...smtpConfig, password: " pass phrase " }, profile).password, " pass phrase ");
});

test("removal attestations bind exact subject, broker, request kind, and policy revision", () => {
  assert.equal(validateRemovalOperatorAttestations(toolInput, removalAttestations).rightoutRemovalPolicyAccepted, true);
  for (const value of [
    undefined,
    { ...removalAttestations, rightoutRemovalPolicyVersion: "2026-01-01" },
    { ...removalAttestations, subjectConsentReviewed: false },
    { ...removalAttestations, authorizedProfileIds: ["profile_ffffffffffffffff"] },
    { ...removalAttestations, authorizedProfileDigests: { [profileId]: "not-a-digest" } },
    { ...removalAttestations, authorizedBrokerIds: ["otherbroker"] },
    { ...removalAttestations, authorizedRequestKinds: ["other_request"] },
    { ...removalAttestations, smtpTransportDigest: "not-a-digest" },
  ]) {
    assert.throws(() => validateRemovalOperatorAttestations(toolInput, value), /rightout_removal_attestation_required/);
  }
});

test("one approved broker email is sent but reported only as submitted", async () => {
  const calls = [];
  const report = await runRemovalSubmission({
    input: toolInput,
    catalog,
    profilePayload,
    smtpConfig,
    operatorAttestations: removalAttestations,
    now: () => new Date("2026-07-12T09:00:00.000Z"),
    async sendMail(value) {
      calls.push(value);
      return { accepted: [broker.removal.recipient], rejected: [], messageId: value.message.messageId };
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].message.to, broker.removal.recipient);
  assert.equal(calls[0].message.from, privateProfile.contactEmail);
  assert.match(calls[0].message.text, /Avery Example/);
  assert.match(calls[0].message.text, /avery@example\.invalid/);
  assert.equal(report.state, "submitted");
  assert.equal(report.delivery.accepted_by_outbound_smtp, true);
  assert.equal(report.delivery.broker_receipt_confirmed, false);
  assert.equal(report.delivery.removal_confirmed, false);
  assert.deepEqual(report.invariants, {
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
  });
  const serialized = JSON.stringify(report);
  for (const secret of [privateProfile.fullName, privateProfile.contactEmail, smtpConfig.username, smtpConfig.password, calls[0].message.text]) {
    assert.equal(serialized.includes(secret), false, secret);
  }
});

test("jurisdiction, catalog, transport rejection, and pre-write abort fail closed", async () => {
  let calls = 0;
  const common = {
    input: toolInput,
    catalog,
    profilePayload,
    smtpConfig,
    operatorAttestations: removalAttestations,
    async sendMail() {
      calls += 1;
      return { accepted: [], rejected: [broker.removal.recipient] };
    },
  };
  await assert.rejects(runRemovalSubmission(common), /rightout_removal_not_accepted/);
  assert.equal(calls, 1);

  calls = 0;
  await assert.rejects(
    runRemovalSubmission({ ...common, catalog: { brokers: [{ ...broker, removal: { ...broker.removal, recipient: "attacker@example.invalid" } }] } }),
    /unsupported_removal_lane/,
  );
  assert.equal(calls, 0);

  await assert.rejects(
    runRemovalSubmission({ ...common, profilePayload: JSON.stringify({ ...privateProfile, jurisdictions: ["DE"] }) }),
    /rightout_removal_snapshot_changed/,
  );
  assert.equal(calls, 0);

  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(runRemovalSubmission({ ...common, signal: aborted.signal }), /rightout_removal_cancelled/);
  assert.equal(calls, 0);

  const uncertainAbort = new AbortController();
  await assert.rejects(
    runRemovalSubmission({
      ...common,
      signal: uncertainAbort.signal,
      async sendMail() {
        uncertainAbort.abort();
        throw new Error("connection_closed");
      },
    }),
    /rightout_removal_transport_failed/,
  );
});

test("US-CA eligibility rejects contradictory country or region before send", async () => {
  let calls = 0;
  for (const changed of [
    { ...privateProfile, country: "DE", region: "CA", jurisdictions: ["US", "US-CA"] },
    { ...privateProfile, country: "US", region: "NY", jurisdictions: ["US", "US-CA"] },
  ]) {
    const changedPayload = JSON.stringify(changed);
    await assert.rejects(runRemovalSubmission({
      input: toolInput,
      catalog,
      profilePayload: changedPayload,
      smtpConfig,
      operatorAttestations: {
        ...removalAttestations,
        authorizedProfileDigests: { [profileId]: removalProfileDigest(changedPayload) },
      },
      async sendMail() { calls += 1; },
    }), /profile_not_eligible_for_removal_lane/);
  }
  assert.equal(calls, 0);
});

test("approved profile and SMTP snapshots cannot change before the write", async () => {
  let calls = 0;
  const common = {
    input: toolInput,
    catalog,
    profilePayload,
    smtpConfig,
    operatorAttestations: removalAttestations,
    async sendMail() {
      calls += 1;
      return { accepted: [broker.removal.recipient], rejected: [] };
    },
  };
  await assert.rejects(
    runRemovalSubmission({ ...common, profilePayload: JSON.stringify({ ...privateProfile, fullName: "Changed Example" }) }),
    /rightout_removal_snapshot_changed/,
  );
  await assert.rejects(
    runRemovalSubmission({ ...common, smtpConfig: { ...smtpConfig, password: "changed-app-password" } }),
    /rightout_removal_snapshot_changed/,
  );
  assert.equal(calls, 0);
});

test("transport failures expose no raw cause, PII, or credentials", async () => {
  const leaked = [privateProfile.contactEmail, smtpConfig.username, smtpConfig.password];
  let caught;
  try {
    await runRemovalSubmission({
      input: toolInput,
      catalog,
      profilePayload,
      smtpConfig,
      operatorAttestations: removalAttestations,
      async sendMail() {
        throw new Error(`SMTP failed for ${leaked.join(" ")}`);
      },
    });
  } catch (error) {
    caught = error;
  }
  assert.ok(caught instanceof Error);
  assert.equal(caught.message, "rightout_removal_transport_failed");
  assert.equal(Object.hasOwn(caught, "cause"), false);
  const exposed = [inspect(caught, { depth: 8 }), caught.stack ?? "", JSON.stringify(caught, Object.getOwnPropertyNames(caught))].join("\n");
  for (const secret of leaked) assert.equal(exposed.includes(secret), false, secret);
});

test("message identity is deterministic for duplicate-friendly SMTP handling", () => {
  const profile = parseRemovalProfile(JSON.stringify(privateProfile));
  const first = __test.deterministicMessageId(toolInput, profile, { id: broker.id });
  const second = __test.deterministicMessageId(toolInput, profile, { id: broker.id });
  assert.equal(first, second);
  assert.doesNotMatch(first, /Avery|avery@example/);
});

test("runtime uses a removal-specific allow-once binding that scan approval cannot satisfy", async () => {
  const plugin = (await import("../../index.ts")).default;
  let beforeToolCall;
  const tools = new Map();
  const pluginConfig = {
    braveApiKey: "dummy-test-key",
    profiles: { [profileId]: { payload: JSON.stringify(privateProfile) } },
    operatorAttestations: {
      braveTermsAccepted: true,
      braveTermsVersion: "2026-02-11",
      braveCustomerResponsibilitiesAccepted: true,
      subjectConsentReviewed: true,
      authorizedProfileIds: [profileId],
      authorizedProfileDigests: { [profileId]: scanProfileDigest(profilePayload) },
      authorizedBrokerIds: ["beenverified"],
    },
    smtpTransport: smtpConfig,
    removalAttestations,
  };
  plugin.register({
    on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
    registerTool(tool) { tools.set(tool.name, tool); },
    registerSecurityAuditCollector() {},
    pluginConfig,
    resolvePath(value) { return value; },
  });

  const decision = await beforeToolCall({
    toolName: "rightout_submit_removal",
    params: toolInput,
    toolCallId: "removal-approved",
  });
  assert.deepEqual(decision.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  assert.equal(decision.requireApproval.timeoutMs, 120_000);
  assert.equal(decision.requireApproval.timeoutBehavior, "deny");
  assert.match(decision.requireApproval.description, /privacy@beenverified\.com/);
  assert.doesNotMatch(decision.requireApproval.description, /Avery|avery@example/);
  decision.requireApproval.onResolution("deny");
  await assert.rejects(
    tools.get("rightout_submit_removal").execute("removal-approved", toolInput),
    /rightout_approval_binding_failed/,
  );

  const scanDecision = await beforeToolCall({
    toolName: "rightout_live_scan",
    params: { profileId, brokerIds: ["beenverified"] },
    toolCallId: "scan-only-approval",
  });
  scanDecision.requireApproval.onResolution("allow-once");
  await assert.rejects(
    tools.get("rightout_submit_removal").execute("scan-only-approval", toolInput),
    /rightout_approval_binding_failed/,
  );

  const removalDecision = await beforeToolCall({
    toolName: "rightout_submit_removal",
    params: toolInput,
    toolCallId: "removal-revoked",
  });
  removalDecision.requireApproval.onResolution("allow-once");
  pluginConfig.removalAttestations.authorizedBrokerIds = ["beenverified", "otherbroker"];
  await assert.rejects(
    tools.get("rightout_submit_removal").execute("removal-revoked", toolInput),
    /rightout_approval_binding_failed/,
  );

  pluginConfig.removalAttestations.authorizedBrokerIds = ["beenverified"];
  pluginConfig.profiles[profileId].payload = JSON.stringify({ ...privateProfile, jurisdictions: ["DE"] });
  pluginConfig.removalAttestations.authorizedProfileDigests[profileId] = removalProfileDigest(pluginConfig.profiles[profileId].payload);
  const ineligible = await beforeToolCall({
    toolName: "rightout_submit_removal",
    params: toolInput,
    toolCallId: "removal-ineligible",
  });
  assert.ok(ineligible.requireApproval);
  ineligible.requireApproval.onResolution("allow-once");
  await assert.rejects(
    tools.get("rightout_submit_removal").execute("removal-ineligible", toolInput),
    /profile_not_eligible_for_removal_lane/,
  );

  pluginConfig.profiles[profileId].payload = profilePayload;
  pluginConfig.removalAttestations.authorizedProfileDigests[profileId] = removalProfileDigest(profilePayload);
  const snapshotBound = await beforeToolCall({
    toolName: "rightout_submit_removal",
    params: toolInput,
    toolCallId: "removal-snapshot-bound",
  });
  snapshotBound.requireApproval.onResolution("allow-once");
  pluginConfig.profiles[profileId].payload = JSON.stringify({ ...privateProfile, fullName: "Changed Example" });
  await assert.rejects(
    tools.get("rightout_submit_removal").execute("removal-snapshot-bound", toolInput),
    /rightout_removal_snapshot_changed/,
  );

  pluginConfig.profiles[profileId].payload = "not-json";
  pluginConfig.smtpTransport.host = "127.0.0.1";
  const piiFreeHook = await beforeToolCall({
    toolName: "rightout_submit_removal",
    params: toolInput,
    toolCallId: "removal-pii-free-hook",
  });
  assert.ok(piiFreeHook.requireApproval);
  piiFreeHook.requireApproval.onResolution("deny");
});
