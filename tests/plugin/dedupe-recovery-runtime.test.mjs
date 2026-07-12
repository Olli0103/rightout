import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

import { createCaseLedger } from "../../lib/cases.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { removalProfileDigest, removalSmtpDigest } from "../../lib/removal.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const input = { profileId, brokerId: "beenverified", requestKind: "delete_and_opt_out" };
const stateKey = "dummy-state-key-with-more-than-32-characters";
const profilePayload = JSON.stringify({
  fullName: "Avery Example", city: "Exampleville", region: "CA", country: "US",
  contactEmail: "avery@example.invalid", jurisdictions: ["US", "US-CA"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["broker_removal"] },
});
const smtpTransport = {
  host: "smtp.gmail.com", port: 465, secure: true, username: "avery@example.invalid",
  password: "dummy-app-password", fromAddress: "avery@example.invalid",
};

function dedupeKey() {
  return `dedupe_${createHash("sha256").update(JSON.stringify([profileId, "beenverified", "delete_and_opt_out"])).digest("hex")}`;
}

async function registerRuntime(stateDir) {
  const plugin = (await import("../../index.ts")).default;
  let beforeToolCall;
  const tools = new Map();
  const removalAttestations = {
    rightoutRemovalPolicyAccepted: true,
    rightoutRemovalPolicyVersion: "2026-07-12-eu1",
    subjectConsentReviewed: true,
    smtpAccountAuthorized: true,
    minimumDisclosureAccepted: true,
    authorizedProfileIds: [profileId],
    authorizedProfileDigests: { [profileId]: removalProfileDigest(profilePayload) },
    authorizedBrokerIds: ["beenverified"],
    authorizedRequestKinds: ["delete_and_opt_out"],
    smtpTransportDigest: removalSmtpDigest(smtpTransport),
  };
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
    registerTool(tool) { const resolved = typeof tool === "function" ? tool({ browser: {} }) : tool; tools.set(resolved.name, resolved); },
    registerSecurityAuditCollector() {},
    pluginConfig: { stateEncryptionKey: stateKey, profiles: { [profileId]: { payload: profilePayload } }, smtpTransport, removalAttestations },
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  return { beforeToolCall, tools };
}

test("orphan pre-intent dedupe recovers safely while a post-intent marker never does", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-dedupe-recovery-"));
  const storeOptions = { stateDir, maxEntries: 500, getSecret: () => stateKey };
  const dedupe = createEncryptedFileKeyedStore({ ...storeOptions, namespace: "rightout-submission-dedupe-v1", defaultTtlMs: 86_400_000 });
  const cases = createCaseLedger(createEncryptedFileKeyedStore({ ...storeOptions, namespace: "rightout-cases-v1", maxEntries: 100 }));
  await cases.recordScan({
    mode: "approval_gated_live_scan", scan_id: "scan_0123456789abcdef", subject_ref: profileId,
    generated_at: "2026-07-12T09:00:00Z",
    results: [{ broker_id: "beenverified", state: "indirect_exposure", reason: "search_index_candidate_observed" }],
  });
  await dedupe.register(dedupeKey(), {
    createdAt: "2026-07-12T09:01:00Z", channel: "smtp_email", profileId, brokerId: "beenverified",
    phase: "dedupe_reserved_before_case_intent",
  });
  const { beforeToolCall, tools } = await registerRuntime(stateDir);
  const approval = await beforeToolCall({ toolName: "rightout_submit_removal", params: input, toolCallId: "orphan-recovery" });
  approval.requireApproval.onResolution("allow-once");
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(tools.get("rightout_submit_removal").execute("orphan-recovery", input, aborted.signal), /rightout_removal_cancelled/);
  assert.equal((await cases.status(profileId)).counts.action_selected, 1);
  assert.equal(await dedupe.lookup(dedupeKey()), undefined);

  await cases.reserveSubmission(profileId, "beenverified", { channel: "smtp_email", discoveryRequirement: "prior_discovery_required" });
  await cases.recordSubmissionUncertain(profileId, "beenverified", { channel: "smtp_email", reason: "synthetic_ambiguous_write" });
  await cases.reconcileSubmission(profileId, "beenverified", "provider_write_not_started");
  await dedupe.register(dedupeKey(), {
    createdAt: "2026-07-12T09:02:00Z", channel: "smtp_email", profileId, brokerId: "beenverified",
    phase: "durable_case_intent_reserved",
  });
  const second = await beforeToolCall({ toolName: "rightout_submit_removal", params: input, toolCallId: "reconciled-recovery" });
  second.requireApproval.onResolution("allow-once");
  await assert.rejects(tools.get("rightout_submit_removal").execute("reconciled-recovery", input, aborted.signal), /rightout_removal_cancelled/);
  assert.equal(await dedupe.lookup(dedupeKey()), undefined);

  await dedupe.register(dedupeKey(), {
    createdAt: "2026-07-12T09:03:00Z", channel: "smtp_email", profileId, brokerId: "beenverified",
    phase: "durable_case_intent_reserved",
  });
  const protectedApproval = await beforeToolCall({ toolName: "rightout_submit_removal", params: input, toolCallId: "protected-dedupe" });
  protectedApproval.requireApproval.onResolution("allow-once");
  await assert.rejects(tools.get("rightout_submit_removal").execute("protected-dedupe", input, aborted.signal), /rightout_duplicate_removal_request/);
});
