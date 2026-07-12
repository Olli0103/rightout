import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

import { removalProfileDigest } from "../../lib/removal.mjs";
import { createCaseLedger } from "../../lib/cases.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const profile = {
  fullName: "Avery Example", city: "Exampleville", region: "CA", country: "US",
  contactEmail: "avery@example.invalid", jurisdictions: ["US", "US-CA"],
  consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["scan", "broker_removal"] },
};
const payload = JSON.stringify(profile);

function fakeRuntime() {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-form-runtime-"));
  return { state: { resolveStateDir() { return stateDir; } } };
}

function json(value) { return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } }); }

test("runtime form lane uses sandbox bridge behind its own allow-once binding", async () => {
  const originalFetch = globalThis.fetch;
  const responses = [
    json({ ok: true, targetId: "tab-1" }),
    json({ ok: true, format: "ai", targetId: "tab-1", snapshot: "Email Agree Continue", refs: {
      e1: { role: "textbox", name: "Email" }, e2: { role: "checkbox", name: "Agree to Terms" }, e3: { role: "button", name: "Continue" },
    } }),
    json({ ok: true, targetId: "tab-1" }), json({ ok: true, targetId: "tab-1" }), json({ ok: true, targetId: "tab-1" }),
    json({ ok: true, format: "ai", targetId: "tab-1", snapshot: "Check your email for a verification email", refs: {} }),
    json({ ok: true }),
  ];
  const calls = [];
  globalThis.fetch = async (url, options) => { calls.push({ url, options }); return responses.shift(); };
  try {
    const plugin = (await import("../../index.ts")).default;
    let beforeToolCall;
    const tools = new Map();
    const formAttestations = {
      rightoutFormPolicyAccepted: true,
      rightoutFormPolicyVersion: "2026-07-12",
      subjectConsentReviewed: true,
      browserFormAuthorized: true,
      minimumDisclosureAccepted: true,
      authorizedProfileIds: [profileId],
      authorizedProfileDigests: { [profileId]: removalProfileDigest(payload) },
      authorizedBrokerIds: ["intelius"],
    };
    const runtime = fakeRuntime();
    plugin.register({
      runtime,
      on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
      registerTool(tool) {
        const resolved = typeof tool === "function" ? tool({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } }) : tool;
        tools.set(resolved.name, resolved);
      },
      registerSecurityAuditCollector() {},
      pluginConfig: { stateEncryptionKey: "dummy-state-key-with-more-than-32-characters", profiles: { [profileId]: { payload } }, formAttestations },
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });
    const caseLedger = createCaseLedger(createEncryptedFileKeyedStore({
      stateDir: runtime.state.resolveStateDir(),
      namespace: "rightout-cases-v1",
      maxEntries: 100,
      getSecret: () => "dummy-state-key-with-more-than-32-characters",
    }));
    await caseLedger.recordScan({
      mode: "approval_gated_live_scan", scan_id: "scan_0123456789abcdef", subject_ref: profileId,
      generated_at: "2026-07-12T08:30:00Z",
      results: [{ broker_id: "intelius", state: "indirect_exposure", reason: "search_index_candidate_observed" }],
    });
    const input = { profileId, brokerId: "intelius", requestKind: "delete_and_opt_out" };
    const denied = await beforeToolCall({ toolName: "rightout_submit_form_removal", params: input, toolCallId: "form-denied" });
    assert.match(denied.requireApproval.description, /External write/);
    assert.doesNotMatch(denied.requireApproval.description, /Avery|avery@example/);
    denied.requireApproval.onResolution("deny");
    await assert.rejects(tools.get("rightout_submit_form_removal").execute("form-denied", input), /rightout_approval_binding_failed/);

    const approved = await beforeToolCall({ toolName: "rightout_submit_form_removal", params: input, toolCallId: "form-approved" });
    approved.requireApproval.onResolution("allow-once");
    const result = await tools.get("rightout_submit_form_removal").execute("form-approved", input);
    assert.equal(result.details.state, "verification_pending");
    assert.equal(result.details.delivery.form_submitted, true);
    assert.equal(result.details.tracking.durable_case_recorded, true);
    assert.equal(JSON.stringify(result.details).includes(profile.contactEmail), false);
    assert.equal(calls.some((call) => String(call.options?.body).includes(profile.contactEmail)), true, "PII must be filled only inside the host browser bridge");

    let restartedBeforeToolCall;
    plugin.register({
      runtime,
      on(name, handler) { if (name === "before_tool_call") restartedBeforeToolCall = handler; },
      registerTool() {}, registerSecurityAuditCollector() {},
      pluginConfig: { stateEncryptionKey: "dummy-state-key-with-more-than-32-characters", profiles: { [profileId]: { payload } }, formAttestations },
      resolvePath(value) { return value; }, logger: { info() {}, warn() {}, error() {}, debug() {} },
    });
    const duplicate = await restartedBeforeToolCall({ toolName: "rightout_submit_form_removal", params: input, toolCallId: "form-after-restart" });
    assert.ok(duplicate.requireApproval, "durable dedupe state must not be decrypted before approval");
    const restartedTools = new Map();
    let restartedHook;
    plugin.register({
      runtime,
      on(name, handler) { if (name === "before_tool_call") restartedHook = handler; },
      registerTool(tool) {
        const resolved = typeof tool === "function" ? tool({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } }) : tool;
        restartedTools.set(resolved.name, resolved);
      },
      registerSecurityAuditCollector() {},
      pluginConfig: { stateEncryptionKey: "dummy-state-key-with-more-than-32-characters", profiles: { [profileId]: { payload } }, formAttestations },
      resolvePath(value) { return value; }, logger: { info() {}, warn() {}, error() {}, debug() {} },
    });
    const duplicateExecutionApproval = await restartedHook({ toolName: "rightout_submit_form_removal", params: input, toolCallId: "form-after-restart-execute" });
    duplicateExecutionApproval.requireApproval.onResolution("allow-once");
    await assert.rejects(
      restartedTools.get("rightout_submit_form_removal").execute("form-after-restart-execute", input),
      /rightout_removal_already_in_flight/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
