import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

import plugin from "../../index.ts";
import { createListingTokenVault } from "../../lib/listing-tokens.mjs";
import { scanProfileDigest } from "../../lib/live-scan.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";

test("runtime direct rescan is exact-handle scoped and requires its own allow-once", async () => {
  const profileId = "profile_a1b2c3d4e5f60718";
  const brokerId = "truepeoplesearch";
  const profilePayload = JSON.stringify({
    fullName: "Avery Example", city: "Exampleville", region: "CA", country: "US",
    consent: { authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL, scope: ["scan"] },
  });
  const key = "dummy-encryption-key-with-more-than-32-characters";
  const stateDir = await mkdtemp(join(tmpdir(), "rightout-direct-runtime-"));
  const hooks = new Map();
  const tools = new Map();
  const config = {
    stateEncryptionKey: key,
    profiles: { [profileId]: { payload: profilePayload } },
    directScanAttestations: {
      rightoutDirectScanPolicyAccepted: true,
      rightoutDirectScanPolicyVersion: "2026-07-12",
      subjectConsentReviewed: true,
      publisherAccessAuthorized: true,
      publisherTermsReviewed: true,
      authorizedProfileIds: [profileId],
      authorizedProfileDigests: { [profileId]: scanProfileDigest(profilePayload) },
      authorizedBrokerIds: [brokerId],
    },
  };
  const api = {
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    logger: { error() {} },
    pluginConfig: config,
    resolvePath(value) { return value; },
    on(name, handler) { hooks.set(name, handler); },
    registerSecurityAuditCollector() {},
    registerTool(value) {
      const tool = typeof value === "function" ? value({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } }) : value;
      tools.set(tool.name, tool);
    },
  };
  plugin.register(api);
  const store = createEncryptedFileKeyedStore({
    stateDir, namespace: "rightout-listing-tokens-v1", maxEntries: 500,
    defaultTtlMs: 180 * 24 * 60 * 60_000, getSecret: () => key,
  });
  const handle = await createListingTokenVault(store, key).storeCandidate({
    profileId, brokerId,
    urls: ["https://www.truepeoplesearch.com/find/person/private-record"],
    officialDomains: ["truepeoplesearch.com"],
    observedAt: "2026-07-12T12:00:00.000Z",
  });
  const input = { profileId, brokerId, listingHandle: handle };
  const hook = hooks.get("before_tool_call");
  const permissionDenied = await hook({ toolName: "rightout_direct_rescan", params: input, toolCallId: "direct-no-provider-permission" });
  assert.equal(permissionDenied.block, true);
  assert.equal(permissionDenied.requireApproval, undefined);
  config.publisherAutomationPermissions = publisherAutomationPermissions([brokerId]);
  const prompt = await hook({ toolName: "rightout_direct_rescan", params: input, toolCallId: "direct-denied" });
  assert.equal(prompt.requireApproval.severity, "critical");
  assert.deepEqual(prompt.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  assert.match(prompt.requireApproval.description, /publisher terms reviewed/);
  assert.equal(prompt.requireApproval.description.includes("private-record"), false);
  prompt.requireApproval.onResolution("deny");
  await assert.rejects(tools.get("rightout_direct_rescan").execute("direct-denied", input), /approval_binding_failed/);

  const wrong = await hook({
    toolName: "rightout_direct_rescan",
    params: { ...input, brokerId: "beenverified" },
    toolCallId: "direct-wrong-scope",
  });
  assert.equal(wrong.block, true);
  await rm(stateDir, { recursive: true, force: true });
});
