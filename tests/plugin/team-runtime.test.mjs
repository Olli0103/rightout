import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { teamSessionBindingDigest } from "../../lib/team-access.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

const profileA = "profile_0123456789abcdef";
const profileB = "profile_fedcba9876543210";
const owner = { sessionKey: "agent:main:rightout-team-owner", agentId: "main", browser: {} };
const manager = { sessionKey: "agent:main:rightout-team-manager", agentId: "main", browser: {} };
const viewer = { sessionKey: "agent:main:rightout-team-viewer", agentId: "main", browser: {} };
const profilePayload = JSON.stringify({
  fullName: "Avery Example", city: "Exampleville", region: "CA", country: "US",
  consent: {
    authorized: true,
    recordedAt: CONSENT_RECORDED_AT,
    validUntil: CONSENT_VALID_UNTIL,
    scope: ["scan"],
    method: "self",
  },
});

async function fixture() {
  const stateDir = mkdtempSync(join(tmpdir(), "rightout-team-runtime-"));
  const tools = new Map();
  let beforeToolCall;
  const config = {
    stateEncryptionKey: "dummy-team-runtime-key-with-more-than-32-characters",
    profiles: { [profileA]: { payload: profilePayload }, [profileB]: { payload: profilePayload } },
    teamAccess: {
      member_0123456789abcdef: {
        role: "owner", sessionBindingDigest: teamSessionBindingDigest(owner), authorizedProfileIds: [profileA],
      },
      member_aaaaaaaaaaaaaaaa: {
        role: "manager", sessionBindingDigest: teamSessionBindingDigest(manager), authorizedProfileIds: [profileA],
      },
      member_fedcba9876543210: {
        role: "viewer", sessionBindingDigest: teamSessionBindingDigest(viewer), authorizedProfileIds: [profileB],
      },
    },
  };
  const plugin = (await import("../../index.ts")).default;
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
    registerTool(tool) {
      const resolved = typeof tool === "function" ? tool(manager) : tool;
      tools.set(resolved.name, resolved);
    },
    registerSecurityAuditCollector() {},
    pluginConfig: config,
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  return {
    stateDir, tools, config,
    beforeToolCall: (event, context) => beforeToolCall(event, { ...context, toolName: event.toolName, toolCallId: event.toolCallId }),
  };
}

test("team mode isolates profiles and prevents manager or viewer reuse of mutating campaign authority", async () => {
  const runtime = await fixture();
  assert.equal(await runtime.beforeToolCall({
    toolName: "rightout_case_status", params: { profileId: profileB }, toolCallId: "viewer-own",
  }, viewer), undefined);
  const viewerCrossScope = await runtime.beforeToolCall({
    toolName: "rightout_case_status", params: { profileId: profileA }, toolCallId: "viewer-cross",
  }, viewer);
  assert.equal(viewerCrossScope.block, true);

  const managerMutation = await runtime.beforeToolCall({
    toolName: "rightout_live_scan", params: { profileId: profileA, brokerIds: ["fullenrich_eu"] }, toolCallId: "manager-write",
  }, manager);
  assert.equal(managerMutation.block, true);
  const viewerMutation = await runtime.beforeToolCall({
    toolName: "rightout_start_campaign",
    params: { profileId: profileB, brokerIds: ["fullenrich_eu"], effects: ["discover"], durationHours: 1, maxEffects: 1 },
    toolCallId: "viewer-campaign",
  }, viewer);
  assert.equal(viewerMutation.block, true);

  const ownerCrossScope = await runtime.beforeToolCall({
    toolName: "rightout_case_status", params: { profileId: profileB }, toolCallId: "owner-cross",
  }, owner);
  assert.equal(ownerCrossScope.block, true);
  const ownerGlobal = await runtime.beforeToolCall({
    toolName: "rightout_refresh_registries", params: {}, toolCallId: "owner-registry",
  }, owner);
  assert.ok(ownerGlobal.requireApproval);

  const campaignInput = {
    profileId: profileA, brokerIds: ["fullenrich_eu"], effects: ["discover"], durationHours: 1, maxEffects: 1,
  };
  const campaignApproval = await runtime.beforeToolCall({
    toolName: "rightout_start_campaign", params: campaignInput, toolCallId: "owner-campaign",
  }, owner);
  campaignApproval.requireApproval.onResolution("allow-once");
  const campaign = await runtime.tools.get("rightout_start_campaign").execute("owner-campaign", campaignInput);
  const managerCampaignReuse = await runtime.beforeToolCall({
    toolName: "rightout_campaign_status", params: { campaignId: campaign.details.campaign_id }, toolCallId: "manager-campaign-status",
  }, manager);
  assert.equal(managerCampaignReuse.block, true);
});

test("team overview and effectiveness are scoped, while dashboard export consumes an exact approval-bound scope", async () => {
  const runtime = await fixture();
  const binding = await runtime.tools.get("rightout_team_session_binding").execute("binding", {});
  assert.equal(binding.details.session_binding_digest, teamSessionBindingDigest(manager));
  assert.equal(binding.details.raw_session_identifier_in_report, false);

  const overview = await runtime.tools.get("rightout_team_overview").execute("overview", {});
  assert.deepEqual(overview.details.profiles.map((item) => item.subject_ref), [profileA]);
  assert.equal(overview.details.member.role, "manager");
  assert.equal("session_binding_digest" in overview.details.member, false);
  assert.equal(overview.details.operational_effectiveness, "needs_evidence");
  assert.doesNotMatch(JSON.stringify(overview.details), /@|https?:\/\//u);

  const effectiveness = await runtime.tools.get("rightout_effectiveness").execute("effectiveness", { profileId: profileA });
  assert.equal(effectiveness.details.operational_effectiveness, "needs_evidence");
  await assert.rejects(
    runtime.tools.get("rightout_effectiveness").execute("effectiveness-cross", { profileId: profileB }),
    /profile_unauthorized/,
  );

  const input = { format: "html" };
  await assert.rejects(runtime.tools.get("rightout_export_dashboard").execute("unapproved", input), /approval_binding_failed/);
  const staleApproval = await runtime.beforeToolCall({
    toolName: "rightout_export_dashboard", params: input, toolCallId: "dashboard-stale",
  }, manager);
  staleApproval.requireApproval.onResolution("allow-once");
  runtime.config.teamAccess.member_aaaaaaaaaaaaaaaa.authorizedProfileIds = [profileA, profileB];
  await assert.rejects(runtime.tools.get("rightout_export_dashboard").execute("dashboard-stale", input), /approval_binding_failed/);

  runtime.config.teamAccess.member_aaaaaaaaaaaaaaaa.authorizedProfileIds = [profileA];
  const approval = await runtime.beforeToolCall({
    toolName: "rightout_export_dashboard", params: input, toolCallId: "dashboard-approved",
  }, manager);
  assert.match(approval.requireApproval.description, /No server, scripts, remote assets, or network request/);
  approval.requireApproval.onResolution("allow-once");
  const exported = await runtime.tools.get("rightout_export_dashboard").execute("dashboard-approved", input);
  assert.equal(exported.details.state, "local_dashboard_exported");
  assert.equal(exported.details.network_service_started, false);
  assert.equal(exported.details.native_approval_consumed, true);
  assert.equal("artifact_path" in exported.details, false);
  assert.doesNotMatch(JSON.stringify(exported.details), /@|https?:\/\//u);
});
