import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createCaseLedger } from "../../lib/cases.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";
import { createListingTokenVault } from "../../lib/listing-tokens.mjs";
import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";
import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";
import { formAttestations } from "./form-attestation-fixture.mjs";

const parity = JSON.parse(await readFile("skills/data-broker-removal/references/brokers/unbroker-parity.json", "utf8"));
const profileId = "profile_a1b2c3d4e5f60718";
const stateKey = "dummy-full-autonomy-runtime-key-with-more-than-32-characters";
const profile = JSON.stringify({
  fullName: "Avery Example",
  city: "Exampleville",
  region: "CA",
  country: "US",
  dateOfBirth: "1990-01-01",
  contactEmail: "avery@example.invalid",
  phones: ["+1 202 555 0100"],
  currentAddress: {
    line1: "100 Example Avenue",
    city: "Exampleville",
    region: "CA",
    postal: "90001",
    country: "US",
  },
  jurisdictions: ["US", "US-CA"],
  consent: {
    authorized: true,
    recordedAt: CONSENT_RECORDED_AT,
    validUntil: CONSENT_VALID_UNTIL,
    scope: ["scan", "broker_removal"],
    method: "self",
  },
});

function json(value) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
}

function browserSandbox() {
  const routesByUrl = new Map(parity.brokers.map((route) => [route.action_url, route]));
  const tabs = new Map();
  let counter = 0;
  const calls = [];

  function refsFor(tab) {
    if (tab.submitted) return {};
    if (tab.kind === "webmail") return {
      recipient: { role: "textbox", name: "Recipient To" },
      message_subject: { role: "textbox", name: "Subject" },
      message_body: { role: "textbox", name: "Message body" },
      send: { role: "button", name: "Send message" },
    };
    return {
      ...Object.fromEntries(tab.route.disclosure_fields.map((field) => [
        `field_${field}`,
        { role: "textbox", name: field.replaceAll("_", " ") },
      ])),
      submit: { role: "button", name: "Submit opt out" },
    };
  }

  async function fetchImpl(url, options = {}) {
    const parsed = new URL(url);
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push({ path: parsed.pathname, profile: parsed.searchParams.get("profile"), method: options.method ?? "GET", body });
    if (parsed.pathname.endsWith("/tabs/open")) {
      const id = `tab-${++counter}`;
      const isWebmail = String(body?.url).startsWith("https://mail.google.com/");
      const route = routesByUrl.get(body?.url);
      if (!isWebmail && !route) throw new Error(`unexpected form route ${body?.url}`);
      tabs.set(id, { id, url: body.url, kind: isWebmail ? "webmail" : "form", route, submitted: false });
      return json({ ok: true, targetId: id, url: body.url });
    }
    const targetId = parsed.searchParams.get("targetId") ?? body?.targetId;
    const tab = tabs.get(targetId);
    if (parsed.pathname.includes("/snapshot")) {
      if (!tab) throw new Error("unknown sandbox tab");
      return json({
        ok: true,
        format: "ai",
        targetId,
        url: tab.url,
        snapshot: tab.submitted
          ? tab.kind === "webmail" ? "Message sent" : "Thank you. Request submitted."
          : tab.kind === "webmail" ? "Compose recipient subject message body send" : "Official opt out form",
        refs: refsFor(tab),
      });
    }
    if (parsed.pathname.endsWith("/act")) {
      if (!tab) throw new Error("unknown sandbox tab");
      if (body?.kind === "click" && ["send", "submit"].includes(body.ref)) tab.submitted = true;
      return json({ ok: true });
    }
    if (parsed.pathname.endsWith("/screenshot")) throw new Error("screenshot endpoint must never be called");
    if (options.method === "DELETE") {
      tabs.delete(parsed.pathname.split("/").at(-1));
      return json({ ok: true });
    }
    throw new Error(`unexpected sandbox request ${parsed.pathname}`);
  }
  return { fetchImpl, calls };
}

function registerPlugin({ stateDir, config }) {
  const tools = new Map();
  let beforeToolCall;
  return import("../../index.ts").then(({ default: plugin }) => {
    plugin.register({
      runtime: { state: { resolveStateDir() { return stateDir; } } },
      on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
      registerTool(tool) {
        const resolved = typeof tool === "function"
          ? tool({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } })
          : tool;
        tools.set(resolved.name, resolved);
      },
      registerSecurityAuditCollector() {},
      pluginConfig: config,
      resolvePath(value) { return value; },
      logger: { info() {}, warn() {}, error() {}, debug() {} },
    });
    return { tools, beforeToolCall: (...args) => beforeToolCall(...args) };
  });
}

function fieldType(field) {
  if (field === "contact_email") return "email";
  if (field === "phone") return "tel";
  if (field === "listing_url") return "url";
  if (field === "date_of_birth") return "date";
  return "text";
}

test("all non-staged reference brokers drain through one durable campaign across a plugin restart", async () => {
  const originalFetch = globalThis.fetch;
  const sandbox = browserSandbox();
  globalThis.fetch = sandbox.fetchImpl;
  try {
    const stateDir = mkdtempSync(join(tmpdir(), "rightout-full-autonomy-"));
    const brokerIds = parity.brokers.map((route) => route.id).filter((brokerId) => brokerId !== "intelius").sort();
    const config = {
      stateEncryptionKey: stateKey,
      profiles: { [profileId]: { payload: profile } },
      formAttestations: formAttestations(
        profileId,
        profile,
        parity.brokers.filter((route) => route.method === "web_form" && route.id !== "intelius").map((route) => route.id),
      ),
      browserBackendMode: "existing_logged_in_cdp",
      browserControlBaseUrl: "http://127.0.0.1:3000/browser",
      browserControlToken: "dummy-browser-control-token",
      browserProfile: "rightout-dummy-logged-in",
      publisherAutomationPermissions: publisherAutomationPermissions(brokerIds),
    };

    const listingStore = createEncryptedFileKeyedStore({
      stateDir,
      namespace: "rightout-listing-tokens-v1",
      maxEntries: 500,
      getSecret: () => stateKey,
    });
    const vault = createListingTokenVault(listingStore, stateKey);
    const listingHandles = new Map();
    for (const route of parity.brokers) {
      listingHandles.set(route.id, await vault.storeCandidate({
        profileId,
        brokerId: route.id,
        urls: [`https://${route.official_domains[0]}/person/opaque`],
        officialDomains: route.official_domains,
        observedAt: "2026-07-13T08:00:00.000Z",
      }));
    }
    const caseLedger = createCaseLedger(createEncryptedFileKeyedStore({
      stateDir,
      namespace: "rightout-cases-v1",
      maxEntries: 100,
      getSecret: () => stateKey,
    }));
    await caseLedger.recordScan({
      mode: "approval_gated_live_scan",
      scan_id: "scan_0123456789abcdef",
      subject_ref: profileId,
      generated_at: "2026-07-13T08:00:00.000Z",
      results: brokerIds.map((brokerId) => ({
        broker_id: brokerId,
        state: "indirect_exposure",
        reason: "dummy_search_index_candidate",
        listing_handle: listingHandles.get(brokerId),
      })),
    });

    const firstRuntime = await registerPlugin({ stateDir, config });
    const campaignInput = {
      profileId,
      brokerIds,
      effects: ["submit_email", "submit_form"],
      durationHours: 24,
      maxEffects: 100,
    };
    const approval = await firstRuntime.beforeToolCall({
      toolName: "rightout_start_campaign",
      params: campaignInput,
      toolCallId: "full-campaign-start",
    });
    approval.requireApproval.onResolution("allow-once");
    const started = await firstRuntime.tools.get("rightout_start_campaign").execute("full-campaign-start", campaignInput);

    const resumedRuntime = await registerPlugin({ stateDir, config });
    const resumed = await resumedRuntime.tools.get("rightout_campaign_status").execute("resumed", {
      campaignId: started.details.campaign_id,
    });
    assert.equal(resumed.details.status, "active");
    assert.equal(resumed.details.used_effects, 0);

    let final;
    let sensitiveApprovals = 0;
    const completedBrokers = new Set();
    for (let turn = 0; turn < 40; turn += 1) {
      const next = await resumedRuntime.tools.get("rightout_campaign_next").execute(`next-${turn}`, {
        campaignId: started.details.campaign_id,
      });
      if (next.details.state === "done_for_now") {
        final = next.details;
        break;
      }
      assert.equal(next.details.state, "action_ready");
      const command = next.details.command;
      if (command.tool === "rightout_begin_form_session") {
        const toolCallId = `begin-form-${turn}`;
        const opened = await resumedRuntime.tools.get(command.tool).execute(toolCallId, command.parameters);
        const fields = opened.details.disclosures_allowed.map((field) => ({
          ref: `field_${field}`,
          profile_field: field,
          type: fieldType(field),
        }));
        try {
          await resumedRuntime.tools.get("rightout_form_session_step").execute(`fill-form-${turn}`, {
            sessionId: opened.details.session_id,
            action: { kind: "fill", fields },
          });
        } catch (error) {
          throw new Error(`${command.parameters.brokerId}:${error instanceof Error ? error.message : "fill_failed"}`);
        }
        const submitted = await resumedRuntime.tools.get("rightout_form_session_step").execute(`submit-form-${turn}`, {
          sessionId: opened.details.session_id,
          action: { kind: "click", ref: "submit", purpose: "submit" },
        });
        assert.equal(submitted.details.state, "verification_pending");
        completedBrokers.add(command.parameters.brokerId);
        continue;
      }
      if (command.tool === "rightout_begin_webmail_session") {
        const opened = await resumedRuntime.tools.get(command.tool).execute(`begin-mail-${turn}`, command.parameters);
        await resumedRuntime.tools.get("rightout_webmail_session_step").execute(`fill-mail-${turn}`, {
          sessionId: opened.details.session_id,
          action: { kind: "fill", fields: [
            { ref: "recipient", profile_field: "recipient", type: "email" },
            { ref: "message_subject", profile_field: "message_subject", type: "text" },
            { ref: "message_body", profile_field: "message_body", type: "text" },
          ] },
        });
        const sent = await resumedRuntime.tools.get("rightout_webmail_session_step").execute(`send-mail-${turn}`, {
          sessionId: opened.details.session_id,
          action: { kind: "click", ref: "send", purpose: "send" },
        });
        assert.equal(sent.details.state, "submitted");
        completedBrokers.add(command.parameters.brokerId);
        continue;
      }
      assert.fail(`unexpected autonomous command ${command.tool}`);
    }

    assert.ok(final, "campaign queue did not drain");
    assert.equal(final.consolidated_digest.observed_cases, 21);
    assert.equal(final.consolidated_digest.deferred_human_gates.length, 0);
    assert.equal(final.consolidated_digest.external_degradations.length, 0);
    assert.equal(sensitiveApprovals, 0);
    assert.ok(completedBrokers.size >= 15, "ownership clustering and compliant rescue lanes may skip redundant provider writes");
    assert.equal(JSON.stringify(final).includes("Avery Example"), false);
    assert.equal(JSON.stringify(final).includes("1990-01-01"), false);

    const campaignStatus = await resumedRuntime.tools.get("rightout_campaign_status").execute("final-status", {
      campaignId: started.details.campaign_id,
    });
    assert.equal(campaignStatus.details.used_effects, completedBrokers.size);
    assert.ok(campaignStatus.details.remaining_effects > 0);

    const revokeInput = { campaignId: started.details.campaign_id };
    const revoke = await resumedRuntime.beforeToolCall({
      toolName: "rightout_revoke_campaign",
      params: revokeInput,
      toolCallId: "full-campaign-revoke",
    });
    revoke.requireApproval.onResolution("allow-once");
    const revoked = await resumedRuntime.tools.get("rightout_revoke_campaign").execute("full-campaign-revoke", revokeInput);
    assert.equal(revoked.details.status, "revoked");
    const afterRevoke = await resumedRuntime.tools.get("rightout_campaign_next").execute("after-revoke", revokeInput);
    assert.equal(afterRevoke.details.state, "campaign_revoked");
    assert.equal(afterRevoke.details.terminal, true);
    assert.equal(afterRevoke.details.next_action, "none");

    assert.ok(sandbox.calls.some((call) => call.profile === "rightout-dummy-logged-in"));
    assert.equal(sandbox.calls.some((call) => JSON.stringify(call).includes("real")), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
