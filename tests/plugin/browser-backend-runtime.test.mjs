import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { CONSENT_RECORDED_AT, CONSENT_VALID_UNTIL } from "./consent-fixture.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const profile = JSON.stringify({
  fullName: "Avery Example", city: "Exampleville", region: "CA", country: "US",
  contactEmail: "avery@example.invalid", jurisdictions: ["US", "US-CA"],
  consent: {
    authorized: true, recordedAt: CONSENT_RECORDED_AT, validUntil: CONSENT_VALID_UNTIL,
    scope: ["scan", "broker_removal"], method: "self",
  },
});

async function inspectBackend({ mode, explicit = false, omitExplicitMode = false, webmailOnly = false }) {
  const stateDir = mkdtempSync(join(tmpdir(), `rightout-browser-${mode}-`));
  const tools = new Map();
  const plugin = (await import("../../index.ts")).default;
  const pluginConfig = {
    stateEncryptionKey: "dummy-browser-backend-key-with-more-than-32-characters",
    braveApiKey: "dummy-brave-key",
    profiles: { [profileId]: { payload: profile } },
    ...(explicit ? {
      browserControlBaseUrl: "http://127.0.0.1:3001/browser",
      browserControlToken: "dummy-browser-control-token",
      browserProfile: `${mode}-profile`,
      ...(!omitExplicitMode ? { browserBackendMode: mode } : {}),
    } : {}),
    ...(webmailOnly ? {} : {
      smtpTransport: {
        host: "smtp.gmail.com", port: 465, secure: true,
        username: "dummy", password: "dummy", fromAddress: "avery@example.invalid",
      },
      imapTransport: {
        host: "imap.gmail.com", port: 993, secure: true,
        username: "dummy", password: "dummy", address: "avery@example.invalid",
      },
    }),
  };
  plugin.register({
    runtime: { state: { resolveStateDir() { return stateDir; } } },
    on() {},
    registerTool(tool) {
      const resolved = typeof tool === "function"
        ? tool({ browser: { sandboxBridgeUrl: "http://127.0.0.1:3000/browser" } })
        : tool;
      tools.set(resolved.name, resolved);
    },
    registerSecurityAuditCollector() {},
    pluginConfig,
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  const setup = await tools.get("rightout_setup").execute("setup", {});
  const doctor = await tools.get("rightout_doctor").execute("doctor", {});
  return { setup: setup.details, doctor: doctor.details };
}

test("setup and doctor distinguish managed OpenClaw, remote cloud CDP, and logged-in CDP backends", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    ok: true,
    checks: [{ id: "live-snapshot", status: "pass" }],
  }), { status: 200, headers: { "content-type": "application/json" } });
  try {
    const managed = await inspectBackend({ mode: "managed_openclaw" });
    assert.equal(managed.setup.selected_autonomous_modes.browser, "managed_openclaw");
    assert.equal(managed.doctor.checks.managed_openclaw_browser, true);
    assert.equal(managed.doctor.checks.browser_backend_operational, true);
    assert.equal(managed.doctor.checks.browser_runtime_prerequisites_verified, true);
    assert.equal(managed.doctor.browser_control_transport, "openclaw_sandbox_browser_bridge");
    assert.equal(managed.doctor.state, "runtime_ready_policy_gates_closed");

    const remote = await inspectBackend({ mode: "remote_cloud_cdp", explicit: true });
    assert.equal(remote.setup.selected_autonomous_modes.browser, "remote_cloud_cdp");
    assert.equal(remote.doctor.checks.remote_cloud_cdp_browser, true);
    assert.equal(remote.doctor.browser_control_transport, "standalone_loopback_http_opt_in");
    assert.equal(remote.doctor.state, "runtime_ready_policy_gates_closed");

    const loggedIn = await inspectBackend({ mode: "existing_logged_in_cdp", explicit: true, webmailOnly: true });
    assert.equal(loggedIn.setup.selected_autonomous_modes.email_send, "browser_webmail");
    assert.equal(loggedIn.setup.selected_autonomous_modes.verification, "unavailable");
    assert.ok(loggedIn.setup.missing.includes("receiver_authenticated_imap_verification"));
    assert.equal(loggedIn.doctor.checks.existing_logged_in_cdp_browser, true);
    assert.equal(loggedIn.doctor.checks.email_send, true);
    assert.equal(loggedIn.doctor.checks.verification, false);
    assert.deepEqual(loggedIn.doctor.supported_browser_backends, [
      "managed_openclaw", "remote_cloud_cdp", "existing_logged_in_cdp",
    ]);
    assert.equal(loggedIn.doctor.state, "needs_attention");

    const explicitWithoutMode = await inspectBackend({ mode: "unspecified", explicit: true, omitExplicitMode: true });
    assert.equal(explicitWithoutMode.setup.selected_autonomous_modes.browser, "backend_mode_required");
    assert.equal(explicitWithoutMode.doctor.checks.browser_backend_configured, false);
    assert.equal(explicitWithoutMode.doctor.checks.browser_backend_reachable, false);
    assert.ok(explicitWithoutMode.doctor.critical.includes("browser_backend_configured"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
