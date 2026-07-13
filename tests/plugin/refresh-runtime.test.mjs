import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";

function registryFixture(count = 100) {
  const headers = [
    "Data broker name:",
    "Data broker primary website:",
    "Data broker primary contact email address:",
    "Data Broker's primary website that contains details on how consumers can exercise their CA Consumer Privacy Act rights, including how to delete their personal information:",
    "The data broker or any of its subsidiaries is regulated by the federal Fair Credit Reporting Act (FCRA):",
  ];
  return [
    "metadata,,,,",
    headers.map((value) => `"${value.replaceAll('"', '""')}"`).join(","),
    ...Array.from({ length: count }, (_, index) => [
      `Official Broker ${index}`,
      `https://broker${index}.example.com`,
      `privacy@broker${index}.example.com`,
      `https://broker${index}.example.com/privacy/request`,
      "No",
    ].join(",")),
  ].join("\r\n");
}

function mockedFetch(implementation) {
  implementation.mock = {};
  return implementation;
}

async function fixture() {
  const tools = new Map();
  let beforeToolCall;
  const plugin = (await import("../../index.ts")).default;
  const pluginConfig = {
    stateEncryptionKey: "dummy-refresh-runtime-key-with-more-than-32-characters",
    publisherAutomationPermissions: publisherAutomationPermissions(["addresses"]),
  };
  plugin.register({
    runtime: { state: { resolveStateDir() { return mkdtempSync(join(tmpdir(), "rightout-refresh-runtime-")); } } },
    on(name, handler) { if (name === "before_tool_call") beforeToolCall = handler; },
    registerTool(tool) {
      const resolved = typeof tool === "function" ? tool({}) : tool;
      tools.set(resolved.name, resolved);
    },
    registerSecurityAuditCollector() {},
    pluginConfig,
    resolvePath(value) { return value; },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  });
  return { tools, beforeToolCall, pluginConfig };
}

test("refresh tools deny missing, denied, and unresolved approvals before network I/O", async () => {
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = mockedFetch(async () => { fetches += 1; throw new Error("must not fetch"); });
  try {
    const runtime = await fixture();
    for (const toolName of ["rightout_refresh_parity_sources", "rightout_refresh_registries"]) {
      const missingId = await runtime.beforeToolCall({ toolName, params: {} });
      assert.equal(missingId.block, true);

      const denied = await runtime.beforeToolCall({ toolName, params: {}, toolCallId: `${toolName}-denied` });
      denied.requireApproval.onResolution("deny");
      await assert.rejects(
        () => runtime.tools.get(toolName).execute(`${toolName}-denied`, {}),
        /rightout_approval_binding_failed/,
      );

      const unresolved = await runtime.beforeToolCall({ toolName, params: {}, toolCallId: `${toolName}-unresolved` });
      assert.ok(unresolved.requireApproval);
      await assert.rejects(
        () => runtime.tools.get(toolName).execute(`${toolName}-unresolved`, {}),
        /rightout_approval_binding_failed/,
      );
    }
    assert.equal(fetches, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("approved publisher refresh probes only written-authorized routes", async () => {
  const originalFetch = globalThis.fetch;
  const urls = [];
  globalThis.fetch = mockedFetch(async (url) => {
    urls.push(String(url));
    return new Response("publisher body must not escape", { status: 200, headers: { "content-type": "text/html" } });
  });
  try {
    const runtime = await fixture();
    const id = "parity-refresh-approved";
    const approval = await runtime.beforeToolCall({ toolName: "rightout_refresh_parity_sources", params: {}, toolCallId: id });
    approval.requireApproval.onResolution("allow-once");
    const result = await runtime.tools.get("rightout_refresh_parity_sources").execute(id, {});
    assert.equal(result.details.evaluated_routes, 22);
    assert.equal(result.details.probed_routes, 1);
    assert.equal(result.details.skipped_permission_required, 21);
    assert.equal(result.details.provider_read_attempts, 1);
    assert.equal(result.details.provider_reads, 1);
    assert.equal(urls.length, 1);
    assert.match(urls[0], /peopleconnect\.us/u);
    assert.doesNotMatch(JSON.stringify(result.details), /publisher body must not escape/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("publisher permission expansion after approval invalidates refresh before any GET", async () => {
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = mockedFetch(async () => { fetches += 1; throw new Error("must not fetch"); });
  try {
    const runtime = await fixture();
    const id = "parity-refresh-mutated";
    const approval = await runtime.beforeToolCall({ toolName: "rightout_refresh_parity_sources", params: {}, toolCallId: id });
    assert.match(approval.requireApproval.description, /addresses/);
    approval.requireApproval.onResolution("allow-once");
    Object.assign(runtime.pluginConfig.publisherAutomationPermissions, publisherAutomationPermissions(["intelius"]));
    await assert.rejects(runtime.tools.get("rightout_refresh_parity_sources").execute(id, {}), /rightout_approval_binding_failed/);
    assert.equal(fetches, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("refresh approval stays readable and bounded for long authorized route sets", async () => {
  const runtime = await fixture();
  const ids = ["advancedbackgroundchecks", "cyberbackgroundchecks", "fastpeoplesearch", "searchpeoplefree", "truepeoplesearch", "usphonebook"];
  runtime.pluginConfig.publisherAutomationPermissions = publisherAutomationPermissions(ids);
  const approval = await runtime.beforeToolCall({ toolName: "rightout_refresh_parity_sources", params: {}, toolCallId: "long-refresh-scope" });
  assert.ok(approval.requireApproval);
  assert.equal(approval.requireApproval.description.length <= 256, true);
  assert.match(approval.requireApproval.description, /6 pinned routes@[a-f0-9]{12}/);
});

test("approved registry refresh reports both current-year and fallback read attempts", async () => {
  const originalFetch = globalThis.fetch;
  const urls = [];
  globalThis.fetch = mockedFetch(async (url) => {
    urls.push(String(url));
    return String(url).endsWith("registry2026.csv")
      ? new Response("not found", { status: 404 })
      : new Response(registryFixture(), { status: 200, headers: { "content-type": "text/csv" } });
  });
  try {
    const runtime = await fixture();
    const id = "registry-refresh-approved";
    const approval = await runtime.beforeToolCall({ toolName: "rightout_refresh_registries", params: {}, toolCallId: id });
    approval.requireApproval.onResolution("allow-once");
    const result = await runtime.tools.get("rightout_refresh_registries").execute(id, {});
    assert.equal(result.details.provider_read_attempts, 2);
    assert.equal(result.details.provider_reads, 2);
    assert.equal(result.details.successful_sources, 1);
    assert.equal(result.details.record_count, 100);
    assert.deepEqual(urls.map((url) => new URL(url).pathname), [
      "/data_broker_registry/registry2026.csv",
      "/data_broker_registry/registry2025.csv",
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
