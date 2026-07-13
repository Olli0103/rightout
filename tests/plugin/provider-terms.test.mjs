import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  assertPublisherAutomationPermission,
  providerTermsHealth,
  validateProviderTermsCatalog,
} from "../../lib/provider-terms.mjs";
import { publisherAutomationPermissions } from "./provider-terms-fixture.mjs";

const raw = JSON.parse(await readFile("skills/data-broker-removal/references/brokers/provider-terms.json", "utf8"));
const catalog = validateProviderTermsCatalog(raw);

test("all 22 parity routes are terms-bound and default-denied", () => {
  const health = providerTermsHealth(catalog);
  assert.equal(health.broker_count, 22);
  assert.equal(health.explicit_automation_prohibitions.length, 8);
  assert.equal(health.needs_evidence.length, 14);
  assert.deepEqual(health.explicitly_permitted, []);
  assert.equal(health.default_publisher_automation, "deny");
  assert.equal(health.contracts.length, 22);
  assert.equal(health.contracts.every((entry) => /^[a-f0-9]{64}$/.test(entry.contract_digest)), true);
});

test("user consent or a generic attestation never substitutes for current written provider authorization", () => {
  const broker = { id: "intelius", method: "web_form" };
  assert.throws(() => assertPublisherAutomationPermission({}, broker, catalog, "submit_form", { browserBackend: "managed_openclaw" }), /rightout_publisher_automation_not_authorized/);
  assert.throws(() => assertPublisherAutomationPermission({ publisherAutomationPermissions: { intelius: true } }, broker, catalog, "submit_form", { browserBackend: "managed_openclaw" }), /rightout_publisher_automation_not_authorized/);

  const permissions = publisherAutomationPermissions(["intelius"]);
  assert.equal(assertPublisherAutomationPermission({ publisherAutomationPermissions: permissions }, broker, catalog, "submit_form", { browserBackend: "managed_openclaw" }).broker_id, "intelius");
  assert.throws(() => assertPublisherAutomationPermission({
    publisherAutomationPermissions: { intelius: { ...permissions.intelius, termsContractDigest: "f".repeat(64) } },
  }, broker, catalog, "submit_form", { browserBackend: "managed_openclaw" }), /rightout_publisher_automation_not_authorized/);
  assert.throws(() => assertPublisherAutomationPermission({
    publisherAutomationPermissions: { intelius: { ...permissions.intelius, validUntil: "2026-07-13T00:00:00.000Z" } },
  }, broker, catalog, "submit_form", { browserBackend: "managed_openclaw", now: Date.parse("2026-07-13T01:00:00.000Z") }), /rightout_publisher_automation_not_authorized/);
  const formOnly = publisherAutomationPermissions(["intelius"], {
    allowedEffects: ["submit_form"], allowedBrowserBackends: ["managed_openclaw"],
  });
  assert.equal(assertPublisherAutomationPermission({ publisherAutomationPermissions: formOnly }, broker, catalog, "submit_form", { browserBackend: "managed_openclaw" }).allowed_effect, "submit_form");
  for (const deniedEffect of ["source_refresh", "publisher_discover", "direct_recheck", "open_verification"]) {
    assert.throws(() => assertPublisherAutomationPermission({ publisherAutomationPermissions: formOnly }, broker, catalog, deniedEffect), /rightout_publisher_automation_not_authorized/);
  }
  assert.throws(() => assertPublisherAutomationPermission({ publisherAutomationPermissions: formOnly }, broker, catalog, "submit_form", { browserBackend: "remote_cloud_cdp" }), /rightout_publisher_automation_not_authorized/);
});

test("mutated provider contracts invalidate existing permission digests", () => {
  const changed = structuredClone(raw);
  changed.brokers.find((entry) => entry.id === "intelius").terms_url = "https://www.intelius.com/terms-of-use/";
  const changedCatalog = validateProviderTermsCatalog(changed);
  assert.throws(() => assertPublisherAutomationPermission({
    publisherAutomationPermissions: publisherAutomationPermissions(["intelius"]),
  }, { id: "intelius", method: "web_form" }, changedCatalog, "submit_form", { browserBackend: "managed_openclaw" }), /rightout_publisher_automation_not_authorized/);
});
