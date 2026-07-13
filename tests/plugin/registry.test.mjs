import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parseCaliforniaRegistryCsv, readBoundedText, registrySummary } from "../../lib/registry.mjs";

function fixture(count = 120) {
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
      `"Official Broker ${index}, Inc."`,
      `https://broker${index}.example.com`,
      `privacy@broker${index}.example.com`,
      `https://broker${index}.example.com/privacy/request`,
      index % 3 === 0 ? "Yes" : "No",
    ].join(",")),
  ].join("\r\n");
}

test("California registry parser preserves official coverage without exposing contact addresses", () => {
  const parsed = parseCaliforniaRegistryCsv(fixture(), {
    sourceUrl: "https://cppa.ca.gov/data_broker_registry/registry2025.csv",
    retrievedAt: "2026-07-13T08:00:00Z",
  });
  assert.equal(parsed.record_count, 120);
  assert.equal(parsed.fcra_count, 40);
  assert.equal(parsed.records[0].name, "Official Broker 0, Inc.");
  assert.equal(parsed.records[0].contact_email_domain, "broker0.example.com");
  assert.equal(JSON.stringify(parsed).includes("privacy@broker0"), false);
  assert.equal(parsed.portals.length, 4);
  const summary = registrySummary(parsed);
  assert.equal(summary.record_count, 120);
  assert.equal(summary.raw_contact_addresses_in_report, false);
  assert.equal("records" in summary, false);
});

test("registry parser rejects wrong sources, malformed CSV, and suspiciously small snapshots", () => {
  assert.throws(() => parseCaliforniaRegistryCsv(fixture(), { sourceUrl: "https://example.com/registry.csv" }), /source_invalid/);
  assert.throws(() => parseCaliforniaRegistryCsv('"unterminated', { sourceUrl: "https://cppa.ca.gov/data_broker_registry/registry2025.csv" }), /csv_invalid/);
  assert.throws(() => parseCaliforniaRegistryCsv(fixture(2), { sourceUrl: "https://cppa.ca.gov/data_broker_registry/registry2025.csv" }), /record_count_invalid/);
});

test("bounded registry reader accepts a normal response and rejects declared oversize", async () => {
  const body = fixture();
  assert.equal(await readBoundedText(new Response(body)), body);
  await assert.rejects(readBoundedText(new Response("x", { headers: { "content-length": String(9 * 1024 * 1024) } })), /download_invalid/);
});

test("parser accepts the currently downloaded official 2025 registry when available", async (t) => {
  let text;
  try { text = await readFile("/tmp/rightout-registry-2025.csv", "utf8"); }
  catch { t.skip("official registry fixture is not present in this environment"); return; }
  const parsed = parseCaliforniaRegistryCsv(text, {
    sourceUrl: "https://cppa.ca.gov/data_broker_registry/registry2025.csv",
    retrievedAt: "2026-07-13T08:00:00Z",
  });
  assert.ok(parsed.record_count >= 500);
  assert.match(parsed.source_sha256, /^[a-f0-9]{64}$/);
});
