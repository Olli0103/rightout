import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { createBrowserFormSubmitter, createBrowserSessionDriver } from "../../lib/browser-form.mjs";

const catalog = JSON.parse(await readFile("skills/data-broker-removal/references/brokers/unbroker-parity.json", "utf8"));
const recipes = catalog.brokers.filter((route) => route.method === "web_form");

function response(value) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
}

for (const route of recipes) {
  test(`generic browser engine opens the exact sourced parity route: ${route.id}`, async () => {
    const targetId = `tab-${route.id}`;
    const fetchImpl = async (url, options) => {
      if (String(url).includes("/tabs/open")) return response({ ok: true, targetId, url: route.action_url });
      return response({
        ok: true, format: "ai", targetId, url: route.action_url,
        snapshot: "Opt out form",
        refs: { submit: { role: "button", name: "Submit removal" } },
      });
    };
    const values = Object.fromEntries(route.disclosure_fields.map((field) => [field, `dummy-${field}`]));
    const opened = await createBrowserSessionDriver({ fetchImpl }).openSession({
      bridgeUrl: "http://127.0.0.1:3000/browser",
      formUrl: route.action_url,
      allowedDomains: route.official_domains,
      allowedFields: route.disclosure_fields,
      values,
      browserProfile: "rightout-parity-test",
    });
    assert.equal(opened.targetId, targetId);
    assert.ok(route.official_domains.includes(opened.snapshot.page_domain) || route.official_domains.some((domain) => opened.snapshot.page_domain.endsWith(`.${domain}`)));
    assert.equal(opened.snapshot.raw_pii_in_snapshot, false);
  });
}

const sandboxSubmittable = recipes;

for (const route of sandboxSubmittable) {
  test(`generic one-page synthetic form fixture exercises normalized contract: ${route.id}`, async () => {
    const refs = Object.fromEntries(route.disclosure_fields.map((field, index) => [
      `field-${index}`,
      { role: "textbox", name: field.replaceAll("_", " ") },
    ]));
    refs.submit = { role: "button", name: "Submit opt out" };
    const calls = [];
    let submitted = false;
    const fetchImpl = async (url, options = {}) => {
      const path = new URL(url).pathname;
      const body = options.body ? JSON.parse(options.body) : undefined;
      calls.push({ path, body });
      if (path.endsWith("/tabs/open")) return response({ ok: true, targetId: `tab-${route.id}`, url: route.action_url });
      if (path.includes("/snapshot")) {
        return response({
          ok: true, format: "ai", targetId: `tab-${route.id}`, url: route.action_url,
          snapshot: submitted ? "Thank you. Request submitted." : "Opt out form",
          refs: submitted ? {} : refs,
        });
      }
      if (path.endsWith("/act")) {
        if (body.kind === "click" && body.ref === "submit") submitted = true;
        return response({ ok: true });
      }
      if (path.includes("/tabs/")) return response({ ok: true });
      throw new Error("unexpected browser bridge request");
    };
    const values = Object.fromEntries(route.disclosure_fields.map((field) => [field, `dummy-${field}`]));
    const recipe = {
      fields: route.disclosure_fields.map((field, index) => ({
        profile_field: field,
        roles: ["textbox"],
        name_contains: [field.replaceAll("_", " ")],
        type: field === "contact_email" ? "email" : field === "listing_url" ? "url" : field === "phone" ? "tel" : "text",
      })),
      submit: { roles: ["button"], name_contains: ["submit opt out"] },
      success_phrases: ["request submitted"],
    };
    const result = await createBrowserFormSubmitter({ fetchImpl })({
      bridgeUrl: "http://127.0.0.1:3000/browser",
      formUrl: route.action_url,
      recipe,
      values,
      browserProfile: "rightout-parity-test",
    });
    assert.equal(result.submitted, true);
    assert.match(result.proof_reference, /^form_[a-f0-9]{24}$/);
    assert.equal(JSON.stringify(result).includes("dummy-"), false);
    assert.equal(calls.some((call) => call.body?.kind === "fill"), true);
    assert.equal(calls.some((call) => call.body?.kind === "click" && call.body.ref === "submit"), true);
  });
}

test("matrix covers all twenty normalized form contracts and separates external availability policy", () => {
  assert.equal(recipes.length, 20);
  assert.equal(sandboxSubmittable.length, 20);
  assert.deepEqual(catalog.brokers.filter((route) => route.method === "web_form" && route.source_status === "needs_evidence").map((route) => route.id), []);
  assert.deepEqual(catalog.brokers.filter((route) => route.method === "web_form" && route.source_status === "observed_official_archive_external_unavailable").map((route) => route.id).sort(), ["clustrmaps", "peekyou"]);
  assert.deepEqual(catalog.brokers.filter((route) => route.method === "web_form" && route.source_status === "observed_200_terms_restrict_automation").map((route) => route.id), ["spokeo"]);
});
