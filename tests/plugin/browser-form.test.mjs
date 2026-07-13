import assert from "node:assert/strict";
import test from "node:test";

import { createBrowserFormSubmitter } from "../../lib/browser-form.mjs";

const recipe = {
  fields: [{ profile_field: "contact_email", type: "text", roles: ["textbox"], name_contains: ["email"] }],
  checkboxes: [{ roles: ["checkbox"], name_contains: ["agree", "terms"] }],
  submit: { roles: ["button"], name_contains: ["continue"] },
  success_phrases: ["verification email", "check your email"],
};

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

function mockFetch(responses) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, ...options, parsedBody: options.body ? JSON.parse(options.body) : undefined });
    const next = responses.shift();
    if (next instanceof Error) throw next;
    if (!next) throw new Error("unexpected bridge call");
    return next;
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

test("browser form fills PII only inside the host bridge and returns an opaque proof", async () => {
  const fetchImpl = mockFetch([
    json({ suggestedTargetId: "rightout-removal", targetId: "raw-cdp-target-1", tabId: "t1", label: "rightout-removal", title: "Suppression", url: "https://suppression.peopleconnect.us/", type: "page" }),
    json({
      ok: true, format: "ai", targetId: "tab-1", url: "https://suppression.peopleconnect.us/",
      snapshot: "Email address. Agree to terms. Continue.",
      refs: {
        e1: { role: "textbox", name: "Email Address" },
        e2: { role: "checkbox", name: "I agree to the Terms of Use" },
        e3: { role: "button", name: "Continue" },
      },
    }),
    json({ ok: true, targetId: "tab-1" }),
    json({ ok: true, targetId: "tab-1" }),
    json({ ok: true, targetId: "tab-1" }),
    json({ ok: true, format: "ai", targetId: "tab-1", url: "https://suppression.peopleconnect.us/verify", snapshot: "Check your email for a verification email.", refs: {} }),
    json({ ok: true }),
  ]);
  const submit = createBrowserFormSubmitter({ fetchImpl, now: () => new Date("2026-07-12T12:00:00Z") });
  const result = await submit({
    bridgeUrl: "http://127.0.0.1:3000/browser",
    formUrl: "https://suppression.peopleconnect.us/",
    recipe,
    values: { contact_email: "avery@example.invalid" },
    browserProfile: "rightout-cloud",
    browserAuthToken: "dummy-browser-token",
  });
  assert.equal(result.submitted, true);
  assert.match(result.proof_reference, /^form_[a-f0-9]{24}$/);
  assert.equal(JSON.stringify(result).includes("avery@example.invalid"), false);
  assert.deepEqual(fetchImpl.calls[2].parsedBody, {
    kind: "fill", fields: [{ ref: "e1", type: "text", value: "avery@example.invalid" }], targetId: "rightout-removal",
  });
  assert.equal(fetchImpl.calls.at(-1).method, "DELETE");
  assert.match(fetchImpl.calls[1].url, /\/snapshot\?format=ai&refs=aria/);
  assert.match(fetchImpl.calls[0].url, /profile=rightout-cloud/);
  assert.equal(fetchImpl.calls[0].headers.Authorization, "Bearer dummy-browser-token");
});

test("browser profile and auth inputs are bounded", async () => {
  const submit = createBrowserFormSubmitter({ fetchImpl: mockFetch([]) });
  await assert.rejects(submit({
    bridgeUrl: "http://127.0.0.1:3000/browser",
    formUrl: "https://suppression.peopleconnect.us/",
    recipe,
    values: { contact_email: "avery@example.invalid" },
    browserProfile: "../unsafe",
  }), /rightout_browser_profile_invalid/);
  await assert.rejects(submit({
    bridgeUrl: "http://127.0.0.1:3000/browser",
    formUrl: "https://suppression.peopleconnect.us/",
    recipe,
    values: { contact_email: "avery@example.invalid" },
    browserAuthToken: "bad\r\ntoken",
  }), /rightout_browser_auth_invalid/);
});

test("CAPTCHA or identity-document gates fail before any fill or submit", async () => {
  const fetchImpl = mockFetch([
    json({ targetId: "tab-1", title: "Suppression", url: "https://suppression.peopleconnect.us/" }),
    json({ ok: true, format: "ai", targetId: "tab-1", snapshot: "Complete CAPTCHA and upload ID", refs: {} }),
    json({ ok: true }),
  ]);
  const submit = createBrowserFormSubmitter({ fetchImpl });
  await assert.rejects(submit({
    bridgeUrl: "http://127.0.0.1:3000/browser", formUrl: "https://suppression.peopleconnect.us/", recipe,
    values: { contact_email: "avery@example.invalid" },
  }), /rightout_form_human_gate_required/);
  assert.equal(fetchImpl.calls.some((call) => call.url.endsWith("/act")), false);
});

test("ambiguous labels and missing success evidence fail closed", async () => {
  const ambiguous = mockFetch([
    json({ targetId: "tab-1", title: "Suppression", url: "https://suppression.peopleconnect.us/" }),
    json({ ok: true, format: "ai", targetId: "tab-1", snapshot: "form", refs: {
      e1: { role: "textbox", name: "Email" }, e2: { role: "textbox", name: "Alternate email" },
      e3: { role: "checkbox", name: "Agree" }, e4: { role: "button", name: "Continue" },
    } }),
    json({ ok: true }),
  ]);
  await assert.rejects(createBrowserFormSubmitter({ fetchImpl: ambiguous })({
    bridgeUrl: "http://127.0.0.1:3000", formUrl: "https://suppression.peopleconnect.us/", recipe,
    values: { contact_email: "avery@example.invalid" },
  }), /rightout_form_contract_mismatch/);

  const noSuccess = mockFetch([
    json({ targetId: "tab-2", title: "Suppression", url: "https://suppression.peopleconnect.us/" }),
    json({ ok: true, format: "ai", targetId: "tab-2", snapshot: "form", refs: {
      e1: { role: "textbox", name: "Email" }, e2: { role: "checkbox", name: "Agree" }, e3: { role: "button", name: "Continue" },
    } }),
    json({ ok: true }), json({ ok: true }), json({ ok: true }),
    json({ ok: true, format: "ai", targetId: "tab-2", snapshot: "Unknown page", refs: {} }),
    json({ ok: true }),
  ]);
  await assert.rejects(createBrowserFormSubmitter({ fetchImpl: noSuccess })({
    bridgeUrl: "http://127.0.0.1:3000", formUrl: "https://suppression.peopleconnect.us/", recipe,
    values: { contact_email: "avery@example.invalid" },
  }), /rightout_form_submission_uncertain/);
});

test("bridge errors and cancellation are sanitized", async () => {
  const failed = createBrowserFormSubmitter({ fetchImpl: mockFetch([new Error("leak avery@example.invalid")]) });
  await assert.rejects(failed({
    bridgeUrl: "http://127.0.0.1:3000", formUrl: "https://suppression.peopleconnect.us/", recipe,
    values: { contact_email: "avery@example.invalid" },
  }), (error) => {
    assert.equal(error.message, "rightout_browser_bridge_failed");
    assert.equal(error.stack.includes("avery@example.invalid"), false);
    return true;
  });
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(createBrowserFormSubmitter({ fetchImpl: mockFetch([]) })({
    bridgeUrl: "http://127.0.0.1:3000", formUrl: "https://suppression.peopleconnect.us/", recipe,
    values: { contact_email: "avery@example.invalid" }, signal: controller.signal,
  }), /rightout_form_cancelled/);
});
