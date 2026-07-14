import assert from "node:assert/strict";
import test from "node:test";

import {
  createImapPoller,
  extractBoundVerificationLink,
  imapTransportDigest,
  newVerificationHandle,
  scoreVerificationLink,
  validateImapConfig,
  __test,
} from "../../lib/imap.mjs";

const transport = {
  host: "imap.gmail.com",
  port: 993,
  secure: true,
  username: "subject@example.invalid",
  password: "app-password",
  address: "subject@example.invalid",
};

const broker = {
  id: "beenverified",
  verification: {
    supported: true,
    channel: "imap",
    sender_domains: ["beenverified.com"],
    link_domains: ["beenverified.com"],
  },
};

function rawMessage({
  from = "privacy@beenverified.com",
  to = "subject@example.invalid",
  link = "https://www.beenverified.com/privacy/confirm?id=opaque",
  date = "Sun, 12 Jul 2026 08:00:00 +0000",
  authenticationResults = "mx.google.com; dkim=pass header.d=beenverified.com",
} = {}) {
  const authLines = (Array.isArray(authenticationResults) ? authenticationResults : [authenticationResults])
    .map((value) => `Authentication-Results: ${value}`);
  return Buffer.from([
    `From: RightOut Test <${from}>`,
    `To: ${to}`,
    `Date: ${date}`,
    ...authLines,
    "Subject: Confirm privacy request",
    "Message-ID: <test-message@beenverified.com>",
    "Content-Type: text/plain; charset=utf-8",
    "",
    `Confirm: ${link}`,
  ].join("\r\n"));
}

function fakeClient(messages) {
  const events = [];
  return {
    events,
    async connect() { events.push("connect"); },
    async getMailboxLock(name, options) {
      events.push(["lock", name, options]);
      return { release() { events.push("release"); } };
    },
    async search() { return messages.map((_, index) => index + 1); },
    async fetchOne(uid) {
      const fixture = messages[Number(uid) - 1];
      const source = fixture?.source ?? fixture;
      return {
        uid: Number(uid),
        source,
        internalDate: fixture?.internalDate ?? new Date("2026-07-12T08:00:00Z"),
        envelope: { messageId: `<${uid}@test>`, date: new Date("2026-07-12T08:00:00Z"), from: [{ address: "privacy@beenverified.com" }] },
      };
    },
    async logout() { events.push("logout"); },
    close() { events.push("close"); },
  };
}

test("IMAP config is pinned to TLS providers and the subject mailbox", () => {
  assert.deepEqual(validateImapConfig(transport, transport.address), transport);
  assert.match(imapTransportDigest(transport), /^[a-f0-9]{64}$/);
  assert.throws(() => validateImapConfig({ ...transport, host: "127.0.0.1" }, transport.address), /rightout_imap_not_configured/);
  assert.throws(() => validateImapConfig({ ...transport, host: "imap.fastmail.com" }, transport.address), /rightout_imap_not_configured/);
  assert.throws(() => validateImapConfig({ ...transport, host: "outlook.office365.com" }, transport.address), /rightout_imap_not_configured/);
  assert.throws(() => validateImapConfig({ ...transport, secure: false }, transport.address), /rightout_imap_not_configured/);
  assert.throws(() => validateImapConfig(transport, "other@example.invalid"), /rightout_imap_identity_mismatch/);
});

test("IMAP accepts bounded OAuth2 bearer credentials and rejects expiry or mixed secrets", async () => {
  const oauth = {
    host: "imap.gmail.com",
    port: 993,
    secure: true,
    username: transport.username,
    authMode: "oauth2",
    oauthAccessToken: "ya29.synthetic-short-lived-token",
    oauthExpiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
    address: transport.address,
  };
  assert.deepEqual(validateImapConfig(oauth, oauth.address), oauth);
  assert.match(imapTransportDigest(oauth), /^[a-f0-9]{64}$/);
  assert.throws(() => validateImapConfig({ ...oauth, password: "mixed" }, oauth.address), /rightout_imap_not_configured/);
  assert.throws(() => validateImapConfig({ ...oauth, oauthExpiresAt: new Date(Date.now() - 60_000).toISOString() }, oauth.address), /rightout_imap_oauth_expired/);
  assert.throws(() => validateImapConfig({ ...oauth, oauthExpiresAt: new Date(Date.now() + 25 * 60 * 60_000).toISOString() }, oauth.address), /rightout_imap_oauth_expired/);

  let clientOptions;
  const client = fakeClient([rawMessage()]);
  const poll = createImapPoller({
    clientFactory: (options) => { clientOptions = options; return client; },
    now: () => new Date("2026-07-12T10:00:00Z"),
  });
  await poll({ transport: oauth, expectedAddress: oauth.address, broker, notBefore: "2026-07-12T07:00:00Z" });
  assert.deepEqual(clientOptions.auth, { user: oauth.username, accessToken: oauth.oauthAccessToken });
  assert.equal("pass" in clientOptions.auth, false);
});

test("verification links require both a broker sender and broker HTTPS link", () => {
  const base = {
    text: "Confirm https://www.beenverified.com/privacy/confirm?id=opaque",
    html: false,
    allowedSenderDomains: ["beenverified.com"],
    allowedLinkDomains: ["beenverified.com"],
  };
  assert.equal(extractBoundVerificationLink({ ...base, senderDomains: ["mailer.beenverified.com"] }), "https://www.beenverified.com/privacy/confirm?id=opaque");
  assert.equal(extractBoundVerificationLink({ ...base, senderDomains: ["attacker.invalid"] }), undefined);
  assert.equal(extractBoundVerificationLink({ ...base, senderDomains: ["beenverified.com"], text: "Confirm https://attacker.invalid/confirm" }), undefined);
  assert.equal(extractBoundVerificationLink({ ...base, senderDomains: ["beenverified.com"], text: "Visit https://www.beenverified.com/home" }), undefined);
  assert.equal(extractBoundVerificationLink({ ...base, senderDomains: ["beenverified.com"], text: "http://www.beenverified.com/confirm" }), undefined);
});

test("anti-phishing scoring denies credentials, foreign domains, and non-HTTPS links", () => {
  assert.deepEqual(scoreVerificationLink("https://www.beenverified.com/privacy/confirm?id=opaque", ["beenverified.com"]), {
    decision: "allow", score: 100, signals: ["verification_intent_token"],
  });
  assert.equal(scoreVerificationLink("https://attacker.invalid/confirm", ["beenverified.com"]).decision, "deny");
  assert.equal(scoreVerificationLink("http://beenverified.com/confirm", ["beenverified.com"]).decision, "deny");
  assert.equal(scoreVerificationLink("https://u:%70" + "@beenverified.com/confirm", ["beenverified.com"]).decision, "deny");
});

test("verification link entity decoding is single-pass", () => {
  const base = {
    html: false,
    senderDomains: ["beenverified.com"],
    allowedSenderDomains: ["beenverified.com"],
    allowedLinkDomains: ["beenverified.com"],
  };
  assert.equal(
    extractBoundVerificationLink({ ...base, text: "https://www.beenverified.com/confirm?a=1&amp;b&#61;2" }),
    "https://www.beenverified.com/confirm?a=1&b=2",
  );
  assert.equal(
    extractBoundVerificationLink({ ...base, text: "https://www.beenverified.com/confirm?a&amp;#61;secret" }),
    "https://www.beenverified.com/confirm?a&#61;secret",
  );
});

test("poller opens INBOX read-only and returns only an opaque message reference plus internal link", async () => {
  const client = fakeClient([rawMessage()]);
  const poll = createImapPoller({ clientFactory: () => client, now: () => new Date("2026-07-12T10:00:00Z") });
  const result = await poll({ transport, expectedAddress: transport.address, broker, notBefore: "2026-07-12T07:00:00Z" });
  assert.equal(result.found, true);
  assert.match(result.message_reference, /^mail_[a-f0-9]{24}$/);
  assert.equal(result.link, "https://www.beenverified.com/privacy/confirm?id=opaque");
  assert.deepEqual(client.events[1], ["lock", "INBOX", { readOnly: true }]);
  assert.ok(client.events.includes("release"));
  assert.ok(client.events.includes("logout"));
});

test("wrong-domain senders and links are ignored without exposing raw mail", async () => {
  const poll = createImapPoller({ clientFactory: () => fakeClient([
    rawMessage({ from: "privacy@attacker.invalid" }),
    rawMessage({ link: "https://attacker.invalid/confirm" }),
  ]) });
  const result = await poll({ transport, expectedAddress: transport.address, broker, notBefore: "2026-07-12T07:00:00Z" });
  assert.deepEqual(result, { found: false, broker_id: "beenverified" });
  assert.equal(JSON.stringify(result).includes("attacker"), false);
});

test("oversized messages are skipped and transport failures are sanitized", async () => {
  const oversized = Buffer.alloc(1_000_001, 65);
  const poll = createImapPoller({ clientFactory: () => fakeClient([oversized]) });
  assert.deepEqual(await poll({ transport, expectedAddress: transport.address, broker, notBefore: "2026-07-12T07:00:00Z" }), { found: false, broker_id: "beenverified" });

  const failed = createImapPoller({ clientFactory: () => ({
    async connect() { throw new Error(`leak ${transport.password}`); },
    async getMailboxLock() {},
    close() {},
    async logout() {},
  }) });
  await assert.rejects(failed({ transport, expectedAddress: transport.address, broker, notBefore: "2026-07-12T07:00:00Z" }), (error) => {
    assert.equal(error.message, "rightout_verification_poll_failed");
    assert.equal(error.stack.includes(transport.password), false);
    return true;
  });
});

test("an already aborted poll never creates a connection", async () => {
  let created = false;
  const poll = createImapPoller({ clientFactory: () => { created = true; return fakeClient([]); } });
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(poll({ transport, expectedAddress: transport.address, broker, notBefore: "2026-07-12T07:00:00Z", signal: controller.signal }), /rightout_verification_cancelled/);
  assert.equal(created, false);
});

test("poller rejects spoofed, misaddressed, and pre-submission messages", async () => {
  const poll = createImapPoller({ clientFactory: () => fakeClient([
    rawMessage({ authenticationResults: "mx.google.com; dkim=fail header.d=beenverified.com" }),
    rawMessage({ to: "other@example.invalid" }),
    { source: rawMessage(), internalDate: new Date("2026-07-12T06:00:00Z") },
  ]) });
  assert.deepEqual(
    await poll({ transport, expectedAddress: transport.address, broker, notBefore: "2026-07-12T07:00:00Z" }),
    { found: false, broker_id: "beenverified" },
  );
});

test("only one receiver-authenticated Gmail result is trusted", async () => {
  const injected = rawMessage({ authenticationResults: [
    "mx.google.com; dkim=pass header.d=attacker.invalid",
    "attacker.invalid; dkim=pass header.d=beenverified.com",
  ] });
  const poll = createImapPoller({ clientFactory: () => fakeClient([injected]) });
  assert.deepEqual(
    await poll({ transport, expectedAddress: transport.address, broker, notBefore: "2026-07-12T07:00:00Z" }),
    { found: false, broker_id: "beenverified" },
  );
  assert.equal(__test.hasAlignedDkimPass(new Map([
    ["authentication-results", [
      "mx.google.com; dkim=pass header.d=attacker.invalid",
      "attacker.invalid; dkim=pass header.d=beenverified.com",
    ]],
  ]), ["beenverified.com"], "imap.gmail.com"), false);
});

test("verification handles contain no broker, subject, or link value", () => {
  const handle = newVerificationHandle();
  assert.match(handle, /^verify_[a-f0-9]{24}$/);
  assert.equal(handle.includes("beenverified"), false);
  assert.equal(handle.includes("subject"), false);
});
