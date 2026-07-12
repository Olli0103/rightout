import assert from "node:assert/strict";
import test from "node:test";

import { imapTransportDigest } from "../../lib/imap.mjs";
import { removalSmtpDigest } from "../../lib/removal.mjs";

test("transport credential bindings are deterministic, scoped, and protocol-separated", () => {
  const password = "dummy-shared-app-password";
  const smtp = {
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    username: "subject@example.invalid",
    password,
    fromAddress: "subject@example.invalid",
  };
  const imap = {
    host: "imap.gmail.com",
    port: 993,
    secure: true,
    username: "subject@example.invalid",
    password,
    address: "subject@example.invalid",
  };
  const smtpDigest = removalSmtpDigest(smtp);
  const imapDigest = imapTransportDigest(imap);

  assert.match(smtpDigest, /^[a-f0-9]{64}$/);
  assert.match(imapDigest, /^[a-f0-9]{64}$/);
  assert.equal(removalSmtpDigest({ ...smtp }), smtpDigest);
  assert.equal(imapTransportDigest({ ...imap }), imapDigest);
  assert.notEqual(removalSmtpDigest({ ...smtp, password: "changed-dummy-app-password" }), smtpDigest);
  assert.notEqual(removalSmtpDigest({ ...smtp, username: "other@example.invalid" }), smtpDigest);
  assert.notEqual(imapTransportDigest({ ...imap, password: "changed-dummy-app-password" }), imapDigest);
  assert.notEqual(imapTransportDigest({ ...imap, username: "other@example.invalid" }), imapDigest);
  assert.notEqual(removalSmtpDigest({ ...smtp, host: "smtp.mail.yahoo.com" }), smtpDigest);
  assert.notEqual(removalSmtpDigest({ ...smtp, port: 587, secure: false }), smtpDigest);
  assert.notEqual(removalSmtpDigest({ ...smtp, fromAddress: "changed@example.invalid" }), smtpDigest);
  assert.notEqual(imapTransportDigest({ ...imap, address: "changed@example.invalid" }), imapDigest);
  assert.throws(() => imapTransportDigest({ ...imap, host: "imap.other.invalid" }), /rightout_imap_not_configured/);
  assert.throws(() => imapTransportDigest({ ...imap, port: 143 }), /rightout_imap_not_configured/);
  assert.throws(() => imapTransportDigest({ ...imap, secure: false }), /rightout_imap_not_configured/);
  assert.notEqual(smtpDigest, imapDigest);
});
