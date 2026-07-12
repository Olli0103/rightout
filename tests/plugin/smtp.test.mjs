import assert from "node:assert/strict";
import test from "node:test";

import { createSmtpSender } from "../../lib/smtp.mjs";

const message = {
  from: "avery@example.invalid",
  to: "privacy@beenverified.com",
  subject: "Privacy request: delete and opt out",
  text: "synthetic",
};

test("SMTP sender enforces TLS, timeouts, and file/URL access denial", async () => {
  const factoryCalls = [];
  const messageCalls = [];
  let closeCalls = 0;
  const sender = createSmtpSender((options) => {
    factoryCalls.push(options);
    return {
      async sendMail(value) {
        messageCalls.push(value);
        return { accepted: [message.to], rejected: [] };
      },
      close() { closeCalls += 1; },
    };
  });
  const result = await sender({
    transport: {
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      username: "smtp-user",
      password: " app password ",
    },
    message,
  });
  assert.deepEqual(result.accepted, [message.to]);
  assert.equal(messageCalls.length, 1);
  assert.equal(closeCalls, 1);
  assert.deepEqual(factoryCalls[0], {
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    requireTLS: false,
    auth: { user: "smtp-user", pass: " app password " },
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
    disableFileAccess: true,
    disableUrlAccess: true,
    tls: { servername: "smtp.gmail.com", rejectUnauthorized: true, minVersion: "TLSv1.2" },
  });
});

test("port 587 requires STARTTLS and abort closes the active transport", async () => {
  const controller = new AbortController();
  const factoryCalls = [];
  let closeCalls = 0;
  const sender = createSmtpSender((options) => {
    factoryCalls.push(options);
    return {
      async sendMail() {
        controller.abort();
        throw new Error("connection_closed");
      },
      close() { closeCalls += 1; },
    };
  });
  await assert.rejects(
    sender({
      transport: {
        host: "smtp.gmail.com",
        port: 587,
        secure: false,
        username: "smtp-user",
        password: "smtp-password",
      },
      message,
      signal: controller.signal,
    }),
    /connection_closed/,
  );
  assert.equal(factoryCalls[0].requireTLS, true);
  assert.ok(closeCalls >= 1);
});

test("invalid SMTP client factory fails before a message call", async () => {
  const sender = createSmtpSender(() => ({}));
  await assert.rejects(
    sender({
      transport: {
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        username: "smtp-user",
        password: "smtp-password",
      },
      message,
    }),
    /rightout_smtp_transport_invalid/,
  );
});

test("an already aborted signal never creates an SMTP transport", async () => {
  const controller = new AbortController();
  controller.abort();
  let factories = 0;
  const sender = createSmtpSender(() => {
    factories += 1;
    return { sendMail() {}, close() {} };
  });
  await assert.rejects(sender({
    transport: { host: "smtp.gmail.com", port: 465, secure: true, username: "u", password: "p" },
    message,
    signal: controller.signal,
  }), /rightout_removal_cancelled_before_transport/);
  assert.equal(factories, 0);
});
