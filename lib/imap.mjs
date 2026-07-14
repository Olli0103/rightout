import { createHash, randomBytes, scryptSync } from "node:crypto";

import { ImapFlow } from "imapflow";
import { simpleParser } from "mailparser";

const ALLOWED_IMAP_ENDPOINTS = new Map([
  ["imap.gmail.com", 993],
]);
const TRUSTED_AUTHSERV_IDS = new Map([["imap.gmail.com", "mx.google.com"]]);
const SAFE_EMAIL = /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i;
const SAFE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const LINK_RE = /https:\/\/[^\s"'<>()[\]{}]+/giu;
const LINK_HINTS = ["verify", "confirm", "remov", "optout", "opt-out", "suppress", "privacy", "delete"];
const MAX_SOURCE_BYTES = 1_000_000;
const MAX_MESSAGES = 30;
const MAX_OAUTH_LIFETIME_MS = 24 * 60 * 60_000;

function cleanString(value, label, min, max) {
  if (typeof value !== "string") throw new Error(`invalid_${label}`);
  const clean = value.trim();
  if (clean.length < min || clean.length > max || /[\u0000-\u001f\u007f]/.test(clean)) throw new Error(`invalid_${label}`);
  return clean;
}

function cleanEmail(value, label = "email") {
  const clean = cleanString(value, label, 3, 254).toLowerCase();
  if (!SAFE_EMAIL.test(clean)) throw new Error(`invalid_${label}`);
  return clean;
}

function cleanDomains(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 12) throw new Error("unsupported_verification_lane");
  const domains = [...new Set(values.map((value) => typeof value === "string" ? value.trim().toLowerCase().replace(/^www\./, "") : ""))];
  if (domains.length !== values.length || !domains.every((value) => SAFE_DOMAIN.test(value))) {
    throw new Error("unsupported_verification_lane");
  }
  return domains.sort();
}

function hostMatches(host, allowedDomains) {
  const clean = host.toLowerCase().replace(/^www\./, "");
  return allowedDomains.some((domain) => clean === domain || clean.endsWith(`.${domain}`));
}

export function scoreVerificationLink(value, allowedDomains) {
  let url;
  try { url = new URL(value); } catch {
    return { decision: "deny", score: 0, signals: ["malformed_url"] };
  }
  const signals = [];
  if (url.protocol !== "https:") signals.push("not_https");
  if (url.username || url.password) signals.push("embedded_credentials");
  if (url.port && url.port !== "443") signals.push("nonstandard_port");
  if (!hostMatches(url.hostname, allowedDomains)) signals.push("outside_catalog_domain");
  if (/\b(?:verify|confirm|remov|optout|opt-out|suppress|privacy|delete)\b/iu.test(`${url.pathname}${url.search}`)) signals.push("verification_intent_token");
  const denied = signals.some((item) => ["not_https", "embedded_credentials", "nonstandard_port", "outside_catalog_domain"].includes(item));
  const score = denied ? 0 : signals.includes("verification_intent_token") ? 100 : 80;
  return { decision: denied ? "deny" : "allow", score, signals: signals.sort() };
}

function addressDomains(addresses) {
  const out = [];
  for (const address of addresses ?? []) {
    const value = typeof address?.address === "string" ? address.address.toLowerCase() : "";
    if (value.includes("@")) out.push(value.split("@").at(-1));
  }
  return out.filter(Boolean);
}

function addressValues(addresses) {
  return (addresses ?? [])
    .map((address) => typeof address?.address === "string" ? address.address.trim().toLowerCase() : "")
    .filter(Boolean);
}

function headerValues(headers, name) {
  const value = headers?.get?.(name);
  if (Array.isArray(value)) return value.map(String);
  return value === undefined || value === null ? [] : [String(value)];
}

function hasAlignedDkimPass(headers, allowedSenderDomains, imapHost) {
  const trustedAuthservId = TRUSTED_AUTHSERV_IDS.get(imapHost);
  const values = headerValues(headers, "authentication-results");
  if (!trustedAuthservId || values.length !== 1) return false;
  const authenticationResults = values[0].toLowerCase();
  const separator = authenticationResults.indexOf(";");
  if (separator < 1 || authenticationResults.slice(0, separator).trim() !== trustedAuthservId) return false;
  if (!authenticationResults || /\bdkim=(?:fail|permerror|temperror|neutral|none)\b/u.test(authenticationResults)) return false;
  return allowedSenderDomains.some((domain) => {
    const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const aligned = new RegExp(`(?:header\\.d=${escaped}(?:[;\\s]|$)|header\\.i=[^;\\s]*@${escaped}(?:[;\\s]|$))`, "iu");
    return /\bdkim=pass\b/u.test(authenticationResults) && aligned.test(authenticationResults);
  });
}

function decodeHtmlEntities(value) {
  // Decode the ampersand last so input such as &amp;#61; is decoded once, not
  // recursively into an equals sign. We only need the entities that occur in
  // HTML-escaped HTTPS query strings; this is deliberately not a general HTML
  // decoder.
  return value.replaceAll("&#x3D;", "=").replaceAll("&#61;", "=").replaceAll("&amp;", "&");
}

export function extractBoundVerificationLink({ text, html, senderDomains, allowedSenderDomains, allowedLinkDomains }) {
  const senders = senderDomains.map((value) => value.toLowerCase());
  if (!senders.some((domain) => hostMatches(domain, allowedSenderDomains))) return undefined;
  const body = decodeHtmlEntities(`${text ?? ""}\n${typeof html === "string" ? html : ""}`);
  const candidates = [...new Set(body.match(LINK_RE) ?? [])].slice(0, 50);
  let best;
  let bestScore = -1;
  for (const candidate of candidates) {
    try {
      const url = new URL(candidate.replace(/[.,;:!?]+$/u, ""));
      if (scoreVerificationLink(url.toString(), allowedLinkDomains).decision !== "allow") continue;
      const lower = `${url.pathname}${url.search}`.toLowerCase();
      const score = LINK_HINTS.reduce((total, hint) => total + (lower.includes(hint) ? 1 : 0), 0);
      if (score < 1 || score <= bestScore) continue;
      bestScore = score;
      best = url.toString();
    } catch {
      // Malformed and non-HTTPS candidates are ignored.
    }
  }
  return best;
}

export function validateImapConfig(value, expectedAddress) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_imap_not_configured");
  const allowed = new Set(["host", "port", "secure", "username", "password", "address", "authMode", "oauthAccessToken", "oauthExpiresAt"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error("rightout_imap_not_configured");
  const host = cleanString(value.host, "imap_host", 4, 253).toLowerCase();
  const port = value.port;
  const secure = value.secure;
  if (ALLOWED_IMAP_ENDPOINTS.get(host) !== port || secure !== true) throw new Error("rightout_imap_not_configured");
  const username = cleanString(value.username, "imap_username", 1, 254);
  const address = cleanEmail(value.address, "imap_address");
  if (address !== cleanEmail(expectedAddress, "profile_email")) throw new Error("rightout_imap_identity_mismatch");
  const authMode = value.authMode ?? "password";
  if (authMode === "oauth2") {
    if (value.password !== undefined) throw new Error("rightout_imap_not_configured");
    const oauthAccessToken = cleanString(value.oauthAccessToken, "imap_oauth_access_token", 16, 8_192);
    const expiresAt = Date.parse(value.oauthExpiresAt);
    const current = Date.now();
    if (typeof value.oauthExpiresAt !== "string" || !Number.isFinite(expiresAt) || expiresAt <= current + 60_000 || expiresAt > current + MAX_OAUTH_LIFETIME_MS) {
      throw new Error("rightout_imap_oauth_expired");
    }
    return { host, port, secure: true, username, authMode, oauthAccessToken, oauthExpiresAt: new Date(expiresAt).toISOString(), address };
  }
  if (authMode !== "password" || value.oauthAccessToken !== undefined || value.oauthExpiresAt !== undefined) {
    throw new Error("rightout_imap_not_configured");
  }
  const password = cleanString(value.password, "imap_password", 1, 1_024);
  if (value.authMode === "password") return { host, port, secure: true, username, authMode, password, address };
  return { host, port, secure: true, username, password, address };
}

export function imapTransportDigest(config) {
  const clean = validateImapConfig(config, config?.address);
  if (clean.authMode === "oauth2") {
    const salt = JSON.stringify([
      "rightout-imap-transport-oauth2-v1",
      clean.host,
      clean.port,
      clean.secure,
      clean.username,
      clean.address,
      clean.oauthExpiresAt,
    ]);
    return scryptSync(clean.oauthAccessToken, salt, 32).toString("hex");
  }
  const salt = JSON.stringify([
    "rightout-imap-transport-v2",
    clean.host,
    clean.port,
    clean.secure,
    clean.username,
    clean.address,
  ]);
  return scryptSync(clean.password, salt, 32).toString("hex");
}

function verificationLane(broker) {
  const verification = broker?.verification;
  if (verification?.supported !== true || verification.channel !== "imap") throw new Error("unsupported_verification_lane");
  return {
    senderDomains: cleanDomains(verification.sender_domains),
    linkDomains: cleanDomains(verification.link_domains),
  };
}

function sourceSize(source) {
  if (Buffer.isBuffer(source)) return source.byteLength;
  if (source instanceof Uint8Array) return source.byteLength;
  if (typeof source === "string") return Buffer.byteLength(source);
  return 0;
}

function messageReference(message, brokerId) {
  return `mail_${createHash("sha256")
    .update(JSON.stringify([brokerId, message.uid, message.envelope?.messageId, message.internalDate]))
    .digest("hex").slice(0, 24)}`;
}

function messageReferences(parsed) {
  const values = [parsed?.inReplyTo, ...(Array.isArray(parsed?.references) ? parsed.references : [parsed?.references])];
  return values.flatMap((value) => typeof value === "string" ? value.match(/<[^<>\s]{3,300}>/gu) ?? [] : []);
}

/**
 * @param {{clientFactory?: Function, parser?: Function, classifier?: Function, now?: Function}} [options]
 */
export function createControllerReplyPoller(options = {}) {
  const {
    clientFactory = (clientOptions) => new ImapFlow(clientOptions),
    parser = simpleParser,
    classifier,
    now = () => new Date(),
  } = options;
  if (typeof classifier !== "function") throw new Error("rightout_controller_reply_classifier_invalid");
  return async function pollControllerReply({ transport, expectedAddress, broker, expectedMessageId, notBefore, sinceDays = 30, signal }) {
    if (!Number.isInteger(sinceDays) || sinceDays < 1 || sinceDays > 30) throw new Error("rightout_controller_reply_window_invalid");
    if (signal?.aborted) throw new Error("rightout_controller_reply_cancelled");
    const config = validateImapConfig(transport, expectedAddress);
    const allowedSenderDomains = cleanDomains(broker?.official_domains);
    if (!/^<rightout\.[a-f0-9]{32}@local\.invalid>$/.test(expectedMessageId ?? "")) throw new Error("rightout_controller_reply_thread_invalid");
    const submittedAt = new Date(notBefore);
    if (typeof notBefore !== "string" || !Number.isFinite(submittedAt.getTime())) throw new Error("rightout_controller_reply_submission_time_invalid");
    const client = clientFactory({
      host: config.host,
      port: config.port,
      secure: true,
      auth: config.authMode === "oauth2"
        ? { user: config.username, accessToken: config.oauthAccessToken }
        : { user: config.username, pass: config.password },
      logger: false,
      disableAutoIdle: true,
    });
    if (!client || typeof client.connect !== "function" || typeof client.getMailboxLock !== "function") throw new Error("rightout_imap_client_invalid");
    const abort = () => { try { client.close?.(); } catch { /* best effort */ } };
    signal?.addEventListener("abort", abort, { once: true });
    let lock;
    try {
      await client.connect();
      if (signal?.aborted) throw new Error("rightout_controller_reply_cancelled");
      lock = await client.getMailboxLock("INBOX", { readOnly: true });
      const since = new Date(now());
      since.setUTCDate(since.getUTCDate() - sinceDays);
      const ids = await client.search({ since }, { uid: true });
      for (const uid of (Array.isArray(ids) ? ids.slice(-MAX_MESSAGES).reverse() : [])) {
        if (signal?.aborted) throw new Error("rightout_controller_reply_cancelled");
        const message = await client.fetchOne(String(uid), { uid: true, envelope: true, internalDate: true, source: true }, { uid: true });
        if (!message || sourceSize(message.source) < 1 || sourceSize(message.source) > MAX_SOURCE_BYTES) continue;
        const parsed = await parser(message.source, { skipHtmlToText: false, skipTextToHtml: true, maxHtmlLengthToParse: MAX_SOURCE_BYTES });
        if (!(message.internalDate instanceof Date) || message.internalDate.getTime() < submittedAt.getTime()) continue;
        if (!addressValues(parsed.to?.value).includes(config.address)) continue;
        if (!hasAlignedDkimPass(parsed.headers, allowedSenderDomains, config.host)) continue;
        const senderDomains = addressDomains(parsed.from?.value ?? message.envelope?.from);
        if (!senderDomains.some((domain) => hostMatches(domain, allowedSenderDomains))) continue;
        if (!messageReferences(parsed).includes(expectedMessageId)) continue;
        const candidate = classifier({ text: parsed.text, processClass: broker.process_class });
        return {
          found: true,
          broker_id: broker.id,
          message_reference: messageReference(message, broker.id),
          ...candidate,
          authentication_signals: ["exact_recipient", "receiver_added_aligned_dkim", "allowed_sender_domain", "exact_message_thread"],
        };
      }
      return { found: false, broker_id: broker.id };
    } catch (error) {
      if (error instanceof Error && error.message === "rightout_controller_reply_cancelled") throw error;
      if (signal?.aborted) throw new Error("rightout_controller_reply_cancelled");
      throw new Error("rightout_controller_reply_poll_failed");
    } finally {
      try { lock?.release?.(); } catch { /* best effort */ }
      signal?.removeEventListener("abort", abort);
      try { await client.logout?.(); } catch { try { client.close?.(); } catch { /* best effort */ } }
    }
  };
}

export function createImapPoller({
  clientFactory = (options) => new ImapFlow(options),
  parser = simpleParser,
  now = () => new Date(),
} = {}) {
  return async function pollBrokerVerification({ transport, expectedAddress, broker, notBefore, sinceDays = 14, signal }) {
    if (!Number.isInteger(sinceDays) || sinceDays < 1 || sinceDays > 30) throw new Error("invalid_verification_window");
    if (signal?.aborted) throw new Error("rightout_verification_cancelled");
    const config = validateImapConfig(transport, expectedAddress);
    const lane = verificationLane(broker);
    const submittedAt = new Date(notBefore);
    if (typeof notBefore !== "string" || !Number.isFinite(submittedAt.getTime())) throw new Error("invalid_verification_submission_time");
    const client = clientFactory({
      host: config.host,
      port: config.port,
      secure: true,
      auth: config.authMode === "oauth2"
        ? { user: config.username, accessToken: config.oauthAccessToken }
        : { user: config.username, pass: config.password },
      logger: false,
      disableAutoIdle: true,
    });
    if (!client || typeof client.connect !== "function" || typeof client.getMailboxLock !== "function") {
      throw new Error("rightout_imap_client_invalid");
    }
    const abort = () => { try { client.close?.(); } catch { /* best effort */ } };
    signal?.addEventListener("abort", abort, { once: true });
    let lock;
    try {
      await client.connect();
      if (signal?.aborted) throw new Error("rightout_verification_cancelled");
      lock = await client.getMailboxLock("INBOX", { readOnly: true });
      const since = new Date(now());
      since.setUTCDate(since.getUTCDate() - sinceDays);
      const ids = await client.search({ since }, { uid: true });
      const selected = Array.isArray(ids) ? ids.slice(-MAX_MESSAGES).reverse() : [];
      for (const uid of selected) {
        if (signal?.aborted) throw new Error("rightout_verification_cancelled");
        const message = await client.fetchOne(String(uid), { uid: true, envelope: true, internalDate: true, source: true }, { uid: true });
        if (!message || sourceSize(message.source) < 1 || sourceSize(message.source) > MAX_SOURCE_BYTES) continue;
        const parsed = await parser(message.source, { skipHtmlToText: true, skipTextToHtml: true, maxHtmlLengthToParse: MAX_SOURCE_BYTES });
        const messageDate = message.internalDate;
        if (!(messageDate instanceof Date) || !Number.isFinite(messageDate.getTime()) || messageDate.getTime() < submittedAt.getTime()) continue;
        if (!addressValues(parsed.to?.value).includes(config.address)) continue;
        if (!hasAlignedDkimPass(parsed.headers, lane.senderDomains, config.host)) continue;
        const senderDomains = addressDomains(parsed.from?.value ?? message.envelope?.from);
        const link = extractBoundVerificationLink({
          text: parsed.text,
          html: parsed.html,
          senderDomains,
          allowedSenderDomains: lane.senderDomains,
          allowedLinkDomains: lane.linkDomains,
        });
        if (!link) continue;
        return {
          found: true,
          broker_id: broker.id,
          message_reference: messageReference(message, broker.id),
          link,
          allowed_link_domains: lane.linkDomains,
          link_security: scoreVerificationLink(link, lane.linkDomains),
        };
      }
      return { found: false, broker_id: broker.id };
    } catch (error) {
      if (error instanceof Error && error.message === "rightout_verification_cancelled") throw error;
      if (signal?.aborted) throw new Error("rightout_verification_cancelled");
      throw new Error("rightout_verification_poll_failed");
    } finally {
      try { lock?.release?.(); } catch { /* best effort */ }
      signal?.removeEventListener("abort", abort);
      try { await client.logout?.(); } catch { try { client.close?.(); } catch { /* best effort */ } }
    }
  };
}

export function newVerificationHandle() {
  return `verify_${randomBytes(12).toString("hex")}`;
}

export const __test = { hostMatches, addressDomains, addressValues, headerValues, hasAlignedDkimPass, verificationLane, messageReference, messageReferences, sourceSize };
