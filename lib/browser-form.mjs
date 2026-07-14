import { createHash } from "node:crypto";

const MAX_JSON_BYTES = 1_000_000;
const SAFE_TARGET = /^[A-Za-z0-9._:-]{1,160}$/;
const SAFE_REF = /^[A-Za-z0-9._:-]{1,160}$/;
const SAFE_PROFILE = /^[A-Za-z0-9._-]{1,64}$/;

function safeBridgeUrl(value) {
  if (typeof value !== "string" || value.length > 2_048) throw new Error("rightout_browser_bridge_unavailable");
  let url;
  try { url = new URL(value); } catch { throw new Error("rightout_browser_bridge_unavailable"); }
  if (!(["http:", "https:"].includes(url.protocol)) || url.username || url.password || url.search || url.hash) {
    throw new Error("rightout_browser_bridge_unavailable");
  }
  return url.toString().replace(/\/$/, "");
}

async function boundedJson(response) {
  const declared = Number(response.headers.get("content-length") || "0");
  if (declared > MAX_JSON_BYTES) throw new Error("rightout_browser_response_invalid");
  const reader = response.body?.getReader();
  if (!reader) throw new Error("rightout_browser_response_invalid");
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_JSON_BYTES) throw new Error("rightout_browser_response_invalid");
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const body = Buffer.concat(chunks.map((value) => Buffer.from(value))).toString("utf8");
  try { return JSON.parse(body); } catch { throw new Error("rightout_browser_response_invalid"); }
}

function withPath(base, path, profile) {
  const url = new URL(base);
  const relative = new URL(path, "http://rightout.local");
  url.pathname = `${url.pathname.replace(/\/$/, "")}${relative.pathname}`;
  url.search = relative.search;
  if (profile !== undefined) url.searchParams.set("profile", profile);
  url.hash = "";
  return url.toString();
}

async function bridgeRequest(fetchImpl, base, path, { method = "GET", body, signal, profile, authToken } = {}) {
  if (profile !== undefined && (typeof profile !== "string" || !SAFE_PROFILE.test(profile))) {
    throw new Error("rightout_browser_profile_invalid");
  }
  if (authToken !== undefined && (typeof authToken !== "string" || authToken.length < 8 || authToken.length > 4_096 || /[\r\n]/.test(authToken))) {
    throw new Error("rightout_browser_auth_invalid");
  }
  let response;
  try {
    response = await fetchImpl(withPath(base, path, profile), {
      method,
      redirect: "error",
      headers: {
        Accept: "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(authToken === undefined ? {} : { Authorization: `Bearer ${authToken}` }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal,
    });
  } catch {
    if (signal?.aborted) throw new Error("rightout_form_cancelled");
    throw new Error("rightout_browser_bridge_failed");
  }
  if (!response.ok) throw new Error("rightout_browser_bridge_failed");
  return boundedJson(response);
}

function normalizeRefs(snapshot) {
  if (!snapshot || snapshot.ok !== true || snapshot.format !== "ai" || !snapshot.refs || typeof snapshot.refs !== "object") {
    throw new Error("rightout_browser_snapshot_invalid");
  }
  const refs = [];
  for (const [ref, value] of Object.entries(snapshot.refs)) {
    if (!SAFE_REF.test(ref) || !value || typeof value !== "object") continue;
    refs.push({
      ref,
      role: String(value.role ?? "").toLowerCase(),
      rawName: String(value.name ?? ""),
      name: String(value.name ?? "").toLowerCase(),
      href: typeof value.href === "string" ? value.href : undefined,
      checked: value.checked === true,
    });
  }
  return refs;
}

function findRef(refs, spec) {
  const roles = new Set(spec.roles);
  const candidates = refs.filter((item) => roles.has(item.role) && spec.name_contains.some((fragment) => item.name.includes(fragment)));
  if (candidates.length !== 1) throw new Error("rightout_form_contract_mismatch");
  return candidates[0].ref;
}

function assertNoHumanGate(snapshot) {
  const text = String(snapshot.snapshot ?? "").toLowerCase();
  if (/\b(?:captcha|recaptcha|hcaptcha|government id|identity document|upload id)\b/u.test(text)) {
    throw new Error("rightout_form_human_gate_required");
  }
}

function assertSuccess(snapshot, phrases) {
  const text = String(snapshot.snapshot ?? "").toLowerCase();
  if (!phrases.some((phrase) => text.includes(phrase))) throw new Error("rightout_form_submission_unconfirmed");
}

function allowedPage(urlValue, domains) {
  let url;
  try { url = new URL(urlValue); } catch { throw new Error("rightout_form_domain_mismatch"); }
  if (
    url.protocol !== "https:" || url.username || url.password
    || !Array.isArray(domains) || !domains.some((domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`))
  ) throw new Error("rightout_form_domain_mismatch");
  return url.toString();
}

function openedTabReference(opened, domains) {
  if (!opened || typeof opened !== "object" || Array.isArray(opened)
    || typeof opened.targetId !== "string" || !SAFE_TARGET.test(opened.targetId)
    || typeof opened.url !== "string") {
    throw new Error("rightout_browser_bridge_failed");
  }
  const reference = [opened.suggestedTargetId, opened.tabId, opened.label, opened.targetId]
    .find((value) => typeof value === "string" && SAFE_TARGET.test(value));
  if (!reference) throw new Error("rightout_browser_bridge_failed");
  return { targetId: reference, url: allowedPage(opened.url, domains) };
}

function redactionPairs(values) {
  const labels = {
    full_name: "<subject_name>",
    first_name: "<subject_first_name>",
    last_name: "<subject_last_name>",
    contact_email: "<contact_email>",
    contact_email_confirm: "<contact_email>",
    listing_url: "<listing_url>",
    listing_id: "<listing_id>",
    date_of_birth: "<date_of_birth>",
    street: "<street>",
    city: "<city>",
    region: "<region>",
    postal: "<postal>",
    phone: "<phone>",
    recipient: "<broker_recipient>",
    message_subject: "<message_subject>",
    message_body: "<message_body>",
  };
  return Object.entries(values ?? {})
    .filter(([key, value]) => labels[key] && typeof value === "string" && value.length >= 2)
    .sort((a, b) => b[1].length - a[1].length)
    .map(([key, value]) => [value, labels[key]]);
}

function redact(value, pairs) {
  let text = String(value ?? "");
  for (const [secret, replacement] of pairs) {
    const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    text = text.replace(new RegExp(escaped, "giu"), replacement);
  }
  return text;
}

function challengeClass(text) {
  const clean = String(text ?? "").toLowerCase();
  if (/\b(?:access denied|request blocked|temporarily blocked|unusual traffic|datadome|cloudflare challenge|checking your browser|verify you are human)\b/u.test(clean)) {
    return "access_blocked";
  }
  if (/\b(?:upload (?:a |your )?(?:government )?id|driver'?s license|passport|phone call|call us|fax|mail a copy|payment|required account|create an account|press and hold|slide to verify)\b/u.test(clean)) {
    return "hard_human_gate";
  }
  if (/\b(?:recaptcha|hcaptcha|turnstile|security question|one[ -]?time (?:password|code)|verification code|otp|authenticator code|sms code)\b/u.test(clean)) {
    return "hard_human_gate";
  }
  if (/\bcaptcha\b/u.test(clean) && !/\barithmetic captcha\b/u.test(clean)) return "hard_human_gate";
  if (/\b(?:arithmetic (?:challenge|captcha)|static arithmetic challenge)\b/u.test(clean)) return "static_challenge_visible";
  if (/\bstatic text challenge\b/u.test(clean)) return "static_text_challenge_visible";
  return "none";
}

function parsedArithmeticChallenge(text) {
  const matches = [...String(text ?? "").matchAll(
    /(?:arithmetic (?:challenge|captcha)|static arithmetic challenge)[^0-9-]{0,80}(-?\d{1,4})\s*([+*x×−-])\s*(-?\d{1,4})(?:\s*=\s*\?)?/giu,
  )];
  if (matches.length !== 1) return null;
  const left = Number.parseInt(matches[0][1], 10);
  const right = Number.parseInt(matches[0][3], 10);
  const symbol = matches[0][2];
  const operator = symbol === "+" ? "add" : ["-", "−"].includes(symbol) ? "subtract" : "multiply";
  const answer = operator === "add" ? left + right : operator === "subtract" ? left - right : left * right;
  if (!Number.isSafeInteger(answer) || Math.abs(answer) > 100_000_000) return null;
  return { left, operator, right, answer };
}

function parsedStaticTextChallenge(refs) {
  const matches = refs.flatMap((item) => {
    if (item.role !== "img") return [];
    const match = /^\s*static text challenge(?: text| value)?\s*[:=-]\s*([A-Za-z0-9]{1,12})\s*$/iu.exec(item.rawName);
    return match ? [match[1]] : [];
  });
  return matches.length === 1 ? matches[0] : null;
}

const VERIFICATION_HINT = /\b(?:opt.?out|remov(?:al|e)?|verif(?:y|ication)?|confirm(?:ation)?|suppress(?:ion)?|privacy|delete)\b/u;

function domainMatches(hostname, domains) {
  return Array.isArray(domains) && domains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
}

function verificationLinkDomain(href, domains) {
  let url;
  try { url = new URL(href); } catch { return null; }
  if (url.protocol !== "https:" || url.username || url.password || !domainMatches(url.hostname, domains)) return null;
  return url.hostname;
}

function authenticatedWebmailMessage(refs, senderDomains, recipient) {
  if (typeof recipient !== "string" || !recipient || !Array.isArray(refs)) return false;
  return refs.some((item) => {
    if (!["dialog", "group", "table"].includes(item.role)) return false;
    const clean = String(item.name ?? "").toLowerCase();
    if (
      !/\b(?:message details|authentication details|security details)\b/u.test(clean)
      || !clean.includes(recipient.toLowerCase())
    ) return false;
    return Array.isArray(senderDomains) && senderDomains.some((domain) => {
      const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return new RegExp(`\\b(?:signed-by|mailed-by)\\s*[:=]?\\s*(?:[a-z0-9.-]+\\.)?${escaped}\\b`, "u").test(clean);
    });
  });
}

function observedOutcomeMarkers(snapshot) {
  const text = String(snapshot?.snapshot ?? "");
  return [
    "verification_email_requested_observed",
    "submission_success_observed",
    "suppression_success_observed",
    "message_sent_observed",
  ].filter((marker) => text.includes(marker));
}

function publicSessionSnapshot(snapshot, {
  allowedDomains, allowedFields = [], values, privacyMode = "generic_form", brokerMessageDomains = [], brokerMessageNames = [],
  verificationRecipient, verificationLinkDomains = [],
}) {
  if (!snapshot || snapshot.ok !== true || snapshot.format !== "ai" || typeof snapshot.url !== "string") {
    throw new Error("rightout_browser_snapshot_invalid");
  }
  const pageUrl = allowedPage(snapshot.url, allowedDomains);
  const pairs = redactionPairs(values);
  const normalized = normalizeRefs(snapshot);
  let refs = normalized.map((item) => ({
    ref: item.ref,
    role: item.role,
    name: redact(item.name, pairs).slice(0, 160),
    ...(item.checked ? { checked: true } : {}),
  }));
  const privateRawText = String(snapshot.snapshot ?? "").slice(0, 100_000);
  const rawText = redact(privateRawText, pairs).slice(0, 100_000);
  let challenge = challengeClass(rawText);
  const arithmetic = challenge === "static_challenge_visible" ? parsedArithmeticChallenge(privateRawText) : null;
  const parsedStaticText = challenge === "static_text_challenge_visible" ? parsedStaticTextChallenge(normalized) : null;
  const staticText = parsedStaticText && !pairs.some(([secret]) => secret.toLowerCase().includes(parsedStaticText.toLowerCase()))
    ? parsedStaticText : null;
  if (challenge === "static_challenge_visible" && arithmetic === null) challenge = "hard_human_gate";
  if (challenge === "static_text_challenge_visible" && staticText === null) challenge = "hard_human_gate";
  let text = rawText;
  if (privacyMode === "generic_form") {
    const fullNameToken = typeof values?.full_name === "string" && values.full_name.trim().length >= 4
      ? values.full_name.trim().toLowerCase() : null;
    const corroborators = Object.fromEntries(Object.entries({
      street: values?.street, city: values?.city, postal: values?.postal, phone: values?.phone,
    }).filter(([, value]) => typeof value === "string" && value.trim().length >= 4)
      .map(([key, value]) => [key, value.trim().toLowerCase()]));
    const hasStrongCorroboration = (name) => {
      const matches = Object.fromEntries(Object.entries(corroborators).map(([key, token]) => [key, name.includes(token)]));
      return matches.phone === true || (matches.street === true && (matches.city === true || matches.postal === true))
        || (matches.city === true && matches.postal === true);
    };
    const fieldSpecs = [
      ["contact_email_confirm", /\b(?:confirm|repeat|re-enter|verify).*(?:email|e-mail)|(?:email|e-mail).*(?:confirm|repeat|verify)\b/u, "confirmation email field"],
      ["contact_email", /^(?!.*\b(?:confirm|repeat|re-enter|verify)\b).*\b(?:email|e-mail)\b/u, "email field"],
      ["date_of_birth", /\b(?:date of birth|birth date|dob)\b/u, "date of birth field"],
      ["first_name", /\b(?:first name|given name)\b/u, "first name field"],
      ["last_name", /\b(?:last name|family name|surname)\b/u, "last name field"],
      ["full_name", /^(?:name(?:\s+<subject_name>)?)$|\b(?:full name|legal name)\b/u, "legal name field"],
      ["listing_url", /\b(?:listing|profile|record).*(?:url|link)|(?:url|link).*(?:listing|profile|record)\b/u, "listing URL field"],
      ["listing_id", /\b(?:listing|profile|record).*(?:id|number)|(?:id|number).*(?:listing|profile|record)\b/u, "listing ID field"],
      ["street", /\b(?:street|address|address line)\b/u, "address field"],
      ["city", /\bcity\b/u, "city field"],
      ["region", /\b(?:state|region|province)\b/u, "region field"],
      ["postal", /\b(?:zip|postal)\b/u, "postal field"],
      ["phone", /\b(?:phone|telephone|mobile)\b/u, "phone field"],
    ];
    refs = normalized.flatMap((item) => {
      const redactedName = redact(item.name, pairs).slice(0, 160);
      if (["textbox", "combobox"].includes(item.role)) {
        if (challenge === "static_challenge_visible" && item.role === "textbox" && /\b(?:arithmetic answer|challenge answer)\b/u.test(redactedName)) {
          return [{ ref: item.ref, role: item.role, name: "arithmetic answer" }];
        }
        if (challenge === "static_text_challenge_visible" && item.role === "textbox" && /\b(?:static text|captcha|challenge) answer\b/u.test(redactedName)) {
          return [{ ref: item.ref, role: item.role, name: "static text challenge answer" }];
        }
        const matches = fieldSpecs.filter(([field, pattern]) => allowedFields.includes(field) && pattern.test(redactedName));
        if (matches.length === 1) return [{ ref: item.ref, role: item.role, name: matches[0][2] }];
        return [];
      }
      if (!["button", "link", "checkbox", "radio"].includes(item.role)) return [];
      const negativeConsent = /\b(?:do not|don't|decline|reject|disagree|without consent)\b/u.test(redactedName);
      const destructive = /\b(?:delete|remove|opt.?out|suppress|submit|send request)\b/u.test(redactedName);
      const candidatePositive = /\b(?:select|choose|view|record|this is me|profile|details)\b/u.test(redactedName);
      const corroboratedRecord = Boolean(fullNameToken) && item.name.includes(fullNameToken)
        && hasStrongCorroboration(item.name)
        && candidatePositive && !destructive;
      if (corroboratedRecord) return [{ ref: item.ref, role: item.role, name: "corroborated subject record", corroborated: true }];
      if (/\b(?:i agree|agree to|accept (?:the )?(?:terms|privacy|policy)|consent to)\b/u.test(redactedName) && !negativeConsent) {
        return [{ ref: item.ref, role: item.role, name: "consent action", ...(item.checked ? { checked: true } : {}) }];
      }
      if (/\b(?:submit|remove|opt.?out|delete|suppress|send request)\b/u.test(redactedName)) {
        return [{ ref: item.ref, role: item.role, name: "submission action" }];
      }
      if (/\b(?:confirm|verify|yes)\b/u.test(redactedName)) return [{ ref: item.ref, role: item.role, name: "confirmation action" }];
      if (/\b(?:search|find)\b/u.test(redactedName)) return [{ ref: item.ref, role: item.role, name: "search action" }];
      if (/\b(?:continue|next|start)\b/u.test(redactedName)) return [{ ref: item.ref, role: item.role, name: "continue action" }];
      return [];
    });
    text = [
      "<generic_form_content_redacted>",
      ...(challenge === "none" ? [] : [`challenge:${challenge}`]),
      `corroborated_subject_records:${refs.filter((item) => item.corroborated === true).length}`,
      ...(/\b(?:verification email|check your email)\b/iu.test(privateRawText) ? ["verification_email_requested_observed"] : []),
      ...(/\b(?:request (?:was )?(?:submitted|received)|successfully submitted|opt.?out request received|thank you)\b/iu.test(privateRawText)
        ? ["submission_success_observed"] : []),
    ].join("\n");
  } else if (privacyMode === "webmail") {
    refs = normalized.flatMap((item) => {
      if (["textbox", "combobox"].includes(item.role) && /\b(?:to|recipient)\b/u.test(item.name)) {
        return [{ ref: item.ref, role: item.role, name: "recipient field" }];
      }
      if (["textbox", "combobox"].includes(item.role) && /\bsubject\b/u.test(item.name)) {
        return [{ ref: item.ref, role: item.role, name: "subject field" }];
      }
      if (["textbox", "combobox"].includes(item.role) && /\b(?:message body|body)\b/u.test(item.name)) {
        return [{ ref: item.ref, role: item.role, name: "message body field" }];
      }
      if (["button", "link"].includes(item.role) && /\b(?:send|send message)\b/u.test(item.name)) {
        return [{ ref: item.ref, role: item.role, name: "send action" }];
      }
      if (["button", "link"].includes(item.role) && /\b(?:discard|delete draft|discard draft)\b/u.test(item.name)) {
        return [{ ref: item.ref, role: item.role, name: "discard action" }];
      }
      return [];
    });
    text = [
      "<webmail_content_redacted>",
      ...(challenge === "none" ? [] : [`challenge:${challenge}`]),
      ...(/\bmessage sent\b/iu.test(rawText) ? ["message_sent_observed"] : []),
    ].join("\n");
  } else if (privacyMode === "webmail_verification") {
    const pageDomain = new URL(pageUrl).hostname;
    const onWebmail = pageDomain === "mail.google.com";
    const senderTokens = [...new Set([
      ...brokerMessageDomains.map((value) => String(value).toLowerCase()),
      ...brokerMessageNames.map((value) => String(value).toLowerCase()),
    ].filter(Boolean))];
    const authenticated = onWebmail
      && authenticatedWebmailMessage(normalized, brokerMessageDomains, verificationRecipient);
    refs = onWebmail ? normalized.flatMap((item) => {
      const name = item.name;
      const messageCandidate = ["link", "button", "row", "gridcell"].includes(item.role)
        && senderTokens.some((token) => name.includes(token)) && VERIFICATION_HINT.test(name);
      const authenticationControl = ["link", "button"].includes(item.role)
        && /\b(?:show details|message details|authentication details|view security details)\b/u.test(name);
      const confirmationDomain = authenticated && ["link", "button"].includes(item.role)
        ? verificationLinkDomain(item.href, verificationLinkDomains) : null;
      const confirmationControl = Boolean(confirmationDomain)
        && (VERIFICATION_HINT.test(name) || /\b(?:click here|continue|complete request)\b/u.test(name));
      if (messageCandidate) return [{ ref: item.ref, role: item.role, name: "broker verification message" }];
      if (authenticationControl) return [{ ref: item.ref, role: item.role, name: "authentication details" }];
      if (confirmationControl) return [{ ref: item.ref, role: item.role, name: "confirmation control", confirmation_domain: confirmationDomain }];
      return [];
    }) : [];
    text = [
      onWebmail ? "<webmail_verification_content_redacted>" : "<verification_destination_content_redacted>",
      ...(challenge === "none" ? [] : [`challenge:${challenge}`]),
      ...(authenticated ? ["verification_message_authenticated"] : []),
      ...(!onWebmail && domainMatches(pageDomain, verificationLinkDomains) ? ["verification_destination_opened_observed"] : []),
      `broker_message_controls:${refs.filter((item) => item.name === "broker verification message").length}`,
      `confirmation_controls:${refs.filter((item) => item.name === "confirmation control").length}`,
    ].join("\n");
  } else if (privacyMode === "publisher_discovery") {
    const fullNameToken = typeof values?.full_name === "string" && values.full_name.trim().length >= 4
      ? values.full_name.trim().toLowerCase() : null;
    const corroborators = Object.fromEntries(Object.entries({
      street: values?.street, city: values?.city, postal: values?.postal, phone: values?.phone,
    }).filter(([, value]) => typeof value === "string" && value.trim().length >= 4)
      .map(([key, value]) => [key, value.trim().toLowerCase()]));
    const hasStrongCorroboration = (name) => {
      const matches = Object.fromEntries(Object.entries(corroborators).map(([key, token]) => [key, name.includes(token)]));
      return matches.phone === true || (matches.street === true && (matches.city === true || matches.postal === true))
        || (matches.city === true && matches.postal === true);
    };
    refs = normalized.flatMap((item) => {
      const redactedName = redact(item.name, pairs).slice(0, 160);
      const searchControl = ["textbox", "combobox", "listbox"].includes(item.role)
        && /\b(?:name|email|phone|address|city|state|zip|postal|search)\b/u.test(redactedName);
      const searchAction = ["button", "link"].includes(item.role)
        && /\b(?:search|find|continue|next|submit query)\b/u.test(redactedName);
      const destructive = /\b(?:delete|remove|opt.?out|suppress|submit|confirm)\b/u.test(redactedName);
      const subjectCandidate = ["button", "link", "radio"].includes(item.role)
        && /\b(?:view|select|choose|record|profile|details)\b/u.test(redactedName)
        && Boolean(fullNameToken) && item.name.includes(fullNameToken)
        && hasStrongCorroboration(item.name) && !destructive;
      if (searchControl) {
        const fieldLabel = /\b(?:email|e-mail)\b/u.test(redactedName) ? "email search field"
          : /\b(?:phone|telephone|mobile)\b/u.test(redactedName) ? "phone search field"
          : /\b(?:street|address)\b/u.test(redactedName) ? "address search field"
          : /\bcity\b/u.test(redactedName) ? "city search field"
          : /\b(?:state|region|province)\b/u.test(redactedName) ? "region search field"
          : /\b(?:zip|postal)\b/u.test(redactedName) ? "postal search field"
          : /\bname\b/u.test(redactedName) ? "name search field"
          : "search field";
        return [{ ref: item.ref, role: item.role, name: fieldLabel }];
      }
      if (searchAction) return [{ ref: item.ref, role: item.role, name: "search action" }];
      if (subjectCandidate) return [{ ref: item.ref, role: item.role, name: "corroborated subject record", corroborated: true }];
      return [];
    });
    text = [
      "<publisher_discovery_content_redacted>",
      ...(challenge === "none" ? [] : [`challenge:${challenge}`]),
      `subject_candidate_controls:${refs.filter((item) => item.corroborated === true).length}`,
    ].join("\n");
  } else if (privacyMode === "peopleconnect_guided") {
    const fullNameToken = typeof values?.full_name === "string" && values.full_name.trim().length >= 4
      ? values.full_name.trim().toLowerCase() : null;
    const corroborators = Object.fromEntries(Object.entries({
      street: values?.street, city: values?.city, postal: values?.postal, phone: values?.phone,
    }).filter(([, value]) => typeof value === "string" && value.trim().length >= 4)
      .map(([key, value]) => [key, value.trim().toLowerCase()]));
    const hasStrongCorroboration = (name) => {
      const matches = Object.fromEntries(Object.entries(corroborators).map(([key, token]) => [key, name.includes(token)]));
      return matches.phone === true || (matches.street === true && (matches.city === true || matches.postal === true))
        || (matches.city === true && matches.postal === true);
    };
    refs = normalized.flatMap((item) => {
      const redactedName = redact(item.name, pairs).slice(0, 160);
      const nameField = ["textbox", "combobox"].includes(item.role)
        && /\b(?:legal name|full name|first name|last name)\b/u.test(redactedName);
      const dobField = ["textbox", "combobox"].includes(item.role)
        && /\b(?:date of birth|birth date|dob)\b/u.test(redactedName);
      const continueAction = ["button", "link"].includes(item.role) && /\b(?:continue|next)\b/u.test(redactedName);
      const corroboratedRecord = ["button", "link", "radio"].includes(item.role)
        && /\b(?:select|choose|record|this is me)\b/u.test(redactedName)
        && Boolean(fullNameToken) && item.name.includes(fullNameToken) && hasStrongCorroboration(item.name);
      const suppressAction = ["button", "link", "radio"].includes(item.role)
        && /\b(?:suppress|suppression|do not display|hide my record)\b/u.test(redactedName);
      if (nameField) return [{ ref: item.ref, role: item.role, name: "legal name field" }];
      if (dobField) return [{ ref: item.ref, role: item.role, name: "date of birth field" }];
      if (continueAction) return [{ ref: item.ref, role: item.role, name: "continue action" }];
      if (corroboratedRecord) return [{ ref: item.ref, role: item.role, name: "corroborated subject record", corroborated: true }];
      if (suppressAction) return [{ ref: item.ref, role: item.role, name: "suppression action" }];
      return [];
    });
    text = [
      "<peopleconnect_guided_content_redacted>",
      ...(challenge === "none" ? [] : [`challenge:${challenge}`]),
      `corroborated_subject_records:${refs.filter((item) => item.corroborated === true).length}`,
      ...(/\b(?:control\s*[:=-]?\s*suppress(?:ed)?|configured as suppressed|suppression complete|record (?:is|was) suppressed)\b/iu.test(rawText)
        ? ["suppression_success_observed"] : []),
    ].join("\n");
  }
  return {
    page_domain: new URL(pageUrl).hostname,
    snapshot: text,
    refs,
    challenge,
    ...(arithmetic && challenge === "static_challenge_visible"
      ? { arithmetic_challenge: { left: arithmetic.left, operator: arithmetic.operator, right: arithmetic.right } }
      : {}),
    ...(staticText && challenge === "static_text_challenge_visible"
      ? { static_text_challenge: { value: staticText } }
      : {}),
    raw_pii_in_snapshot: false,
  };
}

function exactRef(snapshot, ref, roles) {
  if (typeof ref !== "string" || !SAFE_REF.test(ref)) throw new Error("rightout_form_ref_invalid");
  const matches = snapshot.refs.filter((item) => item.ref === ref && roles.includes(item.role));
  if (matches.length !== 1) throw new Error("rightout_form_ref_invalid");
  return matches[0];
}

const FIELD_PURPOSE_PATTERNS = Object.freeze({
  full_name: /^(?:name(?:\s+<subject_name>)?|name search field)$|\b(?:full name|legal name)\b/u,
  first_name: /\b(?:first name|given name)\b/u,
  last_name: /\b(?:last name|family name|surname)\b/u,
  contact_email: /^(?!.*\b(?:confirm|repeat|re-enter|verify)\b).*\b(?:email|e-mail)\b/u,
  contact_email_confirm: /\b(?:confirm|repeat|re-enter|verify).*(?:email|e-mail)|(?:email|e-mail).*(?:confirm|repeat|verify)\b/u,
  date_of_birth: /\b(?:date of birth|birth date|dob)\b/u,
  listing_url: /\b(?:listing|profile|record).*(?:url|link)|(?:url|link).*(?:listing|profile|record)\b/u,
  listing_id: /\b(?:listing|profile|record).*(?:id|number)|(?:id|number).*(?:listing|profile|record)\b/u,
  street: /\b(?:street|address|address line)\b/u,
  city: /\bcity\b/u,
  region: /\b(?:state|region|province)\b/u,
  postal: /\b(?:zip|postal)\b/u,
  phone: /\b(?:phone|telephone|mobile)\b/u,
  recipient: /\brecipient field\b/u,
  message_subject: /\bsubject field\b/u,
  message_body: /\bmessage body field\b/u,
});

function assertFieldPurpose(item, profileField, allowedFields) {
  const semanticName = String(item.name).toLowerCase();
  if (!FIELD_PURPOSE_PATTERNS[profileField]?.test(semanticName)) throw new Error("rightout_form_field_target_mismatch");
  const matches = allowedFields.filter((field) => FIELD_PURPOSE_PATTERNS[field]?.test(semanticName));
  if (matches.length !== 1 || matches[0] !== profileField) throw new Error("rightout_form_field_target_ambiguous");
}

function assertFieldType(profileField, type) {
  const expected = ["contact_email", "contact_email_confirm", "recipient"].includes(profileField) ? "email"
    : profileField === "phone" ? "tel"
    : profileField === "listing_url" ? "url"
    : profileField === "date_of_birth" ? "date"
    : "text";
  if (type !== expected) throw new Error("rightout_form_field_type_mismatch");
}

function assertPurpose(snapshot, item, purpose) {
  const patterns = {
    continue: /\b(?:continue|next|start|search|continue action|search action)\b/u,
    agree: /\b(?:i agree|agree to|accept (?:the )?(?:terms|privacy|policy)|consent to|consent action)\b/u,
    select_record: /\b(?:select|choose|view|record|this is me|corroborated subject record)\b/u,
    submit: /\b(?:submit|remove|opt out|delete|suppress|send request|submission action)\b/u,
    suppress: /\b(?:suppress|suppression|do not display|hide my record|suppression action)\b/u,
    confirm: /\b(?:confirm|verify|yes|confirmation action)\b/u,
    send: /\b(?:send|send message|send action)\b/u,
    open_message: /\bbroker verification message\b/u,
    open_confirmation: /\bconfirmation control\b/u,
    inspect_authentication: /\bauthentication details\b/u,
    discard: /\b(?:discard|delete draft|discard draft)\b/u,
  };
  if (purpose === "agree" && /\b(?:do not|don't|decline|reject|disagree|without consent)\b/u.test(item.name)) {
    throw new Error("rightout_form_action_not_allowed");
  }
  if (!patterns[purpose]?.test(item.name)) throw new Error("rightout_form_action_not_allowed");
  if (["continue", "agree", "submit", "suppress", "confirm", "send", "open_message", "inspect_authentication", "open_confirmation"].includes(purpose)) {
    const candidates = snapshot.refs.filter((candidate) => ["button", "link", "checkbox", "radio", "row", "gridcell"].includes(candidate.role) && patterns[purpose].test(candidate.name));
    if (candidates.length !== 1 || candidates[0].ref !== item.ref) throw new Error("rightout_form_action_ambiguous");
  }
}

export function createBrowserSessionDriver({ fetchImpl = globalThis.fetch, now = () => new Date() } = {}) {
  if (typeof fetchImpl !== "function") throw new Error("rightout_browser_bridge_unavailable");

  async function rawSnapshot(options) {
    const base = safeBridgeUrl(options.bridgeUrl);
    return bridgeRequest(
      fetchImpl,
      base,
      `/snapshot?format=ai&refs=aria&interactive=true&compact=true&targetId=${encodeURIComponent(options.targetId)}&maxChars=100000&timeoutMs=20000`,
      { signal: options.signal, profile: options.browserProfile, authToken: options.browserAuthToken },
    );
  }

  async function inspect(options) {
    return publicSessionSnapshot(await rawSnapshot(options), options);
  }

  async function openSession(options) {
    const base = safeBridgeUrl(options.bridgeUrl);
    allowedPage(options.formUrl, options.allowedDomains);
    const opened = await bridgeRequest(fetchImpl, base, "/tabs/open", {
      method: "POST",
      body: { url: options.formUrl, label: options.label ?? "rightout-autonomous-removal" },
      signal: options.signal,
      profile: options.browserProfile,
      authToken: options.browserAuthToken,
    });
    const tab = openedTabReference(opened, options.allowedDomains);
    try {
      return { targetId: tab.targetId, snapshot: await inspect({ ...options, targetId: tab.targetId }) };
    } catch (error) {
      await bridgeRequest(fetchImpl, base, `/tabs/${encodeURIComponent(tab.targetId)}`, {
        method: "DELETE", profile: options.browserProfile, authToken: options.browserAuthToken,
      }).catch(() => undefined);
      throw error;
    }
  }

  async function captureCandidate(options) {
    const raw = await rawSnapshot(options);
    const candidateUrl = allowedPage(raw.url, options.allowedDomains);
    const startUrl = allowedPage(options.discoveryStartUrl, options.allowedDomains);
    const candidate = new URL(candidateUrl);
    const start = new URL(startUrl);
    candidate.hash = "";
    start.hash = "";
    if (candidate.toString() === start.toString()) throw new Error("rightout_discovery_candidate_not_selected");
    return {
      candidateUrl: candidate.toString(),
      snapshot: publicSessionSnapshot(raw, options),
    };
  }

  async function act(options) {
    if (!SAFE_TARGET.test(options.targetId)) throw new Error("rightout_form_target_invalid");
    const base = safeBridgeUrl(options.bridgeUrl);
    const privateBefore = await rawSnapshot(options);
    const before = publicSessionSnapshot(privateBefore, options);
    if (before.challenge === "hard_human_gate") throw new Error("rightout_form_human_gate_required");
    if (before.challenge === "access_blocked") throw new Error("rightout_browser_access_blocked");
    if (options.beforeActionGuard !== undefined) {
      if (typeof options.beforeActionGuard !== "function") throw new Error("rightout_form_action_not_allowed");
      await options.beforeActionGuard(before);
    }
    const bridgeOptions = { signal: options.signal, profile: options.browserProfile, authToken: options.browserAuthToken };
    const action = options.action;
    if (!action || typeof action !== "object" || Array.isArray(action)) throw new Error("rightout_form_action_not_allowed");
    let externalEffectStarted = false;
    try {
    if (action.kind === "fill") {
      if (!Array.isArray(action.fields) || action.fields.length < 1 || action.fields.length > 12) throw new Error("rightout_form_action_not_allowed");
      const requestedRefs = action.fields.map((field) => field?.ref);
      const requestedFields = action.fields.map((field) => field?.profile_field);
      if (new Set(requestedRefs).size !== requestedRefs.length || new Set(requestedFields).size !== requestedFields.length) {
        throw new Error("rightout_form_field_mapping_ambiguous");
      }
      const fields = action.fields.map((field) => {
        if (!field || typeof field !== "object" || Object.keys(field).some((key) => !["ref", "profile_field", "type"].includes(key))) {
          throw new Error("rightout_form_action_not_allowed");
        }
        const item = exactRef(before, field.ref, ["textbox", "combobox"]);
        if (!options.allowedFields.includes(field.profile_field) || typeof options.values[field.profile_field] !== "string") {
          throw new Error("rightout_form_profile_field_missing");
        }
        if (!new Set(["text", "email", "tel", "url", "date"]).has(field.type)) throw new Error("rightout_form_action_not_allowed");
        assertFieldPurpose(item, field.profile_field, options.allowedFields);
        assertFieldType(field.profile_field, field.type);
        return { ref: field.ref, type: field.type, value: options.values[field.profile_field] };
      });
      externalEffectStarted = true;
      await bridgeRequest(fetchImpl, base, "/act", { method: "POST", body: { kind: "fill", fields, targetId: options.targetId }, ...bridgeOptions });
    } else if (action.kind === "fill_challenge") {
      const item = exactRef(before, action.ref, ["textbox"]);
      if (before.challenge !== "static_challenge_visible" || item.name !== "arithmetic answer") throw new Error("rightout_form_action_not_allowed");
      const arithmetic = before.arithmetic_challenge;
      if (!arithmetic || !Number.isInteger(arithmetic.left) || !Number.isInteger(arithmetic.right)) throw new Error("rightout_form_action_not_allowed");
      const answer = arithmetic.operator === "add" ? arithmetic.left + arithmetic.right
        : arithmetic.operator === "subtract" ? arithmetic.left - arithmetic.right
          : arithmetic.operator === "multiply" ? arithmetic.left * arithmetic.right : Number.NaN;
      if (!Number.isSafeInteger(answer) || Math.abs(answer) > 100_000_000) throw new Error("rightout_form_action_not_allowed");
      externalEffectStarted = true;
      await bridgeRequest(fetchImpl, base, "/act", { method: "POST", body: { kind: "fill", fields: [{ ref: action.ref, type: "text", value: String(answer) }], targetId: options.targetId }, ...bridgeOptions });
    } else if (action.kind === "fill_static_text_challenge") {
      const item = exactRef(before, action.ref, ["textbox"]);
      if (
        before.challenge !== "static_text_challenge_visible" || item.name !== "static text challenge answer"
        || typeof action.answer !== "string" || !/^[A-Za-z0-9]{1,12}$/.test(action.answer)
        || action.answer !== before.static_text_challenge?.value
      ) throw new Error("rightout_form_action_not_allowed");
      externalEffectStarted = true;
      await bridgeRequest(fetchImpl, base, "/act", {
        method: "POST",
        body: { kind: "fill", fields: [{ ref: action.ref, type: "text", value: action.answer }], targetId: options.targetId },
        ...bridgeOptions,
      });
    } else if (action.kind === "click") {
      const item = exactRef(before, action.ref, ["button", "link", "checkbox", "radio", "row", "gridcell"]);
      assertPurpose(before, item, action.purpose);
      if (action.purpose === "open_confirmation") {
        if (
          options.privacyMode !== "webmail_verification"
          || !before.snapshot.includes("verification_message_authenticated")
        ) {
          throw new Error("rightout_webmail_message_not_authenticated");
        }
        const privateItem = normalizeRefs(privateBefore).find((candidate) => candidate.ref === action.ref);
        if (!privateItem || !verificationLinkDomain(privateItem.href, options.verificationLinkDomains)) {
          throw new Error("rightout_webmail_confirmation_link_rejected");
        }
      }
      if (options.privacyMode === "peopleconnect_guided" && action.purpose === "select_record" && item.corroborated !== true) {
        throw new Error("rightout_peopleconnect_record_not_corroborated");
      }
      if (
        options.privacyMode === "peopleconnect_guided" && action.purpose === "select_record"
        && before.refs.filter((candidate) => candidate.corroborated === true).length !== 1
      ) throw new Error("rightout_peopleconnect_record_ambiguous");
      if (["generic_form", "publisher_discovery"].includes(options.privacyMode ?? "generic_form") && action.purpose === "select_record") {
        if (item.corroborated !== true) throw new Error("rightout_form_record_not_corroborated");
        if (before.refs.filter((candidate) => candidate.corroborated === true).length !== 1) {
          throw new Error("rightout_form_record_ambiguous");
        }
      }
      externalEffectStarted = ["continue", "agree", "select_record", "submit", "suppress", "confirm", "send", "open_confirmation"].includes(action.purpose);
      await bridgeRequest(fetchImpl, base, "/act", { method: "POST", body: { kind: "click", ref: action.ref, targetId: options.targetId }, ...bridgeOptions });
    } else throw new Error("rightout_form_action_not_allowed");
    const after = await inspect(options);
    const beforeMarkers = new Set(observedOutcomeMarkers(before));
    const observedTransitions = observedOutcomeMarkers(after).filter((marker) => !beforeMarkers.has(marker));
    return { ...after, observed_transitions: observedTransitions, observed_at: now().toISOString() };
    } catch (error) {
      if (externalEffectStarted) throw new Error("rightout_browser_action_uncertain");
      throw error;
    }
  }

  async function redactedStateReceipt(options) {
    const redacted = await inspect(options);
    const observedAt = now().toISOString();
    const commitmentPayload = {
      version: "rightout-redacted-state-v1",
      observed_at: observedAt,
      page_domain: redacted.page_domain,
      snapshot: redacted.snapshot,
      refs: redacted.refs,
      challenge: redacted.challenge,
    };
    const commitmentSha256 = createHash("sha256").update(JSON.stringify(commitmentPayload)).digest("hex");
    return {
      receipt_reference: `receipt_${commitmentSha256.slice(0, 24)}`,
      commitment_sha256: commitmentSha256,
      commitment_payload: commitmentPayload,
      receipt_basis: "redacted_semantic_state",
      raw_screenshot_in_report: false,
      raw_media_created: false,
    };
  }

  async function discardDraft(options) {
    const base = safeBridgeUrl(options.bridgeUrl);
    const before = await inspect(options);
    const matches = before.refs.filter((item) => ["button", "link"].includes(item.role) && /\b(?:discard|delete draft|discard draft)\b/u.test(item.name));
    if (matches.length !== 1) return { discarded: false, reason: "discard_control_not_observed" };
    await bridgeRequest(fetchImpl, base, "/act", {
      method: "POST",
      body: { kind: "click", ref: matches[0].ref, targetId: options.targetId },
      signal: options.signal,
      profile: options.browserProfile,
      authToken: options.browserAuthToken,
    });
    return { discarded: true };
  }

  async function closeSession(options) {
    const base = safeBridgeUrl(options.bridgeUrl);
    await bridgeRequest(fetchImpl, base, `/tabs/${encodeURIComponent(options.targetId)}`, {
      method: "DELETE",
      profile: options.browserProfile,
      authToken: options.browserAuthToken,
    });
    return { closed: true };
  }

  return { openSession, inspect, act, captureCandidate, redactedStateReceipt, discardDraft, closeSession };
}

export function createBrowserFormSubmitter({ fetchImpl = globalThis.fetch, now = () => new Date() } = {}) {
  if (typeof fetchImpl !== "function") throw new Error("rightout_browser_bridge_unavailable");
  return async function submitBrowserForm({ bridgeUrl, formUrl, recipe, values, signal, browserProfile, browserAuthToken }) {
    const base = safeBridgeUrl(bridgeUrl);
    const bridgeOptions = { signal, profile: browserProfile, authToken: browserAuthToken };
    if (signal?.aborted) throw new Error("rightout_form_cancelled");
    let targetId;
    let submitStarted = false;
    try {
      const opened = await bridgeRequest(fetchImpl, base, "/tabs/open", { method: "POST", body: { url: formUrl, label: "rightout-removal" }, ...bridgeOptions });
      targetId = openedTabReference(opened, [new URL(formUrl).hostname]).targetId;
      const snapshot = await bridgeRequest(fetchImpl, base, `/snapshot?format=ai&refs=aria&interactive=true&compact=true&targetId=${encodeURIComponent(targetId)}&maxChars=100000&timeoutMs=20000`, bridgeOptions);
      assertNoHumanGate(snapshot);
      const refs = normalizeRefs(snapshot);
      const fields = recipe.fields.map((spec) => {
        const value = values[spec.profile_field];
        if (typeof value !== "string" || !value) throw new Error("rightout_form_profile_field_missing");
        return { ref: findRef(refs, spec), type: spec.type, value };
      });
      await bridgeRequest(fetchImpl, base, "/act", { method: "POST", body: { kind: "fill", fields, targetId }, ...bridgeOptions });
      for (const spec of recipe.checkboxes ?? []) {
        await bridgeRequest(fetchImpl, base, "/act", { method: "POST", body: { kind: "click", ref: findRef(refs, spec), targetId }, ...bridgeOptions });
      }
      submitStarted = true;
      await bridgeRequest(fetchImpl, base, "/act", { method: "POST", body: { kind: "click", ref: findRef(refs, recipe.submit), targetId }, ...bridgeOptions });
      const after = await bridgeRequest(fetchImpl, base, `/snapshot?format=ai&refs=aria&compact=true&targetId=${encodeURIComponent(targetId)}&maxChars=100000&timeoutMs=20000`, bridgeOptions);
      assertNoHumanGate(after);
      assertSuccess(after, recipe.success_phrases);
      const at = now().toISOString();
      return {
        submitted: true,
        submitted_at: at,
        proof_reference: `form_${createHash("sha256").update(JSON.stringify([formUrl, at, targetId])).digest("hex").slice(0, 24)}`,
      };
    } catch (error) {
      if (submitStarted) throw new Error("rightout_form_submission_uncertain");
      throw error;
    } finally {
      if (targetId) {
        try { await bridgeRequest(fetchImpl, base, `/tabs/${encodeURIComponent(targetId)}`, { method: "DELETE", signal: undefined, profile: browserProfile, authToken: browserAuthToken }); }
        catch { /* tab cleanup is best effort and never changes submission truth */ }
      }
    }
  };
}

export const __test = {
  safeBridgeUrl, normalizeRefs, findRef, assertNoHumanGate, assertSuccess, boundedJson, withPath,
  allowedPage, redactionPairs, redact, challengeClass, publicSessionSnapshot, exactRef, assertPurpose,
  parsedArithmeticChallenge, observedOutcomeMarkers, openedTabReference,
};
