import { createHash } from "node:crypto";

import { parseRemovalProfile, validateSmtpConfig } from "./removal.mjs";

const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,80}$/;
const SAFE_EMAIL = /^[^@\s]{1,64}@[a-z0-9.-]{3,253}$/;

function cleanInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => !["profileId", "brokerId"].includes(key))) {
    throw new Error("rightout_parity_email_input_invalid");
  }
  if (!SAFE_PROFILE_ID.test(value.profileId) || !SAFE_BROKER_ID.test(value.brokerId)) throw new Error("rightout_parity_email_input_invalid");
  return { profileId: value.profileId, brokerId: value.brokerId };
}

function cleanBroker(value, input) {
  if (
    !value || value.id !== input.brokerId || typeof value.name !== "string" || !SAFE_EMAIL.test(value.rescue_email)
    || !Array.isArray(value.rescue_disclosure_fields)
    || value.rescue_disclosure_fields.some((field) => !["full_name", "contact_email", "listing_url"].includes(field))
    || !value.rescue_disclosure_fields.includes("full_name") || !value.rescue_disclosure_fields.includes("contact_email")
  ) {
    throw new Error("rightout_parity_email_lane_invalid");
  }
  const recipientDomain = value.rescue_email.split("@")[1];
  if (!value.official_domains.includes(recipientDomain)) {
    throw new Error("rightout_parity_email_lane_invalid");
  }
  return { id: value.id, name: value.name, recipient: value.rescue_email, disclosureFields: value.rescue_disclosure_fields };
}

function render(profile, broker, listingUrl) {
  const lines = [
    `Hello ${broker.name} Privacy Team,`,
    "",
    "I request deletion of personal information associated with me and opt out of its sale or sharing. Please use the following information only to identify and process this request:",
    "",
    ...(broker.disclosureFields.includes("full_name") ? [`Name: ${profile.fullName}`] : []),
    ...(broker.disclosureFields.includes("contact_email") ? [`Contact email: ${profile.contactEmail}`] : []),
    ...(listingUrl ? [`Listing URL: ${listingUrl}`] : []),
    "",
    "Please confirm receipt and the outcome. If additional verification is required, please request only information proportionate to this privacy request.",
    "",
    "Regards,",
    profile.fullName,
  ];
  return { subject: "Privacy request: delete and opt out", text: lines.join("\n") };
}

export function buildParityMessage({ input, broker, profilePayload, listingUrl }) {
  const clean = cleanInput(input);
  const route = cleanBroker(broker, clean);
  const profile = parseRemovalProfile(profilePayload);
  if (route.disclosureFields.includes("listing_url") && typeof listingUrl !== "string") throw new Error("rightout_form_listing_handle_required");
  if (listingUrl !== undefined) {
    let parsed;
    try { parsed = new URL(listingUrl); } catch { throw new Error("rightout_parity_email_lane_invalid"); }
    if (parsed.protocol !== "https:" || !broker.official_domains.some((domain) => parsed.hostname === domain || parsed.hostname.endsWith(`.${domain}`))) {
      throw new Error("rightout_parity_email_lane_invalid");
    }
  }
  const rendered = render(profile, route, listingUrl);
  return {
    profile,
    recipient: route.recipient,
    subject: rendered.subject,
    text: rendered.text,
    disclosureFields: [...route.disclosureFields],
  };
}

export async function runParityEmail({ input, broker, profilePayload, smtpConfig, listingUrl, sendMail, signal, now = () => new Date() }) {
  if (signal?.aborted) throw new Error("rightout_removal_cancelled");
  const clean = cleanInput(input);
  const route = cleanBroker(broker, clean);
  const profile = parseRemovalProfile(profilePayload);
  const smtp = validateSmtpConfig(smtpConfig, profile);
  const built = buildParityMessage({ input: clean, broker, profilePayload, listingUrl });
  if (typeof sendMail !== "function") throw new Error("rightout_removal_transport_unavailable");
  const messageId = `<rightout.parity.${createHash("sha256").update(JSON.stringify([clean, profile.consent.recordedAt, route.recipient])).digest("hex").slice(0, 32)}@local.invalid>`;
  let receipt;
  try {
    receipt = await sendMail({
      transport: smtp,
      message: {
        from: smtp.fromAddress,
        to: route.recipient,
        replyTo: smtp.fromAddress,
        subject: built.subject,
        text: built.text,
        messageId,
        headers: { "X-RightOut-Request-Kind": "delete_and_opt_out", "X-RightOut-Policy": "full-unbroker-parity-v1" },
      },
      signal,
    });
  } catch {
    if (signal?.aborted) throw new Error("rightout_removal_cancelled");
    throw new Error("rightout_removal_transport_failed");
  }
  const recipient = route.recipient.toLowerCase();
  const accepted = Array.isArray(receipt?.accepted) && receipt.accepted.some((item) => String(item?.address ?? item).toLowerCase() === recipient);
  const rejected = Array.isArray(receipt?.rejected) && receipt.rejected.some((item) => String(item?.address ?? item).toLowerCase() === recipient);
  if (!accepted || rejected) throw new Error("rightout_removal_not_accepted");
  const at = now().toISOString();
  return {
    report_version: 1,
    subject_ref: clean.profileId,
    broker_id: clean.brokerId,
    request_kind: "delete_and_opt_out",
    state: "submitted",
    generated_at: at,
    delivery: {
      channel: "official_registry_email_rescue",
      recipient: route.recipient,
      accepted_by_outbound_smtp: true,
      broker_receipt_confirmed: false,
      removal_confirmed: false,
    },
    disclosures: {
      to_broker: [...built.disclosureFields],
      values_in_report: false,
      attachments: 0,
      identity_documents: 0,
    },
    proof_references: [`smtp_${createHash("sha256").update(messageId).digest("hex").slice(0, 24)}`],
    raw_pii_in_report: false,
  };
}

export const __test = { cleanInput, cleanBroker, render };
