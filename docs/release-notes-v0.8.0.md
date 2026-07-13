# RightOut v0.8.0

Status: release candidate; tagged publication gates pending.

RightOut 0.8.0 implements the complete normalized pinned Hermes Unbroker
contract surface: 22 broker IDs and 20-form/one-email/one-phone method, route,
input, and verification metadata. It does not claim exact provider-specific
choreography for all form routes; only PeopleConnect has a staged multi-step
provider-flow E2E. It adds
finite revocable campaigns, deterministic queue draining, generic ARIA-ref form
sessions, staged PeopleConnect handling, SMTP and redacted outbound Gmail,
authenticated Gmail IMAP, official registry ingestion, California DROP
tracking, publisher-source quarantine, direct rechecks, and Markdown/JSON/
Sheets-compatible reporting.

The release also closes several overclaim and safety gaps:

- Brave Web Search uses POST, accepts ISO-country profiles including DE/EU,
  selects supported country/language targets or an explicit worldwide fallback,
  drains 59 combined catalog lanes in bounded four-route campaign batches, and
  keeps query/result bodies and result URLs transient;
- every form and publisher-browser lane defaults to deny without current written
  provider authorization bound to the reviewed terms contract;
- current public evidence records 8 explicit automation prohibitions, 14
  `needs_evidence` routes, and zero affirmative permissions;
- form clicks require exact semantic refs, all mandatory fields, durable intent,
  and an observed transition; reproducible receipts commit only to the returned
  redacted semantic state, not screenshots or before/after proof;
- arithmetic is computed host-side; distorted text, CAPTCHA, OTP, ID, phone,
  fax, mail, payment, and accounts remain human;
- browser-only inbox verification performs zero mailbox I/O; autonomous inbound
  verification requires receiver-authenticated Gmail IMAP;
- a campaign binds profile, catalogs, provider terms, browser, transports, and
  permission records, so post-approval mutation fails before provider I/O;
- SecretRef documentation now reflects OpenClaw's eager activation-time
  in-memory resolution rather than claiming lazy post-approval resolution.

`clustrmaps` and `peekyou` remain externally unavailable in current independent
observation. RightOut preserves their archived normalized route evidence and treats
separately sourced rescue email as an independent submission method, never as
proof that the primary form ran.

This release may claim 22/22 normalized broker/method/route/input coverage and
conditional autonomous execution where the provider has authorized it. It does
not claim 100% provider-specific playbook choreography, capability parity,
default autonomous forms, browser-only authenticated verification,
distorted-text OCR, retrievable screenshots, universal deletion, or commercial
managed-service inventory parity.
