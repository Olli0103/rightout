# RightOut / Unbroker parity contract

Reference: official Hermes Unbroker tree at `NousResearch/hermes-agent` commit
`e589b739ca70eba00aa90fd3d0228bada00dbf8f`, reviewed 2026-07-13. The exact
subtree hash is refreshed immediately before release.

This is a clean-room product comparison. RightOut may independently implement
the same outcome, but it does not copy Unbroker code, broker records, templates,
prose, screenshots, or site playbooks. External route facts need independent
official provenance.

## Three separate claims

RightOut never collapses these into one “100%” number:

1. **Normalized contract coverage:** all 22 broker IDs and the exact 20-form,
   one-email, one-phone method/route/input inventory are represented; form
   contracts are generic-fixture tested.
2. **Capability coverage:** campaign, discovery, forms, outbound mail,
   authenticated IMAP, verification links, registry/DROP, rechecks, reporting,
   and recovery have executable RightOut implementations or explicit human
   safety gates.
3. **Currently permitted autonomous execution:** a form/publisher route is live
   only with current written provider authorization bound to the reviewed terms
   contract. Current public evidence permits zero reference form routes, while
   8 explicitly prohibit automation and 14 remain `needs_evidence`.

The normalized contract and technical capability claims were completed in
0.8.1 and remain unchanged and fully gated in 0.9.0.
`implemented` means the same feature is executable; `equivalent_or_stronger`
means RightOut reaches the same technical outcome with a stricter safety or
provenance boundary. Exact provider-specific choreography beyond the reference
generic recipe surface is independently staged only for PeopleConnect. The
third claim is deliberately not called complete. A product cannot infer a
publisher license from subject consent, public reachability, a privacy right,
or Unbroker's implementation.

## Required behavior

- one recorded subject consent plus one finite campaign can drain all effects
  that are within exact scope and separately provider-authorized;
- the grant binds one opaque profile, exact broker/effect set, combined
  core/parity/provider-terms catalog digest, browser/transport/provider-
  permission runtime digest, 1–720 hours, and 1–2,000 effects;
- changed profile, catalog, browser, transport, permission, expiry, revocation,
  or budget fails before provider I/O;
- DOB needs a separate exact critical `allow-once` at the form step;
- static arithmetic is solved locally and an explicitly identified static text
  challenge accepts only its one short snapshot-bound value; dynamic CAPTCHA, OTP, slider,
  security-question, ID, phone, fax, mail, payment, and account gates are human;
- Brave uses the official POST API and keeps query/result bodies and result URLs
  transient;
- SMTP/browser send is only `submitted`; broker receipt/deletion is not inferred;
- browser-only inbound mail uses one exact logged-in Gmail profile binding,
  recipient match, allowed `signed-by`/`mailed-by` domain, and one HTTPS
  allowlisted confirmation control; raw mail and link values are not returned;
  pinned Gmail IMAP remains the structured alternative;
- two time-separated direct absences over the complete known encrypted listing
  set are required for people-search `confirmed_removed`;
- every ambiguous write records durable intent and blocks retry until separately
  approved reconciliation;
- no real person, live mailbox, form, or broker write is used in release tests.

## Public outcome map

| Unbroker outcome | RightOut equivalent |
| --- | --- |
| setup / doctor | `rightout_setup`, `rightout_doctor` |
| browser/CDP detection | named OpenClaw managed, remote/cloud, or logged-in profile plus deep doctor probe |
| intake / dossiers | operator-managed SecretRef profiles; no public PII argument |
| broker inventory | `rightout_unbroker_parity_health` with route and provider-terms state |
| source refresh | PII-free probe only for currently written-authorized publisher routes; all others skipped; no automatic catalog mutation |
| plan / next / done | `rightout_next_actions`, finite campaign, deterministic `rightout_campaign_next` |
| fanout discovery | one bounded four-worker Brave POST batch |
| publisher discovery | separately permission-bound official-domain browser session |
| form removal | generic semantic sessions with durable intent and redacted semantic-state receipts; PeopleConnect has a staged path |
| email send | pinned SMTP or redacted outbound Gmail compose |
| poll / verify link | receiver-authenticated Gmail IMAP plus opaque official-domain link open |
| browser inbox fallback | bound Gmail session with recipient + sender-authentication evidence and an allowlisted confirmation control |
| registry / DROP | CA registry plus VT/OR/TX routing and human-filed DROP record |
| show / due / tasks | case status, due queue, consolidated human digest |
| status / Sheets report | Markdown, structured JSON, and Sheets-compatible rows |

An independently sourced rescue email is additive. It may proceed when its own
recipient, disclosures, provenance, freshness, consent, transport, and campaign
gates pass. It proves only that email submission, never that the primary form
ran or deletion occurred.

## Release evidence

- exact machine-readable baseline and 22-route catalog;
- per-route provider-terms catalog and fail-closed permission bindings;
- dummy/sandbox tests for every normalized contract and effect class, including the staged
  PeopleConnect sequence and mutation/adversarial failures;
- restart, expiry, revocation, budget, scope, permission, duplicate, and
  uncertain-write recovery tests;
- stable/beta packaged OpenClaw inspection, doctor, config/SecretRef/security
  audits, coverage thresholds, Python/installer matrix, npm audit, SBOM,
  checksums, provenance, and independent closing review;
- immutable upstream subtree refresh immediately before publication.

The release may claim complete pinned normalized broker/method/route/input
coverage and complete technical capability parity against this exact reference
subtree. It may not claim complete provider-specific choreography beyond the
reference generic recipe surface, default operational autonomy, current
provider permission, retrievable screenshots, universal deletion, measured
real-world effectiveness, or managed-service inventory parity unless those
facts later become evidenced and tested.
