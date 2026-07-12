# Security and privacy posture

RightOut `0.6.0` treats live broker work as a sequence of independent high-impact actions. Native OpenClaw approval is mandatory for Brave discovery, exact-URL publisher reads, IMAP reads, confirmation-link opens, SMTP sends, sandbox-browser form writes, destructive local purge, human-reviewed controller outcomes, and ambiguous-write reconciliation. Decisions are `allow-once` or `deny`, expire after two minutes, and are bound to the host tool-call ID, exact opaque scope, configuration attestations, and profile digest.

EU controller lanes additionally bind the exact request kind, EU/EEA plus country consistency, official recipient, fixed GDPR template, and catalog-minimum disclosure. Adsquare requires the private profile's Mobile Advertising ID; emetriq initially discloses only contact email and country. Neither lane attaches identity documents, parses controller responses, or claims erasure from SMTP acceptance. A separately approved tool can record only an operator-personally-reviewed controller outcome. Browser/device preference controls remain human-only and are never treated as deletion proof.

## Data boundaries

- Public tool arguments and reports contain opaque references and field categories only.
- Profiles, Brave/SMTP/IMAP credentials, sender/mailbox addresses, and the listing-token encryption key are declared SecretInput paths and must be SecretRefs.
- Brave queries use POST to the fixed guarded endpoint. Search result content is discarded; same-domain candidate URLs become encrypted tokens in private contained state-directory files only when an encryption key is configured.
- The durable case ledger stores broker IDs, state, dates, disclosure field names, sanitized reasons, and opaque proof references—never raw PII, messages, URLs, queries, or page bodies.
- Direct rechecks decrypt exact candidate URLs only inside the plugin, allow only catalog official domains, deny redirects, bound responses to 1 MB, and require a full name plus one configured corroborator for presence.
- IMAP is read-only and Gmail-only, bounded to post-submission INBOX messages, and requires the intended recipient, IMAP `INTERNALDATE` after the recorded submission, exactly one receiver-added `mx.google.com` authentication result with aligned DKIM for the catalog sender domain, plus a catalog-domain link. Raw mail and URLs never enter output; injected authentication headers fail closed.
- SMTP is provider/port/TLS pinned and the sender must equal the subject contact email. Browser form recipes are closed catalog contracts through the host sandbox bridge.

## Fail-closed rules

CAPTCHA, identity-document requests, ambiguous form controls, missing success evidence, redirects, block pages, oversized responses, partial direct checks, changed profiles/transports, invalid catalog scope, expired handles, and denied/expired approvals perform no unapproved follow-on action. They become inconclusive, blocked, or human tasks.

Durable submission intent is written before every provider effect. A possible write failure becomes `submission_uncertain`, retains dedupe, and survives Gateway restart; it is never automatically retried. Only a separately approved operator review may record `provider_write_not_started` and release retry eligibility, or `provider_write_confirmed` and continue tracking.

US people-search removal execution requires durable discovery evidence first. Catalog-locked EU/EEA and US-CA controller data-subject requests use `not_required_for_data_subject_request`; their jurisdiction eligibility, controller, minimum identifiers, consent, and approval are independent gates. Consent must contain a finite `validUntil` after `recordedAt`, no more than 365 days later, and still be valid at execution. Disabling/replacing the SecretRef profile is the revocation mechanism. Inbox verification additionally requires a submitted case and binds every opaque link handle to that case's submission timestamp and evidence reference. Subject-state purge is local-only, separately approved, and reports that the configured profile SecretRef remains until the operator removes it from OpenClaw configuration.

## Evidence semantics

- Brave candidate: `indirect_exposure`, never identity proof.
- Search-index absence: `inconclusive`, never removal proof.
- SMTP acceptance: `submitted`, not broker delivery or processing.
- Browser form success: `verification_pending`, not removal.
- Confirmation-link open: `awaiting_processing`, not removal.
- Direct presence: `found`, or `reappeared` after a prior confirmation.
- First direct 404/410 across every known encrypted listing URL after a prior removal: `awaiting_processing`, never confirmation.
- Second time-separated direct 404/410 across the same known set after the durable recheck time: `confirmed_removed`, scoped to `known_listing_set_only`.
- Human-reviewed EU controller erasure confirmation: `confirmed_removed`, scoped to `controller_response_only`; other identifiers/controllers remain unchecked.

Operator attestations are deployment gates, not legal certification. RightOut does not provide legal advice, guarantee deletion, cover private databases, or verify that no other listing exists.

## Deployment guidance

Add all nine approval-gated tools to `gateway.tools.deny` unless full-operator `/tools/invoke` is intentionally required. Run `openclaw secrets audit --check` and `openclaw security audit --deep` after every configuration change. Third-party OpenClaw plugins are trusted in-process code, not tenant sandboxes; isolate mutually untrusted operators by Gateway and OS identity.

Report vulnerabilities privately through the repository security advisory channel. Do not include real PII, credentials, live listing URLs, or broker mail in reports or fixtures.
