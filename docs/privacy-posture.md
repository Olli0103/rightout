# Privacy posture

Review date: 2026-07-16. Engineering documentation, not legal advice or certification.

The model sees only opaque references, catalog field names, and current redacted
browser refs. OpenClaw resolves active SecretRefs eagerly during Gateway
activation into an in-memory snapshot. Local setup/status/export/doctor paths
may read resolved config or encrypted state to validate, decrypt, or probe but
never return it. RightOut does not send subject PII or provider credentials to
an external provider until an assisted approval or matching finite campaign
grant; SecretRefs are not process isolation.

Brave may receive configured full names/aliases, current/prior locations or
addresses, emails, and phones in bounded POST search vectors. The standard-plan
privacy notice permits query-log retention up to 90 days unless an applicable
Zero Data Retention agreement changes that posture. RightOut stores neither
query/result bodies nor Brave result URLs and returns no raw Brave content or URL.
ISO-country profiles are supported. Where Brave exposes the exact country target,
RightOut also selects a matching search language (for example `DE/de`); otherwise
it uses the explicit worldwide target rather than silently defaulting to US.
An index hit is only an indirect official-domain signal. No hit—especially for
controller, adtech, or B2B domains with no public person surface—is never proof
that the controller holds no subject data.

Only a separately authorized publisher-browser session may encrypt its current
official-domain URL with AES-256-GCM into an opaque token for later recheck.
Plaintext URLs and page content are never stored in the case ledger or returned
to the model. A `publisher_discover` effect requires a current written provider
authorization bound to the reviewed terms contract; publisher terms attestations
or subject consent alone are insufficient. The redacted capture remains an
indirect signal. A separately approved direct recheck reads only that exact URL
and locally compares full name plus a strong configured corroborator.

Removal disclosures are catalog-minimal. The core examples remain:

- BeenVerified email: full name, contact email, region, country;
- EU controller emails: contact email and country, plus full name only for Lead411, 6sense, Cognism, and Lusha;
- UK Cognism controller email: full name, contact email, and country under a separate UK-only request, identity, eligibility, and calendar-month recheck contract;
- California controller emails: full name, contact email, region, country;
- PeopleConnect form initiation: contact email only.

The exact Unbroker parity catalog permits only each route's independently
recorded field categories. Generic form and Gmail sessions resolve those values
inside the plugin; model-visible snapshots replace them with placeholders and
strip unrelated inbox/message content.

EU, UK, and US controller emails use market-specific fixed request templates and stop at `submitted`.
An exact recipient, post-submission, receiver-DKIM-authenticated, official-domain,
Message-ID-thread reply may become an encrypted literal candidate. Conflicting,
quoted, or unknown text and every proportionate identity follow-up remain human
work; recording any outcome needs separate approval. RightOut sends zero
attachments or identity documents and never stores response content. EDAA and
emetriq browser-preference controls are human-only and never recorded as
controller erasure.

SMTP/IMAP/webmail providers and brokers process data under their own policies.
RightOut does not claim zero provider retention. IMAP opens recent INBOX content
read-only and emits neither raw messages nor links. Browser webmail exposes only
catalog-bound outbound compose controls; the inbound browser-mail tool performs
zero mailbox I/O and hands off to a human because authenticated receiver headers
are unavailable in the normal UI contract. IMAP confirmation links stay behind
opaque short-lived handles and pass HTTPS/domain/credential/port scoring.
Password and short-lived OAuth2 modes are mutually exclusive. OAuth tokens are
SecretRefs, never tool arguments or reports, and must expire between one minute
and 24 hours in the future when used.

The durable ledger stores opaque subject/broker IDs, state, timestamps,
disclosure field names, sanitized reasons, due dates, and opaque proofs. It
excludes profile values, queries, candidate URLs, messages, page bodies,
credentials, Message-IDs, and raw receipts. Durable workers store only opaque
campaign/profile/broker references, policy/session digests, lease state, and
sanitized reasons. Optional evidence records accept only sanitized bounded
state facts. Managed redacted exports are tracked in encrypted state, scheduled
for idle expiry, anchored to the original evidence retention window, and fail
purge closed without losing their tracking record when unlink is not confirmed.
Custom target facts remain encrypted behind random opaque handles.

Encrypted subject cases expire after the configured 30-730 day inactivity
period (365 days by default). Short-lived verification, listing, and dedupe
records keep narrower fixed TTLs. On first access, a legacy v1 case without an
expiry is migrated under lock to `createdAt + stateRetentionDays`; an already
expired legacy case is removed immediately. An explicitly approved subject
purge deletes local state earlier. State-key rotation uses one active and
temporary previous SecretRef keys; every store is rewritten under the active
key without exposing key material or PII, and prior refs are removed after
successful verification.

Optional team mode binds owner, manager, and viewer sessions to exact configured
profile sets. Team views never expose raw session identifiers or campaign/worker
authority. Static local dashboard exports are limited to the bound member's
authorized profiles and contain sanitized cases, due counts, route health,
evidence-reference counts, and aggregates only. The files are private and start
no network service. Team roles are not a hosted tenant boundary; every RightOut
tool must be denied on full-operator direct invoke.

Catalog `last_verified` plus `freshness_days` is an execute-time privacy and
destination gate, not only a release-time lint. A stale official source disables
live provider I/O and appears in the PII-free catalog-health report until the
source fact is reviewed and released again.

Evidence semantics are deliberately scoped: `indirect_exposure` is an index or publisher-browser candidate signal; `submission_uncertain` is a write that must not be retried; `submitted` is outbound transport evidence; `verification_pending` is a form/mail step; `awaiting_processing` follows a broker link, processing checkpoint, or first direct absence. People-search `confirmed_removed` requires prior removal plus two time-separated direct absences across the encrypted known listing set. EU, UK, and US controller emails never automatically enter it; a human-reviewed official response can confirm only `controller_response_only`. A DROP portal status, including `deleted`, remains a human-observed platform claim with no confirmation scope. A GPC observation is only an opt-out preference and records neither a deletion request nor provider compliance. New/unindexed URLs, unidentified controller records, other identifiers, non-registered DROP targets, FCRA exceptions, and site-specific GPC compliance are always gaps.

Effectiveness reports expose state-based numerators and denominators but default
to `needs_evidence`. Only explicit versioned out-of-band authorized canary facts
with opaque proof, authorization, and deployment-evidence references
consistent with the profile, broker, state, and observation time can evidence a
narrow operational outcome. Software capability, route count, SMTP acceptance,
and CI success are never treated as deletion effectiveness.

Consent and attestations are exact-scope, digest-bound, non-future technical gates. They are not proof of legal capacity, statutory applicability, or broker compliance. Operators remain responsible for SecretRef protection, subject authority, provider/publisher terms, least-privilege tool policy, Cron scope, and Gateway isolation.
