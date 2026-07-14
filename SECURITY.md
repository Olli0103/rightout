# Security and privacy posture

RightOut supports per-effect assisted tools and bounded autonomous campaigns. The core Brave, exact-URL direct-read, IMAP read/link, SMTP, and closed browser-form tools each receive their own native OpenClaw `allow-once` when invoked without a campaign. Generic-form/outbound-webmail sessions and publisher-browser discovery are campaign-bound. Every form/publisher route additionally requires current written provider authorization bound to the reviewed terms digest; subject/operator consent or an attestation alone is insufficient. Current public evidence authorizes zero reference form routes. In autonomous mode, one native `allow-once` creates a finite, encrypted, revocable campaign grant bound to one opaque profile, exact broker/effect sets, combined catalog/provider-terms and runtime-scope digests, a 1-720 hour lifetime, and a hard effect budget. Every later effect revalidates that durable scope and consumes budget; scope widening, mutation, renewal, or reuse after expiry/revocation is impossible.

An optional durable worker requires a second native approval and binds itself to
that campaign, the current trusted session, the runtime/catalog policy, and the
signed recipe pack. It holds at most one atomic lease, issues only a fixed
RightOut tool/parameter command, and accepts completion only after the campaign
ledger evidences the matching effect. It backs off on transient failures and
stops on ambiguity, drift, repeated failure, human gates, campaign closure, or
revocation. Resume requires another approval and the original unchanged scope.

Destructive local purge, state-key rotation, ambiguous-write reconciliation,
human-reviewed controller outcomes, evidence/dashboard export, California DROP
filing attestation, campaign creation/revocation, and worker enable/resume retain
dedicated native approval boundaries. Interactive decisions time out to deny
after two minutes and are bound to the host tool-call ID and exact normalized
scope.

EU controller lanes additionally bind the exact request kind, EU/EEA plus country consistency, official recipient, fixed GDPR template, and catalog-minimum disclosure. The initial EU request uses contact email and country, plus full name only for Lead411, 6sense, Cognism, and Lusha. US-CA controller lanes bind `delete_and_opt_out`, California eligibility, the official recipient, and full name/contact email/region/country. No lane attaches identity documents or claims erasure/deletion from SMTP acceptance. An authenticated exact-thread controller reply may produce only an encrypted literal outcome candidate. Conflicting, quoted, or unknown text stays manual, and a separately approved tool can record only an operator-personally-reviewed controller outcome. Browser/device preference controls remain human-only and are never treated as deletion proof.

## Data boundaries

- Public tool arguments and reports contain opaque references and field categories only.
- Profiles, Brave/SMTP/IMAP credentials, sender/mailbox addresses, and the
  listing-token encryption key are declared SecretInput paths and must be
  SecretRefs. OpenClaw resolves active refs eagerly into an in-memory activation
  snapshot. Local setup/status/export/doctor paths may read resolved config or
  encrypted state to validate/decrypt/probe but never return it; RightOut does
  not send subject PII or provider credentials externally until an exact
  assisted approval or validated finite campaign grant.
- Brave queries use POST to the fixed guarded endpoint. Query/result bodies and Brave result URLs are discarded and never returned. Only a separately provider-authorized browser discovery may encrypt its current official-domain URL into private state.
- The durable case ledger stores broker IDs, state, dates, disclosure field names, sanitized reasons, and opaque proof references—never raw PII, messages, URLs, queries, or page bodies.
- Optional evidence records accept only bounded sanitized case/controller/route
  facts, are content-addressed and encrypted, and expose metadata only. Redacted
  export requires native approval, a private contained directory, and a second
  sensitive-value scan. Custom-target URLs and source facts enter only through
  an out-of-band local CLI, stay encrypted behind a random opaque handle, and do
  not create a provider execution lane.
- Every subject/provider-effect lane is checked against catalog `last_verified`
  and `freshness_days` before approval and again immediately before execution.
  The separately approved PII-free maintenance refreshes are the narrow
  exception needed to renew those facts: registry refresh is pinned to the
  official CPPA CSV, while publisher-route refresh probes only routes with
  current written provider authorization, captures no body, skips all other
  routes, and never mutates the catalog automatically.
- Direct rechecks decrypt exact candidate URLs only inside the plugin, allow only catalog official domains, deny redirects, bound responses to 1 MB, and require a full name plus one configured corroborator for presence.
- IMAP is read-only and Gmail-only, bounded to post-submission INBOX messages, and requires the intended recipient, IMAP `INTERNALDATE` after the recorded submission, exactly one receiver-added `mx.google.com` authentication result with aligned DKIM for the catalog sender domain, plus a catalog-domain link. Raw mail and URLs never enter output; injected authentication headers fail closed.
- SMTP is provider/port/TLS pinned and the sender must equal the subject contact
  email. Password and OAuth2 modes are mutually exclusive. OAuth access tokens
  must be SecretRefs with a future lifetime between one minute and 24 hours and
  are covered by protocol-separated transport bindings without entering tool
  input/output. Browser form actions use closed catalog contracts through either the
  production OpenClaw sandbox bridge or the opt-in standalone host transport.
- Generic browser sessions accept only current ARIA refs and catalog field names. Managed, remote/cloud CDP, and logged-in browser profiles use the loopback OpenClaw browser-control bridge; optional bearer tokens are SecretRefs. Outbound webmail snapshots redact compose content. Browser-only inbound verification performs zero mailbox I/O; authenticated Gmail IMAP is required for autonomous inbox processing.
- Browser sessions pin the top-level page to catalog official origins before and after actions, but OpenClaw does not expose a per-session RightOut subresource/XHR egress allowlist. Embedded provider processors may receive requests; this is disclosed in approval/docs and publisher automation remains denied without current written authorization covering the processing.
- Verification links are scored fail-closed for HTTPS, embedded credentials, non-standard ports, official-domain membership, and verification intent before becoming an opaque handle or clickable browser control.
- Optional effectiveness reports use sanitized ledger states plus explicit
  profile/broker/state/time-consistent authorized canary references. Software
  capability, SMTP acceptance, and test coverage never count as operational
  effectiveness proof; absent a qualifying canary the verdict is
  `needs_evidence`.
- Static dashboards contain only team-authorized sanitized cases, due work,
  route health, evidence-reference counts, and effectiveness aggregates. They
  are content-addressed private local files with strict CSP, no script, form,
  iframe, remote asset, or network service.

## Fail-closed rules

CAPTCHA, distorted static text, OTP, identity-document requests, ambiguous form controls, missing transition evidence, redirects, block pages, oversized responses, partial direct checks, changed profiles/transports/provider-permission records, invalid catalog scope, expired handles, and denied/expired approvals perform no unapproved follow-on action. They become inconclusive, blocked, or human tasks. Strict arithmetic is the only challenge class computed locally.

Durable submission intent is written before every provider write. A possible write failure becomes `submission_uncertain`, retains dedupe, and survives Gateway restart; it is never automatically retried. Only a separately approved operator review may record `provider_write_not_started` and release retry eligibility, or `provider_write_confirmed` and continue tracking. Campaign autonomy stops at this state.

Durable workers never reinterpret an unresolved lease as success. A policy,
recipe, session, runtime, catalog, or campaign mutation fails before another
command. An expired lease issued before its effect becomes a human gate; a lease
that expired before a plan was issued may be safely reclaimed. Repeated
transient failures stop at the configured threshold instead of looping.

Campaigns, workers, cases, intents, dedupe records, evidence, custom targets,
controller candidates, and verified PeopleConnect flow handles are encrypted
and restart-safe. Active form, discovery, and webmail
sessions are intentionally memory-only: RightOut cannot resume or automatically
close their host/logged-in tabs after an unclean Gateway stop. Gmail may retain
an autosaved PII-containing draft, and filled publisher tabs may remain open.
After a crash/restart, the operator must inspect the named browser profile,
discard any draft, close leftover tabs, review any durable pending intent, and
run `rightout_doctor({})` before resuming. Do not interpret
`durable_campaign_case_resume_ready` as browser-session recovery.

US people-search removal execution requires durable discovery evidence first. Catalog-locked EU/EEA and US-CA controller data-subject requests use `not_required_for_data_subject_request`; their jurisdiction eligibility, controller, minimum identifiers, consent, and approval are independent gates. Consent must contain a finite `validUntil` after `recordedAt`, no more than 365 days later, and still be valid at execution. Disabling/replacing the SecretRef profile is the revocation mechanism. Inbox verification additionally requires a submitted case and binds every opaque link handle to that case's submission timestamp and evidence reference. Subject-state purge is local-only, separately approved, and reports that the configured profile SecretRef remains until the operator removes it from OpenClaw configuration.

Encrypted subject cases expire after 30-730 inactive days (365 by default).
Verification handles, listing handles, and submission dedupe retain shorter
fixed TTLs. Key rotation accepts one active and up to three temporary previous
SecretRef keys; every store stays readable if rotation is interrupted and is
rewritten under the active key. Rotation is separately approved, emits no key
or PII values, and performs no provider call. Previous refs remain configured
until the success report and are then removed.

## Evidence semantics

- Brave or publisher-browser candidate: `indirect_exposure`, never identity proof.
- Search-index absence: `inconclusive`, never removal proof.
- SMTP acceptance: `submitted`, not broker delivery or processing.
- Browser form success: `verification_pending`, not removal.
- Confirmation-link open: `awaiting_processing`, not removal.
- Direct presence: `found`, or `reappeared` after a prior confirmation.
- First direct 404/410 across every known encrypted listing URL after a prior removal: `awaiting_processing`, never confirmation.
- Second time-separated direct 404/410 across the same known set after the durable recheck time: `confirmed_removed`, scoped to `known_listing_set_only`.
- Human-reviewed EU/US controller erasure/deletion confirmation: `confirmed_removed`, scoped to `controller_response_only`; other identifiers/controllers remain unchecked.

Operator attestations are deployment gates, not legal certification. RightOut does not provide legal advice, guarantee deletion, cover private databases, or verify that no other listing exists.

## Deployment guidance

Add every tool marked `replaySafe: false` in `openclaw.plugin.json` to
`gateway.tools.deny` unless full-operator `/tools/invoke` is intentionally
required. If `teamAccess` is configured, deny **all 50 RightOut tools** on that
surface; otherwise direct full-operator invocation is a critical role-bypass
finding. Team members remain bound to exact session/profile scopes, but
third-party OpenClaw plugins are trusted in-process code, not tenant sandboxes.
Isolate mutually untrusted operators by Gateway and OS identity. Run `openclaw
secrets audit --check` and `openclaw security audit --deep` after every
configuration change.

Report vulnerabilities privately through the repository security advisory channel. Do not include real PII, credentials, live listing URLs, or broker mail in reports or fixtures.
