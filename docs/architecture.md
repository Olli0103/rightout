# Architecture

```text
opaque tool input
      |
team session/profile/role scope (when enabled)
      |
before_tool_call: native allow-once OR encrypted finite campaign scope
      |
OpenClaw activation-time SecretRef snapshot; RightOut post-approval use/preflight
      |
      +-- durable worker ----------------------> one leased grammar-bound command
      |       +-- current trusted session schedule OR explicit Cron handoff
      |       +-- checkpoint / backoff / human gate / revoke
      |
      +-- Brave POST discovery ----------------> indirect signal
      +-- publisher browser discovery ---------> encrypted indirect candidate
      |       +-- exact official URL -> AES-GCM opaque listing handle
      |
      +-- encrypted exact URL direct read -----> present / absent-known-set / inconclusive
      +-- password/OAuth SMTP / webmail ------> submitted
      +-- managed/remote browser session ------> verification_pending / human task
      |       +-- blocked primary -> one distinct remote-CDP profile retry
      +-- password/OAuth Gmail IMAP -----------> opaque verification / controller candidate
      +-- bound browser mail -------------------> authenticated opaque confirmation control
      +-- domain-bound confirmation GET --------> awaiting_processing
      |
durable encrypted PII-safe case ledger in the OpenClaw state directory
      +-- encrypted content-addressed evidence vault
      +-- encrypted custom-target quarantine
      +-- next actions
      +-- case status
      +-- due rechecks and effectiveness metrics
      +-- Markdown / JSON / Google Sheets rows
      +-- static local HTML/JSON dashboard export
```

## Trust boundaries

The model sees only opaque profile/broker/handle references, catalog field names,
ARIA refs, and sanitized reports. OpenClaw resolves active SecretRefs eagerly at
Gateway activation into an in-memory snapshot. RightOut reads/uses those values
only after an exact assisted binding or matching campaign. The plugin hook owns
single-use bindings keyed to host tool-call IDs. Autonomous effects match an
encrypted finite campaign containing exact profile, brokers, effect classes,
combined catalog/provider-terms digest, runtime-scope digest, expiry, and budget.
Caller JSON, prose consent, or an unrelated approval are never security boundaries.

An optional encrypted worker record adds a second boundary: campaign, signed
recipe pack, runtime policy, and one-way trusted-session digests must still
match. Atomic leases exclude concurrent turns, commands are validated against a
fixed tool/parameter grammar, and completion is accepted only after the host
records the terminal result of that exact tool, normalized parameters, session,
run, call, still-live lease, and execution digest. Completion boundedly waits
for asynchronous host-hook receipt persistence instead of racing it. Interactive multi-step commands and
inconclusive direct rescans stop for operator continuation instead of being
misclassified as complete. Scheduling can target
only the current bound session after native approval. Lease watchdogs and
startup reconstruction restore active wakes after a crash without renewing or
expanding campaign profile, broker, effect, time, or budget scope. An
unavailable or partially failed replacement schedule moves the worker to a
durable human gate before another command is exposed. Schedule replacement is
state-directory coordinated across processes, and startup recovery must still
match the durable worker schedule token before it may replace a wake. Any local
planning or state failure after a lease is claimed is caught and persisted as a
human gate before the consumed one-shot wake can be lost.

Optional team mode binds each `owner`, `manager`, or `viewer` to one exact
OpenClaw session digest and configured profile set. Managers and viewers receive
sanitized read views only; campaign/worker authority is deliberately omitted.
Owners also fail outside their configured profile set. Because OpenClaw's
full-operator direct tool-invoke surface is higher authority than an agent
session, team mode treats any RightOut tool missing from `gateway.tools.deny` as
a critical audit finding. This is deployment-local isolation, not a hosted
multi-tenant security claim.

Brave discovery and every subsequent live step are separate tools. Core scan,
exact-listing read, SMTP, closed-form, IMAP, and link-open tools may be assisted
individually or consume one matching campaign effect. Generic form/outbound
webmail sessions and publisher-browser discovery are campaign-bound. Form and
publisher access additionally require a current written provider authorization
bound to the reviewed terms contract; operator attestation alone is insufficient.
Brave result URLs are transient and are neither persisted nor returned. Only a
separately authorized bounded publisher-browser session may encrypt its current
official-domain URL into an AES-256-GCM opaque listing handle. The durable case
ledger stores the opaque handle, never plaintext URLs or page bodies.

Direct publisher reads use only decrypted exact candidate URLs, official-domain SSRF policy, HTTPS, no credentials, no redirects, one-megabyte response limits, and no captured/raw output. A presence match requires the configured full name plus one configured location/address/email/phone corroborator. CAPTCHA, access denial, redirects, or partial absence are inconclusive.

Email/form/verification implementations are independently catalog-locked.
Browser sessions use only the OpenClaw bridge, named managed/remote/logged-in
profiles, current ARIA refs, and internal catalog/profile values. The doctor
deep-probes the selected profile; a blocked primary may retry once through a
separate remote-CDP profile, without claiming a solver or bypass. DOB is
disclosed only after an additional exact native human approval. Outbound webmail
snapshots redact compose content. Browser inbound verification is bound to one
exact logged-in Gmail profile and exposes only a recipient-matched message with
an allowed `signed-by`/`mailed-by` domain plus one HTTPS confirmation control on
an allowlisted broker domain. Raw mail and link values stay in the browser
control plane. IMAP opens INBOX read-only and returns an opaque handle only after
intended-recipient and aligned-DKIM checks; links also pass fail-closed phishing
scoring. SMTP has a provider/port/TLS allowlist and minimum-disclosure template.
Password and OAuth2 transports are mutually exclusive. OAuth access tokens must
be SecretRef-resolved, live between one minute and 24 hours, and are included in
protocol-separated transport bindings without entering tool input or output.
Authenticated controller replies additionally require exact recipient,
receiver-added aligned DKIM, official sender domain, post-submission time, and
the outgoing Message-ID thread; even then they become encrypted candidates, not
automatic controller outcomes.

## State and evidence

The ledger supports `new`, `searching`, `inconclusive`, `not_found`, `found`, `indirect_exposure`, `action_selected`, `submission_pending`, `submission_uncertain`, `submitted`, `verification_pending`, `awaiting_processing`, `identity_verification_required`, `partially_removed`, `request_rejected`, `confirmed_removed`, `reappeared`, `human_task_queued`, and `blocked`.

For people-search cases, only a second time-separated trusted direct absence after a prior removal and after the durable recheck time can produce `confirmed_removed`; the scope is the encrypted known listing set. A separately approved, operator-reviewed EU or US controller response can confirm only `controller_response_only`. Only trusted direct presence can turn a listing-set confirmation into `reappeared`. Brave observations never downgrade a confirmed state because search indexes can be stale.

Every SMTP/form effect first commits an encrypted `submission_pending` intent. A possibly-effectful failure becomes `submission_uncertain`; the planner blocks new external writes until a separately approved human reconciliation records either `provider_write_not_started` or `provider_write_confirmed`. Opaque listing handles are retained in the encrypted case record so a later worker or Cron turn can resume without raw URLs.

The community plugin uses the public state-directory resolver with contained
atomic encrypted files. Where the supported host exposes public
`session.workflow` scheduling, an approved worker schedules only its bound
current session; otherwise it emits a deterministic replay-safe Cron handoff.
The evidence vault stores only sanitized bounded records. Its encrypted export
index makes private redacted artifacts subject-, retention-, purge-, and
rotation-aware, schedules their next expiry while idle, and removes interrupted
managed exports on cleanup. Export, cleanup, subject purge, and key rotation are
serialized behind one state-directory-wide cross-process transaction lock so a
successful concurrent export is either durably tracked or subsequently purged,
never orphaned after a reported purge. Failed unlink operations retain the
encrypted index and fail closed. Custom target
facts stay encrypted behind opaque handles and remain non-executable until a
strict Ed25519-signed recipe plus exact current permission is present. Static
dashboard exports are private mode-0600 files with strict CSP, no scripts,
remote assets, forms, or network service. Cluster planning prefers an official
parent request where registry evidence says one request covers related sites,
while later verification remains per known site.
