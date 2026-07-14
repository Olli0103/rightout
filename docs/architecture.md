# Architecture

```text
opaque tool input
      |
before_tool_call: catalog scope + native allow-once OR encrypted campaign scope
      |
OpenClaw activation-time SecretRef snapshot; RightOut post-approval use/preflight
      |
      +-- Brave POST discovery ----------------> indirect signal
      +-- publisher browser discovery ---------> encrypted indirect candidate
      |       +-- exact official URL -> AES-GCM opaque listing handle
      |
      +-- encrypted exact URL direct read -----> present / absent-known-set / inconclusive
      +-- pinned SMTP / redacted webmail ------> submitted
      +-- managed/remote browser session ------> verification_pending / human task
      |       +-- blocked primary -> one distinct remote-CDP profile retry
      +-- pinned IMAP --------------------------> opaque verification / provider page
      +-- bound browser mail -------------------> authenticated opaque confirmation control
      +-- domain-bound confirmation GET --------> awaiting_processing
      |
durable encrypted PII-safe case ledger in the OpenClaw state directory
      +-- next actions
      +-- case status
      +-- due rechecks for official OpenClaw Cron
      +-- Markdown / JSON / Google Sheets rows
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

## State and evidence

The ledger supports `new`, `searching`, `inconclusive`, `not_found`, `found`, `indirect_exposure`, `action_selected`, `submission_pending`, `submission_uncertain`, `submitted`, `verification_pending`, `awaiting_processing`, `identity_verification_required`, `partially_removed`, `request_rejected`, `confirmed_removed`, `reappeared`, `human_task_queued`, and `blocked`.

For people-search cases, only a second time-separated trusted direct absence after a prior removal and after the durable recheck time can produce `confirmed_removed`; the scope is the encrypted known listing set. A separately approved, operator-reviewed EU or US controller response can confirm only `controller_response_only`. Only trusted direct presence can turn a listing-set confirmation into `reappeared`. Brave observations never downgrade a confirmed state because search indexes can be stale.

Every SMTP/form effect first commits an encrypted `submission_pending` intent. A possibly-effectful failure becomes `submission_uncertain`; the planner blocks new external writes until a separately approved human reconciliation records either `provider_write_not_started` or `provider_write_confirmed`. Opaque listing handles are retained in the encrypted case record so a later Cron turn can resume without raw URLs.

The community plugin cannot use the bundled-only keyed-store or session-turn scheduler APIs. It uses only the public state-directory resolver with contained atomic encrypted files, and exposes deterministic replay-safe `rightout_due_rechecks` for official OpenClaw Cron. Cluster planning prefers an official parent request where registry evidence says one request covers related sites, while later verification remains per known site.
