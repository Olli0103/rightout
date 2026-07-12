# Architecture

```text
opaque tool input
      |
before_tool_call: catalog scope + policy snapshot + native allow-once
      |
SecretRef resolution and post-approval digest/preflight checks
      |
      +-- Brave POST discovery ----------------> indirect signal
      |       +-- exact official URL -> AES-GCM opaque listing handle
      |
      +-- encrypted exact URL direct read -----> present / absent-known-set / inconclusive
      +-- pinned SMTP email -------------------> submitted
      +-- sandbox browser recipe --------------> verification_pending / human task
      +-- read-only pinned IMAP ----------------> opaque verification handle
      +-- domain-bound confirmation GET --------> awaiting_processing
      |
durable encrypted PII-safe case ledger in the OpenClaw state directory
      +-- next actions
      +-- case status
      +-- due rechecks for official OpenClaw Cron
```

## Trust boundaries

The model sees only opaque profile/broker/handle references and sanitized reports. OpenClaw resolves SecretRefs inside trusted plugin execution. The plugin hook owns single-use approval bindings keyed to host tool-call IDs; caller JSON, HMAC receipts, prose consent, or a prior approval are never security boundaries.

Brave discovery and every subsequent live step are separate tools. Exact candidate URLs are transiently inspected from Brave results, encrypted with AES-256-GCM under an operator SecretRef, and stored as ciphertext in RightOut's private OpenClaw state-directory store. The durable case ledger never stores them.

Direct publisher reads use only decrypted exact candidate URLs, official-domain SSRF policy, HTTPS, no credentials, no redirects, one-megabyte response limits, and no captured/raw output. A presence match requires the configured full name plus one configured location/address/email/phone corroborator. CAPTCHA, access denial, redirects, or partial absence are inconclusive.

Email/form/verification implementations are independently catalog-locked. The browser lane uses only the host-supplied sandbox bridge and a closed ARIA recipe. IMAP opens INBOX read-only and returns an opaque handle only when both sender and HTTPS link domains match. SMTP has a provider/port/TLS allowlist and minimum-disclosure template.

## State and evidence

The ledger supports `new`, `searching`, `inconclusive`, `not_found`, `found`, `indirect_exposure`, `action_selected`, `submitted`, `verification_pending`, `awaiting_processing`, `confirmed_removed`, `reappeared`, `human_task_queued`, and `blocked`.

Only trusted direct absence after a prior removal can produce `confirmed_removed`; the scope is the encrypted known listing set. Only trusted direct presence can turn it into `reappeared`. Brave observations never downgrade a confirmed state because search indexes can be stale.

The community plugin cannot use the bundled-only keyed-store or session-turn scheduler APIs. It uses only the public state-directory resolver with contained atomic encrypted files, and exposes deterministic replay-safe `rightout_due_rechecks` for official OpenClaw Cron. Cluster planning prefers an official parent request where registry evidence says one request covers related sites, while later verification remains per known site.
