# RightOut v0.9.0 autonomy-platform plan

Status: implementation complete through R1; independent review and final
post-fix release audit remain open. This document is the requirement and
evidence contract for the v0.9.0 work; a checked test or prose claim is not
sufficient unless the corresponding runtime boundary is also implemented.

## Product outcome

RightOut becomes a closed-loop, self-hosted privacy operator. An explicitly
enabled worker wakes a finite campaign, selects one deterministic next action,
executes only through the existing approval/provider-permission boundary,
records the outcome, schedules the next safe wake, and interrupts the operator
only for an evidenced human gate. It never converts technical capability into
provider permission or ambiguous evidence into success.

## Dependency order

1. Durable worker, leases, checkpoints, explicit scheduling, and recipe trust.
2. Provider-authorized direct channels, OAuth mail, and reply candidates.
3. Encrypted evidence and safe custom-target intake.
4. Effectiveness metrics, family/team isolation, and local dashboard exports.
5. Full release gates followed by independent autonomous review loops.

## Requirements and proof

| ID | Requirement | Authoritative proof |
| --- | --- | --- |
| A1 | Durable worker records are encrypted, restart-safe, campaign-bound, leased once, backoff-aware, and revocable. | Worker-store unit tests plus plugin-runtime restart, lease-race, expiry, revocation, mutation, and duplicate-effect tests. |
| A2 | Scheduling is explicit. A tool may schedule only the current trusted OpenClaw session after native approval; unsupported hosts return a deterministic Cron handoff. | Scheduler binding tests, no-session denial, host-unavailable fallback, tag cleanup, and manifest metadata. |
| A3 | Broker recipes are declarative, versioned, source-bound, integrity-checked, expiring, and quarantined on semantic drift. Built-ins are release-attested; external packs require an allowlisted Ed25519 key and detached signature. | Recipe validator/compiler tests, signature tests, expiry/drift tests, exact catalog coverage, and package-content gate. |
| A4 | The worker never invokes a provider effect directly from untrusted plan text. Commands must match the fixed RightOut tool/parameter grammar and an active lease. | Command allowlist/property tests and runtime rejection before provider I/O. |
| M1 | Mail transports support password-based existing providers plus OAuth 2.0 bearer authentication without placing tokens in tool input or reports. | Transport-digest tests, SMTP/IMAP OAuth protocol tests, token mutation tests, and redaction checks. |
| M2 | Authenticated controller replies produce bounded outcome candidates, not automatic legal conclusions. Only exact deterministic evidence may auto-advance a non-terminal deadline; terminal outcomes require separate approval. | Parser adversarial corpus, DKIM/authentication binding, candidate ledger tests, and controller-outcome approval tests. |
| E1 | Optional evidence artifacts are encrypted locally, content-addressed, retention-bound, never emitted in public tool output, and separately export-approved after redaction. | Vault encryption, tamper, retention, purge, path-containment, PII-output, and export-approval tests. |
| C1 | Custom targets accept only an opaque local handle. URL/domain/source facts stay encrypted; unknown routes are quarantined and cannot become provider actions without a signed recipe and current permission contract. | Intake/SSRF/domain-confusion tests, opaque-output checks, recipe/permission binding, and purge tests. |
| L1 | Effectiveness metrics use sanitized state transitions and canary facts only. They distinguish discovery, identity confidence, submission, provider confirmation, reappearance, uncertainty, and human handoff. | Deterministic aggregate tests and zero-PII report checks. |
| U1 | Family/team mode isolates every subject by profile digest and encryption scope. Roles can view sanitized status but cannot reuse another subject's authority, approvals, evidence, or campaign. | Cross-profile and cross-role adversarial runtime tests. |
| U2 | A local dashboard export provides sanitized cases, due work, route health, evidence references, and effectiveness metrics without becoming a network service. | JSON/HTML artifact snapshot tests, CSP/no-script checks, and PII scanners. |
| R1 | All existing v0.8.1 privacy, approval, provider-terms, uncertainty, retention, purge, provenance, and release gates remain true. | Full legacy suite, coverage thresholds, installer/runtime matrix, release checker, dependency audit, package inspection, and source diff review. |
| R2 | Independent autonomous review is repeated until the latest complete source tree has no evidenced open P0/P1/P2/P3 finding. | Versioned review reports, finding-to-fix tests, and a final re-review against the post-fix tree. |

## Current implementation evidence

- A1/A2/A4 implemented: encrypted deterministic workers, exact campaign/session/
  policy binding, atomic leases, unresolved-action gates, evidence-backed
  completion from exact host-observed command receipts, lease watchdogs,
  startup schedule recovery, exponential backoff, native session scheduling,
  deterministic Cron handoff, resume approval, and revocation. Interactive
  multi-step commands and inconclusive direct rescans stop for an operator
  instead of claiming completion. Receipts re-bind session, run, call ID, tool,
  normalized parameters, lease, and execution digest; failed wake recovery
  becomes a durable human gate.
  Evidence: `autonomy-worker.test.mjs` and
  `autonomy-worker-runtime.test.mjs`.
- A3 implemented: the release-attested 22-route pack binds the exact source and
  compiled digests, external packs require trusted strict Ed25519 key types and
  64-byte signatures, packs
  expire, and live form sessions quarantine domain, sensitive-control, policy,
  and semantic drift before provider writes. Evidence: `recipes.test.mjs`, form
  runtime suites.
- M1 implemented: password transport remains backward compatible; OAuth2 SMTP
  and IMAP use only a SecretRef-resolved, 1-minute-to-24-hour bearer token,
  reject mixed credentials, bind token/identity/expiry into protocol-separated
  digests, and never map OAuth credentials into password fields. Evidence:
  `smtp.test.mjs`, `imap.test.mjs`, and `transport-digest.test.mjs`.
- M2 implemented: controller replies are accepted only after exact recipient,
  receiver-added aligned DKIM, official sender domain, submission time, and
  exact outgoing Message-ID thread binding. Literal classifications become
  encrypted candidates; quoted, conflicting, or unknown text stays manual;
  every outcome including terminal candidates still requires a distinct native
  allow-once approval. Evidence: `controller-replies.test.mjs`,
  `controller-reply-runtime.test.mjs`, and `controller-outcome-runtime.test.mjs`.
- E1 implemented: sanitized case snapshots are scoped content-addressed records
  inside the authenticated encrypted store, use bounded retention, fail on
  tamper or sensitive keys/values, return metadata only, purge and rotate with
  the subject, and require a separate native approval for a private contained
  redacted export. An encrypted export index makes artifacts expire and purge
  with the subject, schedules idle cleanup, retains tracking on unlink failure,
  removes interrupted exports, and anchors the strictest deduplicated retention
  to original creation. Evidence: `evidence-vault.test.mjs` and
  `evidence-runtime.test.mjs`.
- C1 implemented as a safe intake boundary, not a new write lane: the local CLI
  accepts raw target facts out of band, stores them encrypted, and returns only
  a random opaque handle. Domain-confusion, credentials, IP targets, non-HTTPS,
  and Unicode-confusable hosts fail closed. Runtime readiness requires one exact
  trusted Ed25519 recipe plus current handle/recipe/domain/effect permission;
  provider execution remains explicitly disabled until a dedicated approved
  session exists. Evidence: `custom-targets.test.mjs` and
  `evidence-runtime.test.mjs`.
- L1 implemented: reports expose explicit numerators and denominators for
  discovery, identity confidence, submission, provider confirmation,
  reappearance, uncertainty, and human handoff. Operational effectiveness is
  `needs_evidence` unless profile/broker/state/time-consistent authorized canary
  facts are configured. Evidence: `effectiveness.test.mjs`.
- U1 implemented: one-way trusted-session bindings map owner, manager, and
  viewer roles to exact configured profile sets. Cross-profile access fails;
  managers/viewers cannot reuse campaign or worker authority; dashboard scope
  changes invalidate approval; and team mode raises a critical audit finding
  unless all 50 RightOut tools are denied on full-operator direct invoke.
  Evidence: `team-access.test.mjs`, `team-runtime.test.mjs`, and the runtime
  security-audit regression in `live-scan.test.mjs`.
- U2 implemented: owner/manager sessions may separately approve a static local
  HTML or JSON dashboard containing only sanitized authorized cases, due work,
  route health, evidence-reference counts, and effectiveness aggregates. Files
  are contained, content-addressed, mode 0600, strict-CSP/no-script, and start no
  service. Evidence: `dashboard.test.mjs` and `team-runtime.test.mjs`.
- R1 passed on the source-complete pre-review tree: technical parity,
  TypeScript, the complete 338/338 plugin suite, compiled build, package
  preflight and archive inspection, clean/force install and rollback, 50 Python
  tests, scan-only and end-to-end dummy runs, workflow hardening, and the
  dependency audit were green on 2026-07-14. Coverage is 90.38% lines, 74.77%
  branches, and 91.34% functions. The release checker has no implementation,
  package, privacy, provenance, or security finding; it intentionally remains
  open only for the requested independent review and final versioned audit.
  After the second review fixes, technical parity, typecheck, and the complete
  347/347 plugin suite are green; coverage is 90.42% lines, 74.88% branches,
  and 91.49% functions. Build will be regenerated before the next frozen review
  commit. The full Python, installer, dummy, package,
  workflow, dependency, and release-check matrix will be rerun after the final
  independent re-review.
- R2 remains open until the explicitly requested autonomous independent review
  runs against the source-complete tree, all findings are fixed, and a second
  reviewer confirms the post-fix tree.

## Non-goals and hard stops

- No dynamic CAPTCHA solver, access-control bypass, stealth evasion claim, or
  provider automation without current written permission.
- No silent retry after an uncertain provider write.
- No raw PII, mailbox body, listing URL, OAuth token, evidence image, or custom
  target URL in public tool parameters, reports, logs, or review artifacts.
- No autonomous ID upload, account creation, payment, phone, fax, postal mail,
  legal escalation, or terminal controller-outcome judgment.
- No hosted multi-tenant service in v0.9.0. The dashboard is a local, static,
  sanitized artifact and family/team authority remains deployment-local.

## Release exit

The version is complete only when every row above has direct current-state
evidence, the release package contains only reviewed artifacts, a clean install
passes against the supported OpenClaw runtime matrix, and the final independent
review was performed after the last source change.
