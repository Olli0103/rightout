# RightOut v0.9.0 autonomy-platform plan

Status: implementation plan. This document is the requirement and evidence
contract for the v0.9.0 work; a checked test or a prose claim is not sufficient
unless the corresponding runtime boundary is also implemented.

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
  completion, exponential backoff, native session scheduling, deterministic
  Cron handoff, resume approval, and revocation. Evidence:
  `autonomy-worker.test.mjs` and `autonomy-worker-runtime.test.mjs`.
- A3 implemented: the release-attested 22-route pack binds the exact source and
  compiled digests, external packs require trusted Ed25519 signatures, packs
  expire, and live form sessions quarantine domain, sensitive-control, policy,
  and semantic drift before provider writes. Evidence: `recipes.test.mjs`, form
  runtime suites, and the full 312-test regression run on 2026-07-14.
- M1 through U2 and the final R1/R2 release evidence remain open. A green Phase
  1 suite is not a v0.9.0 release claim.

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
