# Security model

## Trust boundaries

OpenClaw owns optional-tool exposure, SecretRef resolution, native per-call approval, and SSRF-guarded transport. RightOut owns input minimization, catalog destination policy, fixed scan behavior, result sanitization, and absence of write capabilities. The operator owns subject authorization, secret-provider isolation, tool policy, approval routing, and Gateway exposure.

Prompt text, caller JSON, environment flags, HMAC receipts, local files, page content, and controller-provided domains are not approval authority.

## Controls

| Threat | Control |
| --- | --- |
| Model receives raw PII | Tool schema accepts only opaque profile ID and broker IDs |
| Agent mints, replays, or widens approval | Native OpenClaw `before_tool_call`; allow-once/deny only; single-use expiring binding to tool-call ID plus exact displayed profile/broker scope |
| Stale provider acceptance or unapproved subject scope | Fail-closed exact-profile and broker-search-scope attestations plus pinned Brave terms revision and customer responsibilities |
| No human route | OpenClaw fails closed |
| Plaintext config | SecretInput contracts plus critical plugin security-audit findings |
| Unexpected destination or publisher access | Only fixed Brave HTTPS host, guarded DNS, zero redirects; no publisher fetch implementation |
| Search result overclaim | Same-domain result is only `indirect_exposure`; never `found` or identity proof |
| Cancellation continues network work | Host abort signal is checked and passed to the Brave guarded request; abort is rethrown |
| Debug capture leakage | `capture: false` on every guarded request |
| Search negative becomes false assurance | Live scan never emits `not_found` |
| Raw result leakage | URL/title/snippet/body discarded; allowlisted state and reason fields only |
| Scan becomes removal | No removal/email/form/provider-write implementation or tool |
| Direct Gateway exposure | Recommended `gateway.tools.deny` plus audit warning |

SecretRefs do not make a shared process or OS account safe from a sufficiently privileged agent. Use OS/container separation and a hardened external provider when shell/file capabilities are in scope.

## Live invariants

- per-call native approval;
- raw PII absent from tool params, approval text, reports, and RightOut storage;
- network host limited to `api.search.brave.com`; publisher-domain requests equal zero;
- submissions, email, provider writes, and local PII writes equal zero;
- live negative result equals `inconclusive`;
- only `scan.supported: true` people-search entries are eligible.

## Offline invariants

The Python runner uses synthetic `.invalid` data, makes zero network calls, and cannot transition non-fixture catalog cases. Its filesystem hardening does not authorize real-PII storage.
