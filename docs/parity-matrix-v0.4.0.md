# RightOut 0.4.0 minimum Unbroker parity matrix

Evidence date: 2026-07-12. Reference: official Hermes Unbroker skill commit `2d9fd870b6d105e3b367aaa97477931b6671192e`.

| Capability | RightOut implementation | Executable evidence | Status |
|---|---|---|---|
| Multiple consented subjects | SecretRef profile map and exact profile digests | runtime/config schema tests | pass |
| Multi-vector discovery | bounded Brave vectors for names/aliases, locations/addresses, email, phone | `live-scan.test.mjs` | pass |
| Durable ledger and queue | contained encrypted atomic store, validated state transitions, plan/status/due | `file-keyed-store.test.mjs`, `cases.test.mjs` | pass |
| Email removal | catalog-locked minimum-disclosure SMTP with durable dedupe | `removal.test.mjs`, runtime tests | pass |
| Browser-form removal | host sandbox bridge, closed catalog recipe, CAPTCHA/ID fail-closed | `browser-form.test.mjs`, `form-runtime.test.mjs` | pass |
| Inbound verification | pinned read-only IMAP, dual-domain link validation, opaque handle | `imap.test.mjs`, `verification-runtime.test.mjs` | pass |
| Direct later evidence | encrypted exact URLs, no redirects, name plus corroborator, scoped absence | `listing-tokens.test.mjs`, `direct-rescan.test.mjs` | pass |
| Confirmation/reappearance | prior-removal requirement, known-set confirmation, trusted reappearance | `cases.test.mjs` | pass |
| Ownership clusters | official parent-first policy and child suppression | catalog validator, `cases.test.mjs` | pass |
| Human-task boundary | CAPTCHA, ID, ambiguity, unsupported lanes are queued, not bypassed | browser/form/case tests | pass |
| Native read/write approvals | six independent single-use host bindings | runtime plugin tests | pass |
| Recurring work | deterministic due tool compatible with official OpenClaw Cron | `cases.test.mjs`, manifest/installer validation | pass |
| PII-safe reporting/state | opaque inputs/proofs, encrypted URL tokens, no raw mail/page/query output | plugin tests and release PII/secret scan | pass |

The release checker enforces catalog minimums of 22 people-search entries, 21 discovery lanes, and at least one email, browser-form, direct-rescan, and inbound-verification lane. This is workflow feature parity, not broker-lane breadth or managed-service parity.
