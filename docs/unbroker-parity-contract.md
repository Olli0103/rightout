# RightOut minimum Unbroker parity contract

Status: implementation-complete; release evidence/audit pending. Reviewed against the official
Hermes Unbroker skill at NousResearch/hermes-agent commit
`2d9fd870b6d105e3b367aaa97477931b6671192e` on 2026-07-12.

This is a clean-room product-capability comparison. RightOut does not copy Unbroker
code, broker records, templates, prose, or BADBOOL-derived data.

## Meaning of minimum feature parity

RightOut reaches minimum parity only when every required capability below is both
implemented and covered by executable tests. Matching Unbroker's unsafe or
platform-specific implementation details is not required. RightOut may be stricter,
but a stricter security boundary must not silently remove the user-facing capability.

| Capability class | Required RightOut behavior |
| --- | --- |
| Multiple subjects | Independently operate on multiple opaque `profileId` SecretRef profiles with recorded consent. |
| Search vectors | Use current name/location plus optional aliases, prior locations, emails, and phones without returning raw values to the model. |
| Broker planning | Produce a deterministic per-broker lane, tier, prerequisites, next action, and coverage reason. |
| Two-phase workflow | Perform read-only discovery before any removal write and keep discovery approval separate from submission approval. |
| Durable case ledger | Persist one PII-safe case per subject and broker with validated transitions, history, proof references, disclosure field names, and due dates. |
| Action queue | Return the next safe actions, in-flight verification work, due rechecks, and one consolidated human-task digest. |
| Email removal | Submit catalog-locked minimum-disclosure requests through separately approved SMTP writes with idempotency and rate limits. |
| Form removal | Support catalog-defined browser/form removal where automation is allowed; CAPTCHA, ID, phone, fax, account, and ambiguous flows must fail closed into human tasks. |
| Verification lifecycle | Support `submitted`, `verification_pending`, `awaiting_processing`, `confirmed_removed`, and `reappeared`; only direct later evidence may confirm removal. |
| Inbound verification | Poll a configured inbox read-only, bind messages and links to the exact broker/case, suppress raw mail content, and require a separate approval before opening a confirmation link. |
| Direct later evidence | Recheck only encrypted exact candidate URLs under a separate publisher-access approval; require full name plus a corroborator for presence and every known URL absent for scoped confirmation. |
| Rechecks | Compute deterministic due dates and expose an idempotent recurring runner compatible with OpenClaw Cron. |
| Ownership clusters | Model parent/affiliate coverage and order the parent lane before redundant child work when official evidence supports the relationship. |
| Jurisdiction lane | Surface California DROP and applicable legal-request lanes without pretending eligibility or legal scope is proven. |
| Reports | Provide status counts, in-flight versus confirmed outcomes, overdue work, coverage gaps, human tasks, and PII-safe proof references. |
| At-rest safety | Use the host-resolved private state directory with contained atomic files, opaque keys, AES-256-GCM encryption, no raw PII in the ledger, bounded history/TTLs, and serialized updates. Secret profiles/keys remain SecretRefs. |
| Read/write approval | Every live disclosure, inbox read, verification-link open, form submission, and email submission is a separately bound native OpenClaw approval. |

## Explicit platform adaptations

- Unbroker's agent can use standing authorization. RightOut requires native
  OpenClaw `allow-once` approval for every live disclosure or external write.
- OpenClaw's third-party plugin API does not permit a workspace plugin to schedule
  its own session turns. RightOut therefore exposes due work and a deterministic
  runner; installation creates or documents one official OpenClaw Cron invocation.
- OpenClaw `2026.6.11` also limits its SQLite keyed-store helper to bundled plugins.
  RightOut uses the public state-directory resolver and a tested encrypted atomic
  file store instead of importing an internal API or requiring official-plugin trust.
- Broker breadth is clean-room and source-backed. A broker is not counted as an
  automated lane merely because Unbroker or another product lists it.
- CAPTCHA solving, government-ID upload, phone/fax/voice work, account creation,
  payment, and public-record deletion remain human-only. They still appear in the
  plan and digest, so the capability is not silently dropped.

## Release gate

The stable release must not claim parity while any required row is `missing` or
only a fixture. The release evidence must include:

1. a generated parity matrix tied to tests;
2. dummy E2E coverage for every lane class and lifecycle transition;
3. live-safe network denial and approval-binding tests;
4. catalog provenance/freshness validation;
5. an independent review with no open P0/P1 findings;
6. protected-branch CI plus tag/release verification.
