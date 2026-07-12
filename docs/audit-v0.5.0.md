# RightOut v0.5.0 release audit

Audit date: 2026-07-12.

## Scope

- EU/EEA primary-source research and claim boundaries;
- catalog schema v4 and process classification;
- GDPR email template, recipient and minimum-disclosure locks;
- country, consent, identifier, digest, SMTP, approval, dedupe, and lifecycle gates;
- OpenClaw manifest/config/tool approval conformance;
- tests, packaging, SBOM, and release evidence.

## Findings

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| RO-050 | P1 | “One click” could be conflated with controller erasure. | Added closed `one_click_level`, `effect_scope`, and `erasure_semantics` enums. Controller email/form/portal routes explicitly say `not_one_click`; EDAA/emetriq preferences cannot become removal proof. |
| RO-051 | P1 | A tampered catalog could cross a US request kind into an EU category or vice versa. | Runtime now binds category, process class, request kind, fixed template, discovery rule, confirmation rule, jurisdiction set, and processing window as one closed contract. |
| RO-052 | P1 | Changing both catalog recipient and SMTP-recipient-domain could bypass a simple equality check. | Runtime and Python validator now also require the recipient domain to be an official catalog domain; adversarial tests perform zero sends. |
| RO-053 | P2 | Month-only or review-date policy evidence could be represented as an invented exact publisher date. | Schema v4 accepts an evidenced month (`2025-04`) or explicit `reviewed-YYYY-MM-DD` token and separately tracks `last_verified`. |
| RO-054 | P1 | A shared profile's Mobile Advertising ID could accidentally enter Brave search vectors. | Live-scan parsing permits the private field but excludes it from scan digests, vectors, requests, reports, and the case ledger; tests inspect mocked provider calls. |
| RO-055 | P1 | Free-form `EU` tags could contradict the actual country. | The live lane requires an EU/EEA ISO country, the same exact country tag, and `EU` or `EEA`; contradictory profiles fail before transport. |
| RO-056 | P1 | SMTP acceptance or a browser preference could be mislabeled as deletion. | EU email remains `submitted_until_controller_response`; preference routes are human-only; no EU route can automatically produce `confirmed_removed`. |

Open P0/P1/P2 findings: **none**.

## Verification evidence

- 44 Python tests, including installer rollback/concurrency and dummy no-network gates;
- 85 Node plugin tests, including EU disclosure, jurisdiction, category crossover, official-domain lock, approval, and PII-leak adversarial cases;
- TypeScript typecheck and compiled release build;
- catalog schema v4 validator: 31 entries, 22 people-search, 21 Brave, 3 email, 1 form, 6 EU processes;
- production dependency audit: zero high-or-greater vulnerabilities;
- generated 47-component production SPDX SBOM and identical npm shrinkwrap/lock graph;
- skill-creator validation with isolated PyYAML dependency;
- npm archive content gate and isolated tarball import smoke test;
- current official OpenClaw manifest, hook, permission-request, optional-tool, replay-safety, SecretRef, and runtime-inspection contract review.

Local release decision: **GO**. Final release decision remains conditional on protected-branch PR checks, merged-main checks, annotated-tag checks, and GitHub release checksum verification.
