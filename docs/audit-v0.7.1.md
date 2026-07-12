# Independent closing audit: RightOut v0.7.1

Audit period: 2026-07-12 to 2026-07-13. Scope: the v0.7.1 security patch and the complete
software-release contract inherited from v0.7.0.

## Verdict

**GO for the software release.** Protected PR #13 passed CodeQL, the full
OS/runtime matrix, stable/beta OpenClaw compatibility, and the isolated installer
suite on the final code-bearing commit `e5c412f`. Repeated independent review
reports no open P0, P1, P2, or P3 finding. This verdict does not claim that any
real person's data was found or removed.

## Closed findings

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| RO-073 | P1 | SMTP credential snapshots used fast SHA-256 and exposed an offline-guessable verifier. | Replaced with domain-separated deterministic `scrypt`; regression tests retain exact credential-change binding. |
| RO-074 | P1 | IMAP credential snapshots used fast SHA-256 and exposed an offline-guessable verifier. | Replaced with domain-separated deterministic `scrypt`; regression tests retain exact credential-change binding. |
| RO-075 | P1 | Verification-link entity replacements could recursively decode attacker-controlled content. | Numeric equals entities decode before ampersands, enforcing one decoding pass; adversarial nested-entity test added. |
| RO-076 | P1 | Direct-rescan HTML used regex tag stripping and could treat malformed script content as visible text. | Bounded `html-to-text` parsing now excludes script/style/template/noscript, images, and link destinations; malformed-tag tests added. |
| RO-077 | P1 | Candidate docs claimed terminal independent/remote evidence before the branch existed remotely. | Candidate audit and checklist now distinguish reproduced local gates from protected PR/tag terminal gates. |
| RO-078 | P2 | Third-party notices omitted the new direct parser dependency and had a stale transitive count. | Both notice copies list `html-to-text` and the SBOM-backed root/direct/transitive counts. |
| RO-079 | P2 | The KDF changes relied only on pre-existing password-change tests. | A dedicated transport-binding regression covers determinism, credential changes, account changes, and protocol domain separation. |
| RO-080 | P2 | The root and installed-skill SPDX documents reused one document namespace. | The installed-skill SBOM now has its own UUID-backed SPDX `documentNamespace`. |
| RO-081 | P3 | The exported SMTP digest helper relied on callers to normalize and validate the transport first. | The helper now invokes `validateSmtpConfig` internally before deriving the binding. |
| RO-082 | P3 | Transport-binding tests did not cover every variable or immutable endpoint invariant. | Regression coverage now includes SMTP host/port/TLS/from-address changes, IMAP address changes, and invalid IMAP endpoint/TLS rejection. |
| RO-083 | P2 | A lock removed between an `EEXIST` result and metadata inspection was misclassified as an unsafe path; the first fix also treated every metadata error as disappearance. | Only `ENOENT` is now a benign contention retry; permission/I/O failures, non-directories, and symlinks remain fail-closed. |

## Reproduced evidence

- 138 Node plugin tests, including regression coverage for all four CodeQL findings plus benign-disappearance and non-`ENOENT` lock races;
- 50 Python tests, dummy E2E, installer matrix, TypeScript build and coverage gates;
- production dependency audit with zero known vulnerabilities;
- package/release checker and local OpenClaw runtime inspection/plugin doctor;
- protected PR #13 CodeQL and CI runs on the final code-bearing commit.

The annotated-tag workflow and downloaded-asset verification remain the next
terminal release gates. A failed tag, checksum, provenance, attestation, publish,
or isolated install check invalidates this GO and must not produce a stable
release.

## Evidence boundary

The governing goal prohibits real PII, live scans, emails, form submissions,
inbox reads, link opens, and provider writes. Authorized live-canary outcomes,
real delivery/effectiveness, and future source availability remain deployment
`needs_evidence`, not hidden software-release claims. Managed services still
provide broader private inventories, hosted dashboards, custom human removals,
and effectiveness datasets.
