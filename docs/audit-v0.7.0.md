# Independent closing audit: RightOut v0.7.0

Audit date: 2026-07-12. Candidate commit: `7bc9136`.

## Verdict

**GO for the software release.** The independent read-only closeout reports no
open P0, P1, P2, or P3 finding. This verdict covers the community plugin,
packaged skill, documentation, and release engineering; it does not claim that
any real person's data was found or removed.

## Closed review findings

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| RO-070 | P1 | Catalog-health documentation described a global kill switch while runtime checks covered only selected lanes. | Every provider-I/O approval and execution now fails closed when any catalog entry is stale; regression tests cover an unrelated stale entry. |
| RO-071 | P1 | State-key rotation inspected host-resolved active/previous key values before native approval. | The hook validates only the empty public scope; key-ring validation occurs after a consumed `allow-once`. |
| RO-072 | P1 | Untouched legacy case envelopes without `expiresAt` could survive indefinitely after upgrade. | First access migrates under lock to `createdAt + stateRetentionDays`, persists the envelope, and immediately removes expired or invalid legacy entries. |

## Release-contract scorecard

| Area | Score | Evidence boundary |
| --- | ---: | --- |
| Security engineering | 10/10 | Exact approval bindings, fail-closed network/write paths, crash-safe intent, zero open CodeQL/production-audit findings. |
| Privacy and PII minimization | 10/10 | SecretRef-only private inputs, minimum disclosure, encrypted PII-free state, finite legacy-aware retention, purge and rotation. |
| Native approval boundary | 10/10 | Six provider-I/O and four critical local-state tools accept only `allow-once` or deny; SecretRefs are checked after approval. |
| OpenClaw conformance | 10/10 | Manifest/runtime parity, optional/replay metadata, isolated install, runtime inspect and doctor on current stable/beta. |
| Autonomous orchestration | 10/10 | Deterministic plan, due queue, status, global policy health, restart recovery and Cron handoff; legal/CAPTCHA/ID steps stay human. |
| Discovery coverage | 10/10 | 21 multi-vector Brave lanes with indirect/inconclusive semantics and two exact known-listing rechecks. |
| Executable broker breadth | 10/10 | 28 independently locked targets: 27 fixed-recipient emails and one closed browser-form initiation. |
| EU/EEA coverage | 10/10 | 23 process targets, 18 controller-email lanes, scoped outcomes, and explicit preference-versus-erasure semantics. |
| US/CCPA coverage | 10/10 | Ten executable targets, ownership clusters, California DROP handoff, minimum disclosure and scoped confirmation. |
| Tracking and reporting | 10/10 | Durable intent, uncertainty, verification, processing, controller outcomes, confirmation, reappearance, gaps and PII-safe proof refs. |
| Filesystem and state integrity | 10/10 | Containment, no-follow, AES-256-GCM, atomic fsync, locks, TTL migration, bounded state, corruption/wrong-key failure and purge. |
| Catalog provenance/freshness | 10/10 | 56 clean-room official-source entries, semantic validation, reproducible provenance and global execute-time stale blocking. |
| Installer and upgrade safety | 10/10 | Staged archive validation, isolated runtime inspection, serialized target mutation, rollback, forged-path/symlink defenses and legacy-state migration. |
| Tests and CI | 10/10 | 133 Node tests, 50 Python tests, dummy E2E, installer matrix, OS/runtime matrix and enforced coverage thresholds pass. |
| Documentation and usability | 10/10 | Product README, verified install, recovery, campaign operation, deployment compliance, canary, honest coverage and package-link checks match runtime. |
| Supply chain | 10/10 | Exact production graph, shrinkwrap, SBOM, pinned actions, CodeQL, Dependabot, clean package and source-bound release evidence/attestation workflow. |
| Competitive parity | 10/10 | Reviewed public Unbroker capability/count parity with stricter approvals; managed-service inventory, UI and human-service parity are not claimed. |
| Release quality | 10/10 | Independent two-pass closeout has zero open P0-P3; protected PR CI and tag publication/asset verification are mandatory terminal gates. |

Final software-release score: **10.0/10** across the explicit release contract.

## Reproduced evidence

- 133/133 Node plugin tests;
- 50/50 Python tests, including installer and workflow adversarial cases;
- coverage: 88.60% lines, 73.27% branches, 91.24% functions;
- TypeScript typecheck and build;
- release checker across 129 release-relevant files;
- production dependency audit: zero vulnerabilities;
- current OpenClaw stable/beta CI, CodeQL, Ubuntu/macOS, Node 22/24 and Python 3.11/3.12 checks;
- skill quick validation, schema-v6 catalog/provenance, dummy scan/E2E and clean diff.

## Evidence boundary

The governing goal prohibits real PII, live scans, emails, form submissions,
inbox reads, link opens, and provider writes. Therefore authorized live-canary
results, real provider delivery/effectiveness, and future source availability
remain deployment `needs_evidence`; they are not hidden software-release
findings. Managed services still provide much broader private inventories,
hosted dashboards, custom human removals, and effectiveness datasets.
