# RightOut v0.6.0 ten-of-ten audit

Audit baseline: 2026-07-12. Target branch: `feat/v0.6.0-ten-of-ten-audit`.

This scorecard is a release contract, not a marketing score. A category receives
10/10 only when every stated criterion is implemented and covered by current,
reproducible evidence. Missing or indirect evidence cannot score 10. Safety and
legal constraints are not relaxed to gain autonomy or broker breadth.

## Scoring rule

- 0-2: absent, unsafe, or contradicted by current evidence;
- 3-4: narrow prototype capability;
- 5-6: useful but materially incomplete;
- 7-8: release-quality core with documented product gaps;
- 9: complete design with one remaining evidence or operational gap;
- 10: every category-specific gate below passes with no open P0/P1/P2 finding.

## Baseline

| Area | 10/10 gate | Baseline | Evidence / gap |
| --- | --- | ---: | --- |
| Security engineering | Threat boundaries, hostile-input handling, fail-closed network/write behavior, durable ambiguity handling, dependency audit, and adversarial tests all pass. | 9 | Approval and network gates are strong; a crash after a possible provider write can leave only a short-lived dedupe record instead of a durable visible ambiguous case. |
| Privacy and PII minimization | SecretRef-only inputs, no PII in public surfaces or durable reports, minimum disclosure, retention/purge controls, and PII regression scans pass. | 9 | Minimum disclosure and purge exist; durable ambiguous-write reporting and explicit retention/consent lifecycle evidence need strengthening. |
| Native approval boundary | Every live read, disclosure, write, confirmation, and destructive local action is exact-scope, non-replayable, allow-once, timeout-deny, and execute-time revalidated. | 9 | Implemented for current tools; completion needs explicit tests for every new v0.6 action and current stable/beta runtime inspection. |
| OpenClaw conformance | Manifest, package metadata, SecretRef contracts, optional/replay metadata, hooks, runtime inspection, config validation, security audit, installer and supported-version matrix pass against official contracts. | 9 | Stable 2026.6.11 passes; current beta compatibility and documentation drift are not yet CI gates. |
| Autonomous orchestration | For every supported non-human lane, the skill can plan, execute after required approvals, track, follow up, and resume safely without manual bookkeeping. Unavoidable CAPTCHA/ID/legal judgment remains explicit human work. | 6 | Planning/status/due tools exist, but there is no campaign-level resume/reconciliation surface and most write lanes are manual. |
| Discovery coverage | At least 20 independently sourced broker discovery lanes, multi-vector matching, honest indirect/inconclusive semantics, bounded provider access, and later exact-URL checks where permitted. | 9 | 21 Brave lanes pass; exact later checks exist for only two entries. |
| Executable broker breadth | At least 20 independently evidenced executable removal coverage targets, counting an ownership cluster only when an official source says one request covers its named children; each write path is separately tested and approval-gated. | 3 | Four automated write lanes exist: one US email, one US form, two EU controller emails. |
| EU/EEA coverage | At least eight current official EU controller/process targets, multiple controller and preference process classes, no false one-click/erasure claims, fixed GDPR semantics, country consistency, follow-up and human-reviewed outcome tracking. | 5 | Six classified processes and two executable controller emails exist; controller-response recording and broader controller coverage are missing. |
| US/CCPA coverage | Broad people-search discovery, at least ten executable/effectively covered targets, ownership clusters, California DROP routing, minimum disclosure and later scoped confirmation. | 5 | 22 people-search entries exist, but only BeenVerified and the Intelius/US Search cluster have executable writes. |
| Tracking and reporting | Durable cases cover intent, submission, ambiguous outcome, verification, processing, scoped confirmation, reappearance, overdue work, cluster effect, human tasks, proofs and coverage gaps. | 8 | Most lifecycle states exist; durable pre-write intent/ambiguous outcome and controller-reviewed EU outcomes are missing. |
| Filesystem and state integrity | Opaque keys, containment, no-follow reads, private modes, authenticated encryption, atomic replace, cross-process locks, corruption detection, bounded history/TTL, migrations and safe purge pass. | 9 | Current v1 store passes containment/locking tests; upgrade/migration and key-rotation recovery evidence is limited. |
| Catalog provenance and freshness | Every entry has official primary sources, bounded fact-use scope, semantic validation, freshness expiry, domain and lane closure, ownership evidence and automated source review reporting. | 8 | Strong schema v5 validation and a reproducible local provenance digest exist; external source availability and factual support remain `needs_evidence`. |
| Installer and upgrade safety | Fresh install, forced update, concurrent denial, staging validation, rollback, forged-path defense, runtime inspection, config/secrets/security checks, uninstall/reinstall and migration tests pass. | 9 | Transactional install/update passes; uninstall/reinstall and state-schema migration coverage are incomplete. |
| Tests and CI | Unit, dummy E2E, scan-only invariants, every lane/state, approval/network denial, installer rollback, PII/secret scan, catalog semantics, fuzz/property cases and supported OS/runtime matrix pass. | 8 | 44 Python and 85 Node tests pass; CI is one OS/runtime and has no property/fuzz or beta-compatibility job. |
| Documentation and usability | README, install, security, architecture, operations, contributor guide, clear normal-user output, exact setup examples, failure recovery and honest limits match runtime behavior. | 8 | Documentation is extensive; campaign operation, ambiguous-write recovery and post-release checklist evidence need improvement. |
| Supply chain | Exact production graph, clean archive, lock/shrinkwrap parity, SBOM, vulnerability audit, pinned CI actions, checksums, release provenance and reproducible artifact verification pass. | 8 | SBOM/checksum/archive gates pass; signed provenance/attestation and reproducible CI artifact publication are missing. |
| Competitive feature parity | RightOut matches or exceeds the reviewed Unbroker executable coverage count while retaining stronger approvals, and covers the core tracking/recheck/status classes of managed services without claiming their private inventory or human service. | 5 | Minimum workflow-class parity exists; executable lane breadth and campaign/operator UX do not. |
| Release quality | No open P0/P1/P2, independent review closes, branch/main/tag CI pass, immutable version/tag/release assets verify, and the published checklist records final evidence. | 8 | v0.5.0 is verified, but this v0.6 contract is not implemented, reviewed or released. |

Baseline average: **7.5/10**. Areas below 10 remain release blockers for the
v0.6.0 ten-of-ten claim.

## Current v0.6.0 candidate

Current local evidence: 44/44 Python tests, 96/96 Node tests, TypeScript build,
skill validator, catalog-provenance check, release checker, dependency audit,
stable OpenClaw 2026.6.11 installer tests, and a local 2026.7.1-beta.5 build,
test, packaged install, runtime inspection, and plugin-doctor pass. All use
synthetic data and isolated/mock providers.

| Area | Current | Evidence / remaining boundary |
| --- | ---: | --- |
| Security engineering | 10 | The single-absence P1 is closed; provider-write intent, phased dedupe recovery, uncertain-write stop, adversarial inputs, fail-closed network gates, and zero high production dependency findings pass. |
| Privacy and PII minimization | 10 | SecretRef-only PII, minimum disclosure, finite 365-day consent, execute-time validation, encrypted bounded state, local purge, and PII-safe reports pass. |
| Native approval boundary | 10 | All six provider-I/O and three critical local-state tools use exact one-time host bindings, allow-once/deny, timeout-deny, and execute-time revalidation. |
| OpenClaw conformance | 9 | Twelve-tool manifest/runtime parity passes on stable and current beta locally; the new remote stable/beta matrix remains `needs_evidence`. |
| Autonomous orchestration | 10 | Every supported non-human lane can plan, request exact approvals, execute, persist intent/outcome, reconcile, resume, and expose due work; CAPTCHA/ID/legal/portal judgment remains explicit human work. |
| Discovery coverage | 9 | 21 independently cataloged multi-vector Brave index lanes retain honest indirect/inconclusive semantics and durable opaque listing handles; external source availability remains `needs_evidence`. |
| Executable broker breadth | 3 | Four automated write lanes remain. Validated official human handoffs and ownership clusters improve reach but do not satisfy the stated 20 independently evidenced automated/effective write-path gate. |
| EU/EEA coverage | 9 | Nine reviewed official process targets cover controller email, portal, and browser/device preference classes; controller outcomes, country consistency, minimum disclosure, and non-one-click semantics pass, while current external source truth remains `needs_evidence`. |
| US/CCPA coverage | 6 | 22 people-search targets, 21 scans, official handoffs, ownership clusters, and California DROP routing exist; automated/effectively proven write breadth remains below ten. |
| Tracking and reporting | 10 | Pending/uncertain/submitted/verification/processing/partial/ID/rejected/confirmed/reappeared states, campaign resume, evidence categories, gaps, and human outcomes are durable and PII-safe. |
| Filesystem and state integrity | 10 | Containment, no-follow, private modes, AES-GCM, atomic replace/fsync, cross-process locks, TTL/bounds, v0.5 schema-v1 compatibility, wrong-key failure, and purge pass. |
| Catalog provenance and freshness | 9 | Schema v5, primary-source metadata, honest facts-only use policy, semantic/freshness validation, and reproducible catalog/source-fact digests pass. External page availability and truth of every declared fact remain `needs_evidence`, not cryptographically proven. |
| Installer and upgrade safety | 9 | Source and packed-stage validation, isolated runtime inspection/doctor, fresh/force install, rollback, concurrency, forged-path, symlink, and v1-state compatibility are covered; the remote installer matrix remains `needs_evidence`. |
| Tests and CI | 9 | Local full matrix is green and CI defines Ubuntu/macOS, Node 22/24, Python 3.11/3.12, installer, stable/beta, audit, and release gates. The new remote matrix has not run yet. |
| Documentation and usability | 10 | Setup, 365-day consent, recovery, campaign resume, EU semantics, official handoffs, limits, competitive comparison, and release verification match the runtime. |
| Supply chain | 9 | Exact pins/shrinkwrap/SBOM, clean archive, checksums, pinned actions, main-ancestry/full-matrix release gate, and signed-attestation workflow exist; the v0.6 tag attestation has not been executed. |
| Competitive feature parity | 6 | RightOut exceeds the reviewed approval, ambiguity, and lifecycle safety classes, but Unbroker remains broader in immediately executable people-search removal lanes. |
| Release quality | 8 | Local release gates are green and no known P0/P1 remains. Independent final review, PR/main CI, annotated tag, downloaded assets, and attestation remain open. |

Current average: **8.7/10**. The candidate is not entitled to an all-10 or
broker-breadth-parity claim. The remaining low scores are product/remote-release
evidence gaps, not permission to invent broker recipes or bypass provider
controls.

## Mandatory remediation tracks

1. Persist a pre-write intent and a durable `submission_uncertain` outcome for
   every provider write; never auto-retry an ambiguous effect.
2. Add a separately approved, human-attested reconciliation path for ambiguous
   writes and EU controller responses without accepting model-authored proof.
3. Expand source-backed executable coverage to the stated US and EU thresholds,
   using official ownership-cluster effect only where explicitly evidenced.
4. Add campaign-level PII-safe resume/status reporting and deterministic due
   work suitable for OpenClaw Cron.
5. Add stable plus beta OpenClaw compatibility, OS/runtime, property/adversarial,
   uninstall/reinstall, migration, provenance and supply-chain evidence gates.
6. Repeat independent review until no P0/P1/P2 finding remains, then verify PR,
   merged main, annotated tag, CI and downloaded release assets.

## Evidence boundary

All release tests use synthetic `.invalid` identities, mocks and isolated state.
No live broker scan, form submission, email, provider write or real PII is
permitted by the governing goal. Real-world provider effectiveness therefore
remains deployment evidence and is not part of a software 10/10 claim.
