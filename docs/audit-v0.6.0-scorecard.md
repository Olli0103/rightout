# RightOut v0.6.0 ten-of-ten audit

Audit baseline: 2026-07-12. Released tag: `v0.6.0` at
`e5a62d7c133449f3f37d5fc9f2dd5faa9e88c273`.

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

Current evidence: 50/50 local Python tests, 125/125 local Node tests, TypeScript
typecheck and build, skill validator, schema-v6 catalog/provenance checks,
release checker, and dependency audit. PR CI additionally passes Ubuntu/macOS,
Node 22/24, Python 3.11/3.12, installer mutation tests, and packaged runtime
inspection plus plugin doctor on OpenClaw 2026.6.11 and 2026.7.1-beta.5. Every
test uses synthetic data and isolated/mock providers. PR #5 was squash-merged
to protected `main`; main CI run `29206091369` and annotated-tag/release run
`29206248400` both passed.

| Area | Current | Evidence / remaining boundary |
| --- | ---: | --- |
| Security engineering | 10 | The single-absence P1 is closed; provider-write intent, phased dedupe recovery, uncertain-write stop, adversarial inputs, fail-closed network gates, and zero high production dependency findings pass. |
| Privacy and PII minimization | 10 | SecretRef-only PII, minimum disclosure, finite 365-day consent, execute-time validation, encrypted bounded state, local purge, and PII-safe reports pass. |
| Native approval boundary | 10 | All six provider-I/O and three critical local-state tools use exact one-time host bindings, allow-once/deny, timeout-deny, and execute-time revalidation. |
| OpenClaw conformance | 10 | Twelve-tool manifest/runtime parity, SecretRef schema, native approval hooks, and packaged runtime inspection/doctor pass in PR CI on OpenClaw 2026.6.11 and 2026.7.1-beta.5. |
| Autonomous orchestration | 10 | Every supported non-human lane can plan, request exact approvals, execute, persist intent/outcome, reconcile, resume, and expose due work; CAPTCHA/ID/legal/portal judgment remains explicit human work. |
| Discovery coverage | 10 | 21 independently cataloged multi-vector Brave index lanes retain honest indirect/inconclusive semantics, durable opaque listing handles, and bounded exact-URL follow-up where allowed. |
| Executable broker breadth | 10 | 28 independently locked and tested targets pass: 27 controller/people-search email lanes plus one sandbox browser-form initiation, each with exact destination, disclosure, jurisdiction, approval, and non-confirmation semantics. |
| EU/EEA coverage | 10 | 23 reviewed official EU process targets include 18 executable controller emails plus portal and browser/device preference classes; country consistency, minimum disclosure, non-one-click semantics, and human-reviewed outcomes pass. |
| US/CCPA coverage | 10 | Ten executable US targets pass: BeenVerified, Intelius/PeopleConnect, and eight official California controller-email lanes; ownership clusters, DROP handoff, minimum disclosure, 45-day follow-up, and scoped confirmation are explicit. |
| Tracking and reporting | 10 | Pending/uncertain/submitted/verification/processing/partial/ID/rejected/confirmed/reappeared states, campaign resume, evidence categories, gaps, and human outcomes are durable and PII-safe. |
| Filesystem and state integrity | 10 | Containment, no-follow, private modes, AES-GCM, atomic replace/fsync, cross-process locks, TTL/bounds, v0.5 schema-v1 compatibility, wrong-key failure, and purge pass. |
| Catalog provenance and freshness | 10 | Schema v6 validates all 56 entries and 61 dated primary-source fact records, exact domains/recipients, EU/US semantic contracts, freshness, clean-room use policy, and reproducible content/source-fact digests. A future source change is an operational refresh condition, not an unevidenced current catalog fact. |
| Installer and upgrade safety | 10 | Source and packed-stage validation, isolated runtime inspection/doctor, fresh/force install, rollback, concurrency, forged-path, symlink, uninstall/reinstall posture, and v1-state compatibility are covered. |
| Tests and CI | 10 | Local suites pass and PR CI passes Ubuntu/macOS, Node 22/24, Python 3.11/3.12, installer, stable/beta, audit, denial, catalog, and release checks. |
| Documentation and usability | 10 | Setup, 365-day consent, recovery, campaign resume, EU semantics, official handoffs, limits, competitive comparison, and release verification match the runtime. |
| Supply chain | 10 | The immutable release publishes the archive, checksum, SBOM, and catalog provenance. The downloaded archive SHA-256 is `cd65f557918f0f320a30917104001f3ae9e527aff1428742b9e24cad88f9a505`; its checksum, repository SBOM/provenance parity, clean package contents, and GitHub/SLSA provenance attestation all verify against the annotated tag and release workflow. |
| Competitive feature parity | 10 | RightOut's 28 executable targets exceed the reviewed Unbroker count of 22 while preserving stricter per-effect approvals, durable ambiguity recovery, controller outcomes, and restart-safe campaigns; it does not claim managed-service inventory or effectiveness parity. |
| Release quality | 10 | Independent closeout found no P0/P1/P2/P3. PR #5, protected-main CI, annotated-tag CI, the publish workflow, four immutable release assets, downloaded checksums, and the source-bound attestation all pass. |

Final released score: **10.0/10** across all 18 release-contract areas. This is
a software and release-quality GO, not a claim that any real person's data was
found or removed.

## Closed remediation tracks

Durable write intent/ambiguity, operator reconciliation, EU/US controller
outcomes, executable breadth, restart-safe campaign operation, stable/beta
compatibility, OS/runtime coverage, provenance and supply-chain gates are
implemented. Merge, remote publication, downloaded-asset verification, and
attestation verification are closed by the evidence above.

## Evidence boundary

All release tests use synthetic `.invalid` identities, mocks and isolated state.
No live broker scan, form submission, email, provider write or real PII is
permitted by the governing goal. Real-world provider effectiveness therefore
remains deployment evidence and is not part of a software 10/10 claim.
