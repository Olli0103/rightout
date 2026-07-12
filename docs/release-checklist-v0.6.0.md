# Release checklist: v0.6.0

- [x] Version, manifest, package locks, skill, SBOM, release notes, parity matrix, and catalog provenance agree on v0.6.0.
- [x] All live inputs remain opaque; consent has a finite execute-time expiry.
- [x] Every SMTP/form effect has durable intent and ambiguity handling; retry requires human reconciliation.
- [x] People-search confirmation requires two timed direct absences; EU and US controller outcomes are human-reviewed and scoped.
- [x] Schema-v6 catalog has 56 entries, 61 primary-source fact records, 23 EU processes, 18 executable EU targets, and ten executable US targets; portal/device/DROP workflows remain human-only.
- [x] Every one of 28 executable targets is destination-locked, minimum-disclosure, separately approval-gated, mock-executed, and checked for PII-safe reporting.
- [x] Installer validates the packed archive in an isolated OpenClaw runtime before target mutation and retains rollback/containment locks.
- [x] Node, Python, dummy E2E, adversarial, catalog, release, and installer tests use only synthetic `.invalid` data and mocked/isolated providers.
- [x] CI defines Ubuntu/macOS, Node 22/24, Python 3.11/3.12, stable/beta OpenClaw, installer, dependency-audit, and release-check gates.
- [x] Release workflow requires an annotated version-matching tag and publishes archive, checksum, SBOM, catalog provenance, and signed build attestation.
- [x] Independent closing review reports no open local P0/P1/P2 for the final schema-v6 snapshot.
- [x] PR #5 CI is green and the candidate was squash-merged to protected `main` as `e5a62d7c133449f3f37d5fc9f2dd5faa9e88c273`; main CI run `29206091369` passed.
- [x] Annotated `v0.6.0` tag/release run `29206248400` passed; the four downloaded assets, archive SHA-256 `cd65f557918f0f320a30917104001f3ae9e527aff1428742b9e24cad88f9a505`, repository SBOM/provenance parity, and source-bound GitHub/SLSA attestation verify.
