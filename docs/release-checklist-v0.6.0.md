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
- [ ] Pull request CI is green and the candidate is approved/merged.
- [ ] Annotated `v0.6.0` tag CI and release workflow are green; downloaded assets and attestation verify.
