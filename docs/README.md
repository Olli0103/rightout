# RightOut documentation

This directory separates current operator documentation from historical audit
evidence. The npm/OpenClaw package includes only the current operator documents
listed below; versioned audits, checklists, and release notes stay in the source
repository and GitHub release history.

## Start here

- [Installation and verified release setup](../INSTALL.md)
- [Broker coverage and evidence semantics](broker-coverage.md)
- [Architecture](architecture.md)
- [Approval boundary](approval-boundary.md)
- [Authorized deployment canary](authorized-canary.md)
- [Security posture](../SECURITY.md)
- [Privacy posture](privacy-posture.md)
- [Deployment compliance gate](deployment-compliance.md)
- [OpenClaw conformance](openclaw-conformance.md)
- [Provider and publisher terms review](provider-terms-review.md)
- [Feature benchmark](feature-benchmark.md)
- [Market analysis and global safety roadmap](market-analysis-2026-07.md)
- [v0.10.0 market-safety implementation plan](roadmap-v0.10.0.md)
- [Unbroker parity contract](unbroker-parity-contract.md)
- [Pinned Unbroker baseline](unbroker-parity-baseline.json)
- [Machine-readable parity evidence and release verdict](unbroker-parity-evidence.json)
- [Machine-readable runtime scan coverage](scan-coverage.json)

## Repository-only evidence

Files named `audit-*`, `release-checklist-*`, `release-notes-*`, and
`release-correction-*`, and `parity-matrix-*` are immutable historical or
release-process evidence. They are not runtime instructions and are
deliberately excluded from the distributable plugin archive to prevent an older
audit verdict from being presented as the current product posture.
