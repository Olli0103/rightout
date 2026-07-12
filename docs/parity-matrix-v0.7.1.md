# RightOut 0.7.1 capability and parity matrix

Status: feature parity is unchanged by this security patch. Publication status
is controlled separately by the versioned audit and protected workflows.

| Capability | v0.7.1 gate | Status |
| --- | --- | --- |
| Live discovery | 21 catalog-fresh, approval-gated Brave index lanes | pass |
| Automated writes | 28 catalog-locked email/form targets with durable intent | pass |
| Autonomous operation | Restart-safe plan, due queue, policy health, and compliant human gates | pass |
| State lifecycle | Finite retention including legacy migration, explicit purge, and safe approved key rotation | pass |
| Verification security | Single-pass link decoding, receiver-authenticated mail, separate link-open approval | pass |
| Direct rescan security | Bounded parser-backed visible-text matching on encrypted exact listing URLs | pass |
| Credential binding | Domain-separated `scrypt` SMTP/IMAP snapshot digests | pass |
| Local package/install contract | Clean archive contents, current SBOM, lockfiles, installer tests, runtime inspection, and doctor | pass |
| Protected PR compatibility | Stable `2026.6.11`, beta `2026.7.1-beta.5`, OS/runtime matrix, installer, and CodeQL | pass on PR #13 |
| Local supply-chain contract | Coverage thresholds, zero production-audit findings, current SBOM, release-workflow structure, and pinned actions | pass |
| Tagged artifact evidence | Checksum, catalog provenance, release evidence, attestation, immutable assets, and isolated downloaded-asset verification | terminal after merge |
