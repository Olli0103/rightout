# Release checklist: v0.7.1

- [x] All four post-v0.7.0 CodeQL alerts have code fixes and adversarial regression tests.
- [x] SMTP/IMAP snapshot bindings are deterministic, exact-scope, and use a password-hardening KDF.
- [x] Verification-link decoding is single-pass and publisher HTML extraction is parser-backed and bounded.
- [x] All version, manifest, lock, skill, SBOM, release-note, parity, and provenance metadata agree.
- [x] Distributable package excludes tests, source, internal audits, historical release evidence, and stale verdicts.
- [x] Node/Python/dummy/adversarial/installer/package/PII checks pass with enforced coverage thresholds.
- [x] Local dependency audit, OpenClaw runtime inspection, plugin doctor, and workflow structural validation pass.
- [x] Protected PR workflows require stable/beta compatibility, CodeQL, the OS/runtime matrix, and strict current-branch checks before merge.
- [x] Protected PR #13 passed CodeQL, stable/beta compatibility, all OS/runtime jobs, and the isolated installer on final code-bearing commit `e5c412f`.
- [x] Repeated independent review reports no open P0/P1/P2/P3 in the release candidate.
- [x] The annotated-tag workflow is configured to fail closed unless immutable archive, checksum, SBOM, catalog provenance, release evidence, and attestation are produced.
