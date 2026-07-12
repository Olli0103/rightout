# Release checklist: v0.7.0

- [x] All version, manifest, lock, skill, SBOM, release-note, parity, and provenance metadata agree.
- [x] Distributable package excludes tests, source, internal audits, historical release evidence, and stale verdicts.
- [x] Installation documentation uses a version-pinned release archive and verifies checksum plus attestation.
- [x] Runtime globally blocks live provider I/O when any catalog entry is stale and reports policy health without network access.
- [x] Cases have finite configured retention, untouched legacy cases migrate on first read, and key rotation is restart-safe and separately approved.
- [x] Autonomy resumes campaigns and due work without weakening per-effect approval or human legal gates.
- [x] Node/Python/dummy/adversarial/installer/package/PII checks pass with enforced coverage thresholds.
- [x] OpenClaw stable/beta, CodeQL, dependency audit, and protected-branch checks pass.
- [x] Independent critical review reports no open P0/P1/P2/P3 within the software-release contract.
- [x] The annotated-tag workflow fail-closes unless immutable archive, checksum, SBOM, catalog provenance, release evidence, and attestation are produced; published assets are verified after the tag run.
