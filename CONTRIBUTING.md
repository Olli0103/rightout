# Contributing

RightOut is evidence-first. Mark observed, evidenced, inferred, and open claims explicitly; use `needs_evidence` for missing primary evidence.

## Required checks

```bash
npm ci --ignore-scripts
make test
make scan-only-dummy
make e2e-dummy
make installer-test
make release-check
```

Use only `.invalid` synthetic identities and mocked HTTP responses. Never run a real live scan, store real PII, use a production key, or submit/send anything during development.

## Live plugin changes

- Keep the tool optional and non-replay-safe.
- Keep `profileId` and broker IDs as the complete public parameter surface.
- Keep `allow-once`/`deny` native approval and fail-closed behavior.
- Keep SecretInput contracts and security-audit findings.
- Use only OpenClaw's guarded SSRF runtime with fixed/catalog host allowlists.
- Preserve no-write invariants and sanitized reports/errors.
- Treat no index result as `inconclusive`.
- Add unit, adversarial, isolated install, runtime inspect, SecretRef, and packaging tests for every boundary change.

## Catalog contributions

Research clean-room from official broker/controller/legal sources. Do not copy commercial coverage lists, Privacy Guides, IntelTechniques, BADBOOL, screenshots, or prose. Every record needs official HTTPS URLs/domains, jurisdiction, category/lane, minimum field names, prerequisites, freshness, source-license posture, structured provenance, and original notes.

Sensitive identity documents remain human-only and out of scope. Legal/controller lanes cannot self-authorize a destination. Do not claim eligibility, compliance, removal, or ownership without direct evidence.

Update `CHANGELOG.md`, both version files, package lock, compiled `dist/`, SBOMs, docs, tests, and release notes together.
