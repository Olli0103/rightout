# Changelog

All notable changes to RightOut are documented here.

## 0.2.0-rc.1 - 2026-07-11

### Security

- Removed caller-controlled JSON/HMAC approval receipts and the unsafe live-mode environment override.
- Added an optional, non-replay-safe `rightout_live_scan` OpenClaw tool with native allow-once/deny approval and fail-closed timeout behavior.
- Moved private subject values out of tool parameters into SecretRef-backed opaque profiles and added plaintext/direct-Gateway security audit findings.
- Added fixed/catalog host policy, OpenClaw SSRF-guarded fetches, bounded responses/redirects/timeouts, disabled capture, and sanitized live errors/results.
- Bound allow-once approval to the exact displayed profile/broker scope and host tool-call ID; direct, replayed, expired, or mutated execution fails closed.
- Added query-free broker path policy, record-local JSON-LD matching, abort propagation, and per-scan HMAC proof references.
- Reduced the Python CLI to dummy/read-only capabilities and removed dead live command handlers.
- Added symlink-safe reads, atomic writes, locks, private modes, opaque artifact refs, and plan revisions.
- Added explicit human-only gating rules for sensitive fields.

### Reports and catalog

- Added report schema v3 with scan coverage gaps, full removal-state buckets, sanitized HIBP posture, opaque proof references, and plain-language summaries.
- Added clean-room catalog schema v2 with structured provenance, license posture, freshness, official-domain checks, prerequisites, and lane semantics.
- Added two official-source US people-search scan playbooks with honest `found`/`inconclusive` semantics; live index negatives never become `not_found`.
- Added a source-backed commercial feature benchmark and explicit non-parity statement.

### Packaging and quality

- Added compiled JavaScript output, deterministic npm packing, official OpenClaw plugin install, isolated runtime inspection, SecretRef audit tests, and plugin doctor validation.
- Added transactional installer rollback with canonical managed-path containment, immediate cleanup, and forged-path tests.
- Added root and installed LICENSE, notices, VERSION, and SPDX SBOM artifacts.
- Restored standard unittest discovery and expanded release/adversarial coverage.
- Added CI and release-level secret/PII/static-boundary/package checks.
- Rewrote release, security, privacy, approval, architecture, installation, conformance, and contributor documentation.

## 0.1.1 - 2026-07-11

- Hardened the dummy-first technical preview after the v0.1.0 release audit.
- Disabled live paths by default and reduced catalog provenance risk.

## 0.1.0 - 2026-07-11

- Initial preview. Superseded after an independent audit found release blockers.
