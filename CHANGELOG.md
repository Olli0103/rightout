# Changelog

All notable changes to RightOut are documented here.

## 0.7.0 - 2026-07-12

- Separate distributable operator documentation from repository-only audit and
  historical release evidence.
- Add a deployment compliance gate, honest broker-coverage document, and
  machine-readable release evidence asset.
- Require a version-pinned, checksum- and attestation-verified installation
  path for stable releases.
- Add runtime catalog freshness, finite case retention, safe state-key rotation,
  policy-health reporting, coverage gates, CodeQL, and dependency automation.
- Enforce a global stale-catalog provider-I/O kill switch before approval and
  again at execution, with a PII-free health report.
- Migrate untouched legacy case envelopes to finite retention on first read and
  defer all state-key inspection until after native `allow-once` approval.

## 0.6.0 - 2026-07-12

- Added durable pre-write intent and `submission_uncertain`; possible SMTP/form effects never auto-retry.
- Added separately approved, operator-reviewed `rightout_reconcile_submission` and `rightout_record_controller_outcome` workflows.
- Closed the single-absence confirmation flaw: people-search confirmation now requires two time-separated direct absences, with the second after the durable recheck time.
- Added finite consent expiry through required `consent.validUntil`, a 365-day maximum authorization horizon, and execute-time validation.
- Persisted opaque listing handles in encrypted cases and added campaign resume/reconciliation summaries for OpenClaw Cron.
- Expanded the clean-room catalog to schema v6 with 56 entries, 23 current EU process targets, 18 executable EU controller emails, and eight new California data-broker email lanes.
- Added packaged isolated-installer staging, stable/beta OpenClaw compatibility jobs, Ubuntu/macOS and Node/Python CI coverage, adversarial property tests, catalog provenance digests, and tag-triggered Sigstore/GitHub build provenance.
- Reached 28 independently locked and tested write targets (27 email, one browser-form initiation) while keeping CAPTCHA, identity documents, unclear forms, DROP, and portal/device context as explicit human work.

## 0.5.0 - 2026-07-12

- Added two separately approved EU/EEA controller-email lanes: Adsquare with contact email/Mobile Advertising ID/country, and emetriq with contact email/country.
- Added a fixed `gdpr_erasure_objection` template covering conditional Article 17 erasure, Article 7(3) consent withdrawal, Article 21(2) direct-marketing objection, and Article 19 recipient follow-up.
- Added consistent EU/EEA country validation, required-identifier checks, controller-response-only confirmation semantics, 30-day follow-up scheduling, and no-discovery data-subject-request lifecycle support.
- Added EDAA, emetriq opt-out, Criteo, and Zeotap process metadata that separates browser/device advertising preferences from controller erasure.
- Upgraded the clean-room catalog to schema v4 with 31 entries and added adversarial EU minimum-disclosure, classification, lifecycle, and fail-closed tests.
- Revalidated the OpenClaw plugin manifest, optional/non-replay-safe tools, SecretRef boundary, and per-call `allow-once` approval contract against current official documentation.

## 0.4.0 - 2026-07-12

- Added 22 clean-room people-search entries, 21 multi-vector Brave discovery lanes, ownership clusters, and deterministic parent-first planning.
- Added durable PII-safe case tracking, next actions, status, due rechecks, and reappearance lifecycle.
- Added a closed sandbox-browser form lane, read-only IMAP verification, separate confirmation-link opening, and restart-safe submission dedupe.
- Added encrypted exact-listing handles and separately approved direct rechecks; confirmation is limited to the known listing set and requires prior removal.
- Bound verification mail to a prior submitted case, recipient, post-submission time, and aligned DKIM; removed password-based Microsoft 365 IMAP.
- Enforced discovery before every removal, moved all SecretRef/state reads after approval, hardened cross-process lock ownership, and persisted TTL pruning.
- Added a separately approved local subject-state purge and expanded native approval/security audit/config contracts to ten tools total.
- Added a complete 47-component production SBOM and npm shrinkwrap for reproducible dependency resolution.
- Added the normative Unbroker parity contract, executable parity release gates, updated OpenClaw/installer documentation, and adversarial tests.

## 0.3.0 - 2026-07-12

### Live removal

- Added optional, non-replay-safe `rightout_submit_removal` as a separate provider-write tool; scan approval cannot authorize it.
- Added catalog schema v3 and one clean-room BeenVerified email lane using the current official privacy policy, a catalog-locked recipient, minimum disclosure, and `US-CA` eligibility.
- Added recorded action-specific subject consent, revision-bound scan/removal attestations, normalized profile/SMTP snapshot binding, consistent `US-CA` eligibility, SMTP sender/profile equality, and a fixed provider/port/TLS allowlist.
- Added Nodemailer SMTP transport with TLS validation, timeouts, file/URL access denial, deterministic Message-ID, and process-local duplicate cooldown.
- Exact-pinned Nodemailer and added lockfile/SBOM dependency consistency release gates; Microsoft 365 is excluded until an OAuth 2.0 SMTP contract exists.
- Added report v4 live submission semantics: SMTP acceptance is only `submitted`, never broker receipt, processing, or `confirmed_removed`.
- Expanded Brave-only live discovery to BeenVerified without adding publisher-page requests.
- Reworked the bundled skill from scan-only to a separate scan/removal workflow developed clean-room, using Hermes Unbroker only as a product-shape benchmark.
- Added adversarial tests for approval crossover, profile/SMTP substitution, recipient injection, consent, contradictory jurisdiction, SMTP restrictions, raw transport-error leakage, rejection, abort-before-write, PII-safe reports, and catalog semantics.
- Updated OpenClaw conformance, security, privacy, installer, architecture, provider, benchmark, and release documentation.

## 0.2.0 - 2026-07-11

### Stable release

- Replaced direct publisher-page verification with Brave-index-only discovery; the runtime has no publisher-domain request path.
- Reduced positive signals to honest `indirect_exposure`; live `found`, URL-derived proof references, and retained Search Results are absent.
- Bound operator acceptance to Brave Search API Terms revision `2026-02-11` plus customer responsibilities, exact profile IDs, and broker search scope.
- Updated provider/privacy/approval documentation and stable release gates around transient Search Result processing.
- Updated GitHub Actions to current Node 24-based official releases, pinned to full commit SHAs.
- Retained the native OpenClaw allow-once boundary, SecretRef-only private inputs, zero-write behavior, transactional installer, protected main branch, and explicit non-parity posture.

## 0.2.0-rc.2 - 2026-07-11

### Stable-readiness hardening

- Disabled automated Spokeo scanning after verifying its published automated-access prohibition.
- Added fail-closed operator attestations for subject authorization, Brave terms acceptance, and exact broker access authority.
- Added explicit Brave standard-plan query-log retention disclosure to native approval and privacy documentation.
- Added an atomic cross-process installer transaction lock and concurrency test.
- Pinned every GitHub Actions dependency to a full commit SHA.

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
