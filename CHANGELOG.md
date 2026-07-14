# Changelog

All notable changes to RightOut are documented here.

## 0.9.0 - 2026-07-14

- Added encrypted durable campaign workers with trusted-session binding,
  single-action leases, checkpoints, exponential backoff, explicit scheduling
  or Cron handoff, resume approval, and revocation.
- Added a release-attested declarative 22-route recipe pack, trusted Ed25519
  external packs, expiry, and domain/semantic/sensitive-control drift
  quarantine before provider writes.
- Added mutually exclusive short-lived OAuth2 bearer authentication for pinned
  SMTP and Gmail IMAP transports while preserving password compatibility and
  protocol-separated credential bindings.
- Added authenticated, exact-thread controller reply polling. Literal evidence
  becomes an encrypted bounded candidate; no reply becomes a controller outcome
  without separate native human approval.
- Added an encrypted content-addressed evidence vault with bounded retention,
  tamper checks, subject purge/key rotation, metadata-only public reads, and
  separately approved contained redacted exports.
- Added safe out-of-band custom-target intake. Raw target facts remain encrypted
  behind opaque handles and provider execution stays disabled unless an exact
  signed recipe and current handle/domain/effect permission are present.
- Added evidence-based effectiveness reports with explicit denominators and
  `needs_evidence` as the default operational verdict absent consistent
  authorized canaries.
- Added session-bound owner/manager/viewer team roles with exact subject scopes,
  cross-profile/campaign/worker isolation, and a critical full-operator Gateway
  boundary audit.
- Added separately approved static local HTML/JSON dashboards with strict CSP,
  private contained files, no scripts or remote assets, and no network service.
- Expanded the manifest to 50 tools and retained every v0.8.1 provider-terms,
  approval, uncertainty, encryption, retention, purge, and technical-parity
  invariant.
- Fixed durable-worker crash recovery with lease watchdogs and startup wake
  reconstruction, and bound success to the host-observed terminal result of the
  exact issued command rather than any campaign activity.
- Hardened worker recovery and result correlation: unconfirmed replacement
  schedules become durable human gates; receipts bind session, run, call ID,
  tool, normalized parameters, lease, and execution digest; inconclusive direct
  rescans never count as completed actions.
- Fixed evidence-export lifecycle tracking so managed artifacts honor stricter
  deduplicated retention, interrupted-export cleanup, subject purge, and state
  key rotation.
- Anchored stricter evidence retention to original creation, added idle
  next-expiry cleanup, and retained encrypted tracking whenever artifact unlink
  cannot be confirmed.
- Tightened external recipe trust to the Ed25519 key type and 64-byte signatures,
  and made qualified or negated controller completion text fail closed to manual
  review.
- Serialized evidence export, cleanup, subject purge, and key rotation with a
  state-directory-wide cross-process transaction lock so concurrent plugin
  instances cannot orphan files or recreate state after a reported purge.
- Required a still-live worker lease both before provider I/O and when its exact
  result receipt is recorded; completion now boundedly waits for asynchronous
  host-hook persistence.
- Made partial scheduled-turn replacement failures explicit and fail-closed for
  startup recovery, lease watchdogs, later wakes, and worker resume.
- Added cross-process worker-schedule coordination and a durable state token so
  stale startup recovery cannot replace a newer lease watchdog.
- Made every post-claim worker planning/ledger failure persist a human gate, so
  a consumed one-shot wake cannot leave an active leased worker unscheduled.
- Expanded controller-reply qualification handling for neither/nor,
  although/remaining, legal-retention/extent exceptions, and German equivalent
  wording; only a narrow unqualified completion grammar can be high confidence.

## 0.8.1 - 2026-07-13

- Fixed autonomous discovery campaigns so campaign-authorized scan reports are
  durably recorded and finite scan-only campaigns can terminate.
- Replaced the ambiguous 59-lane claim with a shared runtime/documentation
  contract proving 56 code-enforced Brave lanes: 30 people-search and 26
  controller/B2B lanes, while preserving three reviewed portal lanes as
  `human_only`.
- Made profile country mandatory and report localization, public-index scope,
  private-inventory limits, and unproven discovery effectiveness explicitly.
- Removed the remaining nested-address US defaults from removal profiles;
  scan/removal now share one ISO-country contract and inherit only the explicit
  top-level country.
- Preserved protected case workflow states when mixed scan batches record fresh
  observations, preventing one protected broker from dropping the remainder of
  a batch.
- Added a real campaign-to-live-scan runtime regression, mixed-state case tests,
  non-US coverage tests, and a machine-readable scan-coverage release gate.
- Required GitHub-verified signed annotated release tags and successful GitHub
  artifact-attestation verification before release publication.
- Revalidated managed-service claims against current primary sources and added
  an evidence scale plus peer-reviewed market-effectiveness context so vendor
  inventory claims are never presented as equivalent to runtime proof.
- Stabilized the live Hermes gate on the exact pinned Unbroker subtree rather
  than unrelated upstream `main` commits; any subtree change still fails closed
  for review.

## 0.8.0 - 2026-07-13

- Replaced minimum/count parity with an exact pinned 22-broker normalized method/route/input contract plus machine-readable `implemented`/`conditional`/`gap`/`human_only` capability evidence.
- Added finite revocable autonomous campaign grants, deterministic `campaign_next`, one-batch four-worker discovery, parent reverification, and ownership-cluster ordering.
- Added a separately authorized official-domain publisher-browser fallback after inconclusive index discovery, closing the no-candidate rescan loop without mixing publisher access into Brave authority.
- Added generic source-bound browser forms, managed/remote/logged-in browser profiles, redacted Gmail send, authenticated Gmail IMAP verification, browser-mail zero-I/O handoff, and link phishing scoring.
- Added PII-free live refresh of all official parity source URLs with redirect/failure quarantine, encrypted health snapshots, no body capture, and no automatic catalog mutation.
- Added official California registry ingestion, multi-state portal routing, human-verified DROP tracking, Markdown/JSON/Google Sheets reporting, setup, and doctor tools.
- Expanded exact reference scanning and verification while preserving SecretRef-only PII, encrypted state, intent-before-write, human hard gates, and scoped outcome semantics.
- Separated normalized route provenance from exact provider choreography and external availability: all 20 form contracts are represented and generic-fixture tested, only PeopleConnect has a staged provider-specific E2E, and the ClustrMaps/PeekYou contradiction remains explicit.
- Changed campaign planning so source and human gates are consolidated without blocking later autonomous work; ambiguous provider writes still hard-stop safely.
- Added an exact 22-route provider-terms catalog: 8 published automation prohibitions, 14 `needs_evidence` routes, and zero public permissions. Form/publisher automation now requires current written provider authorization bound to the terms digest; consent/attestation alone fails closed.
- Switched Brave scanning to transient-result semantics: neither query/result bodies nor Brave candidate URLs are persisted or returned, and current 400-character/50-word limits fail closed without truncating identity values.
- Bound campaign scope to browser, transport, catalog, and provider-permission snapshots; post-approval mutations fail before provider I/O.
- Replaced static-challenge overclaims with host-computed strict arithmetic and human-only distorted text/CAPTCHA handling; browser evidence is a redacted semantic-state receipt, not a screenshot or before/after proof.
- Corrected OpenClaw documentation for eager activation-time SecretRef resolution, the 35-tool manifest, fail-closed approval timeout behavior, and current Cron CLI syntax.

## 0.7.1 - 2026-07-12

- Replace fast SHA-256 credential snapshot bindings with domain-separated
  `scrypt` bindings so configured SMTP/IMAP digests resist offline guessing
  while remaining deterministic and exact-snapshot scoped.
- Make verification-link entity decoding single-pass to prevent recursive
  decoding of attacker-controlled mail content.
- Replace regex-based publisher HTML stripping with bounded parser-backed
  visible-text extraction that excludes scripts, styles, templates, noscript,
  image attributes, and link destinations.
- Add adversarial regression tests for all four post-release CodeQL findings
  and promote CodeQL to a mandatory clean release gate.

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
