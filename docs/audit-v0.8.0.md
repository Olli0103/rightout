# Closing audit: RightOut v0.8.0

Audit date: 2026-07-13. Status: independently approved, locally gate-complete
release candidate; tagged publication pending.

## Evidenced in the candidate

- Exact pinned Unbroker normalized inventory: 22 broker IDs plus 20-form,
  one-email, one-phone method/route/input contracts; every capability ID is
  classified as `implemented`, `conditional`, `gap`, or `human_only`.
- Every form contract is represented and generic-fixture tested; only the staged
  PeopleConnect provider-specific path covers email initiation, authenticated IMAP, same named
  browser profile, strong record selection, separate DOB approval, and suppression.
- Brave uses the official Web Search POST contract, ISO-country locale routing,
  bounded four-route autonomous batches across 59 combined eligible catalog
  lanes, and current query limits while persisting/returning zero result URLs.
- Provider terms are machine-bound for all 22 routes. Current public review:
  8 explicit automation prohibitions, 14 `needs_evidence`, zero permissions.
- A form/publisher campaign cannot enter approval without a current written
  provider authorization, exact terms digest, non-future review, and live expiry.
- Profile, browser, transport, catalog, and provider-permission mutations after
  campaign approval fail before provider I/O.
- Form fields/refs are semantic and exact; final controls require complete
  fields, durable provider intent, and an observed transition. A reproducible
  receipt commits only to returned redacted semantic state; it is not a
  screenshot or before/after proof.
- SMTP/form intent, duplicate suppression, uncertain-write reconciliation,
  campaign/case restart resume, retention, purge, and key rotation are encrypted
  and durable. Active browser sessions are memory-only and require manual
  residual tab/draft cleanup after an unclean Gateway stop.
- Browser-only inbound mail performs zero I/O; autonomous inbound verification
  uses intended-recipient plus aligned-DKIM Gmail IMAP evidence and link scoring.
- OpenClaw manifest, approval, browser, SecretRef, and Cron documentation is
  aligned with current official contracts, including eager activation-time
  SecretRef resolution and current OpenClaw fail-closed approval semantics.

## Closing gate evidence

- `npm run check`: 279/279 plugin tests, typecheck, and build passed on the
  source-complete tree.
- `npm run test:coverage`: 89.95% lines, 76.08% branches, and 90.59%
  functions; all enforced 85/70/85 thresholds passed.
- Python: 50/50 skill, filesystem, catalog, installer, rollback, lock, and
  workflow-checker tests passed.
- Offline scan-only and full state-machine dummy E2E passed with synthetic
  fixtures, `network_calls=0`, `provider_writes=0`, and
  `real_pii_processed=false`.
- `npm audit --omit=dev --audit-level=high` found zero vulnerabilities;
  `npm ls --omit=dev --all` reported a valid production tree.
- Fresh npm archives installed and runtime-inspected successfully on OpenClaw
  stable `2026.6.11` and beta `2026.7.1-beta.6`, including all 35 tools and the
  typed `before_tool_call` hook.
- The PII-free Hermes refresh observed main commit
  `bd740f203b44237dbc5c27a2de4d86ef32af4dde`; the Unbroker subtree remains the
  exact pinned tree `f8145c8318a398f0d12dbbd27bb88175ce19519b`.
- Catalog provenance, package-content, SBOM/dependency, workflow hardening,
  manifest, parity, and documentation checks pass. Release tests make no real
  provider write; authorized deployment canaries remain external
  `needs_evidence`.

## Explicit limitations

- Complete 22/22 normalized contract coverage is not exact provider-playbook or
  capability parity. Default autonomous form execution is 0/20 until providers
  supply written authorization; exact live effectiveness remains `needs_evidence`.
- `clustrmaps` and `peekyou` primary hosts are externally unavailable. Their
  archived route evidence and independent rescue email do not prove form success.
- RightOut does not clear soft challenges, solve distorted static text, dynamic
  CAPTCHA, OTP, or ID/account gates. It may retry a distinct preconfigured
  remote profile once, then stops.
- Browser-only inbox authentication and retrievable before/after screenshots are
  not implemented. Visual evidence is a semantic-state commitment, not an image.
- Real-provider effectiveness remains `needs_evidence`; release tests use mocks
  and `.invalid` identities and perform no real-person/provider write.
- No proprietary hundreds/thousands-broker inventory, hosted dashboard, custom
  arbitrary takedown, human specialist, family administration, or dark-web suite.

## Closing verdict

The fresh independent closing review reports no open P0/P1 and confirms every
actionable lower finding from the review closed. The source-complete candidate
is approved for release. Publication is still a separate external step:
protected annotated-tag CI must generate and publish the archive, checksum,
SBOM, attestation, and release evidence from the reviewed main commit before the
release can be reported as live.
