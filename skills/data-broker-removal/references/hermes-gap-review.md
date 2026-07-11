# Hermes `unbroker` Gap Review

Baseline checked 2026-07-11 against `NousResearch/hermes-agent/optional-skills/security/unbroker`.

## Kept

- Consent gate before subject work.
- Opaque subject ids.
- State machine with `found`, `not_found`, `indirect_exposure`, `submitted`, `awaiting_processing`, `confirmed_removed`, `reappeared`, and human/blocker states.
- Field-name-only disclosure ledger.
- Parent/cluster-first removal posture as an operational principle.
- Email verification and verification-link domain scoping.
- Recheck before claiming `confirmed_removed`.
- Human digest for CAPTCHA, phone, fax, mail, government ID, account, and anti-bot barriers.

## Deliberately Changed For OpenClaw

- Hermes defaults toward full autonomy after consent. OpenClaw keeps per-class approvals for real PII, storage, live scans, sends/forms, provider writes, and recurring jobs.
- Hermes can send email and poll IMAP. OpenClaw runner renders drafts and validates links only; Mail/provider writes remain separate approvals.
- Hermes may use browser/cloud upgrades for soft challenges. OpenClaw treats anti-bot/CAPTCHA as bounded operator/human lanes and never uses solver or evasion services.
- Hermes ships a large broker dataset influenced by BADBOOL. OpenClaw ships only a small starter catalog until provenance and license review are complete.

## Added For Community Safety

- Encrypted-storage posture marker before real PII planning.
- GDPR/DSGVO/UK GDPR notes, Article 17 caveats, and a GDPR erasure template.
- Generic GDPR/DSGVO lanes remain human tasks until a controller-specific contact URL and allowed domain are verified.
- Submitted-state records require source/channel and confirmation-status evidence, not just field names.
- Explicit no-identity-document-default rule.
- OpenClaw Skill Workshop and Creating Skills source checks.
- Deterministic dummy E2E and validator with real-PII refusal tests.

## Remaining Release Work

- Expand the broker catalog only with source-backed entries and license-compatible attribution.
- Add more per-site playbooks as test fixtures, not as unverified claims.
- Keep live submissions out of the community release unless a separate provider/write plugin owns those approvals.
