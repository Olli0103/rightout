# Hermes Unbroker clean-room review

Review date: 2026-07-12. Reference snapshot: NousResearch/hermes-agent commit `7c14d2a046217c5ccbaa06a9449b0fcf329221f9`.

No Hermes/Unbroker code, broker records, BADBOOL-derived data, templates, prose, or site playbooks are copied into RightOut.

## Product concepts adopted

- recorded consent before action;
- discovery before deletion;
- minimum disclosure;
- explicit `submitted`, verification, processing, removal, reappearance, blocked, and human-task states;
- no CAPTCHA bypass or automatic identity-document disclosure;
- later verification before `confirmed_removed`.

## RightOut implementation

- `rightout_live_scan`: Brave index-only discovery with native allow-once approval;
- `rightout_submit_removal`: one catalog-locked BeenVerified email with a different native allow-once approval;
- private profile, consent, Brave key, and SMTP values through OpenClaw SecretRefs;
- catalog schema v3 for official source, destination, jurisdiction, request kind, disclosure fields, and confirmation policy;
- live output stops at `submitted`; no false confirmation.

## Deliberate differences

Unbroker defaults to standing authorization and a hands-off action queue after intake. RightOut requires a fresh native approval for every external write. RightOut also excludes browser/form driving, soft-CAPTCHA handling, SMTP/IMAP auto-discovery, verification-link opening, scheduled jobs, autonomous fan-out, and broad broker imports.

These exclusions reduce coverage and automation, but preserve the OpenClaw approval boundary and clean-room catalog policy.

## Remaining gaps

- durable live ledger and status query;
- inbound broker confirmation/verification polling;
- scheduled rechecks and automatic re-removal;
- direct or screenshot removal proof;
- custom URLs;
- more independently verified broker lanes;
- consolidated human-task digest.

Each added write lane requires official current source evidence, a fixed destination, minimum fields, terms/jurisdiction review, separate tests, and independent security review.
