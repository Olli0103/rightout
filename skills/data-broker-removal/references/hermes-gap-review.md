# Hermes Unbroker clean-room review

Review date: 2026-07-12. Reference snapshot: NousResearch/hermes-agent commit `2d9fd870b6d105e3b367aaa97477931b6671192e`.

No Hermes/Unbroker code, broker records, BADBOOL-derived data, templates, prose, or site playbooks are copied into RightOut.

## Product concepts adopted

- recorded consent before action;
- discovery before people-search deletion; controller-specific data-subject requests may proceed without a public listing;
- minimum disclosure;
- explicit `submitted`, verification, processing, removal, reappearance, blocked, and human-task states;
- no CAPTCHA bypass or automatic identity-document disclosure;
- later verification before `confirmed_removed`.

## RightOut implementation

- `rightout_live_scan`: Brave index-only discovery with native allow-once approval;
- `rightout_submit_removal`: 27 catalog-locked US/EU email targets, each with a different native allow-once approval;
- `rightout_submit_form_removal`: one catalog-locked PeopleConnect browser flow with CAPTCHA/ID fail-closed handling;
- Gmail-only, receiver-authenticated verification polling and a separately approved opaque confirmation-link open;
- durable cases, deterministic planning/status/due rechecks, ownership clusters, direct known-listing rechecks, and reappearance tracking;
- private profile, consent, provider credentials, and encrypted local state through OpenClaw SecretRefs;
- catalog schema v6 for official source, facts-only use policy, destination, jurisdiction, request kind, disclosure fields, confirmation policy, and distinct EU/US process semantics;
- outbound and form outputs stop at honest intermediate states; `confirmed_removed` requires later direct absence and remains scoped to the known listing set. EU controller-email responses stay human-reviewed and preference controls are never erasure evidence.

## Deliberate differences

Unbroker defaults to standing authorization and a hands-off action queue after intake. RightOut requires a fresh native approval for every provider read/write and for local subject purge. RightOut uses an official OpenClaw Cron turn for due work instead of self-scheduling, refuses CAPTCHA/identity-document automation, and does not accept arbitrary custom URLs or broad imported broker playbooks.

These differences reduce unattended autonomy while preserving the OpenClaw approval boundary and clean-room catalog policy.

## Remaining gaps

- custom URLs and operator-authored recipes;
- consolidated dashboard/family administration/managed-service capabilities;
- removal effectiveness or private-database coverage evidence.

Each added write lane requires official current source evidence, a fixed destination, minimum fields, terms/jurisdiction review, separate tests, and independent security review.
