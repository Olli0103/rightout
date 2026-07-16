# Operations

## Live scan

Call `rightout_catalog_health({})` before a live campaign. Any stale catalog
entry blocks all live provider I/O until official source facts are reviewed,
the catalog is regenerated, and the updated package passes release validation.

Call `rightout_live_scan(profileId, brokerIds)` only for an explicit user request. Every selected catalog entry must have `scan.supported: true`, appear in scan attestations, and receive a native allow-once approval.

Interpretation:

- `indirect_exposure`: transient Brave official-domain index signal only;
- `inconclusive`: no sufficient signal or provider failure;
- zero publisher requests, writes, raw-result storage, or live proof URLs.

## Live removal

Call `rightout_submit_removal` only for an explicit user request, using the catalog-fixed `delete_and_opt_out`, `gdpr_erasure_objection`, or `uk_erasure_objection` kind. Before OpenClaw offers approval, the hook validates the public scope, catalog lane, market source, recipient/field policy, exact removal attestations, and pseudonymous profile/SMTP digests without opening raw PII or credentials. After `allow-once` but before any network connection, execution resolves the SecretRefs and validates the bound snapshots, subject consent, jurisdiction, required identifier, and SMTP identity.

Current email lanes:

- BeenVerified, `US-CA`, full name/contact email/region/country, prior discovery required;
- eight California controller lanes (Amplemarket, SalesIntel, LeadIQ, Wiza, SignalHire, Hunter, Seamless.AI, ContactOut), full name/contact email/region/country, no prior public-listing discovery required;
- 18 EU/EEA controller lanes, using only each catalog entry's fixed email/country or name/email/country set.
- one separate UK controller lane (`cognism_uk`), using full name/contact email/country, a UK-only template and eligibility gate, proportionate identity follow-up, and a conservative one-calendar-month recheck.

Interpretation:

- `submitted`: outbound SMTP accepted one message;
- broker receipt, processing, and removal: `needs_evidence`;
- extra identity verification: human task;
- later missing Brave result: still `inconclusive`;
- later candidate: possible reappearance/continued exposure, not direct proof.
- EU, UK, or US controller response: human-review evidence; browser/device opt-out remains a separate preference state.

Every email/form path commits `submission_pending` before the provider call. If the effect may have happened but cannot be proven, it becomes `submission_uncertain`; never retry it automatically. The operator must personally review the sent folder, provider confirmation, or other provider-side evidence and separately approve `rightout_reconcile_submission`. `provider_write_not_started` returns to `action_selected`; `provider_write_confirmed` resumes at `submitted` or `verification_pending`.

After personally reviewing an official EU, UK, or US controller response, use `rightout_record_controller_outcome` to record processing, controller-scoped erasure/deletion confirmation, partial outcome, identity follow-up, or rejection. Do not paste the response into tool input and do not use SMTP acceptance as controller evidence. Never attach identity documents automatically; California DROP remains a separate human-only route.

For California DROP, use `rightout_record_drop_filed` only after human filing
and `rightout_record_drop_status` only after human portal inspection. Before
2026-08-01 the case remains `submitted`; after processing starts it may be
`awaiting_processing`. A displayed `deleted` status is not direct record-level
proof and never produces `confirmed_removed`.

For GPC, use `rightout_record_gpc_observed` only after a person checks a
supported browser setting or extension. RightOut records a local preference
fact and performs no browser or provider I/O. Site compliance and legal effect
outside the evidenced California contract remain `needs_evidence`; GPC is never
a deletion request or deletion proof.

For recurring work, call `rightout_due_rechecks(profileId)` from OpenClaw Cron and then `rightout_next_actions(profileId)`. Opaque listing handles are durable. A first complete known-listing-set absence stays `awaiting_processing`; only a second time-separated direct absence after the scheduled time can confirm that narrow scope.

Never fall back to browser, shell, Python, arbitrary email, forms, CAPTCHA work, or extra disclosure.

## State lifecycle

Encrypted subject cases expire after `stateRetentionDays` without an update;
the allowed range is 30-730 days and the default is 365. Verification handles,
listing handles, and submission dedupe keep their shorter fixed TTLs. An
explicit subject purge remains available for earlier erasure.

For state-key rotation, configure a new active `stateEncryptionKey` plus up to
three temporary `previousStateEncryptionKeys`, all as SecretRefs. Invoke
`rightout_rotate_state_key({})` under its own allow-once approval. The operation
can safely resume after interruption because each store remains readable by the
temporary key ring and is always rewritten under the active key. After success,
remove the previous refs, reload secrets, and run the full OpenClaw readiness
gate. Never remove old keys before the rotation report succeeds.

## Offline operations

1. `doctor`: prove package and split live-tool/dummy-runner posture.
2. `validate`: validate catalog and manifest contracts.
3. `plan-dummy`: print a synthetic plan.
4. `scan-only-dummy`: synthetic discovery report.
5. `e2e-dummy`: synthetic full state matrix.
6. `verify-link`: local HTTPS/domain syntax check only.

## Failure handling

- missing SecretRef, profile, consent, attestation, approval route, or policy: block with `needs_evidence`;
- stale/missing provenance: disable the lane;
- scan approval failure: no Brave request;
- removal approval/preflight failure: no SMTP connection;
- SMTP/form error after a possible write: durable `submission_uncertain`; do not auto-retry because delivery may be uncertain;
- raw PII/body/credential in report/error/log: P0;
- cross-tool approval, arbitrary recipient, TLS downgrade, form/CAPTCHA action, or unapproved field: P0;
- missing primary evidence: preserve `needs_evidence`.
