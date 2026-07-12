---
name: data-broker-removal
description: Discover people-search exposure, plan and submit supported US or EU removal requests, distinguish browser-scoped EU advertising preferences from controller erasure, verify broker mail, and recheck known listings through separately approved RightOut tools.
---

# RightOut data-broker removal

Use only the installed RightOut plugin for live work. The deterministic Python runner is synthetic validation, never a live fallback.

## Hard boundary

- Pass only opaque `profileId`, `brokerId`/`brokerIds`, `listingHandle`, `verificationHandle`, and the fixed request kind. Never put names, addresses, email, phone, credentials, raw listing URLs, messages, or documents into chat or tool arguments.
- Require SecretRef-backed profiles/credentials/keys plus exact operator attestations. Missing configuration is `needs_evidence`.
- Every live disclosure, publisher read, inbox read, confirmation-link open, email, or form submission needs its own native OpenClaw `allow-once`. A prior approval never carries over.
- Never route around RightOut with browser, web search, shell, Python, mail, or another provider tool. Use RightOut's browser-form lane only through `rightout_submit_form_removal`.
- Never solve CAPTCHA, upload identity documents, invent authority, or call SMTP/form success a completed removal.
- Treat search-index absence, mailbox silence, ambiguous pages, redirects, block pages, and incomplete form evidence as inconclusive or human work.

## Workflow

1. Call `rightout_next_actions(profileId)` to obtain the deterministic catalog/ledger campaign plan. Obey `campaign.resume_mode`: reconcile uncertain writes before any new external write.
2. For discovery, call `rightout_live_scan(profileId, brokerIds)` with at most two supported brokers per call. Report `indirect_exposure` or `inconclusive` exactly.
3. If discovery returns `listing_handle`, preserve only that opaque handle. Do not reconstruct or expose its encrypted URL.
4. For a supported write lane, call exactly one of:
   - `rightout_submit_removal(profileId, brokerId, delete_and_opt_out)` for the catalog-locked US email lane;
   - `rightout_submit_removal(profileId, brokerId, gdpr_erasure_objection)` for a catalog-locked EU controller email lane;
   - `rightout_submit_form_removal(...)` for the catalog-locked sandbox-browser recipe.
5. Report email as `submitted` and form initiation as `verification_pending`. Neither is removal proof.
   If a write becomes `submission_pending` or `submission_uncertain`, do not retry. After the operator personally checks provider-side evidence, call `rightout_reconcile_submission` under a separate approval. Only `provider_write_not_started` restores retry eligibility.
   For EU controller email, wait for and human-review the controller response, then call `rightout_record_controller_outcome` under its own approval. Never convert SMTP acceptance or a browser/device advertising preference into controller erasure.
6. Where supported, call `rightout_poll_verification` to look for a domain-bound broker message. If a handle is returned, call `rightout_open_verification` only after a new approval.
7. When a known listing must be checked directly, call `rightout_direct_rescan` with its opaque listing handle. This separately approved read is limited to encrypted exact candidate URLs and requires operator publisher-terms review.
8. Report people-search `confirmed_removed` only when the durable case ledger had a prior approved removal and two time-separated trusted direct rechecks found every known listing URL absent, with the second after the scheduled recheck time. Always state `known_listing_set_only` and `new_or_unindexed_listing_urls_not_checked`. For EU controller confirmation, state `controller_response_only` and `other_identifiers_or_controllers_not_checked`.
9. Use `rightout_due_rechecks` for an official OpenClaw Cron turn. A third-party plugin cannot self-schedule a session turn. Use `rightout_case_status` for the current PII-safe ledger.
10. Only when the operator explicitly requests local erasure, call `rightout_purge_subject_state(profileId)` under its own approval. State clearly that provider data and the configured OpenClaw profile SecretRef are not removed by this tool.

For `queue_human_task`, use only the plan's validated `official_action_url` and prerequisites. Never substitute a third-party opt-out guide, copied recipe, guessed form field, browser workaround, or arbitrary email. The human completes CAPTCHA, identity, portal/device context, or legal judgment; RightOut keeps that limitation explicit.

Cluster rules from official registry evidence are deterministic: submit through the catalog parent where one request officially covers the cluster, but later verify each known site. Separate-opt-out children remain separate.

## Output contract

Lead with the evidenced state, then approval, write count, and next action. Distinguish `observed`, `evidenced`, `inferred`, `needs_evidence`, and `human_task`.

Never omit these limits when relevant:

- Brave discovery is indirect.
- SMTP acceptance proves only outbound acceptance.
- Browser form success may prove only initiation.
- One direct absence never confirms removal; two timed absences prove only the encrypted known listing set.
- Commercial/private database coverage and legal outcomes are not guaranteed.
- EU one-stop advertising preferences are browser/device scoped and are not a universal erasure registry.

## Synthetic validation

```bash
python3 {baseDir}/scripts/validate_data_broker_removal.py --skill-dir {baseDir}
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} scan-only-dummy --workdir .tmp/rightout-scan-only
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} e2e-dummy --workdir .tmp/rightout-e2e
```

Never present `fixture_only` output as real evidence. For EU work, read `{baseDir}/references/eu-removal.md`; otherwise read only the relevant reference under `{baseDir}/references/`.
