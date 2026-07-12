# RightOut v0.6.0

RightOut 0.6.0 hardens the v0.5.0 live-scan/removal product loop for crash safety, restart-safe campaign operation, EU controller follow-up, current OpenClaw compatibility, and verifiable release provenance.

## Added

- Durable `submission_pending` intent before every SMTP/form effect and durable `submission_uncertain` for ambiguous outcomes.
- `rightout_reconcile_submission`, separately approval-gated and based only on operator-reviewed provider evidence.
- `rightout_record_controller_outcome` for operator-reviewed processing, controller-scoped confirmation, partial erasure, identity follow-up, and rejection.
- Encrypted persistence of opaque listing handles plus deterministic campaign `resume_mode` for OpenClaw Cron.
- Required finite `consent.validUntil`, capped at 365 days after recording and checked again at execution.
- Sixteen additional official EU controller-email targets, bringing executable EU controller coverage to 18 while retaining human-only portal/device workflows where verification or scope judgment is required.
- Eight official California data-broker controller-email lanes with distinct US legal/process semantics, 45-day operational follow-up, zero automatic identity-document disclosure, and human-reviewed controller outcomes.
- Catalog schema v6 names `source_use_policy`, per-source `fact_scope`, and separate EU/US process contracts honestly; these are RightOut clean-room constraints, not claimed third-party licenses.
- Reproducible catalog/source-fact digests, adversarial public-input properties, isolated packaged installer staging, stable/beta OpenClaw CI, macOS/Ubuntu and Node/Python matrix jobs, and tag-time Sigstore/GitHub provenance.

## Safety corrections

- A single direct 404/410 can never confirm people-search removal. The first complete known-set absence remains `awaiting_processing`; a second time-separated absence after the durable recheck time is required.
- Possible provider writes never auto-retry. Only human-reviewed `provider_write_not_started` releases the dedupe and returns the case to `action_selected`.
- EU and US controller confirmations remain `controller_response_only`; other identifiers/controllers and California DROP are explicitly unchecked.

## Honest scope

The catalog contains 56 entries: 22 people-search targets, 21 Brave discovery lanes, and 23 classified EU controller/preference processes. RightOut has 28 independently locked executable targets: 27 US/EU emails and the Intelius/PeopleConnect browser-form initiation. This exceeds the 22 executable entries in the reviewed public Unbroker skill, though the lane mix differs. CAPTCHA, identity documents, unclear forms, DROP, portal/device identifiers, legal judgment, and controller-response review remain human work.

No release test uses real PII, a live scan, email, form, link open, or provider write.
