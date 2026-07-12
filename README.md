# RightOut

RightOut `0.6.0` is an OpenClaw plugin and bundled skill for consented people-search discovery, US and EU/EEA removal requests, verification, and resumable recurring case follow-up.

It implements the minimum Hermes Unbroker product loop with a stricter security boundary: every live disclosure, publisher read, inbox read, confirmation-link open, email, and form write receives its own native OpenClaw `allow-once` approval. The agent cannot manufacture or reuse approval receipts.

## What it can do

- keep multiple SecretRef-backed subject profiles and a durable PII-safe case ledger;
- discover exposure across 21 of 22 clean-room people-search catalog entries using bounded Brave POST search vectors for names/aliases, locations/addresses, emails, and phones;
- plan all 34 catalog entries, ownership clusters, nine current EU process targets, human tasks, ambiguous-write reconciliation, and due rechecks deterministically;
- send one minimum-disclosure California deletion/opt-out email through the catalog-locked BeenVerified lane;
- send catalog-locked GDPR erasure/objection emails to Adsquare (email/Mobile Advertising ID/country) and emetriq (email/country) for consistently attested EU/EEA profiles, without requiring prior listing discovery;
- distinguish controller erasure requests and portals from browser/device-scoped advertising preferences such as EDAA YourOnlineChoices and emetriq opt-out;
- route current Quantcast, Lotame/Epsilon, and ID5 rights portals as explicit human work where browser/device identifiers, verification, or controller-scope judgment prevent safe automation;
- initiate the Intelius/PeopleConnect suppression flow through OpenClaw's sandbox browser, failing closed on CAPTCHA, ID, ambiguous fields, or missing success evidence;
- poll a subject-owned Gmail IMAP inbox for receiver-authenticated, submission-bound BeenVerified confirmation mail and open an opaque confirmation handle under a separate approval;
- directly recheck encrypted exact candidate URLs for the two catalog lanes that support it, with no redirects and a full-name-plus-corroborator match;
- purge one subject's encrypted local cases, handles, and dedupe records under a separate approval, while explicitly leaving OpenClaw configuration and provider data unchanged;
- persist a provider-write intent before every SMTP/form effect, stop on `submission_uncertain`, and allow retry only after separately approved human reconciliation records `provider_write_not_started`;
- record human-reviewed EU controller outcomes under a separate approval, including processing, partial erasure, identity follow-up, rejection, or controller-scoped confirmation;
- report `submission_pending`, `submission_uncertain`, `submitted`, `verification_pending`, `awaiting_processing`, `identity_verification_required`, `partially_removed`, `request_rejected`, `confirmed_removed`, `reappeared`, human tasks, disclosure field names, opaque evidence references, and coverage gaps.

`confirmed_removed` is deliberately narrow. A people-search case requires a prior approved removal plus two time-separated direct absence observations across every encrypted known listing URL, with the second after the durable recheck time. A human-reviewed EU controller response may confirm only `controller_response_only`. Neither means that all current or future broker records are absent; new/unindexed URLs and other identifiers/controllers remain stated gaps.

EU controller emails remain `submitted` until a human reviews the controller response and separately approves the outcome record. Advertising-preference controls never become `confirmed_removed`. The reviewed primary sources did not evidence a universal pan-EU broker-erasure registry; such a claim remains `needs_evidence`.

## Tools

Live, non-replay-safe, separately approved:

- `rightout_live_scan`
- `rightout_direct_rescan`
- `rightout_submit_removal`
- `rightout_submit_form_removal`
- `rightout_poll_verification`
- `rightout_open_verification`
- `rightout_purge_subject_state` (local destructive action; no provider call)
- `rightout_record_controller_outcome` (local human-reviewed status change; no provider call)
- `rightout_reconcile_submission` (local human-reviewed ambiguous-write reconciliation; no provider call)

Read-only, replay-safe:

- `rightout_next_actions`
- `rightout_case_status`
- `rightout_due_rechecks`

All public arguments are opaque references. Raw PII, queries, listing URLs, mail content, page content, credentials, and broker responses are excluded from reports. Candidate URLs and cases are encrypted at rest with an operator SecretRef key. Opaque listing handles are retained with the case so OpenClaw Cron can resume a due campaign after restart.

## Install and verify

Prerequisites: OpenClaw `2026.6.11` or newer compatible release, Node.js `22.19.0+`, Python `3.11+`, and `git`.

```bash
./install.sh
make test
```

Provider SecretRefs and policy attestations are intentionally not created by the installer. Follow [INSTALL.md](INSTALL.md), then run:

```bash
openclaw config validate
openclaw secrets audit --check
openclaw security audit --deep
openclaw plugins inspect rightout --runtime --json
```

No release test uses real PII, a live broker scan, a form submission, email, or provider write.

## Comparison and limits

Against the official Hermes Unbroker skill, RightOut now has the same minimum capability classes: multi-subject profiles, multi-vector discovery, deterministic ledger/queue, email and browser-form lanes, inbound verification, later direct rechecks, reappearance tracking, clusters, human tasks, and recurring due work. RightOut keeps all external effects behind per-action OpenClaw approvals and uses only clean-room catalog facts.

Unbroker remains broader in immediately executable people-search lanes: its reviewed official skill describes 22 broker entries (20 web-form, one email, one phone), whereas RightOut automates one US email, one US form, and two EU controller-email lanes and plans the remainder as scan or human work. RightOut 0.6.0 adds stronger durable intent/ambiguity recovery, controller-outcome tracking, restart-safe campaign planning, current EU portal classification, and release provenance. It therefore claims approval-safe workflow parity, not broker-lane breadth, effectiveness, managed-service, family-admin, or private-database parity.

See [the parity contract](docs/unbroker-parity-contract.md), [the feature benchmark](docs/feature-benchmark.md), [security posture](SECURITY.md), and [architecture](docs/architecture.md).

## Development

```bash
npm ci --ignore-scripts
npm run check
make test
```

Catalog additions must use official sources and pass the semantic validator. Hermes/BADBOOL data, commercial lists, privacy-guide records, copied templates, and copied prose are prohibited. License: MIT.
