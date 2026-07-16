---
name: data-broker-removal
description: "Run autonomous or assisted RightOut campaigns for consented data-broker discovery, form/email removal, verification, registry coverage, California DROP tracking, durable rechecks, and PII-safe reporting through the installed OpenClaw plugin."
---

# RightOut data-broker removal

Use only the installed RightOut plugin for live work. The Python runner is a
synthetic validator, never a live fallback.

## Non-negotiable boundary

- Public tool inputs contain only opaque `profileId`, `brokerId`/`brokerIds`,
  campaign/session/listing/verification handles, fixed actions, ARIA refs, and
  catalog field names. Never put names, addresses, email, phone, credentials,
  listing URLs, messages, page bodies, identity documents, or OTPs in chat or
  tool arguments.
- Profiles, transport credentials, browser tokens, and encryption keys must be
  SecretRefs. Missing configuration or provenance is `needs_evidence`.
- Never route around RightOut with another browser, shell, mail, web-search, or
  provider tool. RightOut owns the disclosure boundary and durable intent.
- Never solve dynamic CAPTCHA, slider, OTP, or security questions, upload ID,
  place a phone call, send fax/postal mail, pay, create an account, or invent
  authority. A strict arithmetic challenge may use the bounded host-computed
  action; an explicitly identified static text challenge may accept one short
  alphanumeric value returned by the bounded RightOut challenge snapshot.
- Search-index absence, mailbox silence, ambiguous pages, redirects, block
  pages, SMTP acceptance, and one direct absence are not completed removal.

## Setup and doctor

1. Call `rightout_setup({})`. It idempotently initializes encrypted cases for
   configured opaque profiles and contacts no provider.
2. Call `rightout_doctor({})`, `rightout_catalog_health({})`, and
   `rightout_unbroker_parity_health({})`.
   `rightout_setup` reports configuration readiness only. `rightout_doctor`
   performs the official OpenClaw deep browser probe; do not call a configured
   browser operational when that probe fails.
   `software_release_ready` describes the package/catalog gate;
   `autonomous_form_execution_ready` remains false while no selected form route
   has a current written provider authorization record. Do not collapse those
   fields or weaken/bypass the provider gate.
3. Use `rightout_refresh_parity_sources({})` for a live PII-free official-route
   health snapshot. It probes only routes with current written publisher
   authorization; every other route is reported
   `not_probed_permission_required` with zero publisher GET. It never captures
   response bodies or mutates the catalog.
   If a selected lane is stale, changed, quarantined, or `needs_evidence`,
   perform no provider I/O on that lane. A separately cataloged regulator or
   archived-official-page rescue email is a distinct lane and may run only when
   its own provenance and freshness fields pass. An independently evidenced
   normalized contract whose provider is `external_unavailable` remains part of
   the pinned inventory, but
   the primary form must be reported unavailable and never as executed. Review
   and release clean-room official facts;
   never guess or copy a third-party playbook.
4. For registry work, call `rightout_registry_status({})`; if absent or stale,
   call `rightout_refresh_registries({})` to ingest the newest complete official
   California CSV and surface Vermont, Oregon, and Texas portals.

## Autonomous campaign

1. Choose the exact opaque profile and broker set. For reference discovery,
   use the 21 policy-permitted scan IDs returned by the catalog, excluding
   `spokeo`; record Spokeo as a separate human gate because its published terms
   prohibit automated queries. The normalized inventory still contains all 22.
   Include
   `submit_form` only for brokers whose current written provider authorization
   is configured and bound to the returned terms-contract digest.
2. Call `rightout_start_campaign` with only the required effect classes
   (`publisher_discover` is separate from Brave `discover`),
   shortest practical duration, and a finite effect budget. The native
   OpenClaw `allow-once` authorizes this bounded campaign; it is not blanket
   authority. Scope widening is impossible and the grant is revocable.
3. Repeatedly call `rightout_campaign_next(campaignId)`:
   - For `action_ready`, invoke exactly the returned RightOut tool and parameters.
   - If `rightout_poll_verification` returns `next_command`, execute exactly that
     tool and those opaque parameters. In assisted mode it receives its own
     native allow-once; in campaign mode it uses the already bound
     `open_verification` effect.
   - For a form or outbound-webmail session, continue only through its paired `*_step` tool
     using refs observed in the latest redacted snapshot.
   - A returned Intelius/DOB form triggers one separate critical native
     `allow-once` disclosure gate. After approval, continue the normal form
     steps; do not ask the human to re-enter DOB or replace the route.
   - For `human_gate`, stop only the explicitly named safety-critical effect.
     Ordinary source/phone/listing gates are deferred while later autonomous
     work drains and appear in the final consolidated digest.
   - For `done_for_now`, present the single consolidated digest and next wake.
   - For `campaign_completed` or `campaign_revoked`, present the terminal digest
     and do not call another provider-effect tool under that campaign.
4. Never invent a command, broker, URL, field, or ref. Call
   `rightout_campaign_next` again after each completed action.
5. Revoke with `rightout_revoke_campaign` when requested or when its purpose is
   over. Expiry and effect-budget exhaustion also stop it.

After an unclean Gateway/browser restart, do not assume an active form,
discovery, or webmail session resumed. Inspect the configured browser profile,
discard any autosaved Gmail draft, close leftover publisher tabs, reconcile any
durable pending intent, and rerun `rightout_doctor({})`. Only encrypted
campaign/case/intent state is restart-safe; in-memory browser sessions are not.

The deterministic loop orders ambiguous-write reconciliation first, scans all
unresolved scoped brokers in a bounded parallel batch, escalates an inconclusive
index result to separately authorized official-domain browser discovery when a
listing URL is required, re-verifies candidates before writes where publisher access is authorized, submits official
ownership-cluster parents before covered children, selects form/email/phone or
safe rescue lanes, defers non-critical source/human gates without blocking later
brokers, and emits `done_for_now` only when no autonomous action is due.
When the primary browser case is `blocked` and a distinct
`remoteCloudBrowserProfile` is configured, execute the returned
`browserBackend: remote_cloud_cdp` discovery retry exactly once. A failed
remote retry is recorded as a human task; never loop the same retry.

Subject consent, operator consent, a form attestation, or a campaign approval
never grants publisher access. If provider authorization is missing, expired,
future-dated, contract-mismatched, or only implied by public availability, stop
at `human_gate`. Do not manufacture an authorization hash.

## Form sessions

1. Start only from a returned `rightout_begin_form_session` command.
2. Use `inspect` to obtain the latest PII-redacted ARIA refs.
3. Use `fill` with `{ref, profile_field, type}`. The field must appear in
   `form_fields_available`; values are resolved inside the plugin.
   `disclosures_allowed` remains the smaller list of underlying disclosure
   categories. Derived fields such as `first_name`, `last_name`,
   `contact_email_confirm`, and `listing_id` map back to those categories and
   never widen the approved disclosure set.
4. Use only the purpose matching the visible control: `continue`, `agree`,
   `select_record`, `submit`, or `confirm`.
5. A final submit requires every catalog-required field and durable
   intent-before-write. Preserve only a reproducible PII-redacted semantic
   state receipt; it is not a screenshot or before/after proof.
6. `date_of_birth` is filled only after the exact native sensitive-disclosure
   approval requested by the DOB `rightout_form_session_step` fill action and
   bound to that exact active session/field set; it never appears in a
   snapshot or report.
7. Any hard challenge becomes a human gate. Do not switch tools or browsers
   except for the campaign-planned distinct remote-cloud retry above.
   Use `fill_challenge` only for the returned arithmetic-answer ref. Use
   `fill_static_text_challenge` only for a returned static-text-answer ref and
   a 1-12 character alphanumeric value; never use it for dynamic CAPTCHA,
   sliders, OTP, or security questions.

## Publisher discovery sessions

1. Start only from a returned `rightout_begin_discovery_session` command. It
   requires the distinct `publisher_discover` campaign effect plus exact
   `directScanAttestations` and a current written provider authorization;
   Brave authority alone is insufficient.
2. Use only `rightout_discovery_session_step` with the latest redacted refs.
   Fill only a returned allowed profile field and use `continue`, `agree`, or
   `select_record` for the matching visible control.
3. `capture_candidate` is valid only after navigation away from the official
   start page. It encrypts the current official-domain URL and records
   `indirect_exposure`, never `found`.
4. Resume the campaign so the exact-page direct recheck can establish identity
   evidence. If publisher terms prohibit automation, the route stays human or
   uses an independently sourced legal-request lane.

## Email and verification

- SMTP: use `rightout_submit_removal` for the core catalog or
  `rightout_submit_parity_email` for an official parity rescue route.
  A rescue route may remain usable while its broker's primary host is externally
  unavailable, but only the email submission is evidenced; the form is reported
  unavailable, not submitted.
- Logged-in Gmail send: use `rightout_begin_webmail_session`, then its step tool
  with only `recipient`, `message_subject`, and `message_body` field names. Inbox
  and message content remain redacted. `send` is the only final purpose.
- Receiver-authenticated IMAP: use `rightout_poll_verification`, then
  `rightout_open_verification` with the opaque handle.
- Browser-mail verification: when the campaign includes both
  `poll_verification` and `open_verification`, use
  `rightout_begin_webmail_verification` in the exact configured logged-in Gmail
  profile. Continue through `rightout_webmail_session_step` using only
  `open_message`, `inspect_authentication`, and `open_confirmation` refs from
  the latest redacted snapshot. The plugin requires intended-recipient match,
  an allowlisted `signed-by`/`mailed-by` domain, and one HTTPS confirmation
  control on an allowlisted broker domain. Raw mail and link values never leave
  the browser control plane. If any gate is missing or ambiguous, close the
  session and report the human task; never reconstruct a link.
- Verification links must pass HTTPS, credential, port, and official-domain
  phishing checks. Never open a reconstructed or arbitrary URL.

Report SMTP/browser send evidence only as `submitted`. Report a confirmation
link open as `verification_opened`/processing, not deletion.

## California DROP and other registries

For an eligible California profile, DROP is the highest-leverage registry lane.
State account creation, login, residency, and identity verification are human.
After the operator has personally verified that the filing occurred, call
`rightout_record_drop_filed(profileId)` under its separate native approval. It
creates one durable `ca_drop` case scoped to the current official registry
snapshot, tracks the 2026-08-01 processing boundary, a 90-day ordinary
processing deadline, and 45-day checkpoints. It does not claim non-registered
or FCRA data was deleted.

Beginning with the official status window, a person may inspect DROP and call
`rightout_record_drop_status(profileId, observedStatus)` under a new exact
approval. Record only the literal observed state. `deleted` remains a portal
claim and must stay `deletion_confirmed: false`, with no confirmation scope.
Never infer record-level deletion from a government status.

For GPC, RightOut does not configure a browser, extension, or site. After the
operator personally verifies a native browser setting or browser extension,
`rightout_record_gpc_observed(profileId, surface)` may record the local
preference. It is an opt-out-of-sale/sharing signal, not a deletion request or
deletion proof. Per-site receipt, legal effect outside California, and provider
compliance remain `needs_evidence`.

Use `rightout_registry_search` for public controller routing. Do not return raw
registry contact addresses or treat registration as proof the broker holds the
subject's data.

## Assisted mode

If the operator does not authorize a campaign, use the individual effect tools.
The core Brave, exact-listing read, SMTP, closed form, inbox-read, and link-open
tools then require their own native `allow-once`. Approval from one action never
authorizes another. Generic parity form, outbound browser-webmail, and
publisher-browser sessions require a finite campaign; form/publisher access
also requires current written provider authorization. Use a narrow broker/effect
scope and the smallest useful budget when the operator does not want a broad
autonomous run.

## Durable state and outcomes

- `submission_pending` or `submission_uncertain` forbids automatic retry. After
  personal provider-side review, use `rightout_reconcile_submission`; only
  `provider_write_not_started` restores retry eligibility.
- Controller outcomes are recorded through `rightout_record_controller_outcome`
  only after human review. SMTP or browser success never supplies that outcome.
- `confirmed_removed` for people-search means two time-separated trusted direct
  absences across the encrypted known-listing set. Always state that new or
  unindexed URLs were not checked.
- `confirmed_removed` from a controller response is limited to that controller
  and reviewed identifiers.
- DROP portal status and GPC preference state never contribute to
  `confirmed_removed`.
- Use `rightout_due_rechecks` in an official OpenClaw Cron turn. A third-party
  plugin cannot self-schedule the next session turn.
- Use `rightout_export_report` for Markdown, structured JSON, and Google
  Sheets-compatible rows.
- Purge and key rotation require their dedicated tools and native approvals.

## Output contract

Lead with the evidenced state, authorization boundary, provider write count,
and next action. Label facts as `observed`, `evidenced`, `inferred`,
`needs_evidence`, or `human_task`.

Never omit relevant limits:

- Brave discovery is indirect.
- One direct absence does not confirm removal.
- Commercial/private inventories and legal outcomes are not guaranteed.
- EU multi-company browser preferences are not universal controller erasure.
- DROP is human-verified and excludes non-registered/FCRA exceptions.
- Catalog-stale and source-unverified lanes are blocked, not bypassed.
- Current public provider terms authorize zero reference form routes by default;
  8 prohibit automation and 14 remain `needs_evidence`.

## Synthetic validation

```bash
python3 {baseDir}/scripts/validate_data_broker_removal.py --skill-dir {baseDir}
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} scan-only-dummy --workdir .tmp/rightout-scan-only
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} e2e-dummy --workdir .tmp/rightout-e2e
```

Never present `fixture_only` output as real evidence. Read only the relevant
reference under `{baseDir}/references/` for the selected jurisdiction or lane.
