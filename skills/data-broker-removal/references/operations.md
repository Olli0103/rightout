# Operations

## Operating Posture

OpenClaw posture is safer than Hermes autonomy by default:

- Read-only discovery and dummy E2E are allowed.
- Live PII processing, scans, submissions, provider writes, and recurring jobs are approval-bound.
- The runner emits action plans and receipts; it does not send email or submit forms.
- Real PII planning and draft persistence require a runner-verified encrypted/local-storage marker plus explicit `process_real_pii` and `store_dossier` receipts. Operator-attested markers document intent but do not unlock real PII gates unless the runner verifies them; unencrypted exceptions must be narrow `store_dossier` receipt scopes.
- EU/EEA subjects must be routed through GDPR/DSGVO Article 17 only when controller scope is plausible; otherwise use generic removal or monitor-only language.

## Discovery Ladder

1. Check local history and source notes for prior runs.
2. Build a jurisdiction-aware broker plan from the catalog.
3. For scan-only runs, stop at evidence classification and reporting. Do not prepare requests, render drafts, or queue submissions from scan-only mode.
4. For approved live audits, search cheapest first:
   - official broker search/opt-out matcher;
   - search-engine `site:` probe;
   - OpenClaw browser snapshot for JS-only pages;
   - operator-browser check for anti-bot sites;
   - blocked/human task when there is no safe path.
5. Record `found`, `not_found`, `inconclusive`, `indirect_exposure`, or `blocked` with evidence.

## User-Facing Baseline

Commercial tools such as Incogni and DeleteMe set the user expectation: an initial scan, broad broker coverage, recurring rechecks, a dashboard/report, per-broker progress, and clear "what happened next" language. OpenClaw should match the useful visibility, not the black-box autonomy.

Optery adds the strongest transparency benchmark: exposure/removal reports with proof screenshots, real-time dashboard status, activity history, and custom scans/removals. Privacy Bee adds privacy-risk scoring, an encrypted identity vault, exportable source status, and ongoing monitoring. Aura frames data-broker removal as one lane inside broader identity-theft, breach, dark-web, spam/scam, and device-safety protection. OpenClaw should separate those lanes clearly and gate each external action.

Reports should answer:

- Where did the scan find exposure?
- Which brokers were checked and what was inconclusive?
- What was submitted, what is waiting, and what was confirmed removed?
- Which tasks require the operator because of CAPTCHA, phone/fax/mail, account creation, ID proof, or legal-controller uncertainty?
- What is the next recheck window?
- Which HIBP breach/data-class signals raise priority for address, phone, identity, spam-list, credential, or stealer-log risk?

Keep scan evidence, removal evidence, and HIBP breach intelligence separated. A HIBP hit is a risk signal, not proof that a broker currently publishes the subject.

Do not claim catalog completeness. Track broker coverage as a source-backed starter catalog with freshness/provenance, and make gaps visible in reports.

## Have I Been Pwned / Breach Intelligence

- Do not query HIBP for a real email address unless `process_real_pii`, `store_dossier`, and the relevant external-read approval are explicit.
- Prefer operator-supplied HIBP exports/API results or a future approved HIBP connector.
- HIBP API account, paste, domain, and stealer-log searches are authenticated or subscriber-scoped; public breach metadata and Pwned Passwords range checks have different privacy properties.
- Store only sanitized breach names, data classes, dates, and risk tags in reports. Do not store raw account identifiers, passwords, password hashes tied to identity, or full leaked values.
- Use HIBP data classes to prioritize broker cleanup and account-security follow-up; do not treat them as deletion evidence.

## Removal Lanes

- `registry`: state or government registry, such as California DROP when eligible.
- `web_form`: official broker removal form.
- `email`: official privacy or rights-request address.
- `guided_flow`: opt-out flow whose matcher doubles as search.
- `operator_browser`: operator performs a bounded field-by-field check.
- `human_task`: phone, fax, mail, government ID, account creation, hard CAPTCHA, or unclear legal basis. The runner can record the outcome only after `human_completed` evidence.
- `monitor_only`: Google result removal or search alert style workflows that do not remove broker source data.

## Europe / GDPR / DSGVO

- Treat GDPR/DSGVO as a controller-rights lane, not as a universal broker magic wand.
- Verify jurisdiction and controller scope before drafting.
- Use the controller's official privacy/DPO contact or rights portal only.
- Keep the generic EU/EEA catalog lane as `human_task` until the exact controller contact URL and allowed domain have been recorded and verified; record `human_completed` before marking it submitted.
- Ask for erasure of personal data about the subject; for indirect/relative records, target only the subject's identifiers on that third-party page.
- Do not volunteer identity documents, national IDs, passport numbers, full birth dates, or utility bills. If the controller requests proof, queue a human decision with the exact reason and withhold list.
- Track the one-month response window as `awaiting_processing`; `confirmed_removed` still requires a later verification scan.

## Blind Opt-Out

Hermes uses blind opt-out as a default when an official removal lane exists. OpenClaw may recommend it only after:

- subject consent is recorded;
- jurisdiction and disclosure fields are checked;
- the lane is the broker's official channel;
- the operator approves the submission class;
- indirect/third-party exposure is excluded or handled as targeted delete-my-PII.

## Recheck Cadence

- Initial processing window: use broker stated timeline when known; otherwise 14-45 days.
- High-risk subjects: monthly recheck.
- Normal subjects: quarterly recheck.
- Low-risk maintenance: 6-12 month recheck.
- Never create cron without `schedule_recheck` approval.

## Reporting

Reports must separate:

- found exposure;
- no listing found;
- inconclusive scans;
- submitted requests;
- awaiting verification;
- confirmed removals;
- residual public records or paid-tier exposure;
- human-only tasks.
- HIBP/breach risk signals.

The JSON report should contain per-broker statuses, coverage, removal summary, scan-only posture, next actions, and optional HIBP summary. Telegram summaries should be compact and omit raw PII.
