---
name: "data-broker-removal"
description: "Audit and stage consent-gated data-broker removal workflows."
metadata:
  openclaw:
    safety: approval-gated
    source: "NousResearch/hermes-agent optional-skills/security/unbroker"
    requires:
      bins: ["python3"]
---

# Data Broker Removal

Use when The operator asks to find, assess, remove, or monitor personal information on data brokers, people-search sites, or opt-out services.

This skill adapts the verified Hermes `unbroker` design for OpenClaw. It is not a blind import. OpenClaw defaults to read-only audit and proposal mode; external submissions, provider writes, mail sends, broker form submissions, cron changes, and PII retention require explicit approval at the moment of action.

Use the deterministic runner before any live work:

```bash
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} doctor
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} scan-only-dummy --workdir .tmp/data-broker-removal-scan-only
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} e2e-dummy --workdir .tmp/data-broker-removal-e2e
```

## Hard Boundaries

- Consent is mandatory before handling a person's PII for broker removal.
- Never act on a third party unless the operator gives explicit authorization and the subject's consent is clear.
- Default to audit/dummy-run/proposal only.
- Do not submit broker forms, send emails, open verification links, schedule recurring scans, or store sensitive dossiers without a separate approval.
- Do not claim deletion until a later verification scan confirms the listing is gone.
- Do not bypass hard CAPTCHAs, behavioral challenges, phone callbacks, government-ID gates, fax/mail-only workflows, or account-creation requirements.
- Do not volunteer SSNs, ID numbers, full birth dates, or unnecessary identifiers.
- Keep PII out of paths, task titles, chat summaries, and logs. Use opaque subject IDs.

## When To Use

- The operator asks whether a data-broker cleanup tool or link is usable.
- The operator asks to remove his data from people-search sites or brokers.
- The operator asks for a privacy exposure audit, broker opt-out plan, or recurring recheck design.
- The operator asks to adapt Hermes `unbroker` or a similar privacy-removal workflow for OpenClaw.

## Source Baseline

Verified input as of 2026-07-11:

- X status `2075646038053195841` points to Hermes `unbroker`.
- Follow-up link expands to `github.com/NousResearch/hermes-agent/tree/main/optional-skills/security/unbroker`.
- The repo and skill exist publicly under `NousResearch/hermes-agent`.
- The bundled `test_unbroker_skill.py` passed locally: `97/97 passed`.
- Local OpenClaw host has `python3`; `hermes` CLI is not installed.
- Hermes `unbroker` status says v1.0, but live agent-driven broker submission is still an active field-testing frontier.

Treat Hermes `unbroker` as a reference implementation and test corpus, not as production authority for OpenClaw.

## Workflow

1. Clarify scope in one short question if missing: subject, jurisdiction, audit-only vs removal, and whether real PII may be processed locally.

2. Run duplicate/source check:
   - search local memory/Brain/source notes for the exact tool, broker, person, or prior removal run;
   - identify whether this is a new source, a known topic, or an existing workflow.

3. Start with read-only assessment:
   - list likely broker classes and exposure surfaces;
   - identify high-leverage legal lanes such as GDPR/DSGVO/UK GDPR, CCPA/CPRA, and state registries only when jurisdiction applies;
   - do not scan live broker sites with PII until approved.

4. Dummy-run first:
   - run `e2e-dummy`;
   - run `scan-only-dummy` when the operator wants to know "where am I exposed?" before removal planning;
   - verify state transitions, approval gates, report output, no external actions, and opaque paths;
   - inspect generated reports before any live approval.

5. Produce a removal plan before any live action:
   - expected broker list and source of broker data;
   - explicit catalog coverage and gaps; never claim the catalog is complete;
   - fields each broker would require;
   - action type: web form, email request, legal registry, human task, or monitor-only;
   - risk level and required approval for each action class;
   - HIBP/breach intelligence inputs when operator supplied or explicitly approved, summarized as risk tags and data classes, not raw email/account data;
   - recheck schedule proposal, not an active cron.

6. If the operator approves live audit with real PII:
   - create or choose a runner-verified encrypted/local data location first and record that storage posture before persisting real dossiers;
   - treat operator-attested storage markers as documentation only unless the runner marks them verified;
   - keep unencrypted local storage as an explicit scoped exception, not as an encryption marker;
   - record consent and scope;
   - use least-disclosure search vectors;
   - classify findings as `found`, `not_found`, `inconclusive`, `blocked`, or `human_required`;
   - never record names or raw PII in filenames or public summaries.

7. If the operator separately approves submissions:
   - submit only to official broker channels;
   - for GDPR/DSGVO/UK GDPR controller requests, record the specific controller privacy/DPO URL or rights portal and verified allowed domain before drafting, even when the broker has a normal opt-out lane;
   - send only the exact fields required for that broker and legal basis;
   - record channel, field names disclosed, timestamp, and confirmation evidence;
   - queue human-required blockers into a digest instead of interrupting repeatedly.

8. Verify outcomes:
   - re-scan after the broker's stated processing window;
   - mark `confirmed_removed` only after evidence shows the listing is gone;
   - distinguish suppression, hidden-from-free-search, deletion requested, deletion confirmed, and residual exposure.

Load references only when needed:

- `{baseDir}/references/security-model.md` for approvals, PII handling, threat model, and release gates.
- `{baseDir}/references/operations.md` for scan/plan/submit/recheck posture.
- `{baseDir}/references/state-machine.md` for case lifecycle semantics.
- `{baseDir}/references/source-matrix.md` for verified source evidence and caveats.
- `{baseDir}/references/legal/gdpr.md` for GDPR/DSGVO/UK GDPR erasure posture and constraints.
- `{baseDir}/references/brokers/core.json` for the starter broker/registry/catalog lanes.

## Approval Gates

Ask separately before each class of action:

- `process_real_pii`: use the subject's real identifying data locally.
- `store_dossier`: persist a local dossier, ledger, or report containing PII.
- `live_scan`: query broker/people-search sites with real identifiers.
- `send_request`: send email, submit web forms, file legal requests, or open verification links.
- `schedule_recheck`: create or modify cron/automation.
- `provider_write`: write to Todoist, Mail, Calendar, Google, public channels, or other providers.

Approval wording must name what will change and what will not change.

## OpenClaw Adaptation Notes

- Prefer OpenClaw browser tools for controlled web inspection.
- Prefer local deterministic scripts for planning, ledgers, and validation.
- If importing Hermes scripts, isolate them under a proposal or spike path first and run their tests before adapting.
- Use runner-verified encryption before storing real dossiers; local JSON approval receipts must be signed by the platform approval boundary outside test mode.
- Rendered live request drafts are PII-bearing storage and require the same `process_real_pii`, `store_dossier`, and encrypted-storage checks.
- Keep summaries Telegram-safe: no raw addresses, phone numbers, emails, relatives, or DOBs.
- Treat commercial-service comparisons as context only; do not imply guaranteed completeness.
- Community release requires a separate repo review for license provenance, broker catalog attribution, and no personal workspace leakage.

## Output Contract

For checks and verification:

```text
Status: usable / not usable / spike only
Source: exact repo/path/link checked
Local fit: installed / missing / needs adaptation
Risk: main privacy or automation risk
Recommendation: no-op / capture / spike / audit / implement with approval
Next approval needed: exact action, or none
```

For a live audit plan:

```text
Scope: subject + jurisdiction + audit/removal boundary
Data needed: minimum identifiers only
Storage: none / temporary / encrypted local path
Broker lanes: people-search / registry / legal email / human-only
Approval needed before: live scan, submissions, recurring checks
Non-goals: no public records removal, no account deletion, no hard CAPTCHA bypass
```

For user-facing reports, match the expectations set by commercial removal portals without copying their closed workflows:

- scan-only view: where data appears, which brokers were checked, found/not found/inconclusive counts, and no submissions;
- removal-progress view: request sent, waiting for verification, awaiting broker processing, confirmed removed, reappeared;
- per-broker status: broker name, lane, stage, source URL, last note, next recheck;
- human-task digest: CAPTCHAs, phone/fax/mail, government ID, account creation, or controller-scope decisions;
- risk intelligence: HIBP breach/data-class signals and recommended priority, clearly separated from broker-removal evidence;
- compact Telegram summary with no raw PII and a local JSON report path only when storage was approved.

## Validation

Before saying the workflow is ready:

- Run `python3 {baseDir}/scripts/validate_data_broker_removal.py --skill-dir {baseDir}`.
- Run `python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} scan-only-dummy --workdir .tmp/data-broker-removal-scan-only`.
- Run `python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} e2e-dummy --workdir .tmp/data-broker-removal-e2e`.
- Confirm the runner refuses live scans/submissions without explicit approval tokens.
- Check that dummy-run output uses opaque subject IDs and no PII in filenames.
- Confirm report v2 includes broker statuses, removal summary, scan-only posture, and optional HIBP risk summaries without raw account identifiers.
- Confirm OpenClaw approval gates in the final response.
- For behavior changes to Telegram-facing output, run `make clawy-output-evals` when a fixture is touched.

## Non-Goals

- Legal advice.
- Public-record erasure.
- Account deletion from services the subject controls.
- Automated hard-CAPTCHA solving or anti-bot evasion.
- Provider writes or external submissions without explicit approval.
- Turning Hermes into an OpenClaw dependency without a separate architecture decision.
