# RightOut

Approval-gated OpenClaw skill for auditing and staging data-broker, people-search, and rights-based opt-out workflows.

RightOut is built for a specific promise: help an operator understand where personal data may be exposed, prepare removal work, and track verification without silently sending real PII to brokers or providers.

It is not a one-click deletion bot, legal advice, or a complete global broker database.

## What It Does

- Runs dummy end-to-end checks by default.
- Supports scan-only reporting so a user can see exposure status without submissions.
- Produces report v2 sections for found, not found, inconclusive, submitted, awaiting processing, confirmed removed, human tasks, and HIBP risk signals.
- Keeps GDPR/DSGVO, UK GDPR, CCPA/CPRA, California DROP, broker opt-outs, and monitor-only lanes separate.
- Imports HIBP-style breach intelligence only as sanitized risk signals, not as raw leaked values.
- Requires explicit approval gates for real PII, local dossier storage, live scans, external submissions, recheck automation, and provider writes.
- Ships with a source-backed starter catalog of broker/registry/controller flows.

## What It Does Not Do

- It does not guarantee complete removal from every broker.
- It does not bypass CAPTCHAs, phone callbacks, government-ID gates, account creation, or anti-bot controls.
- It does not submit forms, send email, open verification links, query live brokers with real identifiers, schedule cron, or write to providers without approval.
- It does not treat HIBP breach signals as proof that a broker has a current listing.
- It does not copy proprietary broker lists or commercial service coverage claims.

## Repository Layout

```text
skills/data-broker-removal/
  SKILL.md
  README.md
  THIRD_PARTY_NOTICES.md
  references/
  scripts/
  templates/
tests/skills/test_data_broker_removal_skill.py
docs/
```

## Quick Start

```bash
python3 skills/data-broker-removal/scripts/data_broker_removal.py --skill-dir skills/data-broker-removal doctor
python3 skills/data-broker-removal/scripts/data_broker_removal.py --skill-dir skills/data-broker-removal scan-only-dummy --workdir .tmp/rightout-scan-only
python3 skills/data-broker-removal/scripts/data_broker_removal.py --skill-dir skills/data-broker-removal e2e-dummy --workdir .tmp/rightout-e2e
python3 skills/data-broker-removal/scripts/validate_data_broker_removal.py --skill-dir skills/data-broker-removal
python3 -m unittest tests.skills.test_data_broker_removal_skill
```

No network calls or provider writes are required for the dummy validation path.

## OpenClaw Usage

Install or copy `skills/data-broker-removal/` into an OpenClaw workspace skill directory, then load the skill when a user asks for data-broker audit, opt-out planning, removal staging, or privacy exposure review.

The skill is designed to be operator-driven:

1. Start with `doctor`, `scan-only-dummy`, and `e2e-dummy`.
2. Produce an audit/removal plan with minimum required fields.
3. Ask for separate approval before real PII, storage, live scans, submissions, scheduled rechecks, or provider writes.
4. Recheck later before marking anything `confirmed_removed`.

## Approval Gates

RightOut models these gates explicitly:

- `process_real_pii`
- `store_dossier`
- `live_scan`
- `send_request`
- `schedule_recheck`
- `provider_write`

Outside test mode, local approval receipts must be signed by the OpenClaw approval boundary. Receipts are local runner inputs, not a replacement for a real user approval event.

## Privacy And Security Model

RightOut keeps PII out of paths, task titles, chat summaries, and logs. It uses opaque subject IDs, local private file modes, field-name-only disclosure logs, verified storage posture checks, and human-task queues for workflows that require sensitive proof or manual verification.

Read the detailed model in:

- `skills/data-broker-removal/references/security-model.md`
- `skills/data-broker-removal/references/operations.md`
- `skills/data-broker-removal/references/state-machine.md`

## License And Attribution

Code and original documentation in this repository are released under the MIT License.

Important source notes:

- Hermes `unbroker` influenced the design and is MIT-licensed upstream.
- BADBOOL is credited upstream under CC BY-NC-SA 4.0; this repository does not import BADBOOL-derived broker records wholesale.
- IntelTechniques is treated only as a research pointer to official broker/controller URLs; do not copy workbook prose, requirements, contact fields, notes, or bulk records without compatible permission.
- Incogni, DeleteMe, Optery, Privacy Bee, Aura, and HIBP are used as UX/source references only where documented.

Read `skills/data-broker-removal/THIRD_PARTY_NOTICES.md` before expanding the catalog.

## Community Status

RightOut is ready as a conservative, approval-gated OpenClaw workflow. The starter broker catalog is intentionally extensible. Contributions should add provenance, freshness dates, official URLs, license review notes, and tests.

