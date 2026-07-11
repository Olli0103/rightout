# RightOut

Approval-gated OpenClaw skill for auditing and staging data-broker, people-search, and rights-based opt-out workflows.

RightOut is built for a specific promise: help an operator validate a conservative OpenClaw workflow for data-broker removal planning without silently sending real PII to brokers or providers.

Public status: **technical preview**. The public runner supports dummy validation and conservative report plumbing. Live PII processing, live broker scans, request rendering, and submissions are intentionally disabled until a platform-owned OpenClaw approval adapter exists.

It is not a one-click deletion bot, legal advice, or a complete global broker database.

## What It Does

- Runs dummy end-to-end checks by default.
- Supports scan-only reporting so a user can see exposure status without submissions.
- Produces report v2 sections for found, not found, inconclusive, submitted, awaiting processing, confirmed removed, human tasks, and HIBP risk signals.
- Keeps GDPR/DSGVO, UK GDPR, CCPA/CPRA, California DROP, broker opt-outs, and monitor-only lanes separate.
- Imports HIBP-style breach intelligence only as sanitized risk signals, not as raw leaked values.
- Requires explicit approval gates for real PII, local dossier storage, live scans, external submissions, recheck automation, and provider writes.
- Ships with a small official-source starter catalog for legal/registry/monitor-only lanes.

## What It Does Not Do

- It does not guarantee complete removal from every broker.
- It does not bypass CAPTCHAs, phone callbacks, government-ID gates, account creation, or anti-bot controls.
- It does not submit forms, send email, open verification links, query live brokers with real identifiers, schedule cron, or write to providers.
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

## Install

```bash
git clone https://github.com/Olli0103/rightout.git
cd rightout
./install.sh
```

This installs the skill to `~/.openclaw/workspace/skills/data-broker-removal` and runs the validator.

For custom workspaces, updates, and validation details, read `INSTALL.md`.

## OpenClaw Usage

Install or copy `skills/data-broker-removal/` into an OpenClaw workspace skill directory, then load the skill when a user asks for data-broker audit, opt-out planning, removal staging, or privacy exposure review.

The skill is designed to be operator-driven:

1. Start with `doctor`, `scan-only-dummy`, and `e2e-dummy`.
2. Produce an audit/removal plan with minimum required fields.
3. Keep real PII, live scans, submissions, scheduled rechecks, and provider writes out of the public runner until an OpenClaw-owned approval adapter is integrated.
4. Recheck later before marking anything `confirmed_removed` in any future live integration.

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
- Privacy Guides and IntelTechniques are useful research references, but v0.1.1 does not ship broker records derived from them. Do not add third-party list material without compatible licensing, attribution, and clean-room review.
- Incogni, DeleteMe, Optery, Privacy Bee, Aura, and HIBP are used as UX/source references only where documented.

Read `skills/data-broker-removal/THIRD_PARTY_NOTICES.md` before expanding the catalog.

## Community Status

RightOut is ready as a conservative dummy-first technical preview. The starter catalog is intentionally small and extensible. Contributions should add provenance, freshness dates, official URLs, license review notes, and tests.
