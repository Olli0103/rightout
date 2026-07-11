# OpenClaw Data Broker Removal Skill

Dummy-first OpenClaw technical preview for auditing and staging data-broker and people-search removal workflows.

This package is designed for privacy-safe operation:

- dummy E2E by default;
- no live broker scans in the public runner;
- no external submissions or emails in the public runner;
- opaque subject IDs;
- `0600` local dossier, plan, audit, and report files;
- runner-verified encrypted-storage posture, or a narrow explicit unencrypted exception, required before real PII planning and draft persistence;
- field-name-only disclosure logs;
- GDPR/DSGVO, UK GDPR, CCPA/CPRA, and California DROP lanes are jurisdiction-gated;
- generic GDPR/DSGVO controller requests stay human-task only until a specific controller contact and allowed domain are recorded as verified evidence;
- verification-link domain checks;
- no hard CAPTCHA bypass or anti-bot evasion.

## Quick Check

```bash
python3 scripts/data_broker_removal.py doctor
python3 scripts/validate_data_broker_removal.py
python3 scripts/data_broker_removal.py scan-only-dummy --workdir .tmp/data-broker-removal-scan-only
python3 scripts/data_broker_removal.py e2e-dummy --workdir .tmp/data-broker-removal-e2e
```

From the workspace root:

```bash
python3 tests/skills/test_data_broker_removal_skill.py
python3 scripts/security/secret_scan.py
python3 scripts/security/pii_scan.py --public-if-remote-public
```

## Execution Model

The runner is deterministic and local. It plans, records, renders drafts, scopes verification links, imports sanitized breach intelligence, and reports. It does not send email, submit web forms, open broker verification links, schedule cron, query HIBP with real identifiers, or write provider data.

Approval receipts used by the deterministic runner must be scoped, unexpired, timezone-aware, signed by the OpenClaw approval boundary, and verified with `OPENCLAW_APPROVAL_RECEIPT_KEY` outside test mode. They are gate inputs for the local runner, not a replacement for the user-facing approval event.

Live work is split into explicit gates:

- `process_real_pii`
- `store_dossier`
- `live_scan`
- `send_request`
- `schedule_recheck`
- `provider_write`

## User-Facing Outputs

The report model is designed to answer the questions a person expects from Incogni/DeleteMe-style portals:

- scan-only: which brokers were checked and where exposure appears;
- per-broker status: found, not found, inconclusive, submitted, awaiting processing, confirmed removed, or human task;
- removal summary: requests sent, waiting, confirmed removed, reappeared;
- next actions and recheck timing;
- optional HIBP/breach-intelligence risk summary from an operator-supplied export/API result.

HIBP data is treated as breach-risk intelligence, not broker-removal proof. Real HIBP account lookups remain approval-bound.

The starter catalog is intentionally small for public release and limited to official/legal/monitor-only lanes. People-search broker entries should be re-added only through clean-room official-source review with compatible licensing, provenance, freshness dates, and tests. Do not copy third-party broker-list prose, requirements, notes, contact fields, or bulk records into this skill without a compatible license or permission.

## Community Release Caveats

Before enabling live/community production use:

- integrate a platform-owned OpenClaw approval adapter whose secrets cannot be supplied by the calling agent;
- expand the catalog only with clean-room source-backed records and license review;
- keep operator-specific context out of the package;
- include `LICENSE` and `THIRD_PARTY_NOTICES.md` in the installed subtree;
- run dummy E2E and tests;
- document that this is not legal advice and that submissions require explicit operator approval.
