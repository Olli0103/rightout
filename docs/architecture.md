# Architecture

RightOut separates user-facing privacy work into deterministic local stages.

## Stages

1. `doctor`: validate the runner and broker catalog.
2. `intake-subject`: store a subject dossier only after consent and storage gates.
3. `scan-only-dummy`: produce exposure-style reporting without submissions.
4. `plan`: create broker cases and required next actions.
5. `render-request`: prepare request drafts only after required gates.
6. `mark-submitted`: record an operator-approved submission.
7. `mark-removed`: mark confirmed removal only after verification evidence.
8. `report`: summarize status, next actions, human tasks, and risk signals.

## Key Invariants

- Dummy mode must not require approvals.
- Live real-PII mode must require `process_real_pii` and `store_dossier`.
- External submissions must require `send_request`.
- Provider writes must require `provider_write`.
- Scan-only mode must not produce submission actions.
- HIBP signals are risk intelligence, not broker evidence.
- `confirmed_removed` means verified after the fact, not merely requested.

