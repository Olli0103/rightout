# Synthetic case state machine

The state machine validates report semantics only. It does not authorize or execute real actions.

## States

`new`, `searching`, `not_found`, `found`, `inconclusive`, `indirect_exposure`, `action_selected`, `approval_required`, `submitted`, `verification_pending`, `awaiting_processing`, `confirmed_removed`, `reappeared`, `human_task_queued`, and `blocked`.

## Core semantics

- `found` requires synthetic listing evidence.
- `submitted` requires allowlisted field names, official-channel syntax, confirmation status, and an opaque proof reference.
- `confirmed_removed` requires a later-scan marker.
- `reappeared` can follow only a confirmed synthetic removal.
- sensitive fields require a human-only case plus `human_only_explicit` evidence.
- invalid jumps fail closed.

## Community invariant

Only cases with `fixture_only: true` may transition. Shipped catalog cases remain `new` and are reported as `not_checked`. The public CLI exposes no record or mutation command, so a scan-only run cannot enter any removal state.

The live plugin returns a stateless scan report and does not use this persistence/state machine. A live `indirect_exposure` index signal therefore cannot advance to `submitted` or any other removal state.

These states describe test coverage. They are not claims that a request was approved, sent, processed, or verified.
