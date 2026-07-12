# Removal state semantics

States: `new`, `searching`, `not_found`, `found`, `inconclusive`, `indirect_exposure`, `action_selected`, `approval_required`, `submitted`, `verification_pending`, `awaiting_processing`, `confirmed_removed`, `reappeared`, `human_task_queued`, and `blocked`.

## Live semantics

- Scan can return only `indirect_exposure` or `inconclusive`.
- Removal can return only `submitted` after outbound SMTP acceptance.
- Broker receipt, verification, and processing are not currently ingested.
- `confirmed_removed` is unavailable live because index absence is not direct absence evidence.
- A later `indirect_exposure` after submission can indicate possible continued/reappeared exposure but remains indirect.

## Synthetic validation

The dummy runner exercises the complete matrix to validate reporting:

- `found` requires synthetic listing evidence;
- `submitted` requires official-channel syntax, allowlisted field names, confirmation status, and opaque proof;
- `confirmed_removed` requires a later-scan marker;
- `reappeared` follows only synthetic confirmed removal;
- sensitive fields require a human-only explicit gate;
- invalid transitions fail closed.

Only `fixture_only: true` cases may transition in the Python runner. These states prove report logic, not real action.
