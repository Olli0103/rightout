# Removal state semantics

Live plugin states: `new`, `searching`, `not_found`, `found`, `inconclusive`, `indirect_exposure`, `action_selected`, `submission_pending`, `submission_uncertain`, `submitted`, `verification_pending`, `awaiting_processing`, `identity_verification_required`, `partially_removed`, `request_rejected`, `confirmed_removed`, `reappeared`, `human_task_queued`, and `blocked`.

## Live semantics

- Scan can return only `indirect_exposure` or `inconclusive`.
- Removal can return only `submitted` after outbound SMTP acceptance.
- Broker receipt, verification, and processing are not currently ingested.
- Search-index absence can never produce `confirmed_removed`.
- One direct absence after a prior removal records the first observation and remains `awaiting_processing`; a second time-separated absence after the due time may confirm only the known listing set.
- Human-reviewed EU/UK/US controller outcomes may produce a controller-response-scoped confirmation, partial removal, identity follow-up, rejection, or continued processing.
- `submission_pending` and `submission_uncertain` block retry until separately approved human reconciliation.
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
