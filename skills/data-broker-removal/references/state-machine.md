# Case State Machine

One case is one subject against one broker or registry lane.

## States

- `new`: case created, no action.
- `searching`: read-only discovery in progress.
- `not_found`: broker search or opt-out matcher returned no subject listing.
- `found`: listing confirmed as the subject.
- `inconclusive`: scan did not prove found or not found.
- `indirect_exposure`: subject PII appears on another person's record.
- `action_selected`: removal lane chosen.
- `approval_required`: next action needs explicit approval.
- `submitted`: request submitted.
- `verification_pending`: waiting for email/callback verification.
- `awaiting_processing`: broker processing window is open.
- `confirmed_removed`: later scan verified removal.
- `reappeared`: previously removed listing returned.
- `human_task_queued`: requires operator step.
- `blocked`: mechanics broken, hostile, or unsupported.

## Allowed Transitions

```text
new                  -> searching | found | not_found | inconclusive | indirect_exposure | blocked
searching            -> not_found | found | inconclusive | indirect_exposure | blocked
not_found            -> searching | found | inconclusive | indirect_exposure | blocked
inconclusive         -> searching | action_selected | human_task_queued | blocked
found                -> action_selected | approval_required | human_task_queued | indirect_exposure | blocked
indirect_exposure    -> action_selected | approval_required | human_task_queued | not_found | found | blocked
action_selected      -> approval_required | human_task_queued | blocked
approval_required    -> submitted | human_task_queued | blocked
submitted            -> verification_pending | awaiting_processing | human_task_queued | blocked
verification_pending -> awaiting_processing | confirmed_removed | human_task_queued | blocked
awaiting_processing  -> confirmed_removed | human_task_queued | blocked
confirmed_removed    -> reappeared | confirmed_removed
reappeared           -> found | indirect_exposure | action_selected
human_task_queued    -> found | indirect_exposure | action_selected | submitted | verification_pending | awaiting_processing | confirmed_removed | blocked
blocked              -> searching | found | not_found | inconclusive | indirect_exposure | action_selected | human_task_queued
```

Same-state updates are idempotent when they only add evidence, notes, timestamps, or next-check dates.

## Invariants

- `submitted -> not_found` is invalid. A submitted no-match flow resolves through `awaiting_processing` or a note, not a rollback.
- `blocked -> submitted` must pass through `action_selected` or `approval_required`.
- `confirmed_removed` requires evidence from a later verification scan.
- `submitted` requires disclosed field names plus confirmation evidence and an official source URL whose domain matches the case record.
- `human_only` cases require `human_completed` evidence before `submitted`.
- Direct submissions are never queued without an approval gate unless the run is a dummy test.
