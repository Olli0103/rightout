# Authorized deployment canary

This runbook verifies a real deployment without turning private data into test
fixtures or weakening RightOut's approval boundary. It is not part of repository
CI and was not executed for the software release.

## Entry gate

Proceed only when all of the following are evidenced outside the model:

- the subject is the operator or has given valid, current authority;
- the deployment-compliance gate is complete for the applicable jurisdictions;
- Brave, SMTP, IMAP, secret storage, retention, and transfer terms are approved;
- OpenClaw config, secret, security, runtime-inspection, and doctor checks pass;
- `openclaw plugins inspect rightout --runtime --json` proves the installed
  package exposes the exact v0.10.0 52-tool contract; a source checkout alone is
  not runtime evidence;
- the catalog-health report has zero stale entries;
- the profile uses SecretRefs and contains only the minimum identifiers needed;
- an operator is present for every native `allow-once` decision and human task.

If any item is absent, stop and record `needs_evidence` without contacting a
provider.

## Staged canary

1. Run `rightout_next_actions` and `rightout_catalog_health`. Confirm that no
   provider call or write occurred and that the intended broker scope is exact.
2. Approve one Brave discovery lane for one authorized profile. Verify that the
   result exposes only opaque references and classifies an index candidate as
   `indirect_exposure`, never identity proof.
3. If the subject independently confirms the target and the legal gate permits
   it, approve exactly one catalog-locked request. Verify durable intent exists
   before the provider call and that the result is only `submitted` or
   `verification_pending`.
4. Exercise only the documented confirmation or recheck path. CAPTCHA, identity
   documents, disputed authority, legal exceptions, and unexpected portals go
   to a human and stop automation.
5. Restart the Gateway before the next due action. Verify that the case resumes
   without duplicate provider writes and that uncertain writes require explicit
   reconciliation.
6. Only after the assisted path is understood, approve one finite campaign and
   one durable worker in the exact current session. Verify one leased command,
   checkpointed effect, current-session scheduling (or explicit Cron handoff),
   revoke behavior, and stop-on-human-gate semantics. Do not use a multi-broker
   worker as the first live action.
7. If team mode is in scope, verify viewer/manager/owner access from their exact
   sessions, cross-profile denial, full Gateway direct-invoke denial, and one
   static local dashboard export containing no PII or remote resource.
8. Complete a subject purge test after retaining only the sanitized operational
   evidence required by the deployment policy.

## Sanitized evidence record

Record only:

- plugin/OpenClaw versions and release-evidence digest;
- opaque profile, broker, case, and proof references;
- approval decision type and timestamp, not prompt secrets or profile values;
- state transitions and sanitized provider status classes;
- duplicate-write count, unexpected disclosure count, and operator handoffs;
- worker lease/checkpoint/revoke state and scheduler-vs-handoff status;
- optional `canary_<opaque>` proof references for a state-consistent delivered
  identity review, delivered submission, controller confirmation, direct
  absence, reappearance, or human handoff—never the raw evidence behind the
  reference;
- Canary records use schema v2 and include an opaque profile and broker,
  `startedAt`, `observedAt`, the proof reference, a SHA-256 authorization
  reference, and a SHA-256 deployment-evidence reference. Identity reviews also
  carry exactly one of `true_positive`, `false_positive`, `false_negative`, or
  `true_negative`;
- whether the documented retention and purge behavior completed.

Never archive raw names, addresses, emails, phones, queries, listing URLs,
messages, form bodies, controller responses, credentials, identity documents,
or screenshots containing them.

## Exit criteria

The canary passes only when approvals cannot be replayed, no raw PII appears in
tool output or the case ledger, disclosures match the catalog, duplicate writes
are zero, restart recovery is deterministic, ambiguous outcomes fail closed,
and purge/retention behavior matches policy. Operational effectiveness requires
both reviewed identity observations with visible precision/recall denominators
and at least one scoped provider-outcome, direct-absence, or reappearance fact.
Delivery or outcome evidence alone remains only
`partially_evidenced_by_authorized_canaries`. A broker's eventual action remains
narrow evidence for that controller and identifier set—not proof of universal
deletion or future non-reappearance.

The release does not claim this canary has run. Until an authorized deployment
records consistent facts, `rightout_effectiveness` must remain
`needs_evidence`.
