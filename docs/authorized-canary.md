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
6. Complete a subject purge test after retaining only the sanitized operational
   evidence required by the deployment policy.

## Sanitized evidence record

Record only:

- plugin/OpenClaw versions and release-evidence digest;
- opaque profile, broker, case, and proof references;
- approval decision type and timestamp, not prompt secrets or profile values;
- state transitions and sanitized provider status classes;
- duplicate-write count, unexpected disclosure count, and operator handoffs;
- whether the documented retention and purge behavior completed.

Never archive raw names, addresses, emails, phones, queries, listing URLs,
messages, form bodies, controller responses, credentials, identity documents,
or screenshots containing them.

## Exit criteria

The canary passes only when approvals cannot be replayed, no raw PII appears in
tool output or the case ledger, disclosures match the catalog, duplicate writes
are zero, restart recovery is deterministic, ambiguous outcomes fail closed,
and purge/retention behavior matches policy. A broker's eventual action remains
narrow evidence for that controller and identifier set—not proof of universal
deletion or future non-reappearance.
