---
name: data-broker-removal
description: Scan supported data brokers and submit catalog-locked removal requests through separate native OpenClaw approvals.
---

# RightOut data-broker removal

Use the installed RightOut plugin for live discovery and removal. Keep the two authorization scopes separate.

## Hard boundary

- Pass only opaque `profileId`, `brokerId` or `brokerIds`, and the fixed request kind to RightOut tools.
- Never ask the user to paste a name, address, email, phone number, date of birth, listing URL, verification token, credential, identity document, or breach value into chat or tool arguments.
- Require private profiles, recorded subject consent, provider credentials, and operator attestations to exist as OpenClaw SecretRefs before live work. If they are missing, return `needs_evidence`.
- Never replace native OpenClaw approval with prose, a local receipt, a model-generated token, or a previous approval.
- Never use browser, web search, shell, Python, email, forms, or provider tools as a fallback around a blocked RightOut lane.
- Never solve or bypass a CAPTCHA. Never upload an identity document. Route unsupported forms and sensitive verification to a human task.
- Never claim legal advice, certification, broker receipt, processing, or completed removal without direct evidence.

## Live scan

1. Confirm the user asked for live discovery and supplied an existing opaque profile reference.
2. Select only catalog brokers with `scan.supported: true`.
3. Call `rightout_live_scan` once with the exact opaque profile and broker IDs.
4. Let OpenClaw request `allow-once` or `deny` for that scan only.
5. Report `indirect_exposure` and `inconclusive` exactly. A Brave index candidate is not identity proof; index absence is not proof of absence.
6. Do not fetch publisher pages or reconstruct result URLs, titles, snippets, bodies, queries, or profile values.

## Broker removal

1. Confirm the user explicitly asked to submit a removal and supplied an existing opaque profile reference.
2. Select only a catalog broker with `removal.supported: true` and a request kind allowed by that broker.
3. Call `rightout_submit_removal` once with `profileId`, `brokerId`, and `requestKind: delete_and_opt_out`.
4. Let OpenClaw request a new `allow-once` or `deny`. A scan approval never authorizes this write.
5. Treat a successful result only as `submitted`. SMTP acceptance is not broker receipt, broker processing, or removal confirmation.
6. Explain any broker verification follow-up as a human task. Do not ask for extra PII unless a future catalog lane explicitly marks it human-only.
7. Use a later, separately approved read-only scan to look for reappearance. Because the supported scan is index-only, absence remains `inconclusive`; do not upgrade it to `confirmed_removed`.

The current automated removal scope is intentionally narrow: one catalog-locked email to BeenVerified for an attested `US-CA` subject. Other broker lanes remain human-only or unsupported until their official channel, terms, minimum fields, and approval contract are independently verified.

## Output contract

For a scan, lead with:

```text
Posture: approval-gated read-only live scan
Approval: native OpenClaw allow-once for scan
Provider writes: 0
Submissions: 0
```

For a removal submission, lead with:

```text
Posture: approval-gated broker removal submission
Approval: separate native OpenClaw allow-once for removal
State: submitted
Removal confirmed: no
Raw PII in report: no
```

Then state what is evidenced, inferred, `needs_evidence`, or a human task. Preserve contradictions and coverage gaps.

## Synthetic validation

The Python runner is dummy-only and never performs a live scan or provider write:

```bash
python3 {baseDir}/scripts/validate_data_broker_removal.py --skill-dir {baseDir}
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} scan-only-dummy --workdir .tmp/rightout-scan-only
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} e2e-dummy --workdir .tmp/rightout-e2e
```

Never present `fixture_only` output as a real result.

For catalog or security maintenance, read only the relevant reference:

- `{baseDir}/references/security-model.md`
- `{baseDir}/references/operations.md`
- `{baseDir}/references/state-machine.md`
- `{baseDir}/references/source-matrix.md`
- `{baseDir}/references/brokers/core.json`
