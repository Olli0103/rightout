---
name: "data-broker-removal"
description: "Run approval-gated, read-only people-search scans or validate synthetic privacy reporting."
homepage: "https://github.com/Olli0103/rightout"
metadata:
  openclaw:
    safety: approval-gated-read-only
---

# RightOut data-broker scan

Use this skill for a live, read-only scan through the installed RightOut plugin or for local synthetic report validation.

## Live boundary

- Use only the optional `rightout_live_scan` tool for live work.
- Tool arguments may contain only an opaque `profileId` and explicit catalog `brokerIds`.
- Never ask the user to paste a name, address, email, phone number, date of birth, listing URL, verification token, credential, or breach value into chat or tool arguments.
- A private subject profile and the Brave Search key must already be configured by the operator as OpenClaw SecretRefs. If either is unavailable, stop with `needs_evidence`; do not collect PII as a workaround.
- Never use browser, web search, shell, Python, files, email, forms, or provider tools as a live fallback.
- Every call requires native OpenClaw plugin approval with only `allow-once` or `deny`. No approval route, denial, timeout, cancellation, or hook failure means no scan.
- The operator must separately attest the exact authorized opaque profile IDs, Brave terms revision `2026-02-11`, Brave customer responsibilities, and every broker included in the Brave index-search scope. Missing or changed attestations mean no approval and no network.
- Never submit a removal, send email, complete a form, solve a CAPTCHA, open a verification link, schedule monitoring, or write to a provider.
- Treat `indirect_exposure` only as a transient same-domain Brave index signal, never proof of identity, ownership, page contents, or current listing. Index absence is `inconclusive`, never `not_found`.
- Never request, open, verify, or reconstruct a publisher result URL. RightOut's live network boundary is Brave Search only.
- Do not claim compliance certification, legal eligibility, removal, or provider action.

## Live workflow

1. Confirm the user asked for a live scan and supplied an existing opaque profile reference, not PII.
2. Limit broker selection to catalog entries whose `scan.supported` is `true`.
3. Treat `scan.supported: false` and published automation prohibitions as absolute tool exclusions; do not fall back to browser, shell, or direct HTTP access.
4. Call `rightout_live_scan` once with the opaque profile reference and chosen broker IDs.
5. Let OpenClaw present and resolve the native approval. Do not simulate, replace, or pre-approve it in prose.
6. Report checked brokers, `indirect_exposure` or `inconclusive`, provider disclosure categories, and coverage gaps. Never reveal or reconstruct the private profile, Search Results, URLs, titles, snippets, bodies, queries, or API key.

## Synthetic validation

The bundled Python runner is intentionally dummy-only and has no live command:

```bash
python3 {baseDir}/scripts/validate_data_broker_removal.py --skill-dir {baseDir}
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} \
  scan-only-dummy --workdir .tmp/rightout-scan-only
python3 {baseDir}/scripts/data_broker_removal.py --skill-dir {baseDir} \
  e2e-dummy --workdir .tmp/rightout-e2e
```

Never present `fixture_only` results as user results.

## Output contract

For a live result, lead with:

```text
Posture: approval-gated read-only live scan
Approval: native OpenClaw allow-once
Provider writes: 0
Submissions: 0
Emails: 0
Raw PII in report: no
```

Then state what was checked, what was evidenced, what is inferred, and what remains `needs_evidence`. Preserve contradictions and coverage gaps.

For catalog or security work, read only the relevant references:

- `{baseDir}/references/security-model.md`
- `{baseDir}/references/operations.md`
- `{baseDir}/references/state-machine.md`
- `{baseDir}/references/source-matrix.md`
- `{baseDir}/references/brokers/core.json`

## Non-goals

Removal submissions, recurring monitoring, legal advice, compliance certification, identity protection, dark-web monitoring, account deletion, CAPTCHA handling, and autonomous provider writes.
