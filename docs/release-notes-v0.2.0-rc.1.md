# RightOut v0.2.0-rc.1

> Safety update after publication: automated Spokeo scanning is disabled on `main` because Spokeo's published consumer terms prohibit automated queries, scraping, and crawling. Do not use the RC's Spokeo live lane. TruePeopleSearch live use on later builds requires explicit operator authorization attestations.

This prerelease turns RightOut into an installable OpenClaw plugin and skill with an approval-gated, read-only live people-search scan.

## Highlights

- optional, non-replay-safe `rightout_live_scan` tool;
- native OpenClaw allow-once/deny approval after tool selection, with a single-use expiring binding to the exact displayed profile and broker scope before network execution;
- opaque profile references with SecretRef contracts for the private profile and Brave key;
- one conditional TruePeopleSearch live playbook; the originally shipped Spokeo live lane is superseded by the safety update above;
- Brave POST discovery plus guarded same-domain direct-page verification;
- `found` or honest `inconclusive` live states; index absence never becomes `not_found`;
- no removal submission, email, forms, CAPTCHA, scheduling, or provider writes;
- conservative query-free profile-path and record-local JSON-LD `Person` verification;
- PII-safe reports with per-scan HMAC proof references and explicit coverage gaps;
- compiled JavaScript npm archive, transactional official OpenClaw installer with rollback, runtime inspect, plugin doctor, SecretRef audit, CI, SBOMs, and release scans;
- source-backed commercial feature comparison with explicit non-parity.

## Install

```bash
npm ci --ignore-scripts
./install.sh
```

Then follow `INSTALL.md` for out-of-band SecretRef provisioning, optional-tool policy, approval routing, Gateway direct-invoke hardening, and readiness audits.

## Important limits

- This is a live-scan prerelease, not a deletion service.
- On current `main`, only conditional TruePeopleSearch scanning is live-enabled; Spokeo automation is disabled.
- A direct page match is medium-confidence discovery evidence, not identity or ownership proof.
- SecretRefs are not OS/process isolation.
- Commercial automated removals, recurring monitoring, dashboards, screenshots, custom assistance, family plans, Google cleanup, identity vaults, and dark-web/credit protection are not implemented.
- No real PII, production key, live subject scan, or provider write was used in development/release testing.

## Evidence status

- Local mocked/offline, package, isolated OpenClaw install/runtime, SecretRef, and audit matrices pass.
- Real-provider end-to-end behavior remains `needs_evidence` by design and must be validated only in an authorized production deployment.
- The exact independent v0.1.0 audit artifact remains `needs_evidence`; the release does not invent its finding IDs or wording.
