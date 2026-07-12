# Release checklist: v0.3.0

## Version and package

- [x] Root/package/manifest/skill/SBOM versions match `0.3.0`.
- [x] Compiled `dist/` matches a clean TypeScript build and includes scan/removal libraries.
- [x] Package contains manifest, skill, licenses, notices, SBOM, docs, and no tests/node_modules/bytecode.
- [x] `npm audit --omit=dev --audit-level=high` is clean and runs in CI.

## OpenClaw runtime

- [x] Runtime inspection shows status `loaded`, both optional tools, and `before_tool_call`.
- [x] `openclaw plugins doctor` passes.
- [x] `openclaw config validate`, secrets audit, and deep security audit pass in isolated install tests.
- [x] Both tools are documented for `tools.allow` and `gateway.tools.deny`.

## Approval and privacy

- [x] Scan and removal use different action-bound allow-once approvals.
- [x] Cross-tool approval, replay, mutation, missing ID, timeout, denial, and attestation changes fail closed.
- [x] Public schemas contain no raw PII, recipient, body, URL, SMTP host, or credentials.
- [x] SecretInput contracts and plaintext audit findings cover every private value.
- [x] Brave retention/disclosure and SMTP/broker disclosure are explicit.

## Removal lane

- [x] BeenVerified official current policy source and recipient are independently verified.
- [x] Catalog schema v3 locks request kind, recipient domain, fields, jurisdiction, verification posture, and confirmation policy.
- [x] Consent, exact scope, sender/profile equality, and SMTP TLS allowlist fail closed.
- [x] Mocked acceptance reports only `submitted`; rejection/error/abort-before-write never claim submission.
- [x] No real SMTP or broker request is used in tests.
- [x] Forms, CAPTCHAs, browser automation, attachments, identity documents, and auto-retry remain absent.

## Scan and reporting

- [x] Brave remains the only scan destination and RightOut publisher requests remain zero.
- [x] `indirect_exposure` stays distinct from `found`; index negatives remain `inconclusive`.
- [x] Report v4 and synthetic full state matrix validate.
- [x] Live removal never claims `confirmed_removed`.

## Required commands

```bash
make test
make scan-only-dummy
make e2e-dummy
make installer-test
make release-check
npm audit --omit=dev --audit-level=high
npm pack --ignore-scripts
```

## Independent review and release

- [x] Independent review reports no P0/P1.
- [x] Review findings are fixed and the full matrix is rerun.
- [ ] PR merges to protected `main` with green CI.
- [ ] Annotated `v0.3.0` tag points at the merged commit.
- [ ] Tag CI is green and GitHub release/assets/checksums are published.

Decision remains `NO-GO` until every applicable item is evidenced.
