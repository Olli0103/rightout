# Release checklist: v0.4.0

## Code and contracts

- [x] Ten manifest tools match runtime registration and replay metadata.
- [x] Six provider-I/O actions plus local subject purge have distinct native `allow-once` bindings and deny-on-timeout.
- [x] SecretInput paths cover profiles, Brave/SMTP/IMAP values, and listing encryption key.
- [x] Durable ledger, dedupe, encrypted listing tokens, and opaque verification tokens are bounded.
- [x] `confirmed_removed` requires prior removal plus scoped trusted direct absence.
- [x] Removal requires prior durable discovery; verification mail is submission/recipient/time/DKIM bound.
- [x] SecretRef and durable-state reads occur only after a valid interactive approval binding.
- [x] File locks use live-PID owner tokens; TTL pruning persists; subject-state purge is available under separate approval.
- [x] Microsoft 365 password IMAP is excluded; production SBOM and shrinkwrap cover the full runtime graph.

## Parity and safety

- [x] Parity matrix covers every normative capability class.
- [x] Catalog has 22 people-search entries and clean-room official provenance.
- [x] CAPTCHA, ID, redirects, ambiguous forms/pages, and partial checks fail closed.
- [x] No real PII, live scan, email, form, verification link, or provider write used in tests.
- [ ] Independent final audit has no open P0/P1.

## Verification and publication

- [ ] `make test`, dummy matrices, installer matrix, npm audit, PII/secret scan are green on the release commit.
- [ ] Immutable-tree release check and packed-archive install are green.
- [ ] Protected pull request is merged and branch protection is satisfied.
- [ ] Annotated `v0.4.0` tag points at the merged commit.
- [ ] GitHub release assets/checksums/SBOM are published and tag CI is green.
