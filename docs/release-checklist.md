# Release checklist

## Scope and evidence

- [ ] Root/package/manifest/skill/SBOM versions match the immutable `v0.2.0` tag.
- [x] Missing primary audit evidence remains `needs_evidence`.
- [x] README/release notes say live **scan**, not live deletion or commercial parity.
- [x] No unrelated, personal, secret, or generated local artifacts are committed.

## OpenClaw and approval

- [x] OpenClaw 2026.6.11 isolated packed install succeeds.
- [x] Runtime inspect shows `loaded`, optional `rightout_live_scan`, and `before_tool_call`.
- [x] Approval offers only allow-once/deny and fails closed on deny/timeout/cancel/no-route/hook failure.
- [x] Approval displays exact opaque profile/brokers and is single-use bound to tool-call ID plus frozen scope.
- [x] Public tool schema contains only opaque profile ID and broker IDs.
- [x] Direct `/tools/invoke` hardening and trust model are documented/audited.
- [x] `plugins doctor`, config validation, SecretRef audit, and security audit pass or have explicitly accepted non-critical findings.

## Security and privacy

- [x] SecretInput contracts cover Brave key and every profile payload.
- [x] No plaintext profile/key, real PII, secrets, absolute user paths, or raw live fixtures exist.
- [x] Guarded HTTPS, DNS/SSRF policy, catalog allowlists, redirects, limits, timeouts, and capture denial are tested.
- [x] Only Brave Search is reachable; publisher-domain requests and direct-page verification code are absent.
- [x] Search Results are transiently reduced to `indirect_exposure`/`inconclusive`; raw and derived result artifacts are not retained.
- [x] Abort signals reach every request and cancel before or during outbound work.
- [x] Installer restores config and the prior managed extension after a post-install runtime validation failure.
- [x] Reports/errors omit PII, keys, queries, URLs, raw bodies, and unallowlisted errors.
- [x] Live invariants prove zero local PII writes, submissions, emails, and provider writes.
- [x] Index absence is inconclusive, never not-found.
- [x] Offline filesystem and zero-network invariants pass.

## Catalog, legal, and product claims

- [x] Catalog schema/provenance/freshness/domain/lane tests pass.
- [x] Live selection accepts only supported people-search entries.
- [x] Controller domains cannot self-authorize; sensitive documents remain human-only/out of scope.
- [x] GDPR/DSGVO/CCPA/DROP language is posture, not legal/compliance assurance.
- [x] Commercial comparison cites official sources and states all missing capabilities.
- [x] Published provider terms/robots are reviewed; prohibited publisher automation is disabled and publisher pages are never requested.
- [x] Approval discloses Brave's published standard query-log retention maximum.
- [x] Operator acceptance is bound to Brave Terms revision `2026-02-11` and customer responsibilities.

## Package and tests

```bash
npm ci --ignore-scripts
make test
make scan-only-dummy
make e2e-dummy
make installer-test
```

- [x] `npm pack` contains compiled `dist/`, manifest, skill, license, notices, docs, and SBOM; excludes tests/node_modules.
- [x] Standard unittest discovery and Node tests are green.
- [x] Fresh/force install, failed preflight no-write, source symlink, SecretRef, runtime inspect, and doctor cases pass.
- [x] Independent review reports no open P0/P1, fixes are applied, and the entire matrix is rerun.
- [x] CI is green on the final release-content commit.
- [x] CI action dependencies are pinned to full commit SHAs.
- [x] Installer concurrency lock and adversarial concurrent-run test pass.

## Publish decision

- `GO` for the stable approval-gated read-only index-scan plugin only when every applicable gate is evidenced.
- `NO-GO` for any removal, monitoring, legal-service, or feature-parity claim.
- Provider account/key validity remains a deployment readiness check. The stable software release does not claim a particular operator subscription is active and uses no real PII to manufacture release evidence.
