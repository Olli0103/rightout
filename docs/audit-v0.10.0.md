# Closing adversarial audit: RightOut v0.10.0

Audit date: 2026-07-16. Scope: the complete v0.10.0 market-safety, UK rights,
authorized-canary, DROP, GPC, catalog, documentation, package, and release-gate
diff against `v0.9.0` (`778b161fb9d2d100952348c758ce7a143ef5d832`).

## Review closure

| Finding | Severity | Evidence | Closure |
| --- | --- | --- | --- |
| RO-100 | P2 | Market and rights contract objects were shallow-frozen, and market reports returned nested aliases to the live policy. In-process mutation could change later policy evaluation. | Added recursive freezing to market, UK, DROP, and GPC contracts; market reports now clone policy records. Negative tests mutate returned data and verify the live contract is unchanged. |
| RO-101 | P2 | California DROP filing approval named a current official registry snapshot but bound only the broker count. A different snapshot with the same count could satisfy the approval. | Added strict source URL/hash/time/count/chunk validation, a 45-day freshness bound, an exact registry snapshot digest, durable case binding, report evidence, and approval-time/execute-time mutation regression. |
| RO-102 | P3 | Two separately approved DROP-status or GPC observations could execute out of order, and canary timestamps accepted non-canonical date-time forms. | Bound status/preference approvals to the latest stored proof revision and required canonical UTC millisecond timestamps. Concurrent stale approvals now fail closed. |

Post-fix adversarial review found no open P0, P1, P2, or P3 issue in the
reviewed source tree. This statement is a Codex source audit, not a claim of an
independent human review or a real deployment canary. GitHub CodeQL and the
protected CI/release workflows provide separate automated review evidence.

## Evidence reviewed

- Every new public tool schema, `before_tool_call` approval, execute-time
  revalidation, SecretRef boundary, provider-I/O path, durable-state write,
  report export, and package inclusion path for market readiness, UK rights,
  DROP, GPC, and canary facts.
- Exact 22-route parity market contracts and the profile-jurisdiction checks on
  email, form, browser, webmail, verification, recovery, and worker paths.
- Upgrade behavior for schema-v1 campaign state: old campaigns lack a market
  digest and stop instead of inheriting authority.
- Current official EDPB, ICO, California DROP, California GPC, and Cognism
  sources, plus current vendor-published counts used by the market analysis.
- Release workflow requirements for protected-main ancestry, a
  GitHub-verified signed annotated tag, full CI dependencies, archive checksum,
  SBOM, machine-readable evidence, and GitHub attestation verification.

## Current source evidence

- Node plugin tests: 376/376 pass on the frozen release tree.
- Coverage: 91.39% lines, 75.84% branches, and 91.77% functions.
- Python and installer tests: 55/55 pass, including isolated install,
  force-reinstall, rollback, concurrency, and fail-closed validation cases.
- Validator, scan-only dummy, and full dummy E2E complete with schema-v7 catalog
  validation and no real-person or provider activity.
- Technical parity: 56 capabilities, 51 direct implementations, five
  equivalent-or-stronger, and 22 normalized route contracts.
- Production dependency audit: zero vulnerabilities at the configured high
  severity gate.
- Release checker, package-content, workflow, provenance, documentation,
  market-policy, dependency, secret-pattern, archive, and diff gates are green;
  the npm archive contains 94 allowlisted entries.
- PR CI, signed-tag, published-asset checksum, SBOM, and attestation results are
  recorded by GitHub rather than inferred here.

## Residual boundaries

- Real-provider effectiveness, authorized deployment canaries, installed
  runtime inspection, private broker inventory, and current written provider
  permission remain `needs_evidence` unless separately produced.
- Market policy is operational safety metadata, not legal advice or authority.
- DROP and GPC are separate government/preference mechanisms; neither is
  universal coverage or direct record-level deletion proof.
