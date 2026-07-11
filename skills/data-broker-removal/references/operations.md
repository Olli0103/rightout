# Operations

## Live operation

Use only `rightout_live_scan(profileId, brokerIds)`. The profile ID must already exist in operator-configured SecretRef-backed plugin config. Supported broker IDs come from catalog entries with `category: people_search` and `scan.supported: true`, and every selected ID must appear in operator-owned Brave search-scope attestations. The runtime contacts only Brave Search and never a publisher domain.

Every call invokes native allow-once/deny approval. No approval route, denial, timeout, cancellation, provider error, or absent index candidate fails closed or returns `inconclusive`.

Interpretation:

- `indirect_exposure`: transient Brave same-domain index signal, not identity or current-listing proof;
- `inconclusive`: no sufficient index signal or provider failure;
- no live proof reference, URL, title, snippet, body, or other Search Result is retained;
- zero submissions/emails/provider writes/local PII storage: enforced live invariant.

Never fall back to browser, shell, Python, email, forms, or web-search tools for a real subject.

## Offline operations

1. `doctor`: package and split live-plugin/dummy-runner posture.
2. `validate`: catalog and plugin manifest contracts.
3. `plan-dummy`: print a synthetic plan.
4. `scan-only-dummy`: synthetic found/not-found/inconclusive reporting.
5. `e2e-dummy`: synthetic removal-state reporting.
6. `verify-link`: local HTTPS/domain syntax check.

Offline `fixture_only` results are never user evidence. `not_checked_by_offline_dummy_runner` means catalog metadata was loaded without a live query.

## Failure handling

- validation, package, runtime-inspect, secret-audit, or security-audit failure: no-go;
- stale/missing catalog provenance: block the catalog entry;
- approval failure: no network call;
- missing profile/key: `needs_evidence`, never ask for PII in chat;
- missing subject, pinned Brave revision/customer-responsibility, or broker search-scope attestation: block before approval and network;
- raw PII or URL in a report/error/log: P0;
- any publisher request, unexpected network destination, or provider write: P0;
- missing primary audit evidence: preserve `needs_evidence`.
