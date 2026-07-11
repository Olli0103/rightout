# Operations

## Live operation

Use only `rightout_live_scan(profileId, brokerIds)`. The profile ID must already exist in operator-configured SecretRef-backed plugin config. Supported broker IDs come from catalog entries with `category: people_search` and `scan.supported: true`, and every selected ID must also appear in operator-owned broker-access attestations. Published automation prohibitions are absolute exclusions.

Every call invokes native allow-once/deny approval. No approval route, denial, timeout, cancellation, provider error, anti-bot response, or absent index candidate fails closed or returns `inconclusive`.

Interpretation:

- `found`: exact name plus city/region in one JSON-LD `Person` record on a query-free catalog-policy page; medium-confidence candidate, not ownership proof;
- `inconclusive`: no sufficient direct evidence;
- opaque proof reference: correlation handle only, not a URL or screenshot;
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
- missing subject/Brave/broker attestation: block before approval and network;
- raw PII or URL in a report/error/log: P0;
- unexpected network destination or any provider write: P0;
- missing primary audit evidence: preserve `needs_evidence`.
