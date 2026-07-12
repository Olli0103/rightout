# RightOut OpenClaw skill

Version `0.6.0`. This skill ships inside the RightOut plugin.

The plugin provides twelve tools: approval-gated Brave discovery, exact-URL direct recheck, US/EU email and sandbox-browser removal, inbox polling, confirmation-link opening, local subject-state purge, human-reviewed controller outcomes, ambiguous-write reconciliation, plus read-only next-action, status, and due-recheck tools. Public arguments contain opaque references only; profiles, Mobile Advertising IDs, provider credentials, encryption keys, consent, and operator attestations remain SecretRef-backed.

RightOut has durable PII-safe case tracking and never equates outbound acceptance, a form transition, a browser/device advertising preference, or search-index absence with removal. People-search `confirmed_removed` requires a prior removal plus two timed direct-absence observations across the encrypted known listing set; EU controller-email outcomes remain human-reviewed and controller-scoped, and new/unindexed listings remain a stated coverage gap.

The Python runner is an offline dummy validation harness. `fixture_only` results are never real-person evidence. Catalog records are clean-room facts from official sources; Hermes Unbroker and commercial products are product benchmarks only.
