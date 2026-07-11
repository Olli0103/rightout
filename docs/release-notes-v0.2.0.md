# RightOut v0.2.0

RightOut 0.2.0 is the first stable release of the approval-gated, read-only OpenClaw people-search index scanner.

## Stable security boundary

- the only live network destination is the official Brave Search API endpoint;
- RightOut never requests, follows, verifies, or stores a publisher result URL;
- live positive results are `indirect_exposure` index signals, never identity proof, direct `found`, or proof of a current listing;
- index absence and provider failures remain `inconclusive`, never `not_found`;
- Search Result URLs, titles, snippets, bodies, queries, and derivative proof references are absent from reports and storage;
- every live call still requires native OpenClaw `allow-once` approval bound to the exact opaque profile, broker search scope, Brave Terms revision `2026-02-11`, and Brave customer responsibilities;
- zero publisher requests, submissions, email, forms, scheduling, provider writes, and local PII writes.

## Provider and privacy posture

The scan sends full name, city, region, and country to Brave Search after approval. Brave's published privacy notice states that standard Search API query logs may be retained for up to 90 days unless an applicable Zero Data Retention agreement governs the account. Operators remain responsible for the Brave account, privacy notices/consents, subject authority, and customer/end-user obligations.

## Scope

This stable release provides narrow live index discovery plus PII-safe reporting and a dummy-only removal-state validation harness. It is not an automated removal, monitoring, legal-service, identity-protection, or commercial feature-parity product. Spokeo remains excluded from live selection. No real-person data or provider write was used for release testing.
