# RightOut v0.3.0

RightOut 0.3.0 adds the first real broker-removal write while preserving a strict OpenClaw approval boundary.

## New

- Separate optional `rightout_submit_removal` tool with native allow-once approval.
- One independently sourced BeenVerified `delete_and_opt_out` email lane for attested California subjects.
- Recorded action-specific subject consent, exact scan/removal attestations, normalized profile/SMTP snapshot bindings, catalog-locked recipient and fields, pinned SMTP TLS endpoints, and PII-safe submitted-only reports.
- Catalog schema v3, report v4, and expanded Brave-only discovery for BeenVerified.
- Clean-room product-architecture comparison with Hermes Unbroker, Incogni, Optery, DeleteMe, and Kanary.

## Safety posture

- Scan approval cannot authorize removal.
- Changed scan profiles or removal profile/SMTP snapshots fail before network access.
- Contradictory `US-CA` country/region/jurisdiction claims fail before SMTP.
- Microsoft 365 is excluded because this release does not implement its required OAuth 2.0 SMTP flow.
- The model never supplies PII, email recipient/body, SMTP destination, or arbitrary request type.
- SMTP acceptance is `submitted`, not broker receipt or removal.
- Forms, CAPTCHAs, browser automation, identity documents, mailbox polling, and scheduling remain disabled.
- Development and release tests use only `.invalid` identities and mocked providers; no real broker request was sent.
- Production dependencies are exact-pinned and checked against the lockfile and SPDX SBOM.

## Current live scope

- Read-only Brave index scan: TruePeopleSearch and BeenVerified.
- Removal submission: BeenVerified email, `US-CA`, one request per separately approved call.
- Spokeo: human-only because published terms prohibit automated queries/access.

## Known product gaps

No durable live dashboard/ledger, inbound verification, scheduled rechecks, screenshot proof, custom URLs, private-database coverage, or broad broker automation. RightOut does not claim feature/effectiveness parity with managed removal services.
