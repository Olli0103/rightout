# Operations

## Live scan

Call `rightout_live_scan(profileId, brokerIds)` only for an explicit user request. Every selected catalog entry must have `scan.supported: true`, appear in scan attestations, and receive a native allow-once approval.

Interpretation:

- `indirect_exposure`: transient Brave official-domain index signal only;
- `inconclusive`: no sufficient signal or provider failure;
- zero publisher requests, writes, raw-result storage, or live proof URLs.

## Live removal

Call `rightout_submit_removal(profileId, brokerId, delete_and_opt_out)` only for an explicit user request. Before OpenClaw offers approval, the hook validates the public scope, catalog lane, recipient/field policy, exact removal attestations, and pseudonymous profile/SMTP digests without opening raw PII or credentials. After `allow-once` but before any network connection, execution resolves the SecretRefs and validates the bound snapshots, subject consent, jurisdiction, and SMTP identity.

Current lane: BeenVerified, `US-CA`, official privacy email, full name/contact email/region/country.

Interpretation:

- `submitted`: outbound SMTP accepted one message;
- broker receipt, processing, and removal: `needs_evidence`;
- extra identity verification: human task;
- later missing Brave result: still `inconclusive`;
- later candidate: possible reappearance/continued exposure, not direct proof.

Never fall back to browser, shell, Python, arbitrary email, forms, CAPTCHA work, or extra disclosure.

## Offline operations

1. `doctor`: prove package and split live-tool/dummy-runner posture.
2. `validate`: validate catalog and manifest contracts.
3. `plan-dummy`: print a synthetic plan.
4. `scan-only-dummy`: synthetic discovery report.
5. `e2e-dummy`: synthetic full state matrix.
6. `verify-link`: local HTTPS/domain syntax check only.

## Failure handling

- missing SecretRef, profile, consent, attestation, approval route, or policy: block with `needs_evidence`;
- stale/missing provenance: disable the lane;
- scan approval failure: no Brave request;
- removal approval/preflight failure: no SMTP connection;
- SMTP error after send begins: `rightout_removal_transport_failed`; do not auto-retry because delivery may be uncertain;
- raw PII/body/credential in report/error/log: P0;
- cross-tool approval, arbitrary recipient, TLS downgrade, form/CAPTCHA action, or unapproved field: P0;
- missing primary evidence: preserve `needs_evidence`.
