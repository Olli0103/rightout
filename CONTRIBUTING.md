# Contributing

RightOut is evidence-first. Mark observed, evidenced, inferred, and open claims explicitly; use `needs_evidence` for missing primary evidence.

## Required checks

```bash
npm ci --ignore-scripts
make test
make scan-only-dummy
make e2e-dummy
make installer-test
make release-check
```

Use only `.invalid` synthetic identities, mocked HTTP responses, and mocked SMTP transports. Never run a real live scan, store real PII, use production credentials, or submit/send anything during development.

## Live plugin changes

- Keep provider-I/O, campaign creation/revocation, DROP attestation, and critical local/human-decision tools optional and non-replay-safe. Keep pure setup/doctor/planning/status/report tools optional and replay-safe; tests must compare manifest metadata to runtime registration.
- Keep opaque profile/broker IDs and fixed enums as the complete public parameter surface.
- Keep `allow-once`/`deny` native approval and fail-closed behavior.
- Keep scan, direct read, removal, form, inbox, and link-open attestations/bindings separate; cross-action approval is P0.
- Keep SecretInput contracts and security-audit findings.
- Use OpenClaw's guarded SSRF runtime. Brave discovery stays fixed-host/index-only; a publisher request is allowed only for an encrypted exact candidate URL in a catalog `direct_rescan` lane, with redirects denied and a separate native approval.
- Keep Brave terms revision/customer-responsibility attestations inside the single-use approval binding.
- Keep direct publisher-access attestations and current written provider authorization records separate. A form/publisher route must bind the written authorization hash to the exact reviewed terms digest; a terms-review attestation alone is insufficient. Never infer permission from public reachability, subject consent, or search indexing.
- Never persist or return Brave result URLs. Store only a separately authorized publisher-browser candidate through the AES-256-GCM listing-token vault; reports and durable case records remain URL- and PII-free.
- For removal, lock recipient, request kind, jurisdiction, and minimum disclosure in the catalog; never accept body, recipient, URL, or SMTP host from tool arguments.
- Keep the static SMTP endpoint/port/TLS matrix, sender/profile equality, recorded consent check, transport timeouts, and file/URL access denial.
- Report SMTP acceptance only as `submitted` and form initiation only as `verification_pending`; never infer broker receipt or removal.
- Treat no index result as `inconclusive`.
- Add unit, adversarial, isolated install, runtime inspect, SecretRef, and packaging tests for every boundary change.

## Catalog contributions

Research clean-room from official broker/controller/legal sources. Do not copy commercial coverage lists, Privacy Guides, IntelTechniques, BADBOOL, screenshots, or prose. Every record needs official HTTPS URLs/domains, jurisdiction, category/lane, minimum field names, prerequisites, freshness, an explicit facts-only source-use policy, structured provenance, and original notes. Do not mislabel that policy as a license granted by the source.

Sensitive identity documents remain human-only and out of scope. Legal/controller lanes cannot self-authorize a destination. Do not claim eligibility, compliance, removal, or ownership without direct evidence.

Update `CHANGELOG.md`, both version files, package lock, compiled `dist/`, SBOMs, docs, tests, and release notes together.
