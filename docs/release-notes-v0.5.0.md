# RightOut v0.5.0

RightOut 0.5.0 adds evidence-backed EU/EEA controller-removal workflows without weakening the v0.4.0 per-action OpenClaw approval boundary.

## Added

- Two catalog-locked `gdpr_erasure_objection` email lanes:
  - Adsquare: contact email, Mobile Advertising ID, and country;
  - emetriq: contact email and country.
- A fixed GDPR template that requests Article 17 erasure where applicable, withdraws consent under Article 7(3), objects to direct marketing and related profiling under Article 21(2), and asks for Article 19 recipient-notification information.
- Catalog schema v4 and six classified EU processes covering controller email, controller portal, and browser/device advertising-preference paths.
- EU/EEA country consistency, required Mobile Advertising ID, minimum-disclosure, no-prior-discovery data-subject-request lifecycle, a 30-day operational reminder, and controller-response-only confirmation semantics. The reminder is not a legal deadline calculator.
- A PII-safe plan output that reports process class, effect scope, erasure semantics, one-click level, and official fixed action URL.

## Security and truthfulness

- Every email still requires exact out-of-band attestations plus a fresh native OpenClaw `allow-once` decision.
- The public tool receives only opaque profile/broker references and a fixed request kind.
- Profiles, SMTP credentials, Mobile Advertising IDs, message bodies, and controller responses never appear in the report.
- Browser/device preference controls remain human-only and can never produce `confirmed_removed`.
- EU SMTP acceptance remains `submitted`; controller receipt, legal outcome, erasure, and suppression are not inferred.
- The removal policy revision changed to `2026-07-12-eu1`, forcing explicit re-attestation.

## Known limits

- No official universal pan-EU data-broker erasure registry was evidenced in the reviewed primary sources.
- Criteo and Zeotap remain human-only because their controller flows require portal/app context not covered by a closed deterministic form recipe.
- Controller responses and identity follow-up require human review.
- People-search discovery remains the existing 21-lane US Brave-index scope; EU adtech profiles are often identifier-based and are not discoverable by a person's name.
- No release test uses real PII or performs a live scan, SMTP send, browser write, inbox read, confirmation-link open, or controller action.

## Compatibility

- OpenClaw `2026.6.11+`
- Node.js `22.19.0+`
- Python `3.11+`
- Existing v0.4.0 encrypted case data remains schema-compatible. Operators must recompute profile bindings and re-accept the new removal-policy revision before using an email lane.
