# Privacy posture

Review date: 2026-07-12. This is engineering documentation, not legal advice or certification.

## Data minimization

The model sees only opaque profile/broker references and fixed request enums. Raw profile values and credentials are resolved from OpenClaw SecretRefs inside the plugin.

### Scan disclosure

To Brave Search:

- full name;
- city;
- region;
- country.

RightOut sends the query in a POST body, but Brave still processes it. Brave's published standard-plan privacy notice permits query-log retention up to 90 days unless an applicable Zero Data Retention arrangement changes that posture.

To broker pages: nothing. RightOut never requests them.

### Removal disclosure

For the current BeenVerified email lane:

- full name;
- contact email;
- region;
- country.

Recipient: official catalog address `privacy@beenverified.com`.

The message contains no address, phone, date of birth, age, relatives, listing URL, government ID, identity document, or authorization letter. If the broker requests additional identity proof, RightOut reports a human follow-up rather than disclosing more automatically.

The SMTP provider necessarily processes sender, recipient, headers, and body according to the operator's provider agreement. RightOut does not claim zero retention at the SMTP provider or broker.

## Consent and authority

Live scan requires operator-owned exact-scope attestations. Live removal additionally requires:

- `consent.authorized: true` inside the private profile;
- `broker_removal` in consent scope;
- a valid non-future consent timestamp;
- operator review of consent, SMTP authority, minimum disclosure, exact profile/broker/request kind, and policy version `2026-07-12`;
- a catalog-supported jurisdiction (`US-CA` for the current lane).

These are fail-closed technical gates. They are not independent proof that a person has legal capacity, that a law applies, or that a broker must comply.

## Retention

RightOut itself does not persist raw live PII, queries, Search Results, email bodies, SMTP credentials, Message-IDs, or raw receipts. The returned report contains opaque IDs, field categories, broker/channel facts, sanitized status, and an opaque hash-based proof reference.

OpenClaw sessions may retain tool inputs/results according to operator configuration; those results are designed to be PII-safe. Secret providers, Brave, SMTP providers, and brokers have their own retention policies outside RightOut's control.

## Accuracy and status

- `indirect_exposure` is an index signal, not proof of identity or current page content.
- `inconclusive` is not `not_found`.
- `submitted` means outbound SMTP accepted the message, not that the broker received or acted on it.
- `confirmed_removed` is not emitted by the current live path.
- a later missing index result remains `inconclusive`; a later index candidate can indicate possible reappearance but still requires review.

## Legal posture

The catalog records jurisdictions, official channels, minimum fields, prerequisites, and primary-source provenance. GDPR/DSGVO, CCPA/CPRA, and California DROP references explain possible rights and eligibility constraints but do not decide them for a user. Unsupported or sensitive lanes remain human-only.

## Deployment responsibilities

The operator must protect SecretRefs and approval routes, use an authorized SMTP account/app password, review provider terms, validate subject authority, configure least-privilege tool policy, and isolate the Gateway when an agent has broad local access.
