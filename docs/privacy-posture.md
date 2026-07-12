# Privacy posture

Review date: 2026-07-12. Engineering documentation, not legal advice or certification.

The model sees only opaque references. Private profiles and credentials are resolved from OpenClaw SecretRefs after native approval.

Brave may receive configured full names/aliases, current/prior locations or addresses, emails, and phones in bounded POST search vectors. The standard-plan privacy notice permits query-log retention up to 90 days unless an applicable Zero Data Retention agreement changes that posture. RightOut returns no raw Brave content.

An official-domain candidate URL may be encrypted with AES-256-GCM under an operator SecretRef and stored as an opaque token in RightOut's private OpenClaw state-directory files for later recheck. Plaintext URLs and page content are never stored in the case ledger or returned to the model. A separately approved direct recheck discloses the normal HTTP request to that publisher and locally compares the configured name plus one corroborator; operators must review publisher terms and authority first.

Removal disclosures are catalog-minimal:

- BeenVerified email: full name, contact email, region, country;
- PeopleConnect form initiation: contact email only.

SMTP/IMAP providers and brokers process data under their own policies. RightOut does not claim zero provider retention. IMAP opens recent INBOX content read-only and emits neither raw messages nor links. Confirmation links are kept behind opaque short-lived handles.

The durable ledger stores opaque subject/broker IDs, state, timestamps, disclosure field names, sanitized reasons, due dates, and opaque proofs. It excludes profile values, queries, candidate URLs, messages, page bodies, credentials, Message-IDs, and raw receipts.

Evidence semantics are deliberately scoped: `indirect_exposure` is an index signal; `submitted` is outbound SMTP acceptance; `verification_pending` is a form/mail step; `awaiting_processing` follows a broker link; `confirmed_removed` requires prior removal plus direct absence across the encrypted known listing set. New/unindexed URLs are always a coverage gap.

Consent and attestations are exact-scope, digest-bound, non-future technical gates. They are not proof of legal capacity, statutory applicability, or broker compliance. Operators remain responsible for SecretRef protection, subject authority, provider/publisher terms, least-privilege tool policy, Cron scope, and Gateway isolation.
