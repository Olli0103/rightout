# Security model

OpenClaw owns SecretRef resolution, native approval, state-directory resolution, browser sandbox, and Gateway execution. RightOut owns opaque schemas, exact-scope single-use bindings, catalog policy, transport/domain restrictions, contained atomic encrypted state files, ciphertext listing tokens, and sanitized reports. Operators own subject authority, provider/publisher terms, accounts, approval routing, Cron scope, tool policy, and process isolation.

| Threat | Control |
|---|---|
| Raw PII reaches model | opaque inputs; SecretRef profiles; sanitized outputs |
| Agent invents/reuses approval | host tool-call ID plus native allow-once/deny; consumed two-minute binding |
| Cross-action widening | six independent tool/policy/attestation bindings |
| Candidate URL leaks at rest | AES-256-GCM vault under SecretRef key; opaque handle only |
| Publisher SSRF/redirect | exact stored HTTPS URL, catalog official-domain SSRF policy, redirects denied |
| False direct match | full name plus configured corroborator; CAPTCHA/block/ambiguity fail closed |
| Arbitrary broker write | catalog recipient/form recipe/request kind and minimum fields |
| Mail spoofing | pinned read-only IMAP plus sender-domain and link-domain agreement |
| Duplicate submission | durable register-if-absent cooldown plus transient guard |
| False completion | prior removal plus all-known-URL direct absence required; scoped coverage gap |
| Direct Gateway exposure | deny all seven approval-gated tools on `gateway.tools.deny`; audit otherwise |

The Python runner is dummy-only with `.invalid` identities and zero provider calls/writes. SecretRefs do not isolate trusted plugin code from the Gateway OS account; mutually untrusted tenants require separate Gateways/OS identities.
