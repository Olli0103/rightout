# Security model

## Trust boundaries

OpenClaw owns optional-tool exposure, SecretRef resolution, native approval, and the Gateway process. RightOut owns input minimization, catalog policy, action-specific binding, transport restrictions, and result sanitization. The operator owns subject authority, provider accounts, approval routing, tool policy, and process isolation.

## Controls

| Threat | Control |
| --- | --- |
| Raw PII reaches model args | Opaque profile/broker refs and fixed request enum only |
| Scan without consent or changed subject | Recorded `scan` consent, operator review, and normalized profile digest checked before Brave access |
| Scan approval widens to write | Tool name/action class included in single-use binding |
| Agent invents approval | Native OpenClaw allow-once/deny; no local receipt/HMAC path |
| Stale/wide scope | Revision-bound exact profile/broker/action attestations plus normalized profile/SMTP SHA-256 bindings rechecked at execution |
| Action without consent | Recorded `broker_removal` consent plus operator consent review |
| Arbitrary email destination | Recipient/domain/request kind locked in schema-v3 catalog |
| Excess disclosure | Fixed field set; no address, phone, DOB, ID, listing URL, or attachments |
| SMTP SSRF/TLS downgrade | Compile-time host/port/TLS matrix; TLS validation; no tool-supplied host |
| Message pulls local/remote content | Nodemailer file and URL access disabled |
| Duplicate send | Non-replay-safe metadata, deterministic Message-ID, consumed approval, process-local cooldown |
| False completion | SMTP handoff emits only `submitted`; current live path never confirms removal |
| Publisher access | Fixed Brave endpoint through OpenClaw SSRF guard; no publisher fetch |
| Search overclaim | `indirect_exposure` or `inconclusive` only |
| PII leakage | Values/bodies/receipts omitted; opaque proof reference only |
| Direct Gateway exposure | deny both tools on `gateway.tools.deny`; audit warning otherwise |

## Live invariants

- separate native approval per scan/removal call;
- raw PII absent from public params, approval descriptions, reports, and RightOut storage;
- scan network host is only `api.search.brave.com`;
- removal recipient is only the selected supported catalog recipient;
- forms, CAPTCHA bypasses, attachments, and identity documents equal zero;
- live scan never emits `not_found`;
- live removal never emits `confirmed_removed`.

SecretRefs do not isolate a trusted in-process plugin from the Gateway OS account. Strong hostile-user/agent isolation requires separate Gateways and OS identities.

## Offline invariant

The Python runner uses `.invalid` fixtures, makes zero network/provider calls, and cannot transition a non-fixture catalog case.
