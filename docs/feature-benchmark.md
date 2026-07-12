# Feature benchmark: RightOut, Hermes Unbroker, and managed services

Review date: 2026-07-12.

Primary product references:

- [Hermes Unbroker official skill at reviewed commit](https://github.com/NousResearch/hermes-agent/tree/2d9fd870b6d105e3b367aaa97477931b6671192e/optional-skills/security/unbroker)
- [Incogni features](https://incogni.com/features/remove-my-information-from-internet) and [dashboard statuses](https://support.incogni.com/hc/en-us/articles/4904721869458-What-do-the-data-removal-statuses-on-my-dashboard-mean)
- [Optery plans](https://www.optery.com/pricing/)
- [DeleteMe features](https://joindeleteme.com/)
- [Kanary features](https://www.kanary.com/)

Claims from commercial pages describe vendor offerings; RightOut does not independently verify their effectiveness or private-database coverage.

| Capability | RightOut 0.4.0 | Hermes Unbroker | Managed services | Result |
|---|---|---|---|---|
| Multiple subjects | Up to 20 opaque SecretRef profiles | consented dossiers | family/team tiers vary | minimum parity |
| Discovery vectors | name/aliases, current/prior location/address, email, phone via Brave | dossier-driven search | broad scans claimed | minimum class parity; RightOut indirect |
| Broker breadth | 22 people-search catalog entries; 21 Brave lanes | 22 current broker entries | hundreds claimed by some vendors | not breadth parity |
| Deterministic ledger/queue | durable encrypted state-directory cases, due dates, clusters, proof refs | ledger and queue | dashboard/status tracking | minimum parity |
| Email removal | one catalog-locked lane | one email lane | broad | capability parity, not breadth |
| Browser form | one closed sandbox-browser recipe | 20 web-form lanes | broad/manual automation | capability parity, much narrower |
| Phone lane | human task only | one phone lane | specialist handling varies | safe human parity only |
| CAPTCHA/ID | fail closed to human task | human digest/manual work | human specialists | minimum parity |
| Inbound verification | read-only IMAP plus opaque link handle for one lane | verification polling | tracked responses | capability parity, narrow |
| Direct later check | encrypted exact URLs, name plus corroborator, no redirects | recurring rechecks | recurring scans claimed | minimum parity |
| Reappearance | trusted direct presence changes confirmed case to `reappeared` | rechecks/requeue | monitoring claimed | minimum parity |
| Scheduling | deterministic due tool for official OpenClaw Cron | recurring orchestration | managed scheduler | platform-equivalent; plugin cannot self-schedule |
| Native per-action approval | every live read/write gets `allow-once` | standing authorization workflow | vendor consent | RightOut stricter |
| Dashboard/app | PII-safe reports and read tools only | CLI/agent workflow | usually yes | missing UI parity |
| Custom removals/team service | human tasks only | human digest | offered by some vendors | not parity |

## Clean-room boundary

RightOut adopts product capability classes, not Unbroker implementation or broker data. It does not copy Hermes code, templates, prose, broker records, BADBOOL material, privacy-guide lists, or commercial inventories. RightOut catalog provenance is limited to official broker/government facts with original notes and semantic validation.

The official Unbroker reference currently has broader immediately executable operations: 20 web-form, one email, and one phone lane. RightOut has one email and one form lane; other brokers are still scan or human work. Therefore the accurate claim is **minimum workflow feature parity**, not broker-lane, effectiveness, managed-operations, or commercial-service parity.

## Approval difference

Unbroker is designed for agent operation after standing authorization. RightOut deliberately requires a new host-authoritative approval for each live disclosure/read/write. This reduces unattended convenience but prevents a scan approval, model-generated receipt, or prior action from authorizing a broker write.
