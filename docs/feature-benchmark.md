# Feature benchmark: RightOut, Hermes Unbroker, and managed services

Review date: 2026-07-12.

Primary product references:

- [Hermes Unbroker official skill at reviewed commit](https://github.com/NousResearch/hermes-agent/tree/2d9fd870b6d105e3b367aaa97477931b6671192e/optional-skills/security/unbroker)
- [Incogni features](https://incogni.com/features/remove-my-information-from-internet) and [dashboard statuses](https://support.incogni.com/hc/en-us/articles/4904721869458-What-do-the-data-removal-statuses-on-my-dashboard-mean)
- [Optery plans](https://www.optery.com/pricing/)
- [DeleteMe features](https://joindeleteme.com/)
- [Kanary features](https://www.kanary.com/)

Claims from commercial pages describe vendor offerings; RightOut does not independently verify their effectiveness or private-database coverage.

| Capability | RightOut 0.6.0 | Hermes Unbroker | Managed services | Result |
|---|---|---|---|---|
| Multiple subjects | Up to 20 opaque SecretRef profiles | consented dossiers | family/team tiers vary | minimum parity |
| Discovery vectors | name/aliases, current/prior location/address, email, phone via Brave | dossier-driven search | broad scans claimed | minimum class parity; RightOut indirect |
| Broker breadth | 56 catalog entries; 21 Brave lanes, 23 EU processes, and 28 executable targets | 22 reviewed executable broker entries | hundreds claimed by some vendors | RightOut exceeds reviewed public executable count; managed inventory not parity |
| Deterministic ledger/queue | durable encrypted state-directory cases, due dates, clusters, proof refs | ledger and queue | dashboard/status tracking | minimum parity |
| Email removal | 27 catalog-locked lanes: nine US and 18 EU | one email lane | broad | exceeds reviewed public count in this lane |
| Browser form | one closed sandbox-browser recipe | 20 web-form lanes | broad/manual automation | capability parity, much narrower |
| Phone lane | human task only | one phone lane | specialist handling varies | safe human parity only |
| CAPTCHA/ID | fail closed to human task | human digest/manual work | human specialists | minimum parity |
| Inbound verification | read-only IMAP plus opaque link handle for one lane | verification polling | tracked responses | capability parity, narrow |
| Direct later check | encrypted exact URLs, name plus corroborator, no redirects | recurring rechecks | recurring scans claimed | minimum parity |
| Reappearance | trusted direct presence changes confirmed case to `reappeared` | rechecks/requeue | monitoring claimed | minimum parity |
| Scheduling | deterministic due tool for official OpenClaw Cron | recurring orchestration | managed scheduler | platform-equivalent; plugin cannot self-schedule |
| Native per-action approval | every live read/write gets `allow-once` | standing authorization workflow | vendor consent | RightOut stricter |
| Crash-safe submission intent | encrypted intent before SMTP/form; ambiguous outcome blocks retry until human reconciliation | not evidenced in reviewed public skill | vendor-internal | RightOut explicit |
| Campaign resume | durable cases, due queue, opaque listing handles, deterministic resume mode, OpenClaw Cron handoff | queue and status loop | dashboards and managed operations | workflow parity, no hosted dashboard |
| EU/US controller outcomes | separately approved human-reviewed processing/partial/ID/rejection/controller-confirmed states | not evidenced in reviewed public skill | managed follow-up varies | RightOut explicit and scoped |
| Dashboard/app | PII-safe reports and read tools only | CLI/agent workflow | usually yes | missing UI parity |
| Custom removals/team service | human tasks only | human digest | offered by some vendors | not parity |
| EU legal/process semantics | 18 fixed controller-email lanes, country consistency, 30-day reminder for the one-month response rule, controller-response review | no separate EU process taxonomy evidenced in reviewed skill | Incogni says it uses GDPR/CCPA requests and recurring follow-up | RightOut explicit and scoped |
| US/CCPA semantics | ten executable targets, eight controller-email lanes with 45-day recheck, DROP human handoff, no automatic ID documents | no separate CCPA process taxonomy evidenced in reviewed skill | managed services abstract per-broker processes | RightOut explicit and scoped |
| EU “one click” distinction | EDAA/emetriq preference controls separated from erasure; Criteo/Zeotap portals human-only | not evidenced in reviewed skill | managed services abstract per-broker processes | RightOut prevents false deletion claims |

## Clean-room boundary

RightOut adopts product capability classes, not Unbroker implementation or broker data. It does not copy Hermes code, templates, prose, broker records, BADBOOL material, privacy-guide lists, or commercial inventories. RightOut catalog provenance is limited to official broker/government facts with original notes and semantic validation.

The official Unbroker reference at the reviewed commit has 22 executable operations: 20 web-form, one email, and one phone lane. RightOut has 28 independently tested targets: 27 email and one browser-form initiation. RightOut therefore exceeds the reviewed public target count, while Unbroker retains a broader web-form/phone people-search mix. RightOut is also explicit about native per-effect approvals, durable ambiguous-write recovery, EU/US controller outcomes, encrypted restart-safe handles, and build provenance. Managed services additionally claim much broader inventories, hosted dashboards, recurring managed submissions, screenshot reports, compliance scoring, custom removals, and human escalation. The accurate claim is **reviewed public executable-count parity plus a stronger approval/safety boundary**, not removal-effectiveness, hosted-dashboard, or commercial-service parity.

## Approval difference

Unbroker is designed for agent operation after standing authorization. RightOut deliberately requires a new host-authoritative approval for each live disclosure/read/write. This reduces unattended convenience but prevents a scan approval, model-generated receipt, or prior action from authorizing a broker write.
