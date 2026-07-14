# RightOut 0.8.1 / pinned Unbroker matrix

Reference: Hermes Unbroker commit
`e589b739ca70eba00aa90fd3d0228bada00dbf8f`, reviewed 2026-07-14; current
upstream subtree hash remains unchanged.

| Gate | Evidence | Verdict |
| --- | --- | --- |
| Exact 22 broker IDs | parity catalog and validator | passed |
| Exact 20 form / one email / one phone inventory | baseline and catalog | passed |
| Normalized method/route/input contracts | catalog validator and synthetic form matrix | 22/22 |
| Executable recipe class | 20 per-contract fixtures plus durable all-route campaign E2E; PeopleConnect staged separately | passed; equivalent to the reference generic-or-explicit recipe class without copying its playbook data |
| Current public form-automation permission | provider-terms matrix | 0 allowed; 8 prohibited; 14 `needs_evidence` |
| Permission enforcement | contract digests, expiry, runtime/campaign mutation tests | passed, default deny |
| Finite autonomous campaign | real campaign/live-scan regression plus scope/budget/restart/revoke/expiry tests | passed for authorized Brave discovery and separately provider-authorized effects |
| Brave live scan | shared runtime coverage gate; POST; explicit ISO country; four-route batches; transient results | 56 code-enforced lanes: 30 people-search plus 26 controller/B2B; 3 controller portals remain `human_only` |
| Discovery meaning | report schema and non-US tests | public search index only; private inventory, identity/absence proof, and real-world effectiveness are `needs_evidence` |
| Publisher browser/direct read | official domains, separate effect/access gates | passed only with separate authorization |
| Browser forms | generic semantic refs, intent, state receipts, static arithmetic/text policy | technical path passed; live permission and effectiveness remain `needs_evidence` |
| Outbound mail | SMTP and redacted Gmail compose | passed |
| Inbound verification | receiver-authenticated Gmail IMAP | passed |
| Browser-only inbound verification | bound Gmail profile, recipient plus sender-authentication evidence, allowlisted HTTPS confirmation control | passed when configured and campaign-authorized; no raw mail/link output |
| Visual evidence | redacted semantic-state commitment | equivalent opaque evidence capability; no retrievable screenshot or managed-service before/after proof |
| Registry/DROP/report/recheck/restart | runtime and state tests | passed |
| `clustrmaps` / `peekyou` availability | source refresh and independent review | normalized contracts retained; primary hosts externally unavailable |

Verdict: **complete 22/22 normalized broker/method/route/input coverage, 56
code-enforced public-index discovery lanes, and complete technical capability
parity through implemented or equivalent-and-stricter paths. This is not a
claim of copied/identical playbook data, private-inventory visibility, current
provider permission, default autonomous form execution, or evidenced
real-world removal effectiveness.**
