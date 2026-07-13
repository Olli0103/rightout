# RightOut 0.8.0 / pinned Unbroker matrix

Reference: Hermes Unbroker commit
`e589b739ca70eba00aa90fd3d0228bada00dbf8f`, reviewed 2026-07-13.

| Gate | Evidence | Verdict |
| --- | --- | --- |
| Exact 22 broker IDs | parity catalog and validator | passed |
| Exact 20 form / one email / one phone inventory | baseline and catalog | passed |
| Normalized method/route/input contracts | catalog validator and synthetic form matrix | 22/22 |
| Exact provider-specific playbook choreography | staged provider-flow evidence | gap: only PeopleConnect staged independently |
| Current public form-automation permission | provider-terms matrix | 0 allowed; 8 prohibited; 14 `needs_evidence` |
| Permission enforcement | contract digests, expiry, runtime/campaign mutation tests | passed, default deny |
| Finite autonomous campaign | scope/budget/restart/revoke/expiry tests | passed for separately provider-authorized effects |
| Brave live scan | POST, ISO-country locale routing, 59 combined policy-permitted lanes in four-route autonomous batches; pinned reference subset 21/22 with Spokeo human gate; query limits and zero result persistence | passed |
| Publisher browser/direct read | official domains, separate effect/access gates | passed only with separate authorization |
| Browser forms | generic semantic refs, intent, state receipts, arithmetic | conditional; live provider choreography/effectiveness remains `needs_evidence` |
| Outbound mail | SMTP and redacted Gmail compose | passed |
| Inbound verification | receiver-authenticated Gmail IMAP | passed |
| Browser-only inbound verification | zero-I/O human handoff | explicit limitation |
| Visual evidence | redacted semantic-state commitment | no screenshot or before/after proof |
| Registry/DROP/report/recheck/restart | runtime and state tests | passed |
| `clustrmaps` / `peekyou` availability | source refresh and independent review | normalized contracts retained; primary hosts externally unavailable |

Verdict: **complete 22/22 normalized broker/method/route/input coverage, but not
100% exact playbook choreography, capability parity, or default autonomous
execution.** Software release readiness is a separate immutable
package/security/review gate.
