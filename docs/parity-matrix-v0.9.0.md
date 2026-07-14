# RightOut 0.9.0 / pinned Unbroker and autonomy-platform matrix

Reference: Hermes Unbroker commit
`e589b739ca70eba00aa90fd3d0228bada00dbf8f`, reviewed 2026-07-14; the pinned
security-relevant subtree remains unchanged. The autonomy-platform rows are
RightOut requirements, not reference-product claims.

| Gate | Evidence | Verdict |
| --- | --- | --- |
| Exact normalized inventory | parity catalog, baseline, validator, synthetic matrix | passed: 22 brokers; 20 form, one email, one phone |
| Executable recipe class | release-attested pack, 20 fixtures, durable all-route E2E, staged PeopleConnect | passed without copying reference playbook data |
| Recipe trust and drift | source/compiled digests, Ed25519, expiry, domain/semantic/sensitive tests | passed |
| Current public form-automation permission | provider-terms matrix | 0 allowed; 8 prohibited; 14 `needs_evidence` |
| Permission enforcement | contract digests, expiry, runtime/campaign mutation tests | passed, default deny |
| Finite campaign | scope/budget/restart/revoke/expiry/live-scan tests | passed |
| Durable worker | encrypted state, atomic leases, checkpoints, backoff, session/policy binding, scheduler/handoff, resume/revoke tests | passed |
| Brave discovery | shared runtime coverage gate; POST; ISO country; transient results | 56 code-enforced lanes; three controller portals remain `human_only` |
| Discovery meaning | report schema and non-US tests | public index only; identity, private inventory, and effectiveness remain `needs_evidence` |
| Publisher browser/direct read | official domains, separate access/effect gates | passed only with current provider authorization |
| Browser forms | semantic refs, intent, state receipts, drift quarantine | technical path passed; live permission/effectiveness remain `needs_evidence` |
| Outbound mail | password/OAuth2 pinned SMTP and redacted Gmail compose | passed |
| Inbound verification/replies | receiver-authenticated Gmail IMAP, exact thread, encrypted candidates | passed; no automatic controller outcome |
| Evidence vault | encryption, content addressing, retention, tamper, purge/rotation, approved export | passed |
| Custom targets | encrypted opaque intake, SSRF/domain-confusion rejection, signed recipe/permission binding | safe readiness passed; provider execution intentionally absent |
| Effectiveness | explicit denominators and consistent canary gates | passed; default operational verdict `needs_evidence` |
| Team isolation | exact session/profile roles, cross-scope denial, campaign/worker non-reuse, Gateway audit | passed for one deployment; not hosted multi-tenancy |
| Local dashboard | private static HTML/JSON, strict CSP, no scripts/remote assets/network service | passed |
| Registry/DROP/report/recheck/restart | runtime and durable-state suites | passed |
| `clustrmaps` / `peekyou` availability | source refresh and independent review | normalized contracts retained; primary hosts externally unavailable |

Verdict: **complete pinned 22/22 normalized contract coverage plus the complete
v0.9.0 autonomy-platform runtime boundary. This is not a claim of copied or
identical provider choreography, current provider permission, hosted service
parity, private-inventory visibility, default autonomous form execution, or
evidenced real-world removal effectiveness.**
