# RightOut v0.10.0 market-safety plan

Status: G1-G10 implemented and release-gated in the v0.10.0 source. GitHub
publication and real-deployment effectiveness remain separate evidence.

## Outcome

RightOut must distinguish, at runtime, between:

- a country being technically targetable by public-index discovery;
- a privacy right being evidenced in that jurisdiction;
- RightOut having an implemented request contract;
- the subject or operator having authority;
- the provider permitting the selected automation class; and
- an outcome being evidenced.

No one layer may substitute for another.

## Requirements

| ID | Requirement | Proof | Status |
| --- | --- | --- | --- |
| G1 | Machine-readable market readiness covers EU/EEA, UK, California, other US states, Canada, Brazil, Australia, Japan, Singapore, India, and unknown markets. | deterministic unit tests and `rightout_catalog_health` runtime output | implemented |
| G2 | Every market record has official sources, review dates, evidence status, exact RightOut support, safe default, and open requirements. | schema validation, no-network tests, and PII scan | implemented |
| G3 | California DROP phase changes at 2026-08-01 without implying portal automation. | boundary-time tests | implemented |
| G4 | Setup and doctor expose market-policy health and warn on review-due or stale core sources. | runtime tests | implemented |
| G5 | Rights-execution planning and approvals bind the current market-policy digest. | planner, approval, mutation, and pre-I/O runtime tests | implemented |
| G6 | Execute-time checks stop unsupported or stale market rights before SecretRef use and provider I/O. | adversarial mutation and zero-I/O tests | implemented: controller requests, campaign drift, and all 22 parity provider routes are market-bound |
| G7 | Release validation fails on stale core market sources or undocumented market claims. | release-check tests | implemented |
| G8 | Authorized canary metrics measure identity accuracy and scoped effectiveness without raw PII. | canary fixtures, denominator tests, and evidence schema | implemented: v2 authorization/deployment-bound facts, precision/recall/accuracy, coverage, and time-to-outcome |
| G9 | UK rights execution uses a separate current ICO-bound contract and never reuses the EU/EEA gate. | UK request, identity, deadline, and negative tests | implemented: one `cognism_uk` route with separate process/template/eligibility, proportional identity handoff, calendar-month recheck, and cross-market substitution failures |
| G10 | DROP and GPC remain human/preference workflows and never become deletion proof. | state-machine and reporting tests | implemented: phase-aware human DROP filing/status, 90-day/45-day tracking, human-observed GPC state, zero browser/provider I/O, and fail-closed deletion semantics |

## Dependency order

1. G1-G3: diagnostic market contract.
2. G4: operator visibility.
3. G5-G7: enforceable market boundary and release gate.
4. G8: operational truth.
5. G9-G10: core-market expansion without weakening the boundary.

## Non-goals

- no autonomous government identity verification or DROP login;
- no jurisdiction inference from IP address, browser locale, or search target;
- no provider permission inferred from privacy law or subject consent;
- no general erasure claim for Canada, Australia, Singapore, or another market
  whose evidenced rights are narrower or conditional;
- no rights pack generated from model knowledge without primary-source review;
- no arbitrary custom-target write lane;
- no weakening of current approval, uncertainty, retention, purge, recipe, or
  evidence gates.

## Upgrade boundary

Campaign records created before G5 do not contain a market-policy digest and
therefore fail closed with `rightout_campaign_market_policy_binding_required`.
Operators must start a new separately approved campaign. RightOut never migrates
or renews standing provider authority silently.
