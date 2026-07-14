# Broker coverage

Review date: 2026-07-13. Counts describe software/source contracts, not proven
real-world removals.

## Exact pinned Unbroker surface

| Capability | Coverage | Release state |
| --- | ---: | --- |
| Reference broker IDs | 22 of 22 | exact |
| Web-form contracts | 20 of 20 | normalized method/route/input contracts feed a generic engine with per-contract fixtures and a durable all-route campaign E2E; only PeopleConnect needs and has a separately staged same-browser flow; default deny without current written provider authorization |
| Email methods | 1 of 1 | evidenced |
| Phone methods | 1 of 1 | human like reference; official email rescue also available |
| One-batch Brave discovery | 21 of 22 | tested, indirect index evidence only; Spokeo is a separate human-only gate because its published terms prohibit automated queries |
| Publisher-browser fallback after inconclusive index search | 0 routes enabled by public evidence alone | requires current written provider authorization; 8 routes explicitly prohibit automation and 14 remain `needs_evidence` |
| Generic form contract fixtures | 20 of 20 | synthetic one-page fixtures cover split-name/email-confirm/listing-ID aliases; they do not prove exact live provider choreography or effectiveness |
| Authenticated IMAP verification | catalog-supported Gmail routes | implemented; authorized canary still required |
| Browser-only inbound verification | catalog-supported Gmail routes | exact logged-in profile binding, recipient plus allowed `signed-by`/`mailed-by` domain, one HTTPS allowlisted confirmation control, no raw mail/link output |
| Exact known-listing recheck | every source-ready route except published automation prohibition | terms/authority attestation required |

`clustrmaps` and `peekyou` are external runtime degradations, not missing
RightOut normalized contracts. One pinned Unbroker site-playbook pass records both as
dead/404, while the pinned broker records retain their routes, document
datacenter anti-bot/access failures, require residential confirmation, and
leave `last_verified` unset. Current independent checks find the hosts
unavailable. RightOut independently evidences the exact historic official
historical routes, keeps the primary routes marked unavailable, and provides separately
sourced rescue email (`support@clustrmaps.com` and `ccpa@peekyou.com`) with
independent disclosure and freshness contracts. A rescue submission is never
reported as a form submission or confirmed removal.

## Additional clean-room coverage

| Capability | Additional coverage |
| --- | ---: |
| Core catalog entries | 56 |
| Combined Brave index discovery lanes | 56 code-enforced: 30 people-search plus 26 EU/US controller or B2B domains; three controller portal entries remain `human_only` |
| Global autonomous scan batching | deterministic groups of four across an exact scan-only campaign scope |
| Independently locked core removal targets | 28 |
| EU/EEA controller email targets | 18 |
| US core executable targets | 10 |
| Live official California registry snapshot | complete official CSV is parsed and encrypted; the runtime snapshot count is authoritative and intentionally not hard-coded |
| Other official registry portals | Vermont, Oregon, Texas |

The broader core catalog improves coverage but is not Unbroker-parity evidence.
Profiles require an explicit ISO country. EU profiles use an ISO member-country
code such as `DE` and are localized through Brave country/language targeting when supported; other ISO
countries use explicit worldwide targeting. Localization is a technical query
setting, not evidence that a broker exposes a discoverable public person surface.
For controller, adtech, and B2B brokers an absent index hit is especially weak:
the service may hold private or identifier-linked data without publishing a
person-search page, so RightOut reports only `inconclusive`.
California DROP is a separate human-verified, registry-wide route; it excludes
non-registered brokers and may not delete FCRA-regulated data.

The public provider-terms review found zero affirmative automation permissions,
8 explicit prohibitions, and 14 `needs_evidence` routes. This is an operational
coverage limit. A provider-specific written exception can enable the matching
generic contract lane; subject/operator consent cannot, and exact live
effectiveness remains `needs_evidence`.

## Honest outcome boundary

`indirect_exposure`, `submitted`, and `verification_pending` are not removal
proof. People-search `confirmed_removed` covers only the encrypted known-listing
set after two timed direct absences. A controller response covers only that
controller and reviewed identifiers. Private inventories, new/unindexed URLs,
legal exceptions, and future reappearance remain outside any completion claim.
