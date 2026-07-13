# Feature benchmark

Review date: 2026-07-13. Unbroker reference: Hermes commit
`e589b739ca70eba00aa90fd3d0228bada00dbf8f`. Comparisons use public product
claims and clean-room facts; no competitor code, broker record, template,
playbook, prose, or screenshot was copied.

## Pinned Unbroker comparison

| Capability | RightOut 0.8.1 | Pinned Unbroker | Honest verdict |
| --- | --- | --- | --- |
| Broker IDs | exact 22 | 22 | exact |
| Normalized method inventory | 20 form, one email, one phone handoff | 20 form, one email, one phone | exact inventory |
| Form choreography | generic semantic engine synthetic-tested against 20 normalized route/input contracts; staged PeopleConnect E2E | provider-specific autonomous browser playbooks | gap: no claim of exact choreography for 19 form routes |
| Standing autonomy | one revocable profile/broker/effect/time/budget grant | standing authorization | tighter RightOut scope |
| Discovery | bounded Brave POST; optional separately permitted publisher browser | search/browser fanout | equivalent workflow class; RightOut keeps Brave results transient |
| Identity confidence | indirect search candidate, then full name plus strong corroborator | parent verification | equivalent outcome with explicit confidence states |
| Browser backends | managed, remote/cloud CDP, existing logged-in CDP; one distinct remote retry | local/raw CDP and Browserbase | equivalent backend classes; no claim that RightOut clears a challenge |
| Arithmetic challenge | strict host-side add/subtract/multiply | static challenge handling | covered for arithmetic only |
| Static distorted text | human gate | OCR/manual policy | gap: no local OCR |
| Dynamic CAPTCHA/OTP/ID | human gate | human gate/retry | safe fallback equivalent |
| Email send | pinned SMTP and redacted Gmail compose | SMTP and browser compose | equivalent outcome |
| Inbound verification | authenticated Gmail IMAP | IMAP and browser mail | IMAP equivalent; browser-only path is a human gate |
| Visual proof | commitment over PII-redacted semantic state plus exact direct-read evidence | screenshot/evidence workflow | weaker; not an image or before/after proof |
| Registries and DROP | CA CSV, VT/OR/TX routing, human DROP filing | same classes | equivalent class |
| Rechecks | exact known-listing set, timed absence, reappearance, Cron handoff | recurring rechecks/Cron | equivalent with narrower absence claim |
| Reporting | Markdown, JSON, digest, Sheets-compatible rows | Markdown/digest/Sheets | equivalent plus structured JSON |
| Ambiguous writes | durable intent, uncertain state, human reconciliation | durable ledger | stricter retry safety |

The generic capability engine can attempt each normalized form contract when
the provider supplies current written authorization and the live page matches
the semantic contract. This does not prove exact provider choreography or live
effectiveness. In the current public terms review, 8/22 routes
explicitly prohibit automation and 14/22 remain `needs_evidence`; none publishes
an automation permission. Therefore “100% Unbroker autonomy by default” is not a
truthful or compliant release claim. The exact matrix is in
[provider-terms-review.md](provider-terms-review.md).

The pinned Unbroker evidence is internally contradictory for `clustrmaps` and
`peekyou`: recipes remain recorded while a later operator pass reports dead/404
and leaves `last_verified` unset. Current independent checks also find both
primary hosts externally unavailable. RightOut preserves that contradiction,
keeps the normalized contract evidence, reports the primary route unavailable, and treats a
separately sourced rescue email as an independent method rather than fake form
success.

## Managed-service comparison

The figures below are current vendor claims, not independently verified
effectiveness. Counting methods also differ, so totals are not directly
comparable with one another or with RightOut's catalog.

### Evidence scale

- **Repository-enforced:** an exact public contract is tied to runtime code,
  machine-readable evidence, and a release test. RightOut uses this class for
  its 56 scan lanes, 22 normalized Unbroker contracts, state semantics, and
  approval/provider-permission gates.
- **Vendor-published:** the cited vendor page establishes what the vendor
  advertises, not route-level execution, correct identity matching, deletion,
  or sustained effectiveness. Every managed-service row below remains in this
  class unless separately measured.
- **Independently measured:** a 2025 peer-reviewed
  [PoPETs study](https://petsymposium.org/popets/2025/popets-2025-0125.pdf)
  measured four commercial services over a one-month subscription. Across its
  participants, 41.1% of retrieved records were correctly linked to the user
  and 48.2% of identified records were reported removed on average; Incogni
  measured highest at 76.6% and Kanary lowest at 23.4%. The authors explicitly
  limit generalization because participants were mainly US university students,
  only four services were studied, submitted PII differed, and participants did
  not independently verify every claimed deletion. This study does not measure
  RightOut, whose real-provider effectiveness remains `needs_evidence`.

| Vendor | Current primary-source feature claim | Evidence status | Evidenced RightOut gap |
| --- | --- | --- | --- |
| Incogni | [420+ automated brokers](https://incogni.com/features/remove-my-information-from-internet), continuous recurring removal, real-time request/broker-response tracking, exact-URL custom removals handled by specialists, Exposure Scanner, and a monthly downloadable Risk Assessment | Vendor-published inventory/features; independently measured in the 2025 study, with the study limits above | 56 code-enforced public-index scan lanes and 56 core catalog entries, finite campaigns plus operator-owned Cron, PII-safe reports, and no hosted dashboard, Exposure Scanner, arbitrary-URL specialist service, or downloadable risk product |
| Optery | [630+ automated sites and 945+ total sites through custom requests](https://www.optery.com/pricing/), monthly scans/removals, before/after screenshots, human privacy agents, custom scans/removals, CAPTCHA solving, verification-link clicks, legal demands, and automated email replies; the same page advertises family plans, real-time dashboard, SSO/SCIM/SAML, Public API, Activity History, Limited Power of Attorney, and ID verification | Vendor-published inventory/features; independently measured in the 2025 study, with the study limits above | no dynamic-CAPTCHA solving, broad private inventory, retrievable screenshots, arbitrary custom-removal service, public API/admin/SSO/SCIM/SAML product, ID/LPOA automation, family UX, or human privacy-agent service |
| Privacy Bee | Its [current pricing matrix](https://privacybee.com/pricing/) lists 516 people-search sites for Essentials, 1,121 broader brokers for Pro/Signature, and 181,048 supported custom sites; it advertises search, breach, paste, dark-web, social-exposure, map-blur, threat-hunting, analyst, and custom-takedown services. Its help center separately claims [1,000+ continuously scanned broker/people-search sites plus 180,000+ researched custom sites](https://support.privacybee.com/getting-started/what-sites-does-privacy-bee-scan) | Vendor-published inventory/features; not included in the cited 2025 effectiveness experiment | no comparable private inventory, general search/social/dark-web/breach/paste monitoring, map-blur workflow, threat-hunting/red-team service, custom-site team, or managed enterprise service |
| Kanary | [Google results, registries, court/doxxing sources and data brokers](https://www.kanary.com/remove-from-sites), threat-model prioritization, screenshots/links/reproducible steps, and legal/research/enforcement escalation; the page publishes cumulative counts of unique sites with found PII and requests sent, not a directly comparable automated-broker inventory. Its [plans](https://www.kanary.com/) add 30-day or faster scans, progress reports, custom removals, privacy experts, and family options | Vendor-published inventory/features; independently measured in the 2025 study, with the study limits above | no general Google/forum/court/social cleanup, personalized threat model, screenshot evidence, managed escalation network, hosted report/dashboard, custom specialist service, or family plan |

RightOut is stronger in a different dimension: it is self-hosted, its public
tool surface is opaque, approvals and provider permissions are scope-bound, and
ambiguous writes cannot silently retry. Those controls do not erase the
managed-service feature gaps above.

Inventory size is therefore not treated as an effectiveness proxy. RightOut's
competitive claim is narrower and auditable: exact code-enforced scope,
explicit confidence states, no invented deletion, and `needs_evidence` wherever
authorized real-world effectiveness has not been measured.

## Where RightOut is stronger

- self-hosted OpenClaw deployment with opaque public inputs;
- explicit native approvals plus finite revocable campaign authority;
- provider-terms contracts bound into the runtime/campaign digest;
- no Brave query/result persistence and no raw candidate URL in reports;
- intent-before-write, uncertain-submission lockout, and separate reconciliation;
- confidence states that do not turn “email sent” into “record deleted”;
- reproducible clean-room catalogs, tests, SBOMs, and package provenance.

## Where RightOut is weaker

- no proprietary hundreds/thousands-broker network or private-database access;
- no hosted dashboard, managed specialists, billing/admin, or broad family UX;
- no retrievable screenshots, static-text OCR, browser-only authenticated inbox
  verification, arbitrary custom removals, or CAPTCHA service;
- live effectiveness remains `needs_evidence` until an authorized deployment
  uses real subject data; release tests intentionally make no broker write.

The defensible release statement is: **RightOut covers the complete pinned
22-broker normalized method/route/input contract surface and a broader, safer
workflow. It does not have 100% exact provider-playbook or capability parity,
and current provider terms prevent default autonomous publisher execution.**
