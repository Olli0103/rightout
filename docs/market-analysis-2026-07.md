# Market analysis and global safety roadmap

Review date: 2026-07-16. This is a product and engineering analysis, not legal
advice, a certification, or proof of real-world deletion effectiveness.

## Evidence method

The comparison separates five evidence classes:

- **repository-enforced**: current RightOut code, schemas, validators, and tests;
- **official regulator**: a regulator, legislature, or standards body;
- **vendor-published**: a vendor's own current feature and coverage claims;
- **independently measured**: a published experiment with stated limitations;
- **needs_evidence**: the available evidence does not justify a broader claim.

Vendor inventory counts are not normalized. A "site", "broker", affiliate,
private database, custom target, search result, and controller are different
units. Counts are recorded only to show market positioning, never as a proxy for
correct identity matching, deletion, or lasting effectiveness.

## Executive conclusion

The market has split into five product classes:

1. managed consumer removal subscriptions with recurring scans and removals;
2. high-risk and enterprise protection with human analysts, APIs, SSO, and
   administrative reporting;
3. authorized-agent apps that exercise privacy rights across ordinary
   companies as well as brokers;
4. government or browser-level universal mechanisms such as California DROP and
   Global Privacy Control;
5. self-hosted or agent-native automation, where RightOut and the pinned
   Unbroker reference operate.

RightOut should not compete primarily on the largest advertised broker count.
Its defensible position is a **self-hosted, auditable privacy operator whose
authority, evidence, and uncertainty are machine-enforced**. That position is
valuable, but incomplete. The main gap is no longer the execution engine. It is
operational evidence and breadth: measured real-world outcomes, more exact
market-specific rights packs, and reviewed provider authorization remain thin.

The current worktree now has a machine-readable market-readiness layer in
`rightout_catalog_health`, binds it into planning/approval/execute-time gates,
adds deployment-bound canary metrics, separates the UK route from EU/EEA, and
keeps DROP/GPC as human/preference workflows. The diagnostic policy itself
still cannot authorize an action, and these software controls do not establish
real-world effectiveness.

## Market structure

### Managed consumer removal

The common promise is "set and forget": collect a subject profile, scan a
proprietary inventory, submit requests, handle verification, repeat, and show a
dashboard.

| Product | Current vendor-published position | Product signal |
| --- | --- | --- |
| Incogni | [420+ automated brokers](https://incogni.com/features/remove-my-information-from-internet), recurring requests, dashboard tracking, an Exposure Scanner, a downloadable Risk Assessment, family plans, and specialist-backed custom removals; the current home page advertises [2,000+ additional custom sites](https://incogni.com/) | broad international consumer service combining automation and human exceptions |
| Optery | [380+, 555+, or 635+ automated sites by tier](https://www.optery.com/pricing/), custom removals, search-engine outdated-content submissions, before/after screenshots, family plans, and human agents; [business features](https://www.optery.com/business/) include SSO/SAML, SCIM, and administrative reporting, while its [API](https://www.optery.com/api/) exposes scans, removals, and screenshots | strongest public emphasis on visual proof, API embedding, and enterprise administration |
| DeleteMe | recurring scans, dashboards, reports, verification handoffs, and custom requests; its [business tiers](https://help.joindeleteme.com/hc/en-us/articles/13878887262867-Business-Plan-Features) add higher cadence, Google audits, map masking, and specialist work, while its [international business product](https://help.joindeleteme.com/hc/en-us/articles/15250115925011-DeleteMe-International-for-Businesses) uses country-specific coverage | mature service model with human operations and international enterprise packaging |
| Privacy Bee | [516 people-search sites at Essentials and 1,121 broader brokers at Pro/Signature](https://privacybee.com/pricing/), plus a claimed 181,048 custom sites, search monitoring, breach/paste/dark-web alerts, map blurring, analyst escalation, and high-risk services | broadest adjacent-exposure and human-response bundle among the reviewed vendor claims |
| Kanary | [managed monitoring, custom removals, expert escalation, family support, and higher-risk services](https://www.kanary.com/); the standard product is US-only and the advanced tier advertises US and UK availability | smaller, high-touch privacy and safety service with escalation positioning |

Observed feature pattern: every leading managed service combines automation with
humans. Human operations are not a temporary defect; they are the market's
fallback for identity checks, custom targets, legal escalation, CAPTCHA, account
access, and provider-specific exceptions.

### Authorized-agent privacy-rights apps

[Permission Slip by Consumer Reports](https://innovation.consumerreports.org/initiatives/permission-slip/)
is broader than a traditional people-search remover. It lets users request
deletion or opt out of sale at ordinary companies, acts as an authorized agent,
tracks request state, and offers automation across 100+ brokers plus human
advocates. This suggests a market expansion from "remove my people-search
listing" toward "operate my privacy rights portfolio."

RightOut currently focuses on brokers and selected controllers. A future rights
portfolio is strategically relevant, but must not be implemented as an
arbitrary-target write tool. It needs signed jurisdiction packs, controller
identity, exact request classes, minimum disclosure, deadline rules, and a
human-only path for disputed authority or identity.

### Government and universal mechanisms

California [DROP](https://privacy.ca.gov/drop/) launched for consumer requests
on 2026-01-01 and says one request reaches more than 600 registered brokers.
Broker processing begins on 2026-08-01. DROP uses government eligibility
verification and does not eliminate FCRA or non-registered coverage gaps.
RightOut correctly keeps the portal action and identity flow human-only.

[Global Privacy Control](https://globalprivacycontrol.org/) is a browser signal
for sale/sharing preferences. California recognizes it as a valid opt-out
mechanism, and the standard is now a W3C Privacy Working Group work item. GPC is
not deletion, controller erasure, or proof that a site complied. It is a
separate prevention and preference surface.

These mechanisms reduce the value of blindly submitting hundreds of bespoke
requests. RightOut should detect, route, and verify them without impersonating
the user or treating a preference signal as deletion.

### Self-hosted and agent-native automation

The pinned Hermes Unbroker reference provides 22 normalized routes and standing
authorization semantics. RightOut 0.10.0 reaches that technical contract surface
and adds stronger approval, encrypted state, uncertain-write handling, recipe
trust, and durable worker constraints.

The self-hosted category remains much less mature than managed services in
inventory, user experience, operational evidence, and human escalation. Its
advantage is control: local deployment, inspectable source, explicit authority,
and lower reliance on another centralized privacy vendor holding the full
subject profile.

## What effectiveness research says

The peer-reviewed PoPETs 2025 study
[Measuring the Accuracy and Effectiveness of PII Removal Services](https://petsymposium.org/popets/2025/popets-2025-0125.php)
studied Optery, Kanary, Mozilla Monitor, and Incogni with 71 participants. It
reported that 41.1% of retrieved records were judged correctly linked to the
participant and that 48.2% of identified records were reported removed on
average during a one-month subscription. Incogni measured highest at 76.6% and
Kanary lowest at 23.4%.

Those figures are independently measured but not universal. The authors note
that only four services were tested, participants and supplied PII differed,
the subscription window was short, and participants did not independently
verify every claimed deletion. The correct product conclusion is not that every
service has a 48.2% success rate. It is that:

- identity accuracy must be measured separately from discovery volume;
- removal must be measured separately from submission;
- results vary materially by subject and broker;
- catalog size alone is not an effectiveness claim;
- reappearance and coverage gaps must remain visible.

An emerging July 2026 preprint,
[Let My Data Go](https://arxiv.org/abs/2607.04552), reports that a significant
fraction of California-registered brokers failed to reply to or acknowledge
synthetic opt-out and deletion requests, and that some demanded intrusive
identity verification. This is preliminary evidence, not a released standard.
It reinforces the need for durable deadlines, non-response states,
proportionate-identity gates, and escalation evidence.

## Feature taxonomy for this product class

| Capability | Market expectation | Safety failure to prevent | RightOut 0.10.0 |
| --- | --- | --- | --- |
| Subject profile | multiple names, emails, phones, addresses, family members | centralizing excessive PII or exposing it to the model | encrypted SecretRef profiles; opaque public references |
| Discovery | broker scans, search results, custom URLs, recurring monitoring | false identity matches and index absence presented as proof | 56 public-index lanes; `indirect_exposure`; no raw result persistence |
| Identity confidence | screenshots, profile matching, user confirmation | removing another person's record | full name plus a strong corroborator for direct presence; operational accuracy still `needs_evidence` |
| Rights and authority | self, family, authorized agent, employee protection | invented residency, power of attorney, or legal eligibility | finite consent and attestations; no general authorized-agent portfolio |
| Removal transport | forms, email, browser, portal, phone, specialists | provider-terms bypass, CAPTCHA evasion, or excess disclosure | catalog-locked email/form/browser paths; provider automation default deny |
| Verification | inbox confirmation, screenshots, direct checks, replies | SMTP acceptance or one 404 called deletion | authenticated Gmail IMAP, exact-thread candidates, two timed direct absences |
| Recurrence | periodic rescans and repeated requests | unbounded agent authority or duplicate writes | finite campaigns, effect budgets, revocation, leases, dedupe, uncertain-write stop |
| Evidence | dashboards, screenshots, reports, audit history | raw PII leakage or unverifiable completion claims | encrypted semantic evidence, PII-safe reports, static dashboard |
| Custom targets | arbitrary URL or company request | SSRF, domain confusion, arbitrary agent writes | encrypted quarantine only; signed recipe and permission required |
| Human escalation | privacy agents, legal escalation, crisis response | silently improvising around gates | deterministic human gates; no managed human service |
| Enterprise | SSO, SCIM, API, admin, audit, high-risk employees | confusing local roles with tenant isolation | session-bound local roles; no hosted tenancy, SSO/SCIM, or public API |
| International | country availability, localized rights and requests | one jurisdiction's rights copied globally | ISO discovery is global; executable rights routes are not globally modeled |
| Preventive controls | GPC, account deletion, map blur, breach/dark-web alerts | calling prevention or alerting "removal" | human-verified local GPC observation implemented; no browser configuration or site-compliance claim |

## Regulatory and market-readiness matrix

### EU and EEA

The [EDPB](https://www.edpb.europa.eu/topics/key-gdpr-concepts/data-subject-rights_en)
lists access, rectification, erasure, restriction, objection, portability, and
automated-decision rights. Its SME guidance says controllers should facilitate
requests, normally answer within one month, document handling, and avoid
disproportionate identity demands.

RightOut evidence:

- 18 exact controller email routes are implemented;
- browser/device preference portals remain distinct from controller erasure;
- no official pan-EU broker deletion registry was evidenced;
- publisher automation still requires current written authorization;
- operational effectiveness is `needs_evidence`.

Verdict: **core assisted and bounded-autonomous support for exact catalog routes,
not universal EU coverage**.

### United Kingdom

The ICO says all data-protection provisions of the
[Data (Use and Access) Act 2025](https://ico.org.uk/about-the-ico/what-we-do/legislation-we-cover/data-use-and-access-act-2025/the-data-use-and-access-act-2025-duaa-summary-of-the-changes/)
were in force by 2026-06-19. UK individual rights persist, while some rules such
as automated decision-making and reasonable/proportionate searches changed.

RightOut now keeps UK execution technically separate from EU/EEA:

- `cognism_uk`, evidenced by Cognism's current
  [privacy policy](https://www.cognism.com/en/privacy-policy), is the only
  current executable UK route;
- its process class, request kind, template, eligibility, identity rule,
  rights-contract digest, and deadline policy are all UK-specific;
- initial disclosure is limited to full name, subject-controlled email, and
  country; identity documents are never sent automatically;
- the ordinary ICO one-calendar-month date is calculated as a conservative
  start-of-day recheck. Any identity-clock change, extension, weekend, or public
  holiday adjustment requires human-reviewed controller evidence;
- SMTP acceptance remains submission evidence only, and real-world outcome is
  still `needs_evidence`.

The EU route cannot accept the UK request kind, the UK route cannot accept the
EU template, and stale UK market evidence stops execution before SecretRef use
or provider I/O.

Verdict: **one catalog-limited assisted UK controller route is implemented;
additional UK providers and measured effectiveness remain `needs_evidence`**.

### United States — California

California provides CCPA/CPRA rights, authorized-agent requests, GPC recognition,
and DROP. The official [CCPA guide](https://oag.ca.gov/privacy/ccpa) also
documents exceptions and identity/agent verification. DROP is a separate
residency-verified mechanism, not a substitute for every controller request.

RightOut evidence:

- selected California controller email routes exist;
- the official registry CSV is parsed into encrypted state;
- DROP filing can be recorded only after a human verifies it;
- before 2026-08-01 the durable case remains `submitted`; after processing
  starts, human-observed checkpoints remain `awaiting_processing`;
- the operational tracker records the official 90-day processing window and
  45-day broker access cycle;
- a person may record the literal DROP status, but even `deleted` remains a
  portal claim with `deletion_confirmed: false` and no confirmation scope;
- portal submission and government identity verification are not automated;
- GPC can be recorded only after a person verifies a supported browser setting
  or extension; RightOut performs no browser/provider I/O, and per-site
  compliance remains `needs_evidence`;
- FCRA and non-registered entities remain coverage gaps.

Verdict: **strongest US market, with safe human-only DROP tracking and a
strictly non-deletion GPC preference record**.

### Other US states

State rights, authorized-agent rules, universal opt-out signals, appeals, and
data-broker registrations form a moving patchwork. RightOut currently routes
the Vermont, Oregon, and Texas registries but does not implement a complete
state-by-state rights engine.

Verdict: **registry routing and discovery only; exact execution remains
`needs_evidence`**.

### Canada

The federal privacy commissioner describes PIPEDA access, correction,
limitation, retention, safeguards, and consent withdrawal. Provincial laws and
the scope of deletion differ. A general GDPR-style erasure right must not be
inferred from retention or consent principles.

Verdict: **human-only; federal/provincial policy pack required**.

### Brazil

The ANPD lists confirmation, access, correction, portability, anonymization,
blocking, deletion in defined circumstances, consent withdrawal, and complaint
routes under LGPD. Exceptions and legal basis matter.

Verdict: **human-only; a Portuguese rights pack and controller directory are
required**.

### Australia

The OAIC documents access and correction rights and an obligation to destroy or
de-identify information no longer needed, subject to exceptions. It does not
justify a blanket user-triggered erasure claim.

Verdict: **human-only; do not label correction or retention duties as universal
deletion**.

### Japan

The PPC documents access, correction, cease-use, and erasure conditions under
APPI. Identity methods, request conditions, language, and local procedure need
market-specific review.

Verdict: **human-only**.

### Singapore

The PDPC documents consent withdrawal, access, correction, retention, and
disposal obligations. These do not create a universal deletion request.

Verdict: **human-only**.

### India

The DPDP Act 2023 and Digital Personal Data Protection Rules 2025 are official,
with phased enforcement material published by MeitY. Exact current duties and
route availability require a time-sensitive refresh before implementation.

Verdict: **`needs_evidence`; human-only**.

### All other markets

No claim is made from technical ISO-country discovery support to a legal right,
provider permission, or executable request path.

Verdict: **discovery-only followed by manual market review**.

## RightOut comparison

### Where RightOut is ahead

- explicit evidence states avoid deletion theater;
- profile PII and credentials stay out of public tool inputs and reports;
- provider writes require exact approval or a finite grant;
- campaigns are bounded by profile, brokers, effects, time, and budget;
- ambiguous writes become durable `submission_uncertain` and do not retry;
- provider terms and written permissions are runtime inputs, not disclaimer text;
- signed recipes, drift quarantine, encrypted state, key rotation, retention,
  purge, and exact result receipts are stronger than typical vendor-visible
  controls;
- self-hosting reduces reliance on another centralized service holding the
  subject's full privacy profile.

### Where RightOut is behind

- no proprietary hundreds/thousands-broker inventory or private-database access;
- no evidenced live canary or independently measured effectiveness;
- no dedicated Canada, Brazil, Australia, Japan, Singapore, India, or complete
  US-state rights pack; UK support is limited to one separately contracted
  controller route, and the 22 parity routes carry an exact
  US/California provider-request contract, but that route eligibility is not a
  universal privacy right;
- no automatic GPC configuration or live per-site receipt/compliance
  verification; only a human-verified local preference observation exists;
- no hosted mobile/dashboard experience, billing, SSO/SCIM, or public API;
- no managed analyst, crisis, legal, map-blur, social, breach, paste, or dark-web
  service;
- no Microsoft 365 mail transport and only Gmail receiver-authenticated IMAP;
- no retrievable before/after screenshots;
- no arbitrary custom-target execution;
- no standardized authorized-agent evidence lifecycle.

### Contradiction to preserve

RightOut has technical form capability for all 20 pinned form contracts, while
the current provider review finds zero public automation permissions. Technical
parity and operational autonomy are therefore both true and false in different
senses:

- **true**: the bounded engine can execute the normalized contracts;
- **false**: no reviewed public provider currently authorizes live autonomous
  form execution by default.

The product must keep that contradiction visible. It should expand through
official email, registry, API, and provider-authorized routes before attempting
to maximize browser automation.

## Product strategy

The recommended position is:

> RightOut is the self-hosted, evidence-first privacy operator for people and
> organizations that need bounded autonomy without outsourcing their complete
> identity profile or accepting unverifiable deletion claims.

Four product pillars follow:

1. **Market-safe autonomy** — every action has an evidenced jurisdiction,
   authority, provider, disclosure, and expiry contract.
2. **Outcome integrity** — discovery, identity, submission, provider response,
   direct absence, and reappearance stay separate and measurable.
3. **Extensible official coverage** — signed source and rights packs expand
   safely without arbitrary agent execution.
4. **Deployable trust** — local-first consumer use plus isolated enterprise
   deployments, verified packages, audit exports, and clear operator duties.

## Prioritized improvement plan

### P0 — Market safety and operational truth

1. Add a machine-readable market-readiness report with source review dates,
   exact support levels, human-only defaults, and time-sensitive DROP/India
   review points. **Implemented in the current worktree.**
2. Bind market policy into setup, doctor, planner, campaign approval, and
   execute-time checks. Unsupported rights execution must stop before SecretRef
   use or provider I/O. **Implemented for controller requests and all 22 parity
   provider routes.**
3. Add a validator that fails release when a core market source is stale,
   contradictory, or missing. **Implemented in the current worktree.**
4. Build an authorized canary harness that records identity precision,
   submission delivery, provider outcome, time to outcome, reappearance,
   handoffs, and coverage gaps without storing raw PII. **Implemented as the
   versioned v2 canary evidence contract; a real deployment run remains
   `needs_evidence`.**

### P1 — Core-market completeness

5. Implement a dedicated UK rights pack using current ICO evidence. Keep UK
   GDPR separate from EU/EEA contracts. **Implemented for one evidenced
   Cognism route; broader inventory and real outcomes remain `needs_evidence`.**
6. Upgrade the California DROP handoff: phase-aware guidance, explicit
   eligibility and identity human gates, status checkpoints, and deadline
   tracking. Do not automate government login or identity proof.
   **Implemented; portal status remains non-proof.**
7. Add GPC readiness and verification as a preference feature, never as
   deletion proof. **Implemented as human-verified local observation; per-site
   compliance remains `needs_evidence`.**
8. Add non-response, partial response, excessive identity request, denied,
   appealed, and complaint-ready lifecycle states.
9. Improve identity confidence with subject-reviewed match candidates and
   measured precision/recall, without returning raw candidate URLs to the model.

### P2 — Safe international expansion

10. Create a signed rights-pack schema covering jurisdiction, request classes,
    authority, minimum fields, deadlines, extension/appeal rules, identity
    policy, exceptions, language, source digests, and expiry.
11. Add assisted-only packs in this order: Canada, Brazil, Australia, Japan,
    Singapore, India. Autonomy remains off until exact routes and local review
    are evidenced.
12. Expand official registries and controller directories. Registry presence is
    routing evidence, not proof that a subject's data exists.
13. Add additional authenticated mail providers only after receiver-added
    authentication semantics and OAuth flows are independently tested.

### P3 — Coverage and enterprise deployment

14. Scale signed provider recipes and source refresh through reviewable
    community contributions and release attestations.
15. Add a local operator UI and stable local API for status, approvals, and
    sanitized evidence; keep raw PII and secrets off the API surface.
16. Add enterprise identity mapping and audit export. Treat mutually untrusted
    tenants as separate Gateway/OS deployments rather than stretching local team
    roles into fake multi-tenancy.
17. Define a pluggable human-escalation contract that can hand off a bounded case
    without granting the service broader campaign authority.

### P4 — Adjacent privacy surfaces

18. Add account-deletion and general company-rights packs after the broker model
    is stable.
19. Add optional breach, paste, dark-web, map, social, or search-result modules
    only as separate evidence types with separate retention and outcome claims.
20. Keep reputation management, legal enforcement, ID upload, payment, phone,
    fax, and postal mail outside autonomous execution.

## Success measures

The roadmap should be judged by:

- zero stale core-market sources at release;
- zero rights/provider writes without exact market and provider authority;
- zero automatic retries after uncertain writes;
- identity precision, not hit volume;
- independently reproducible state transitions;
- measured submission, response, confirmed-scope removal, reappearance, and
  human-handoff rates;
- explicit coverage denominators;
- complete purge and retention evidence;
- no raw subject PII in public tools, reports, logs, fixtures, or release
  artifacts.

Until a real authorized canary supplies those measurements, RightOut's
real-world effectiveness remains `needs_evidence`.
