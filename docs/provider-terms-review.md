# Provider access and retention review

Review date: 2026-07-12. This is an engineering release gate, not legal advice or a compliance certification.

## Brave Search API

Official sources:

- [Search API Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service), last updated 2026-02-11;
- [Search API privacy notice](https://api-dashboard.search.brave.com/documentation/resources/privacy-notice), updated 2025-12-04;
- [Web Search POST API reference](https://api-dashboard.search.brave.com/api-reference/web/search/post), documenting the JSON request body and WebSearch response;
- [Search API product page](https://brave.com/search/api/).

Release-relevant facts:

- the customer must accept the API terms, protect the key, meet applicable privacy-notice/consent duties, and ensure end-user obligations;
- ordinary Search Results may only be stored transiently unless the customer's plan grants broader rights;
- customers accessing result URLs remain responsible for complying with the publishers' terms;
- the privacy notice states that standard-plan search-query logs may be retained for up to 90 days; Zero Data Retention is an enterprise option subject to the applicable agreement and legal obligations.

RightOut therefore uses the officially documented Web Search POST body rather than putting PII in a query URL, returns no raw Search Results, stores no query/result body, discloses the 90-day maximum in the native approval, and blocks live use until the operator attests terms revision `2026-02-11` plus Brave's customer/end-user responsibilities. An official-domain result URL can be encrypted into an opaque host token. Accessing it is a different tool, policy, attestation, and native approval.

## Spokeo

Official sources:

- [Consumer Terms of Use](https://www.spokeo.com/terms-of-use-consumer);
- [robots.txt](https://www.spokeo.com/robots.txt).

The published consumer terms prohibit scraping, crawling, data mining, automated queries, and robots/spiders or other automatic devices against Spokeo servers. The published robots policy also disallows search and profile paths for general agents.

Decision: `scan.supported: false`, `human_only: true`. RightOut performs no automated Spokeo request and does not permit an agent fallback.

## TruePeopleSearch

Official site and removal entry point:

- [TruePeopleSearch](https://www.truepeoplesearch.com/);
- [removal entry point](https://www.truepeoplesearch.com/removal).

The official terms and robots endpoints returned access-denied responses during the non-PII review. The controlled browser surface also rejected navigation under its safety policy. No public automated-access permission was evidenced, and no permission is inferred from public reachability, search indexing, or subject authorization alone.

Decision: Brave discovery never accesses TruePeopleSearch. A separate direct-rescan lane may read only an exact encrypted candidate URL after the operator independently reviews publisher terms and attests access authority. It denies redirects and fails closed on CAPTCHA/blocking/ambiguity. Public automated-access permission remains `needs_evidence`; RightOut does not infer it, and the lane must not be configured where the operator cannot establish permission.

## BeenVerified

Official sources:

- [Privacy and cookies policy](https://www.beenverified.com/faq/privacy/), marked last updated 2025-10-21;
- [California DOJ historical data-broker registration](https://oag.ca.gov/data-broker/registration/186586), used only as corroboration and not copied into the catalog.

The current official policy states that privacy requests, including deletion and public-information opt-out requests, may be sent to `privacy@beenverified.com`. The policy also warns that identity verification or additional information may be required. RightOut independently records only the current official policy URL/contact fact in the catalog.

Decision: `removal.supported: true` for one email lane and `delete_and_opt_out` request, restricted to an attested `US-CA` profile. The message uses only name, contact email, region, and country. It does not claim protected-person status, attach authorization documents, or volunteer age/address/ID. A follow-up request for additional verification is human-only. SMTP acceptance remains `submitted` until independent evidence exists.

BeenVerified discovery remains Brave index-only. A separately configured and approved direct-rescan lane may later read only exact encrypted candidate URLs under the same operator terms/authority gate; it is not part of discovery or email approval.

## EU and EEA controller requests and quick preferences

Official sources:

- [EDPB data-subject-rights guide](https://www.edpb.europa.eu/sme/be-compliant/respect-individuals-rights_en);
- [EDPB lawful-processing and consent guide](https://www.edpb.europa.eu/sme/be-compliant/process-personal-data-lawfully_en);
- the 18 controller-policy URLs recorded per executable entry in the schema-v6 catalog, including FullEnrich, Dealfront, Snov.io, Kaspr, Lead411, Surfe, 6sense, Cognism, and Lusha;
- [emetriq privacy notice](https://www.emetriq.com/datenschutz/) and [browser opt-out](https://www.emetriq.com/opt-out/);
- [EDAA YourOnlineChoices description](https://edaa.eu/);
- [Criteo rights page](https://www.criteo.com/privacy/your-rights/);
- [Zeotap privacy policy](https://zeotap.com/privacy-policy/).
- [Quantcast privacy choices](https://www.quantcast.com/privacy-choices) and [data-subject-rights page](https://www.quantcast.com/privacy/data-subject-rights/);
- [Lotame Services Privacy Notice](https://www.lotame.com/privacy/services-privacy-notice/) and [Epsilon rights form](https://legal.epsilon.com/dsr/);
- [ID5 privacy policy](https://id5.io/trust/privacy-policy) and official ID5 Sync privacy portal routing.

The EDPB says controllers should facilitate electronic requests, respond within one month, may extend by two months for complexity after notifying the subject within the first month, and may request additional identity information only where reasonable doubts exist. Erasure is conditional and has exceptions; direct-marketing objection does not require reasons. Consent withdrawal must be as easy as giving consent.

Decision: 18 catalog-locked `gdpr_erasure_objection` email lanes are enabled. Each source record must explicitly support the controller right and email-submission channel. Lead411, 6sense, Cognism, and Lusha disclose full name, subject-controlled email, and country; the others disclose only email and country. Every lane requires a consistent EU/EEA country, private-profile consent and digest, exact broker/request attestations, SMTP identity, and a fresh native `allow-once`. No prior listing is required to exercise the right. SMTP acceptance is only `submitted`; controller replies and any requested identity follow-up are human work.

EDAA YourOnlineChoices and emetriq's own browser opt-out are cataloged as preference controls, not controller erasure. Criteo, Zeotap, Quantcast, Lotame/Epsilon, and ID5 remain human-only controller portals because their official flows require controller forms, verification, scope judgment, or device/browser identifiers not covered by a closed, deterministic RightOut form recipe. Lotame explicitly distinguishes deletion of a behavior profile from retention of identifiers used to honor restrictions, so total-erasure wording is prohibited. The reviewed primary sources did not evidence a universal pan-EU data-broker erasure registry; that negative remains a bounded research conclusion, not a legal certification.

## SMTP provider authentication

Official source:

- [Microsoft Exchange Online Basic authentication deprecation](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online).

RightOut 0.7.1 supports app-password SMTP/IMAP only and has no OAuth 2.0 token contract. Microsoft documents permanent removal of Basic authentication for SMTP AUTH client submission beginning in March 2026; Microsoft 365 does not fit this password-only contract. SMTP remains pinned to Gmail, Yahoo, iCloud, and Fastmail. IMAP verification is Gmail-only and accepts exactly one receiver-added `mx.google.com` authentication result; Yahoo, iCloud, Fastmail, and Microsoft 365 IMAP remain unsupported until their authserv/OAuth behavior is separately evidenced and implemented.

## Stable-release meaning

A stable RightOut package can prove that its software boundaries are deterministic and fail closed. It cannot certify a deployer's legal basis or private provider agreement. Stable readiness therefore requires all of the following:

1. no catalog entry with a published automation prohibition is live-enabled;
2. Brave discovery makes no publisher request; direct publisher reads require an exact encrypted candidate, explicit catalog support, operator terms/authority attestation, and a separate approval;
3. Brave terms revision, customer responsibilities, and subject authorization are explicit scan gates;
4. each scan receives its own native approval showing data disclosure and retention;
5. each removal receives a different native approval showing broker, recipient, and field categories;
6. removal destinations and minimum fields are independently verified from official sources and catalog-locked;
7. SMTP acceptance is never presented as broker receipt or removal;
8. search-index behavior may return `inconclusive` without being presented as proof of absence;
9. direct absence is accepted only across the complete known encrypted URL set and is reported with its new/unindexed-listing coverage gap.
10. EU/EEA controller requests use official destinations, a fixed Article 17/7(3)/21(2)/19 template, exact minimum fields, and human-reviewed controller outcomes;
11. US-CA controller requests use official destinations, a fixed deletion/opt-out template, exact minimum fields, and human-reviewed controller outcomes;
12. browser/device advertising preferences are never reported as universal or controller-wide erasure.
