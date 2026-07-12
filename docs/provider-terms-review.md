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

RightOut therefore uses the officially documented Web Search POST body rather than putting PII in a query URL, returns no raw Search Results, stores no query/result body, discloses the 90-day maximum in the native approval, and blocks live use until the operator attests terms revision `2026-02-11` plus Brave's customer/end-user responsibilities. It examines result URLs transiently for an HTTPS official-domain signal and never accesses a displayed URL.

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

Decision: RightOut does not access TruePeopleSearch. The catalog keeps its official domain only as a Brave `site:` search scope. The runtime discards every returned URL/title/snippet/body and reports only `indirect_exposure` or `inconclusive`. TruePeopleSearch automation permission therefore remains unknown but is not a runtime access dependency.

## BeenVerified

Official sources:

- [Privacy and cookies policy](https://www.beenverified.com/faq/privacy/), marked last updated 2025-10-21;
- [California DOJ historical data-broker registration](https://oag.ca.gov/data-broker/registration/186586), used only as corroboration and not copied into the catalog.

The current official policy states that privacy requests, including deletion and public-information opt-out requests, may be sent to `privacy@beenverified.com`. The policy also warns that identity verification or additional information may be required. RightOut independently records only the current official policy URL/contact fact in the catalog.

Decision: `removal.supported: true` for one email lane and `delete_and_opt_out` request, restricted to an attested `US-CA` profile. The message uses only name, contact email, region, and country. It does not claim protected-person status, attach authorization documents, or volunteer age/address/ID. A follow-up request for additional verification is human-only. SMTP acceptance remains `submitted` until independent evidence exists.

BeenVerified live discovery remains Brave index-only; RightOut does not fetch the BeenVerified site during a user scan.

## SMTP provider authentication

Official source:

- [Microsoft Exchange Online Basic authentication deprecation](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online).

RightOut 0.3.0 supports app-password SMTP only and has no OAuth 2.0 token contract. Microsoft documents permanent removal of Basic authentication for SMTP AUTH client submission beginning in March 2026. Decision: Microsoft 365 is not in the v0.3.0 SMTP allowlist. Adding it later requires a separately reviewed OAuth 2.0 SecretRef and refresh-token flow. Gmail, Yahoo, iCloud, and Fastmail remain restricted to their pinned TLS endpoints and require a provider/account configuration that permits the supplied app credential.

## Stable-release meaning

A stable RightOut package can prove that its software boundaries are deterministic and fail closed. It cannot certify a deployer's legal basis or private provider agreement. Stable readiness therefore requires all of the following:

1. no catalog entry with a published automation prohibition is live-enabled;
2. no scan path makes a publisher-domain request;
3. Brave terms revision, customer responsibilities, and subject authorization are explicit scan gates;
4. each scan receives its own native approval showing data disclosure and retention;
5. each removal receives a different native approval showing broker, recipient, and field categories;
6. removal destinations and minimum fields are independently verified from official sources and catalog-locked;
7. SMTP acceptance is never presented as broker receipt or removal;
8. search-index behavior may return `inconclusive` without being presented as proof of absence.
