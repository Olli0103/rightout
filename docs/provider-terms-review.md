# Provider access and retention review

Review date: 2026-07-11. This is an engineering release gate, not legal advice or a compliance certification.

## Brave Search API

Official sources:

- [Search API Terms of Use](https://api-dashboard.search.brave.com/documentation/resources/terms-of-service), last updated 2026-02-11;
- [Search API privacy notice](https://api-dashboard.search.brave.com/documentation/resources/privacy-notice), updated 2025-12-04;
- [Search API product page](https://brave.com/search/api/).

Release-relevant facts:

- the customer must accept the API terms, protect the key, meet applicable privacy-notice/consent duties, and ensure end-user obligations;
- ordinary Search Results may only be stored transiently unless the customer's plan grants broader rights;
- customers accessing result URLs remain responsible for complying with the publishers' terms;
- the privacy notice states that standard-plan search-query logs may be retained for up to 90 days; Zero Data Retention is an enterprise option subject to the applicable agreement and legal obligations.

RightOut therefore returns no raw Search Results, stores no query/result body, discloses the 90-day maximum in the native approval, and blocks live use until the operator attests terms revision `2026-02-11` plus Brave's customer/end-user responsibilities. It examines result URLs transiently for an HTTPS official-domain signal and never accesses a displayed URL.

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

## Stable-release meaning

A stable RightOut package can prove that its software boundaries are deterministic and fail closed. It cannot certify a deployer's legal basis or private provider agreement. Stable readiness therefore requires all of the following:

1. no catalog entry with a published automation prohibition is live-enabled;
2. no live path makes a publisher-domain request;
3. Brave terms revision, customer responsibilities, and subject authorization are explicit configuration gates;
4. each call still receives a native allow-once approval showing the data disclosure and retention limit;
5. search-index behavior may return `inconclusive` without weakening any safety boundary or being presented as proof of absence.
