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

RightOut therefore returns no raw Search Results, stores no query/result body, discloses the 90-day maximum in the native approval, and blocks live use until the operator attests acceptance of the applicable Brave terms.

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

Decision: the catalog keeps one conditional live integration so the plugin remains live-scan capable only for an operator who has independently obtained or verified applicable automated-access authority. The plugin blocks before approval and network unless `operatorAttestations.authorizedProfileIds` contains the exact selected profile and `authorizedBrokerIds` explicitly contains `truepeoplesearch`. Public terms status remains `needs_evidence`.

## Stable-release meaning

A stable RightOut package can prove that its software boundaries are deterministic and fail closed. It cannot certify a deployer's legal basis or private provider agreement. Stable readiness therefore requires all of the following:

1. no catalog entry with a published automation prohibition is live-enabled;
2. missing or uncertain broker authority requires a broker-specific operator attestation;
3. Brave terms acceptance and subject authorization are explicit configuration gates;
4. each call still receives a native allow-once approval showing the data disclosure and retention limit;
5. real-provider behavior remains operationally conditional and may return `inconclusive` without weakening any safety boundary.
