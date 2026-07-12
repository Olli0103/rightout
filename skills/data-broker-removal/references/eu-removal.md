# EU and EEA removal processes

Last reviewed: 2026-07-12. This is operational product guidance, not legal advice.

## What “one click” means

There is no evidenced official pan-EU equivalent of California DROP in the reviewed primary sources. Treat any claim of universal EU broker erasure as `needs_evidence`.

RightOut's controller emails are not “one click”: each controller/request is separately scoped, attested, approved, sent, and followed up. `one_click_level` therefore says `not_one_click_controller_email` for those lanes.

The reviewed simple controls have narrower effects:

| Process | Effect | RightOut classification |
| --- | --- | --- |
| [EDAA YourOnlineChoices](https://edaa.eu/) | One-stop preference control for tailored advertising by participating companies in the current browser; it relies on browser storage. | `preference_only_not_controller_erasure` |
| [emetriq browser opt-out](https://www.emetriq.com/opt-out/) | Stops further emetriq interest-profile collection for the current browser. The official page says previously linked data becomes unassignable and is automatically deleted after a short period. The opt-out cookie must remain and the action must be repeated per browser/device. | `browser_opt_out_then_short_term_unlinked_data_deletion` |
| [Criteo rights page](https://www.criteo.com/privacy/your-rights/) | Controller-specific form for Article 17 erasure and Article 21 objection. | `controller_erasure_request_not_yet_confirmed` |
| [Zeotap privacy policy](https://zeotap.com/privacy-policy/) | Cookie-ID portal or Ad-ID mobile app for access/deletion of data linked to the supplied identifier. | `controller_portal_erasure_request_not_yet_confirmed` |
| [Quantcast privacy choices](https://www.quantcast.com/privacy-choices) | EU rights page routing erasure and other rights to a controller-specific portal. | `controller_erasure_request_not_yet_confirmed` |
| [Lotame Services Privacy Notice](https://www.lotame.com/privacy/services-privacy-notice/) | Epsilon rights form; verification and digital-identifier scope matter, and restriction flags/identifiers may be retained after behavior-profile deletion. | `controller_portal_erasure_request_not_yet_confirmed` |
| [ID5 privacy page](https://id5.io/trust/privacy-policy) | Links EEA/UK rights and a browser/device-context privacy portal. | `controller_portal_erasure_request_not_yet_confirmed` |

Cookie, browser, device, consent, and marketing controls must never be reported as controller-wide erasure unless the controller independently confirms that outcome.

## RightOut automated EU lanes

RightOut has 18 independently catalog-locked controller-email targets. The catalog records the current official policy URL, recipient domain, minimum initial identifiers, dated review, and exact process semantics for FullEnrich, emetriq, Dealfront, Snov.io, Kaspr, StackAdapt, Bombora, Seedtag, Audiencerate, Lead411, Surfe, GumGum, Smaato, Teads, MiQ, 6sense, Cognism, and Lusha.

Lead411, 6sense, Cognism, and Lusha use full name, subject-controlled email, and country to locate a professional profile. The remaining initial requests disclose only the catalog-declared minimum email/country set. A controller may request proportionate follow-up, but RightOut never attaches an identity document automatically.

For every lane:

- EU/EEA membership, exact country tag, consent, profile digest, SMTP digest, broker, request kind, and minimum fields are checked before transport;
- no listing discovery is required to exercise a data-subject right;
- SMTP acceptance means only `submitted`;
- these EU controller-email cases do not automatically transition to `confirmed_removed`; after personally reviewing the official response, the operator may separately approve `rightout_record_controller_outcome`, whose confirmation scope is only `controller_response_only`;
- no identity document is attached or requested proactively.

## Request content and follow-up

The fixed template requests Article 17 erasure where applicable, withdraws consent under Article 7(3), objects to direct marketing and related profiling under Article 21(2), asks for the outcome, asks for the applicable basis or exception if data is retained, and requests Article 19 recipient-notification information.

Operational follow-up follows the [EDPB data-subject-rights guide](https://www.edpb.europa.eu/sme/be-compliant/respect-individuals-rights_en):

1. Keep the initial request electronic, concise, controller-specific, and limited to identifiers the official channel says it needs.
2. Track the legal one-month response deadline. RightOut's 30-day due date is an operational reminder, not a jurisdiction-aware deadline calculator. A controller may extend by two further months for complexity, but must inform the subject within the first month.
3. Provide extra identity information only when the controller has reasonable doubts and only to the proportionate extent needed. Route ID-document requests to a human task.
4. Keep receipt, response, exception, recipient-notification, and follow-up evidence in the PII-safe case ledger where supported. Never infer receipt from SMTP acceptance.
5. If the controller refuses or does not respond, preserve the reason or silence as evidence and route a complaint or legal review to a human. Do not have the agent assert entitlement or file a complaint automatically.

The [EDPB consent guidance](https://www.edpb.europa.eu/sme/be-compliant/process-personal-data-lawfully_en) also says withdrawal must be as easy as giving consent. That requirement supports simple consent controls; it does not turn a consent withdrawal into proof that every controller record was erased.
