# Feature benchmark: RightOut, Hermes Unbroker, and removal services

Review date: 2026-07-12. This compares publicly documented product categories, not effectiveness, security certification, or legal compliance. Vendor figures are vendor claims and can change.

Primary product sources reviewed:

- [Hermes Unbroker](https://hermes-agent.nousresearch.com/docs/user-guide/skills/optional/security/security-unbroker): consented multi-subject dossiers, deterministic ledger/queue, browser/form/email lanes, verification polling, human digest, and recurring rechecks.
- [Incogni removal features](https://incogni.com/features/remove-my-information-from-internet), [statuses](https://support.incogni.com/hc/en-us/articles/4904721869458-What-do-the-data-removal-statuses-on-my-dashboard-mean), and [custom removals](https://support.incogni.com/hc/en-us/articles/25599884277778-How-can-I-submit-a-link-for-Custom-Removals): recurring broker requests, status dashboard, custom links, specialist handling, and broad claimed coverage.
- [Optery](https://www.optery.com/), [removal reports](https://help.optery.com/en/article/what-is-a-removals-report-1ht35vl/), and [verification](https://help.optery.com/en/article/how-can-i-verify-the-profiles-optery-says-have-been-removed-have-actually-been-removed-yh009a/): scans, automated/custom removals, dashboard/history, and before/after screenshot proof.
- [DeleteMe workflow](https://help.joindeleteme.com/hc/en-us/articles/8142303949587-How-Does-DeleteMe-Work) and [monitoring](https://help.joindeleteme.com/hc/en-us/articles/8171611866899-Do-you-constantly-monitor-my-info-around-the-clock): broker search, removal, verification, re-removal, reports, and custom requests.
- [Kanary](https://www.kanary.com/): self-guided/managed removals, Google/social coverage, recurring scans, family options, reports, and escalation support.

## Capability matrix

| Capability | RightOut 0.3.0 | Reference products | Status |
| --- | --- | --- | --- |
| Live discovery | Brave index-only for 2 catalog brokers | Broad direct/private scans claimed | implemented, narrow and indirect |
| Explicit subject consent | Consent inside SecretRef profile plus operator attestation | Unbroker and managed services use intake/authorization | implemented |
| Per-action native approval | Separate OpenClaw allow-once for scan and removal | Unbroker defaults to standing authorization; vendor consent models vary | implemented, stricter |
| PII absent from model tool args | Opaque refs only | Not generally evidenced in public vendor material | implemented |
| Broker removal submission | One catalog-locked BeenVerified SMTP request | Core feature with broad coverage | implemented, one lane |
| Minimum disclosure | Fixed name/email/region/country | Claimed/practiced by several services; implementation details vary | implemented for supported lane |
| CAPTCHA/form safety | No automation; human-only | Unbroker/browser services support more form lanes | implemented as fail-closed limit |
| Submission lifecycle semantics | `submitted`, verification/processing/removal/reappearance model | Dashboards expose comparable states | implemented; live stops at submitted |
| Broker receipt/verification polling | None | Unbroker polls email; managed services track responses | missing |
| Direct removal proof | No screenshots or direct absence evidence | Optery/DeleteMe emphasize proof/reports | missing |
| Recurring monitoring and re-removal | Manual later scan only | Standard commercial/Unbroker capability | missing |
| Durable live case history/dashboard | PII-safe result in OpenClaw session only | Common dashboard/ledger capability | missing |
| Custom URL removals | None | Incogni/Optery/DeleteMe support custom cases | missing |
| Human specialist/escalation service | Human task instructions only | Commercial services offer staff workflows | out of scope for software-only release |
| Family/team administration | Multiple opaque profiles possible; no administration UI | Common paid feature | partial data model only |
| Google/social/image cleanup | Human/reference lanes only | Kanary and some managed tiers cover these | not implemented |
| Private-database broker coverage | None | Incogni claims many private brokers | not implemented |
| Public API/integration | Two OpenClaw tools | APIs vary by vendor/tier | implemented for OpenClaw |
| Identity/dark-web/credit/VPN bundle | None | Broader suites may bundle these | out of scope |

## Unbroker clean-room adoption

RightOut uses Unbroker as a product-architecture reference, not a code or data source. Adopted concepts:

- consent before action;
- separate discovery and delete phases;
- least disclosure;
- explicit lifecycle states;
- human tasks for CAPTCHA/ID/phone/fax;
- later verification and reappearance awareness.

RightOut deliberately rejects Unbroker's default hands-off submission model for OpenClaw. Every external write gets a new native approval. RightOut also does not import Unbroker's broker files, BADBOOL-derived material, templates, code, or prose.

Reference snapshot: NousResearch/hermes-agent commit `7c14d2a046217c5ccbaa06a9449b0fcf329221f9` reviewed 2026-07-12.

## Release conclusion

RightOut now has a complete, internally coherent minimum workflow: SecretRef profile and consent, live discovery, a real catalog-locked removal write, separate approval scopes, honest submission state, human-only blockers, and removal/reappearance report semantics.

It does not have coverage or managed-service parity with Incogni, Optery, DeleteMe, Kanary, or Hermes Unbroker. The largest remaining product gaps are durable live tracking, inbound verification, scheduled rechecks, proof artifacts, custom URLs, and broker breadth. Claiming feature/effectiveness parity would be false.
