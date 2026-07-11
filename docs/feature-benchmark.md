# Feature benchmark: RightOut and commercial privacy services

Review date: 2026-07-11. This is a source-backed scope comparison, not an effectiveness test or endorsement. Commercial claims below are vendor claims and may change.

Official product material describes broad service expectations:

- Optery advertises exposure/removal reports, screenshots, status tracking, recurring scans, custom removals, and dashboard history ([Optery](https://www.optery.com/), [Exposure Report help](https://help.optery.com/en/articles/6495279-what-is-an-exposure-report-and-where-can-i-find-it)).
- Incogni advertises an exposure scanner/risk view, automated data-removal requests, request status, recurring handling, and custom removals ([Incogni](https://incogni.com/), [Exposure Scanner](https://incogni.com/blog/incogni-exposure-scanner)).
- DeleteMe describes scanning, removal, verification, monitoring for reappearance, privacy reports, and assisted/custom removal work ([How DeleteMe works](https://joindeleteme.com/how-it-works/)).
- Privacy Bee advertises exposure/risk scoring, dashboard progress, automated removals, and repeated scans ([Privacy Bee](https://privacybee.com/)).
- Aura bundles data-broker removal with broader identity/digital-security features and recurring monitoring ([Aura data removal](https://www.aura.com/digital-security/data-removal-service)).

## Capability matrix

| Capability | RightOut 0.2.0-rc.1 | Commercial benchmark | Status |
| --- | --- | --- | --- |
| Live people-search discovery | Two explicit catalog brokers; Brave discovery plus query-free, catalog-path, structured-record verification | Broad scans claimed | implemented, narrow |
| Per-call human approval | Native OpenClaw allow-once/deny | Vendor account/service consent models vary | implemented, differentiated |
| PII absent from agent tool params | Opaque SecretRef profile ID only | Not evidenced from public marketing | implemented |
| Found/inconclusive semantics | One JSON-LD `Person` record must match exact name and city/region; loose text and index negatives never produce `found`/`not_found` | Exposure/report semantics vary | implemented |
| Evidence artifact | Per-scan HMAC opaque proof ref only | Screenshots and detailed reports commonly claimed | partial by design |
| Removal status model | Full synthetic report states | Dashboards/status commonly claimed | model only, no live removals |
| Automated removal/submission | None | Core commercial feature | not implemented |
| Recurring monitoring/reappearance | State/report schema only; no scheduler | Commonly claimed | not implemented |
| Custom/manual removal service | None | Some vendors claim human/custom assistance | not implemented |
| Dashboard/history | JSON report only | Commonly claimed | not implemented |
| Family/team coverage | None | Available in some products | not implemented |
| Google result cleanup | Reference catalog lane only | Claimed by some products | not implemented |
| Identity vault/dark web/credit/VPN | None | Bundled by broader security suites such as Aura | out of scope |
| Public API/integrations | OpenClaw tool only | Varies by vendor/plan | partial |

## Release conclusion

RightOut has the minimum coherent feature set for an approval-gated live-scan plugin: private profile indirection, explicit broker selection, live discovery, direct verification, honest uncertainty, sanitized evidence, catalog policy, and report UX.

It does **not** have feature parity with commercial removal services. Claiming parity would be false. Closing the removal/monitoring gaps would add external writes, identity verification, legal/terms obligations, recurring jobs, retention, customer support, and materially different approval capabilities. Those changes require separate goals and security reviews; they are not silently folded into a scan approval.
