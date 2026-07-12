# Native OpenClaw approval boundary

RightOut has six provider-I/O tools plus one local destructive purge tool. Each passes through `before_tool_call`, accepts only `allow-once` or `deny`, times out to deny after two minutes, and binds the decision to the host tool-call ID plus an exact normalized scope. Bindings are deleted on execution and cannot authorize another tool.

| Tool | Approval covers | Explicitly does not cover |
|---|---|---|
| `rightout_live_scan` | one profile, up to two brokers, pinned Brave policy/profile digest | publisher read, removal, mail, form |
| `rightout_direct_rescan` | one profile/broker/listing handle, exact encrypted URL set, direct policy | discovery, removal, redirects, other URLs |
| `rightout_submit_removal` | one catalog email/request kind/profile/SMTP snapshot | retry, other broker, completion claim |
| `rightout_submit_form_removal` | one catalog browser recipe/profile | CAPTCHA, ID, arbitrary browsing |
| `rightout_poll_verification` | one profile/broker/read-only mailbox snapshot | link opening or write |
| `rightout_open_verification` | one short-lived broker-bound link handle | another link, mailbox read, completion claim |
| `rightout_purge_subject_state` | one opaque subject's encrypted local cases, handles, and dedupe records | provider deletion, OpenClaw config/SecretRef deletion, another subject |

Configuration contains revision-bound attestations for each action class. Digests bind the exact profile and, where applicable, SMTP/IMAP transport. Direct scans additionally require publisher-access authority and operator terms review for the selected broker. These deployment attestations are not legal certification and do not replace the interactive native approval.

The hook deliberately validates opaque scope and attestations before approval without exposing PII. After approval, execution resolves SecretRefs and repeats snapshot, consent, jurisdiction, transport, catalog, domain, and minimum-disclosure checks before any network effect. Changed or missing values invalidate the call.

`/tools/invoke` is a full-operator surface. Production guidance denies all seven approval-gated tools through `gateway.tools.deny` unless direct operator invocation is intended. Read-only case tools can remain available.

OpenClaw plugins are trusted in-process code. Native approval prevents unintended actions in the normal operator flow but is not a sandbox against a malicious plugin or a mutually untrusted tenant. Use separate Gateways/OS identities for that boundary.
