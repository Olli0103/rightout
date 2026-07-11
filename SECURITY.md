# Security policy

## Supported live posture

RightOut `0.2.0` supports approval-gated, read-only scans of catalog entries whose `scan.supported` is `true`. It supports no removal submission, email, form, CAPTCHA, verification-link, scheduler, or provider-write capability.

Never put real PII in chat, tool arguments, repository files, dummy-runner files, logs, issues, or vulnerability reports. The live tool accepts only an opaque SecretRef-backed profile ID and broker IDs.

## Enforced controls

- optional tool; exposure requires OpenClaw tool policy opt-in;
- native `before_tool_call.requireApproval` after tool selection and before execution;
- `allow-once` and `deny` only; critical severity; 120-second timeout; fail-closed denial/cancellation/no-route behavior;
- operator-owned exact-profile scope plus Brave terms revision `2026-02-11` and customer-responsibility attestations normalized into the approval binding, then independently rechecked before network execution;
- a single-use, expiring binding from the host-authoritative tool-call ID to the exact displayed profile and broker scope; mutation, replay, direct execution, or missing binding fails before config or network access;
- no caller-created approval receipt, HMAC key, environment bypass, or public live Python command;
- SecretInput contracts for the Brave key and every profile payload;
- OpenClaw security-audit findings for plaintext inputs and direct Gateway exposure;
- one fixed HTTPS Brave endpoint, SSRF/DNS guard, zero redirects, response-size limits, timeout, and disabled debug HTTP capture;
- POST search body, transient same-domain index classification, sanitized errors, and no raw PII/Search Result/URL/title/snippet/body/query/key in results;
- no publisher-domain network request exists; OpenClaw abort-signal propagation reaches every Brave request, with cancellation rethrown rather than converted to an ordinary result;
- published provider-access restrictions encoded fail-closed in the catalog; Spokeo automation is disabled;
- index absence remains `inconclusive`;
- zero submissions, emails, provider writes, and local PII storage.

Prompt text, caller JSON, local files, broker/controller content, and agent-readable secrets are not approval boundaries. OpenClaw's plugin permission service owns the per-call approval. SecretRefs protect supported config persistence but are not process isolation; a deployment must protect the Gateway process and secret provider from agent shell/file access.

Operator attestations are explicit deployment gates, not proof created by RightOut. The operator must verify subject authority out of band and accept the pinned Brave terms/customer obligations. Brave's standard API privacy notice permits query-log retention up to 90 days, while Zero Data Retention is an enterprise option. TruePeopleSearch public automated-access permission remains unknown but is no longer a runtime dependency because RightOut never accesses its pages.

## Recommended deployment controls

- use a hardened file or exec SecretRef provider outside the workspace;
- run `openclaw secrets audit --check` and `openclaw security audit --deep`;
- deny `rightout_live_scan` on `gateway.tools.deny` unless direct operator invocation is required;
- keep the Gateway on loopback/private ingress with authentication;
- do not enable OpenClaw debug proxy capture for private workflows; RightOut also sets `capture: false` on its guarded requests;
- separate OS user/container/process privileges when the agent has shell access.

## Report a vulnerability

Use a private GitHub security advisory with synthetic fixtures only. Report approval bypasses, SecretRef/plaintext failures, any publisher-domain request, unexpected network destinations, DNS/redirect bypasses, raw PII/Search Result leakage, direct tool-policy exposure, filesystem escapes, hidden writes, catalog provenance issues, or incorrect `indirect_exposure`/`inconclusive` claims.
