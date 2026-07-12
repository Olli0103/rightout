# Security policy

## Supported live posture

RightOut `0.3.0` supports two distinct live actions:

- Brave index-only discovery for catalog entries with `scan.supported: true`;
- one minimum-disclosure SMTP removal request for catalog entries with `removal.supported: true`.

The current write scope is BeenVerified only, request kind `delete_and_opt_out`, and an attested `US-CA` subject. Forms, CAPTCHAs, browser automation, identity documents, verification-link opening, mailbox polling, and recurring scheduling are not implemented.

Never put real PII or credentials in chat, tool arguments, repository files, dummy-runner files, logs, issues, or vulnerability reports.

## Enforced controls

- Both tools are optional and non-replay-safe.
- Public parameters contain only opaque profile/broker references and fixed request-kind enums.
- Profiles, Brave key, SMTP username/password, and sender address are declared SecretInput paths.
- Scan and removal have separate revision-bound operator attestations, recorded action-specific subject consent, normalized profile bindings, and separate native approvals.
- `before_tool_call.requireApproval` offers only `allow-once` and `deny`, at critical severity with a 120-second deny-on-timeout.
- The host tool-call ID, normalized input, current attestations, action class, catalog removal destination, and operator-generated normalized profile/SMTP SHA-256 bindings are bound into a single-use expiring approval.
- A scan approval cannot authorize `rightout_submit_removal`; mutated, replayed, expired, or directly executed calls fail closed.
- After approval and before network access, removal additionally rechecks both bound snapshots, recorded subject consent in the SecretRef profile, matching jurisdiction, exact SMTP sender/profile email equality, and minimum-disclosure acceptance.
- Removal recipient and disclosure categories are catalog-locked. The agent cannot supply an address, subject, body, SMTP host, or arbitrary field.
- SMTP is restricted to a static provider/port/TLS matrix. TLS 1.2+, certificate validation, timeouts, and Nodemailer file/URL access denial are enforced.
- A deterministic Message-ID reduces accidental duplicate handling; successful submissions also receive a process-local 24-hour cooldown. Restarting the Gateway clears that cooldown, so every later send still requires a new explicit approval.
- SMTP acceptance is reported only as `submitted`; it is never broker receipt or `confirmed_removed`.
- Reports contain only opaque proof references and field categories, not the email body, Message-ID, credentials, or profile values.
- Scan traffic uses OpenClaw's SSRF-guarded fixed Brave endpoint, zero redirects, bounded response reads, disabled capture, and abort propagation.
- No publisher page is fetched. A same-domain candidate is only `indirect_exposure`; absence is `inconclusive`.
- Spokeo automated access remains disabled by catalog policy.
- The Python runner remains dummy-only and cannot transition a real catalog case.

Prompt text, caller JSON, model-created tokens, local receipts, HMACs, environment flags, broker content, and controller-provided destinations are not approval authority.

## Trust and limitations

OpenClaw plugins execute inside the Gateway trust boundary. SecretRefs reduce persisted-secret exposure but do not isolate secrets from a same-privilege process or an agent that can inspect the Gateway environment, memory, or provider files. Use OS-user/container separation and a hardened external secret provider where shell or file access is broad.

The SMTP server's acceptance only proves that the operator's outbound server accepted the message. Broker delivery, identity verification, processing, suppression, deletion, and later reappearance remain open until separately evidenced. RightOut currently has no durable live case database or mailbox-verification integration; the returned PII-safe report is the submission record.

Operator attestations are deployment gates, not legal certification. The operator must establish subject authority and eligibility. RightOut does not provide legal advice or guarantee compliance.

Consent records are scope-bound, non-future, digest-bound, and separately reviewed by the operator, but v0.3.0 does not impose a universal maximum age or maintain a revocation registry. Deployments must update/revoke the SecretRef profile and bindings when authority changes. SHA-256 bindings are pseudonymous sensitive metadata, not anonymous data.

## Recommended deployment controls

- use a hardened file or exec SecretRef provider outside the workspace;
- use a scoped SMTP app password;
- run `openclaw secrets audit --check` and `openclaw security audit --deep`;
- deny both RightOut tools on `gateway.tools.deny` unless direct operator invocation is required;
- keep the Gateway on authenticated loopback/private ingress;
- keep debug proxy capture disabled for private workflows;
- protect approval channels from unauthorized users;
- separate OS/container privileges when the agent has shell access.

## Report a vulnerability

Use a private GitHub security advisory with synthetic fixtures only. Report approval crossover/bypass, plaintext SecretRef failures, arbitrary SMTP destinations, recipient/body injection, TLS downgrade, duplicate/replay behavior, unexpected network destinations, publisher requests, PII leakage, catalog provenance failures, filesystem escapes, hidden writes, or incorrect exposure/removal-state claims.
