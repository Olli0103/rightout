# Architecture

## Runtime

```text
operator SecretRefs                         clean-room catalog schema v3
  profile + consent                          scan policy + removal policy
  Brave key                                  official recipient + fields
  SMTP identity/credential                   jurisdiction + provenance
          |                                             |
          +---------------- OpenClaw plugin ------------+
                               |
            +------------------+------------------+
            |                                     |
 rightout_live_scan                    rightout_submit_removal
 optional, replaySafe=false             optional, replaySafe=false
 opaque profile + broker IDs            opaque profile/broker + fixed kind
            |                                     |
 separate before_tool_call approval     separate before_tool_call approval
            |                                     |
 Brave guarded HTTPS POST               pinned SMTP TLS endpoint
            |                                     |
 indirect/inconclusive report           submitted-only report
```

The tools share profiles and catalog data but no approval authority. Each execution validates and consumes a binding tagged with its exact tool name.

## Live scan data flow

1. OpenClaw resolves the profile and Brave key from SecretRefs.
2. The model sees only opaque IDs.
3. RightOut validates supported broker scan policies, recorded scan consent, and current attestations including a normalized profile digest.
4. OpenClaw presents a scan-specific allow-once prompt.
5. After approval, RightOut rechecks the bound profile snapshot, then POSTs one site query per broker to `api.search.brave.com` using the Plugin SDK SSRF guard.
6. It checks transiently for an HTTPS result on an official broker domain.
7. It discards all result content and returns only sanitized states and coverage gaps.

Publisher requests, redirects, raw-result storage, and provider writes are absent.

## Live removal data flow

1. OpenClaw resolves profile/consent and SMTP values from SecretRefs.
2. The model supplies only `profileId`, `brokerId`, and `delete_and_opt_out`.
3. RightOut resolves the PII-free catalog lane and exact opaque-scope attestations, including operator-generated normalized profile/SMTP digests.
4. OpenClaw presents a removal-specific allow-once prompt with broker, recipient, and field categories; the hook does not parse profile or SMTP secrets.
5. After approval, RightOut resolves secrets and verifies both bound snapshots, consent, jurisdiction, SMTP endpoint, sender/profile equality, and minimum fields before opening a connection.
6. RightOut renders the fixed request internally and sends one TLS-protected SMTP message.
7. The result reports only `submitted`, an opaque proof reference, and explicit uncertainty.

No request body, profile value, credential, or raw SMTP receipt is returned or persisted by RightOut. A 24-hour in-process cooldown blocks accidental duplicate scope during one Gateway lifetime; each post-restart send still requires a new approval.

## Reporting semantics

- `indirect_exposure`: Brave returned an HTTPS candidate on the selected official domain; identity and current content remain unverified.
- `inconclusive`: index/provider evidence cannot prove presence or absence.
- `submitted`: outbound SMTP accepted the message; broker receipt/removal remain unverified.
- `confirmed_removed`: available only in the synthetic state machine because the current live plugin has no direct absence proof.
- `reappeared`: modeled and tested synthetically; live detection can only show a later indirect signal.

## Dummy runner

The Python runner exposes only `doctor`, `validate`, `plan-dummy`, `scan-only-dummy`, `e2e-dummy`, and `verify-link`. It makes no network request, reads no live profile, and cannot transition a shipped catalog case. It retains opaque IDs, containment checks, symlink rejection, private permissions, atomic writes, locking, and revision conflict protection for synthetic artifacts.

## Deliberate limits

- no publisher fetch or browser automation;
- no form/CAPTCHA/identity-document lane;
- no inbound email or verification-link polling;
- no durable live case database or scheduler;
- no claim of commercial coverage/effectiveness parity;
- no legal advice or certification.
