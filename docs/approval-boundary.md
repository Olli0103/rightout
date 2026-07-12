# Approval boundary

Status: `implemented_separately_for_live_scan_and_live_removal`.

## OpenClaw contract

RightOut follows OpenClaw's documented split:

- optional tool policy controls whether a tool is visible to the model;
- `before_tool_call.requireApproval` pauses one selected call before execution;
- only `allow-once` and `deny` are offered;
- timeout behavior is explicitly `deny` for the pinned stable OpenClaw `2026.6.11` contract;
- the plugin consumes the approval once and revalidates the exact scope immediately before action.

Primary references: [Plugin hooks](https://docs.openclaw.ai/plugins/hooks), [Plugin permission requests](https://docs.openclaw.ai/plugins/plugin-permission-requests), [Tool plugins](https://docs.openclaw.ai/plugins/tool-plugins), and [Plugin manifest](https://docs.openclaw.ai/plugins/manifest).

## Two non-interchangeable capabilities

```text
rightout_live_scan
  input: profileId + brokerIds
  destination: api.search.brave.com
  effect: read-only index search
  write authority: none

rightout_submit_removal
  input: profileId + brokerId + fixed requestKind
  destination: catalog recipient via pinned operator SMTP
  effect: one external email write
  scan authority: none required or inherited
```

Each hook result binds the host-authoritative tool-call ID to:

- tool name/action class;
- normalized opaque input;
- current revision-bound attestation snapshot, including normalized profile and SMTP SHA-256 bindings;
- for removal, the resolved broker name, recipient, fields, jurisdiction policy, and catalog revision facts.

Execution deletes the binding before network work. Missing, expired, replayed, cross-tool, mutated, or config-revoked bindings fail with `rightout_approval_binding_failed`.

## Scan approval

The prompt displays profile ID, broker IDs, Brave terms revision, disclosure categories, retention summary, and the no-publisher/no-write posture. Recorded `scan` consent and operator review are mandatory; the normalized disclosed profile snapshot is bound into the approval and rechecked before network access. It authorizes only a POST to Brave Search. A publisher fetch, email, form, or later tool call is outside scope.

## Removal approval

Before an approval prompt is offered, RightOut verifies only PII-free policy inputs:

1. a catalog-supported email lane and fixed request kind;
2. an official, catalog-locked recipient;
3. exact opaque-profile/broker/request-kind operator attestations plus non-plaintext normalized profile/SMTP snapshot bindings.

The hook deliberately does not open or parse the SecretRef profile or SMTP secrets before approval. After `allow-once`, but before any network connection, execution verifies that the resolved values still match both bound SHA-256 snapshots, then verifies recorded subject consent, eligible jurisdiction, SMTP sender equality with the subject contact email, and the allowed SMTP host/port/TLS combination. A failed post-approval preflight performs no provider write. The digests are operator configuration, not caller-provided approval receipts and never replace native approval.

The prompt shows the opaque profile, broker, exact public recipient, disclosure field categories, action count, and that this is an external write. It never shows the profile values or credentials.

Approval authorizes one SMTP send. It does not authorize retries, additional brokers, extra fields, identity documents, CAPTCHA handling, forms, browser activity, or claims that removal succeeded.

## Direct Gateway invoke

OpenClaw's `/tools/invoke` is a full-operator surface. Plugin hooks still run, but ordinary RightOut operation does not require direct invoke. Production guidance denies both `rightout_live_scan` and `rightout_submit_removal` on `gateway.tools.deny`; the plugin security audit warns if either is exposed.

## Non-boundaries

The following never authorize an action:

- user or model prose saying “approved”;
- caller-created JSON/HMAC receipts;
- environment flags;
- prior scan/removal approvals;
- tool result contents;
- broker/controller page content;
- agent-accessible config or files.

OpenClaw's plugin permission service and operator-owned config are the supported boundary. OpenClaw plugins remain trusted in-process code, so strong multi-user or hostile-agent isolation requires separate Gateways and OS identities.
