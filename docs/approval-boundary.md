# OpenClaw approval boundary

Status: `implemented_for_read_only_live_scan_only`.

## Implemented capability

RightOut integrates OpenClaw's native plugin permission request flow exactly at `before_tool_call`, after model selection and before execution:

- title: bounded live broker scan;
- description: exact opaque profile ID and broker IDs, disclosed field categories, provider, verification scope, and no-write statement; no raw profile values;
- severity: `critical`;
- decisions: `allow-once`, `deny`;
- timeout: 120 seconds;
- timeout behavior: deny.

OpenClaw blocks on denial, timeout, cancellation, hook failure, or missing approval route. On `allow-once`, RightOut stores only a short-lived single-use binding between the host tool-call ID and the exact normalized profile/broker scope shown in the prompt. Execution consumes it before accessing already materialized config values or making a network request; replay, expiry, direct invocation, or parameter mutation fails closed. The tool is optional, so model visibility is a separate operator opt-in through tool policy.

Official references: [plugin permission requests](https://docs.openclaw.ai/plugins/plugin-permission-requests), [building plugins](https://docs.openclaw.ai/plugins/building-plugins), [tool plugins](https://docs.openclaw.ai/plugins/tool-plugins), and [plugin manifest](https://docs.openclaw.ai/plugins/manifest).

## Bound data and action

The approved call contains only an opaque profile ID and one or two broker IDs, all displayed exactly in the approval. The plugin code fixes the action class to read-only scan, fixes the search provider endpoint, derives destinations from the validated catalog, limits candidate requests, and has no submission/email/provider-write implementation. An agent cannot widen the approved call into a removal action.

OpenClaw materializes SecretRef-backed plugin config before registration, so raw PII may reside in Gateway/plugin-process memory from config load until reload or restart. RightOut accesses it only after a valid approval binding. It is not in model-visible tool parameters or approval text. RightOut registers critical security-audit findings when the source config uses plaintext instead of SecretRefs.

## Direct invoke and operator trust

OpenClaw's `/tools/invoke` is a full-operator surface. It runs plugin hooks, but direct invocation is unnecessary for normal RightOut use. Production guidance adds `rightout_live_scan` to `gateway.tools.deny`; the plugin security audit warns when this hardening is absent. See OpenClaw's [Tools invoke API](https://docs.openclaw.ai/gateway/tools-invoke-http-api).

## Explicitly unauthorized capabilities

No approval exists for removal request rendering, form submission, email, CAPTCHA, verification links, identity-document upload, recurring monitoring, scheduling, or provider writes. Those capabilities are absent, not hidden behind an approval flag.

Adding any such capability requires a separate tool, independent destination/field policy, a new per-call native approval, replay/scope tests, retention design, provider terms review, and independent security review. A scan approval can never authorize a removal action.

## Residual limits

- SecretRefs are not process, OS, or call-lifetime isolation; the Gateway/plugin process may hold resolved config until reload or restart.
- A compromised OpenClaw runtime, installed plugin, OS account, or secret provider is outside this plugin boundary.
- The human approval confirms disclosure/action categories and selected broker count, not raw values; showing raw PII on approval surfaces would itself create leakage.
- Commercial providers' downstream retention and legal roles are not controlled by RightOut.

These limits must remain visible in deployment and privacy documentation.
