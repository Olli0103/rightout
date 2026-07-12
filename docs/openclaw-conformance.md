# OpenClaw conformance

Review date: 2026-07-12. Target: stable OpenClaw `2026.6.11` / Plugin API `>=2026.6.11`. Where the rolling website and the released package documentation differ, release behavior is validated against the pinned package's documentation, types, runtime, and isolated install tests.

## Package and manifest

- root `openclaw.plugin.json` is present and its `id` matches `definePluginEntry`;
- package loads compiled `./dist/index.js`;
- `contracts.tools` declares exactly `rightout_live_scan` and `rightout_submit_removal`;
- both runtime registrations use `{ optional: true }` and both manifest entries set `optional: true`, `replaySafe: false`;
- tool availability uses `toolMetadata.configSignals` without loading the runtime;
- `configContracts.secretInputs` declares Brave key, profile payloads, SMTP username/password, and sender address;
- config schema rejects unknown fields and constrains IDs, enums, attestations, SMTP hosts, ports, and SecretRef-shaped inputs;
- plugin skill directory is declared through `skills: ["./skills"]`.
- activation explicitly sets `onStartup: false`; tool contracts and config signals keep the plugin lazy until its capabilities are needed.

Official references: [manifest](https://docs.openclaw.ai/plugins/manifest), [building plugins](https://docs.openclaw.ai/plugins/building-plugins), [tool plugins](https://docs.openclaw.ai/plugins/tool-plugins), and [skills](https://docs.openclaw.ai/skills).

## Runtime imports and APIs

- `definePluginEntry` comes from `openclaw/plugin-sdk/plugin-entry`;
- SSRF helpers come from `openclaw/plugin-sdk/ssrf-runtime`;
- tools are registered with `api.registerTool`;
- policy uses typed `api.on("before_tool_call", ...)`;
- security findings use `api.registerSecurityAuditCollector`;
- plugin-relative catalog path uses `api.resolvePath`;
- runtime config uses the resolved `api.pluginConfig` snapshot.

No OpenClaw internal module is imported.

## Approval contract

Both tools use `before_tool_call.requireApproval` with:

- critical severity;
- only `allow-once` and `deny`;
- 120-second timeout;
- explicit `timeoutBehavior: "deny"` for the pinned stable OpenClaw `2026.6.11` contract;
- `onResolution` that records a short-lived binding only after `allow-once`.

Bindings include action class and are revalidated/consumed before execution. The pinned stable package documents and evaluates `timeoutBehavior`; RightOut sets it to `deny` explicitly. Timeout, cancellation, missing routes, and malformed or missing decisions therefore fail closed. This follows the version-matched OpenClaw `2026.6.11` plugin hooks and permission-request documentation shipped with the pinned runtime. Optional visibility and runtime permission are both used because OpenClaw documents them as different gates.

## Secrets and security audit

OpenClaw resolves SecretRefs before plugin execution while source-config audit retains ref markers. RightOut uses this split to:

- keep raw values out of public tool schemas;
- audit plaintext source config;
- validate resolved values only inside trusted plugin code;
- avoid config writes or agent-readable profile files.

See OpenClaw [Secrets management](https://docs.openclaw.ai/gateway/secrets) and [Plugin SDK runtime](https://docs.openclaw.ai/plugins/sdk-runtime).

## Network behavior

The scan uses OpenClaw's SSRF guard, fixed HTTPS destination, DNS policy, zero redirects, disabled capture, bounded response reads, and abort propagation.

SMTP is not HTTP and therefore cannot use the SSRF fetch guard. RightOut instead rejects arbitrary SMTP destinations with a compile-time host/port/TLS matrix, requires certificate validation and TLS 1.2+, disables message file/URL access, and accepts no host from model input.

## Install and runtime verification

The release workflow uses:

```bash
openclaw plugins install <packed-archive>
openclaw plugins inspect rightout --runtime --json
openclaw plugins doctor
```

OpenClaw's CLI documentation states that runtime inspection is required to prove registered hooks/tools rather than relying on cold manifest inventory. Gateway restart/reload is required after a code update.

## Known platform boundary

OpenClaw treats installed plugins as trusted in-process code. Native approval is an operator guardrail, not a multi-tenant sandbox. Deployments with mutually untrusted users or agents must use separate Gateways and OS identities. RightOut does not claim otherwise.
