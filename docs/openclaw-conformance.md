# OpenClaw conformance

Validated against OpenClaw `2026.6.11` on 2026-07-11.

## Documentation mapping

| RightOut behavior | OpenClaw contract |
| --- | --- |
| Combined tool and hook entry | `definePluginEntry` from [Building plugins](https://docs.openclaw.ai/plugins/building-plugins) |
| Optional tool | tool registration plus manifest metadata from [Tool plugins](https://docs.openclaw.ai/plugins/tool-plugins) |
| Per-call approval | `before_tool_call.requireApproval` from [Plugin permission requests](https://docs.openclaw.ai/plugins/plugin-permission-requests) |
| Manifest/config/tool contracts | [Plugin manifest](https://docs.openclaw.ai/plugins/manifest) |
| Secret-backed config | `configContracts.secretInputs` and [Secrets management](https://docs.openclaw.ai/gateway/secrets) |
| Guarded outbound fetch | `openclaw/plugin-sdk/ssrf-runtime` from [Plugin SDK runtime](https://docs.openclaw.ai/plugins/sdk-runtime) |
| Production install | compiled JS archive through [Plugins CLI](https://docs.openclaw.ai/cli/plugins) |
| Direct invoke posture | [Tools invoke API](https://docs.openclaw.ai/gateway/tools-invoke-http-api) |

## Runtime evidence

The release matrix installs a packed archive into an isolated `OPENCLAW_STATE_DIR`, then requires:

- plugin status `loaded`;
- tool `rightout_live_scan`, `optional: true`;
- typed hook `before_tool_call`;
- no `plugins doctor` issue;
- SecretRef config validation and `secrets audit --check` with zero plaintext/unresolved findings;
- compiled `dist/index.js` and `dist/lib/live-scan.mjs` in the npm archive.

OpenClaw's `plugins build/validate --entry` generator expects `defineToolPlugin` metadata and is not the correct validation path for a combined tool-plus-hook `definePluginEntry`. RightOut therefore uses TypeScript typecheck, unit tests, npm pack, official plugin install, runtime inspect, plugin doctor, config validation, and security/secret audits as the conformance matrix.

## Minimum version

The installer rejects OpenClaw older than `2026.6.11`. `package.json` also records the plugin API and Gateway compatibility floor.
