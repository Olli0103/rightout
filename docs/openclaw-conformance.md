# OpenClaw conformance

Review date: 2026-07-12. Target: stable OpenClaw `2026.6.11` / Plugin API `>=2026.6.11`, verified against the pinned package documentation, types, runtime, and isolated installer tests.

- `openclaw.plugin.json` declares all ten registered tools, exact optional/replay metadata, lazy config signals, SecretInput paths, the two fixed removal request kinds, closed config schema, skill directory, and `onStartup: false`.
- `definePluginEntry`, `api.registerTool`, typed `before_tool_call`, `api.registerSecurityAuditCollector`, `api.resolvePath`, and `api.runtime.state.resolveStateDir` are public plugin APIs used by the community plugin.
- HTTP uses the public SSRF runtime. The sandbox browser form uses only the official tool-factory `browser.sandboxBridgeUrl`; no internal browser runtime import is used.
- Six provider-I/O tools and one local destructive purge tool use critical `requireApproval`, `allow-once`/`deny`, 120-second timeout, explicit deny on timeout, and `onResolution` bindings. Three state/report tools are replay-safe and make no network request.
- OpenClaw SecretRefs keep raw values out of public schemas. Source-config audits detect plaintext while runtime code validates resolved values after approval.
- OpenClaw `2026.6.11` documents `openKeyedStore` as bundled-plugin-only and rejects it for an ordinary community install. RightOut therefore uses the public state-directory resolver plus its own private, contained, AES-256-GCM encrypted, atomic file stores. They provide bounded entry counts/TTLs, owner-token cross-process locks, persisted TTL pruning, and serialized updates without importing an internal OpenClaw state module.

The plugin cannot call the bundled-only session-turn scheduler. Recurring work is exposed through deterministic `rightout_due_rechecks` and documented for official OpenClaw Cron instead of importing an internal scheduler or pretending to self-schedule.

OpenClaw's `plugins build` generator applies to entries that expose `defineToolPlugin` static metadata. RightOut needs `definePluginEntry` because it combines tools, approval hooks, and a security-audit collector, as the official tool-plugin and hook documentation directs. Its manifest is therefore explicit and is checked against runtime registration, config schema, tool contracts, optional/replay metadata, and isolated `plugins inspect` output instead of misusing the simple-tool generator.

Release verification installs an actual npm archive, uses `openclaw plugins inspect rightout --runtime --json`, runs `openclaw plugins doctor`, validates configuration, audits SecretRefs/security, and restarts/reloads after updates.

Official references: [plugin manifest](https://docs.openclaw.ai/plugins/manifest), [tool plugins](https://docs.openclaw.ai/plugins/tool-plugins), [plugin hooks](https://docs.openclaw.ai/plugins/hooks), [plugin permission requests](https://docs.openclaw.ai/plugins/plugin-permission-requests), [SDK runtime](https://docs.openclaw.ai/plugins/sdk-runtime), [secrets](https://docs.openclaw.ai/gateway/secrets), and [Cron](https://docs.openclaw.ai/automation/cron-jobs).

Installed plugins are trusted in-process code. Approval is an operator guardrail, not a hostile-plugin or multi-tenant sandbox; mutually untrusted users require separate Gateways and OS identities.
