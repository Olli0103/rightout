# OpenClaw conformance

Review date: 2026-07-14. Target: stable OpenClaw `2026.6.11` / Plugin API
`>=2026.6.11`, with compatibility inspection against npm beta
`2026.7.1-beta.6`.

## Manifest and runtime

- `openclaw.plugin.json` declares exactly the 50 registered tools, optional and
  replay-safety metadata, lazy config signals, SecretInput paths, strict closed
  JSON Schema, skill directory, and `onStartup: false`.
- `definePluginEntry`, `api.registerTool`, typed `before_tool_call`,
  `api.registerSecurityAuditCollector`, `api.resolvePath`, and
  `api.runtime.state.resolveStateDir` are the public APIs used by the plugin.
  Durable workers additionally use `api.session.workflow` only to schedule or
  unschedule the exact current trusted session after native approval. A lease
  watchdog covers every issued action and startup reconstructs active wakes
  from encrypted worker routing state; unconfirmed recovery scheduling moves
  the worker to a human gate, and hosts without that capability receive an
  explicit Cron handoff on interactive enable. `after_tool_call` records only a
  terminal result re-bound to the exact session, run, call ID, tool, normalized
  parameters, lease, and execution digest and cannot widen the campaign.
- The official SSRF-aware HTTP runtime is used for remote HTTP. Production
  sandboxed agents use OpenClaw's `toolContext.browser.sandboxBridgeUrl`
  contract backed by `agents.defaults.sandbox.browser`. Unsandboxed/host-profile
  lanes use the public standalone loopback API; only that mode requires the
  Gateway service to set `OPENCLAW_EAGER_BROWSER_CONTROL_SERVER=1`, restart,
  expose `gateway.port + 2`, and provide bearer-token auth. Tests mock the
  sandbox bridge but do not redefine its production contract.
- AI snapshots and `/act` require Playwright plus an available Chromium-based
  browser. `rightout_doctor` uses `/doctor?deep=true&profile=...`; reachability
  alone is insufficient and both operational and deep-snapshot checks must pass.
- Browser refs are treated as page- and snapshot-scoped. A fresh snapshot and
  exact semantic binding are required before every action.

## Approval behavior

Assisted provider I/O, campaign creation/revocation, worker enable/resume, DOB
disclosure, evidence/dashboard export, and critical local decisions use
`before_tool_call.requireApproval` with only
`allow-once`/`deny`, a 120-second timeout, and typed `onResolution` bindings.
Current OpenClaw fails closed for missing, malformed, cancelled, denied,
unroutable, unresolved, and timed-out decisions. RightOut intentionally omits
the deprecated and ignored `timeoutBehavior` compatibility field.

Campaign-authorized calls do not request a second prompt, but they must match
the immutable profile, exact brokers/effects, combined catalog/provider-terms
digest, runtime transport/browser/provider-permission digest, expiry, revocation
state, and remaining budget. OpenClaw approval descriptions stay within the
Gateway limit by naming the pinned 22-broker catalog and concrete effect labels;
the immutable digest remains in the non-PII binding rather than replacing the
human-readable scope. The full exact scope is still bound cryptographically.
The campaign approval explicitly names the possible subject-field classes,
recipient/processor classes, and selected browser backend in addition to the
human-readable pinned target label or explicit short target list, concrete
effect names, lifetime, and effect budget. The full exact scope remains in the
approval binding.

## SecretRef truth

OpenClaw resolves active SecretRefs **eagerly during Gateway activation** into
an in-memory snapshot. Startup fails when an active ref cannot resolve; reload
atomically swaps a complete new snapshot or keeps the last known good one.
RightOut does not claim lazy post-approval SecretRef resolution.

Its actual guarantee is narrower: RightOut does not send subject PII or provider
credentials to an external provider before an exact assisted approval or a
validated campaign grant. Local setup/status/export/doctor operations may read
resolved configuration or the state key to validate profiles, decrypt encrypted
state, and probe the configured loopback browser service; they never return
those values. Campaign preapproval itself binds only opaque scope and does not
read profile/transport/key secrets. Since plugins run in-process, SecretRefs and
approvals are not isolation against a malicious plugin.

## Cron

An explicitly approved durable worker may schedule only its exact current
trusted OpenClaw session. The scheduled turn still receives only one
grammar-bound command under the unchanged finite campaign; scheduling never
renews or widens authority. The worker replaces its same-tag wake atomically,
keeps an expiry watchdog while a command is unresolved, and reconstructs active
wakes after Gateway restart. If replacement registration cannot be confirmed,
the active worker becomes a durable human gate rather than silently losing its
wake. If the host does not expose the supported workflow
scheduler, RightOut returns a deterministic PII-free handoff for the official
`openclaw cron add` interface (the documented `cron create` alias is also
accepted). Inspect fallback runs with:

```bash
openclaw cron run <job-id> --wait --wait-timeout 10m
openclaw cron runs --id <job-id> --limit 50
```

Read-only monitoring jobs should allow only health/status/report/planning tools.
A provider effect must still pass its own assisted approval or a still-active
finite campaign. Campaigns expire after at most 720 hours; Cron never silently
renews authority.

## Package verification

The installer validates source, packs the real npm archive, installs that
archive into an isolated OpenClaw home/state directory, checks the exact
manifest/runtime tools and approval hook, and runs plugin doctor before target
mutation. Release verification repeats stable/beta inspection, config and
SecretRef audits, deep security audit, coverage, Python/installer matrices,
package inspection, SBOM comparison, provenance, and transactional rollback.

Optional team roles are an agent-session boundary, not a new OpenClaw tenant
sandbox. Team mode requires every RightOut contract tool in
`gateway.tools.deny` for the full-operator direct-invoke surface; the security
audit treats any omission as critical.

Official references: [manifest](https://docs.openclaw.ai/plugins/manifest),
[building plugins](https://docs.openclaw.ai/plugins/building-plugins),
[hooks](https://docs.openclaw.ai/plugins/hooks),
[permission requests](https://docs.openclaw.ai/plugins/plugin-permission-requests),
[browser control](https://docs.openclaw.ai/tools/browser-control),
[SecretRefs](https://docs.openclaw.ai/gateway/secrets), and
[Cron](https://docs.openclaw.ai/cli/cron).

Installed plugins are trusted code. Mutually untrusted users require separate
Gateways and OS identities.
