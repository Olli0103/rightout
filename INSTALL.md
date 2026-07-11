# Install and enable RightOut

## 1. Prerequisites

- OpenClaw `2026.6.11` or newer
- Node.js `22.19` or newer and npm
- Python 3 for package/catalog validation
- a Brave Search API subscription key
- an operator-owned secret provider outside the agent workspace

## 2. Install the complete plugin

```bash
git clone https://github.com/Olli0103/rightout.git
cd rightout
npm ci --ignore-scripts
./install.sh
```

Use `./install.sh --force` for an existing registration. `./install.sh --link` is development-only. The normal path compiles and packs a minimal archive before calling `openclaw plugins install`; TypeScript checkout fallback is not used in the installed release.

Verify:

```bash
openclaw plugins inspect rightout --runtime --json
openclaw plugins doctor
```

Expected runtime evidence includes status `loaded`, optional tool `rightout_live_scan`, and typed hook `before_tool_call`.

The installer snapshots the OpenClaw config and any existing managed `extensions/rightout` installation before mutation. If installation succeeds but runtime inspection or plugin doctor fails, it atomically restores the config and prior managed extension. Linked external source trees are never deleted.

An atomic lock at `.rightout-install.lock` under the OpenClaw state directory rejects concurrent installer transactions. A stale lock must be removed manually only after verifying that no RightOut installer process is active.

## 3. Provision private inputs out of band

Create an operator-controlled secret document outside the workspace and agent-readable paths. Its logical JSON values are:

```json
{
  "braveApiKey": "provider-key",
  "profiles": {
    "profile_a1b2c3d4e5f60718": "{\"fullName\":\"...\",\"city\":\"...\",\"region\":\"CA\",\"country\":\"US\"}"
  }
}
```

Do not create this file through an agent, commit it, or put it in the OpenClaw workspace. Configure a hardened OpenClaw `file` or `exec` secret provider, then set refs. Example paths:

```bash
openclaw config set plugins.entries.rightout.config.braveApiKey \
  --ref-provider rightout_secrets --ref-source file --ref-id /braveApiKey

openclaw config set plugins.entries.rightout.config.profiles.profile_a1b2c3d4e5f60718.payload \
  --ref-provider rightout_secrets --ref-source file \
  --ref-id /profiles/profile_a1b2c3d4e5f60718
```

The profile JSON permits only `fullName`, `city`, `region`, and optional `country: "US"`. The tool receives only the random-looking hex reference `profile_a1b2c3d4e5f60718`; it never receives these values.

## 4. Record operator attestations

Live use is blocked until an operator—not an agent—has verified subject authorization for each exact opaque profile ID, reviewed and accepted Brave Search API Terms revision `2026-02-11`, accepted Brave's customer/end-user responsibilities, and approved each broker domain included in the Brave index-search scope. RightOut never requests a broker page. Spokeo remains excluded from live selection as an additional conservative catalog control.

Only after completing that out-of-band review, configure the exact authorized set:

```bash
openclaw config set plugins.entries.rightout.config.operatorAttestations \
  '{"braveTermsAccepted":true,"braveTermsVersion":"2026-02-11","braveCustomerResponsibilitiesAccepted":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedBrokerIds":["truepeoplesearch"]}' \
  --strict-json
```

This is a fail-closed configuration gate, not a legal certification by RightOut. A future Brave terms revision intentionally invalidates the pinned attestation until code, documentation, and operator acceptance are reviewed. Brave's published privacy notice states that standard-plan query logs may be retained for up to 90 days; ZDR requires an applicable enterprise arrangement. See [provider access and retention review](docs/provider-terms-review.md).

OpenClaw SecretRefs reduce persisted-secret exposure but are not OS/process isolation. For a strong deployment, separate the Gateway/secret provider from agent-readable files and shell access. See OpenClaw's [Secrets management](https://docs.openclaw.ai/gateway/secrets).

## 5. Configure tool and Gateway policy

Because the tool is optional, add `rightout_live_scan` to the applicable `tools.allow` policy without overwriting unrelated existing entries.

Also add it to `gateway.tools.deny` unless direct full-operator `/tools/invoke` access is explicitly required. This deny affects the direct HTTP surface, not ordinary agent selection:

```json5
{
  gateway: { tools: { deny: ["rightout_live_scan"] } }
}
```

Configure a local UI or explicit `approvals.plugin` route. With no route, calls fail closed. OpenClaw documents the routing contract in [Plugin permission requests](https://docs.openclaw.ai/plugins/plugin-permission-requests).

## 6. Readiness gate

```bash
openclaw config validate
openclaw secrets audit --check
openclaw security audit --deep
openclaw plugins inspect rightout --runtime --json
openclaw plugins doctor
```

Resolve every `rightout.secretref.*` and `rightout.operator_attestations` critical finding before live use. Resolve or consciously accept the `rightout.gateway.tools_invoke` warning.

No real-person live scan is part of installation or release testing. A production scan begins only when a user explicitly requests it, the optional tool is visible, and the native approval is resolved with `allow-once`. It contacts only Brave Search; it never follows or fetches a returned publisher URL.
