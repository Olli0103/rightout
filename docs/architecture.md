# Architecture

## Live path

```text
operator-owned SecretRefs                    catalog schema v2
  Brave key + private profile                supported broker IDs/domains
              \                               /
               v                             v
model -> optional rightout_live_scan(profileId, brokerIds)
                         |
                         v
              native before_tool_call approval
              allow-once | deny | fail closed
                         |
                         v
       plugin accesses already materialized profile
                         |
             +-----------+-----------+
             |                       |
             v                       v
    Brave POST search          same-domain candidate GET
    fixed guarded host         catalog guarded host + redirects
             \                       /
              +----------+-----------+
                         v
              sanitized report v3 only
```

The model-visible call and transcript contain no raw PII. OpenClaw materializes SecretRef-backed plugin config before plugin registration, so the Gateway/plugin process may hold the resolved profile and key from config load until reload or restart. RightOut accesses them only after approval and never writes or returns them. SecretRefs are a config-persistence control, not OS/process or call-lifetime isolation.

## OpenClaw integration

`index.ts` uses `definePluginEntry` because one plugin registers both a tool and a typed hook. The tool is optional and `replaySafe: false`. The manifest declares tool/config/SecretInput contracts. Production packaging compiles `index.ts` and `lib/live-scan.mjs` into `dist/`; `package.json` points OpenClaw at `dist/index.js`.

The `before_tool_call` hook validates and normalizes the exact profile/broker scope, displays it in `requireApproval`, and binds an `allow-once` resolution to the host-authoritative tool-call ID for 120 seconds. Execution consumes that binding before accessing the already materialized config values or making a request. Missing, expired, replayed, denied, or parameter-mutated calls fail closed. Direct Gateway invoke paths also traverse the hook; RightOut nevertheless recommends an explicit `gateway.tools.deny` entry to remove the direct full-operator HTTP surface.

All external requests use `openclaw/plugin-sdk/ssrf-runtime` with HTTPS required, DNS/SSRF policy, exact/suffix host allowlists, bounded redirects, timeouts, size limits, safe headers, capture disabled, and OpenClaw abort-signal propagation. Candidate URLs must also have no credentials, query, or fragment and match an anchored catalog profile-path policy.

## Result semantics

- `found`: a permitted direct candidate page contained one JSON-LD `Person` object with the exact normalized full name and matching city/region in that same record. This is medium-confidence structured discovery evidence, not identity/ownership proof.
- `inconclusive`: no candidate, no structured record match, loose/reflected page text, anti-bot/login response, provider/network/policy failure, or unsupported proof condition.
- `not_found`: intentionally never emitted by live v0.2 scans because search-index absence cannot prove absence.

Proof references are HMAC-SHA-256-derived opaque IDs over broker ID plus candidate URL using a fresh random secret for each scan. The secret is erased after use, so identical URLs do not create a stable cross-scan correlation handle; candidate URLs themselves are not returned.

## Offline runner

The Python runner exposes only `doctor`, `validate`, `plan-dummy`, `scan-only-dummy`, `e2e-dummy`, and `verify-link`. It has no network or live subject command. Its private filesystem model uses opaque IDs, lexical containment, symlink rejection, `O_NOFOLLOW` where supported, `0700` directories, `0600` files, locks, revision compare-and-swap, atomic replace, and fsync.

Synthetic removal states exist only to verify report UX and transitions. They do not authorize or execute a removal.
