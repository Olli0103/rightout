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
                         |
                         v
              Brave POST search only
              fixed guarded host, zero redirects
              transient domain classification
                         |
                         v
              sanitized report v3 only
```

The model-visible call and transcript contain no raw PII. OpenClaw materializes SecretRef-backed plugin config before plugin registration, so the Gateway/plugin process may hold the resolved profile and key from config load until reload or restart. RightOut accesses them only after approval and never writes or returns them. SecretRefs are a config-persistence control, not OS/process or call-lifetime isolation.

## OpenClaw integration

`index.ts` uses `definePluginEntry` because one plugin registers both a tool and a typed hook. The tool is optional and `replaySafe: false`. The manifest declares tool/config/SecretInput contracts. Production packaging compiles `index.ts` and `lib/live-scan.mjs` into `dist/`; `package.json` points OpenClaw at `dist/index.js`.

The `before_tool_call` hook validates and normalizes the exact profile/broker scope plus the complete exact-profile, pinned-Brave-revision, customer-responsibility, and broker-search-scope attestation snapshot. It displays the disclosure and Brave retention limit in `requireApproval`, then binds an `allow-once` resolution to the host-authoritative tool-call ID for 120 seconds. Execution reconstructs the normalized current snapshot, compares the full binding, consumes it, and passes the actual snapshot to the live library for independent validation before reading the profile/key or making a request. Missing, changed, expired, replayed, denied, unattested, or parameter-mutated calls fail closed.

The only external request uses `openclaw/plugin-sdk/ssrf-runtime` with HTTPS required, the exact Brave host allowlist, zero redirects, timeout, size limit, safe headers, capture disabled, and OpenClaw abort-signal propagation. Result URLs are parsed transiently only to classify an HTTPS official-domain candidate; they are never requested, returned, hashed into a proof reference, or stored.

## Result semantics

- `indirect_exposure`: Brave returned at least one HTTPS result on the selected official domain. This is an index signal, not identity, ownership, page-content, or current-listing proof.
- `inconclusive`: no same-domain index candidate, provider/network/policy failure, or unsupported proof condition.
- `not_found`: intentionally never emitted by live v0.2 scans because search-index absence cannot prove absence.

Live reports contain no proof reference because deriving or retaining evidence from a Search Result would weaken the transient-use posture. The report carries only the selected broker ID, state, sanitized reason, provider disclosure, and coverage gaps.

## Offline runner

The Python runner exposes only `doctor`, `validate`, `plan-dummy`, `scan-only-dummy`, `e2e-dummy`, and `verify-link`. It has no network or live subject command. Its private filesystem model uses opaque IDs, lexical containment, symlink rejection, `O_NOFOLLOW` where supported, `0700` directories, `0600` files, locks, revision compare-and-swap, atomic replace, and fsync.

Synthetic removal states exist only to verify report UX and transitions. They do not authorize or execute a removal.
