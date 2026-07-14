# Closing audit: RightOut v0.9.0 source candidate

Audit date: 2026-07-14. Status: the autonomy-platform requirements A1-A4,
M1-M2, E1, C1, L1, U1-U2, R1, and R2 are closed in source and current local
regression evidence. Independent Round 6 reviewed the frozen post-fix commit
`9312d54e369387dba9ce315c8852d51fbb7240c2` and returned `CLEAN` with no open
P0, P1, P2, or P3 finding. Publication remains a separate protected-main,
signed-tag, and GitHub CI action; this audit does not claim that action already
happened.

## Review closure

| Round | Reviewed source | Result and closure |
| --- | --- | --- |
| 1 | `6d3de5e` | Found crash wake recovery, exact command-result correlation, evidence-export purge, deduplicated retention, strict Ed25519 key-type, and controller-reply negation defects. All received focused regressions and were closed in `29799d2`. |
| 2 | `29799d2` | Found unavailable-scheduler startup recovery, globally keyed receipts, fail-open export unlink, idle evidence expiry, broader negation, and inconclusive-rescan completion defects. Closed in `dadb7c4`. |
| 3 | `dadb7c4` | Found same-instance evidence lifecycle races, expired-lease receipt acceptance, partial schedule-replacement success, and qualified-reply classification defects. Closed in `ee3b61f`; installer hook inspection was corrected in `a116fe5`. |
| 4 | `ee3b61f` | Found cross-instance/process evidence lifecycle races, stale startup recovery replacing a newer watchdog, and legal-retention reply qualification defects. Closed with state-directory transaction locks and durable worker schedule tokens in `31563c6`. |
| 5 | `31563c6` | Found one post-claim lost-wake path when local planning failed after a one-shot schedule had been consumed. Closed in `9312d54` by durably human-gating every post-claim planner/ledger failure and reproducing the corrupt-ledger path at runtime. |
| 6 | `9312d54` | `CLEAN`. The independent read-only review found no open P0-P3 and rechecked every earlier closure, installer hooks, package output, dependency audit, and the clean frozen worktree. |

## Current source evidence

- Plugin suite: 354/354 pass. Coverage passes at 90.68% lines, 74.92%
  branches, and 91.26% functions.
- TypeScript typecheck and compiled distribution build pass. The source and
  distribution both expose the required `before_tool_call` and
  `after_tool_call` runtime hooks.
- Technical parity passes at 56/56 pinned capabilities: 51 directly
  implemented and five equivalent-or-stronger, with 22 normalized provider
  contracts. Default operational autonomy remains false.
- Python core, workflow, filesystem-security, public-boundary, and installer
  tests pass at 50/50, including fresh and force OpenClaw runtime installation.
- Validation, offline scan-only dummy, and offline state-machine dummy E2E pass
  without live network calls, provider writes, or real-person data.
- CI, release, and CodeQL workflow checkout hardening validates all five
  checkout steps.
- Production dependency audit reports zero vulnerabilities. Package preflight,
  archive inspection, build, and packed runtime checks pass.
- Worker effects remain fixed-command, live-lease, campaign, session, policy,
  approval, provider-permission, and exact host-receipt bound. Uncertain writes
  do not retry silently; failed scheduling and post-claim local failures become
  durable human gates.
- Evidence export, expiry, cleanup, purge, and rotation are encrypted and
  coordinated across independent instances and processes. Custom targets stay
  opaque and cannot become provider actions without a trusted recipe and
  current permission contract.
- Authenticated controller mail produces bounded encrypted candidates, not
  automatic legal conclusions. Terminal outcomes retain a separate native
  approval.

## Explicit non-claims

- Synthetic fixtures and mocked providers do not prove real-provider discovery,
  removal, delivery, or long-term effectiveness.
- No successful Oliver Posselt live canary is evidenced in this audit. Real
  scan and removal effectiveness therefore remains `needs_evidence` until an
  installed, configured, explicitly authorized canary is run and independently
  verified.
- Complete technical capability and contract coverage does not grant current
  provider permission or authorize CAPTCHA bypass, stealth evasion, account
  creation, identity upload, payment, postal mail, legal escalation, or silent
  uncertain-write retries.
- The local dashboard is a private static artifact, not a hosted multi-tenant
  service.

## Remaining external release action

The source candidate is locally publishable. It still has to merge through the
protected `main` process. A separately authorized GitHub-verifiable signed,
annotated `v0.9.0` tag must then run CI and release automation, which must
recreate and verify the archive, checksum, SBOM, artifact attestation, and
release evidence. Until those external steps complete, no tag, GitHub release,
or deployed real-person canary is claimed.
