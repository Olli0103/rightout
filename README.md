# RightOut

RightOut `0.3.0` is an OpenClaw plugin and bundled skill for two separately authorized actions:

1. a read-only live people-search scan through the Brave Search API; and
2. one catalog-locked broker removal request through the operator's SMTP account.

The tools are `rightout_live_scan` and `rightout_submit_removal`. Both are optional, non-replay-safe, accept only opaque references, and require their own native OpenClaw `allow-once` approval. A scan approval cannot authorize an email or any other provider write.

## What works live

### Scan

`rightout_live_scan(profileId, brokerIds)` sends name and US location from a SecretRef-backed profile to Brave Search in a POST body. It never requests a broker page and never returns or stores PII, queries, result URLs, titles, snippets, or bodies.

- same-domain index candidate: `indirect_exposure`;
- no candidate or provider failure: `inconclusive`;
- never `found` or `not_found` from index-only evidence.

The current scan catalog covers TruePeopleSearch and BeenVerified through Brave only. Spokeo automation remains disabled because its published terms prohibit automated access.

The scan requires recorded `scan` consent, operator review, and a normalized profile digest bound into the approval. A changed profile fails before Brave receives a request.

### Removal

`rightout_submit_removal(profileId, brokerId, requestKind)` can currently send one `delete_and_opt_out` email to BeenVerified's official `privacy@beenverified.com` address for an operator-attested `US-CA` subject. The plugin:

- requires recorded subject consent inside the private profile;
- requires separate removal policy, consent, exact-scope, minimum-disclosure, and SMTP attestations bound to normalized profile/transport SHA-256 snapshots;
- locks the recipient and field categories in catalog schema v3;
- restricts SMTP to pinned Gmail, Yahoo, iCloud, or Fastmail TLS endpoints; Microsoft 365 is excluded because this release has no OAuth 2.0 SMTP flow;
- sends only full name, contact email, region, and country;
- performs no form submission, CAPTCHA work, identity-document upload, or browser automation.

A successful SMTP handoff is reported only as `submitted`. It is not evidence that the broker received, processed, or completed the request. Later index absence remains `inconclusive`, so RightOut does not claim `confirmed_removed` from its current live evidence.

## Security boundary

Private profiles and credentials live in OpenClaw SecretRefs, not chat or tool arguments. Native `before_tool_call.requireApproval` runs after tool selection and before execution. Only `allow-once` and `deny` are offered; denial, timeout, cancellation, missing approval routing, changed attestations, changed bound profile/SMTP snapshots, mutated parameters, or a missing host tool-call ID fails closed.

RightOut also registers security-audit checks for plaintext profiles, Brave keys, SMTP credentials/sender address, incomplete attestations, and direct Gateway tool exposure. Add both tools to `gateway.tools.deny` unless full-operator `/tools/invoke` access is intentionally required.

See [approval boundary](docs/approval-boundary.md), [privacy posture](docs/privacy-posture.md), [OpenClaw conformance](docs/openclaw-conformance.md), and [security policy](SECURITY.md).

## Install

Prerequisites: Node.js 22.19+, npm, Python 3, and OpenClaw 2026.6.11+.

```bash
git clone https://github.com/Olli0103/rightout.git
cd rightout
npm ci --ignore-scripts
./install.sh
```

The installer builds and validates the package, installs through OpenClaw's plugin CLI, inspects the live runtime, and rolls back a failed update. Follow [INSTALL.md](INSTALL.md) for SecretRefs, attestations, optional-tool policy, and approval routing. Installation and release testing never contact a real broker or use real PII.

## Validation

```bash
make test
make scan-only-dummy
make e2e-dummy
make installer-test
make release-check
```

The Python runner remains dummy-only. Report v4 and the complete removal state matrix are synthetic validation; live removal state currently stops at `submitted`.

## Scope and comparison

RightOut now has the core product shape used by Hermes Unbroker and commercial services—discovery, explicit removal submission, lifecycle semantics, human-task boundaries, and reappearance-aware reporting—but not their breadth or managed operations. It has one automated removal lane, no dashboard, no mailbox polling, no scheduler, no screenshot proof, no custom-removal team, and no family/enterprise administration.

The evidence-backed comparison with Incogni, Optery, DeleteMe, Kanary, and Hermes Unbroker is in [docs/feature-benchmark.md](docs/feature-benchmark.md). No commercial broker list, Hermes code, BADBOOL data, or third-party prose is copied into RightOut.
