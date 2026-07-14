# RightOut v0.9.0

RightOut 0.9.0 turns the finite campaign engine into a closed-loop,
self-hosted privacy operator while preserving every v0.8.1 approval,
provider-terms, uncertainty, encryption, and evidence boundary.

- Durable workers are encrypted, restart-safe, campaign- and session-bound,
  single-lease, backoff-aware, revocable, and able to schedule only their exact
  current trusted OpenClaw session. Exact result receipts bind session, run,
  call ID, tool, normalized parameters, lease, and execution digest. Lease
  watchdogs recover on startup; failed recovery becomes a human gate.
  Unsupported hosts receive an explicit PII-free Cron handoff on enable.
- A release-attested declarative 22-route recipe pack now binds source and
  compiled digests. External packs require an allowlisted Ed25519 key and valid
  signature; expiry, domain drift, semantic drift, and sensitive controls stop
  before provider writes.
- Existing password mail remains compatible. Pinned SMTP providers and Gmail
  IMAP additionally accept mutually exclusive short-lived OAuth2 bearer
  SecretRefs with protocol-separated transport bindings. Microsoft 365 remains
  unsupported because its endpoints, tenant flow, and authentication semantics
  are not implemented by this contract.
- Authenticated controller replies must match recipient, receiver-added aligned
  DKIM, official sender domain, post-submission time, and the exact outgoing
  Message-ID thread. Literal text produces only an encrypted candidate; every
  outcome still needs separate human approval.
- Optional evidence snapshots are encrypted, content-addressed, bounded,
  retention-aware, tamper-checked, and metadata-only by default. Redacted local
  export requires a separate approval and contained private path. Managed
  exports have encrypted lifecycle tracking, creation-anchored stricter
  retention, idle expiry scheduling, and fail-closed purge.
- Custom-target intake is an out-of-band encrypted quarantine boundary. Public
  tools see only opaque handles. A signed recipe and exact current permission
  can establish readiness, but v0.9.0 intentionally exposes no custom-target
  provider execution tool.
- Effectiveness reports separate discovery, identity confidence, submission,
  provider confirmation, reappearance, uncertainty, and human handoff with
  explicit denominators. Operational effectiveness remains `needs_evidence`
  without consistent authorized canary facts.
- Session-bound owner, manager, and viewer roles isolate exact configured
  profile scopes. Managers/viewers cannot reuse campaign or worker authority;
  team mode critically requires all RightOut tools to be denied on full-operator
  direct invoke.
- Owner/manager sessions may separately approve a static local HTML or JSON
  dashboard. It contains only sanitized authorized state, uses strict CSP and
  private contained files, and starts no service or network request.

The manifest now declares 50 tools. The pinned Unbroker technical baseline
remains exact at 22/22 normalized contracts, while current public provider
evidence still authorizes zero live form routes. Real-provider effectiveness,
private inventory visibility, and an authorized deployment canary remain
separate operational evidence, not software-release claims.

The release archive must come from a GitHub-verified signed annotated `v0.9.0`
tag and pass checksum, SBOM, package-content, workflow-attestation, clean-install,
security, and post-fix independent-review gates.
