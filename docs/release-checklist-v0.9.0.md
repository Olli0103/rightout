# Release checklist: v0.9.0

- [x] A1/A2/A4 durable worker, trusted-session scheduling/handoff, lease,
  session/run/call/tool/parameter-bound result receipt, watchdog/startup
  recovery failure gate, checkpoint, backoff, revoke/resume, conclusive-result
  policy, and fixed-command grammar are implemented and runtime-tested.
- [x] A3 release-attested recipes, strict Ed25519 external trust, expiry, and
  drift quarantine are implemented and package-bound.
- [x] M1 password/OAuth2 transport compatibility, expiry, mutation, protocol
  separation, and redaction are tested.
- [x] M2 authenticated exact-thread controller replies remain encrypted
  candidates and every outcome retains a separate human approval.
- [x] E1 evidence encryption, addressing, retention, tamper, purge/rotation,
  metadata-only reads, creation-anchored strict retention, idle expiry, and
  approved managed private export fail-closed purge are tested.
- [x] C1 custom-target intake is encrypted/opaque and cannot become a provider
  action from raw URL input or unsigned/unpermitted recipes.
- [x] L1 effectiveness metrics expose denominators and default to
  `needs_evidence` absent consistent authorized canaries.
- [x] U1 team roles isolate sessions/profiles and cannot reuse foreign
  campaign/worker authority; full-operator bypass is a critical audit finding.
- [x] U2 dashboard exports are private static artifacts with strict CSP, no
  script/remote asset/network service, and approval-bound exact team scope.
- [x] Legacy technical parity, privacy, approval, provider-terms, uncertainty,
  retention, purge, and provenance tests remain green.
- [x] Version, manifest, lock/shrinkwrap, SBOM, compiled distribution, README,
  architecture, security, privacy, install, conformance, canary, benchmark,
  release notes, and parity matrix are synchronized.
- [x] Run every source/package/coverage/Python/installer/dummy/security/workflow
  release gate on the source-complete tree and inspect the packed archive.
- [ ] Run the requested autonomous independent source review, fix every
  evidenced P0/P1/P2/P3 finding, and repeat review on the post-fix tree.
- [ ] Write the final versioned audit only after the last fix, rerun all release
  gates, and confirm a clean worktree plus publishable signed-tag state.

Publication remains a separate external signed-tag CI action. This checklist
does not claim the `v0.9.0` tag, GitHub release, archive attestation, installed
deployment, or authorized real-person canary already exists.
