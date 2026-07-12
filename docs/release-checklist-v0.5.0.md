# Release checklist: v0.5.0

- [x] Catalog schema v4 validates with 31 official-source entries.
- [x] Adsquare and emetriq recipient, minimum fields, jurisdiction, request kind, and controller-response semantics are catalog-locked.
- [x] EDAA, emetriq opt-out, Criteo, and Zeotap are classified without treating preferences as erasure.
- [x] Python skill and Node plugin test suites pass with no real network or PII.
- [x] Typecheck, build, release checker, package audit, and skill validation pass.
- [x] OpenClaw config schema, contracts, optional/replay-safe metadata, runtime inspection, and security audit conform.
- [x] SBOM and shrinkwrap match the v0.5.0 production dependency graph.
- [x] Packed tarball installs and passes the isolated smoke test.
- [x] Secret, path, placeholder, and dirty-artifact scans pass.
- [x] Release audit has no open P0, P1, or P2 finding.
- [ ] Pull request checks pass and the reviewed change is merged to protected `main`.
- [ ] Annotated `v0.5.0` tag points to the merged commit and tag CI passes.
- [ ] GitHub release artifact checksum matches the committed `SHA256SUMS`.
