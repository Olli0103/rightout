# Release checklist: v0.10.0

- [x] G1-G7 market readiness, review dates, setup/doctor visibility,
  approval/runtime policy binding, and stale-core release blocking are
  implemented and negatively tested.
- [x] G8 authorized-canary schema v2 preserves raw-PII exclusion, exact
  authorization/deployment digests, identity denominators, scoped outcomes,
  coverage, timing, and `needs_evidence` defaults.
- [x] G9 UK execution is isolated to `cognism_uk` with an ICO-bound request,
  identity, eligibility, template, and response-window contract.
- [x] G10 DROP and GPC remain human/preference workflows and never become
  government-login automation, browser automation, site-compliance proof, or
  direct deletion proof.
- [x] All 22 parity routes are market-bound before profile access or provider
  I/O, and all earlier provider-permission, approval, uncertainty, recipe,
  retention, purge, evidence, and durable-worker gates remain green.
- [x] The adversarial source audit has no open P0, P1, P2, or P3 finding after
  closing policy mutability, DROP snapshot binding, stale observation approval,
  and canary timestamp findings.
- [x] Current EDPB, ICO, California DROP, California GPC, Cognism, and cited
  market-product facts were checked against primary publisher sources.
- [x] Version, manifest, package lock/shrinkwrap, skill version, production
  SBOM, compiled distribution, README, install guide, operator docs, changelog,
  release notes, parity matrix, audit, and checklist are synchronized.
- [x] Full Node source/package/coverage, Python, installer, dummy E2E,
  dependency, catalog-provenance, technical-parity, workflow, and archive gates
  pass on the frozen release tree.
- [x] GitHub workflow definitions require the Node/Python matrix, installer,
  OpenClaw compatibility, and exact `main` ancestry gates before publication.
- [x] The release workflow definition requires a GitHub-verified signed
  annotated tag plus checksums, SBOM, release evidence, catalog provenance,
  upstream evidence, archive, and attestation assets.

The checklist distinguishes source readiness from publication evidence. The PR,
merged commit, signed tag, workflow run, and published assets are verified after
this source checklist is frozen. Real provider authorization,
installed-deployment inspection, authorized canaries, and real-world
effectiveness remain separate and may stay `needs_evidence`.
