# Independent closing audit: RightOut v0.6.0

Audit date: 2026-07-12. Released tag: `v0.6.0` at
`e5a62d7c133449f3f37d5fc9f2dd5faa9e88c273`.

## Verdict

**PASS and GO: RightOut v0.6.0 is released and its remote evidence verifies.**

An independent read-only reviewer reproduced the final schema-v6 snapshot,
official-source semantics, and material local gates. PR CI subsequently passed
the declared OS/runtime matrix and both OpenClaw versions. PR #5 was merged to
protected `main`; main CI, annotated-tag CI, publication, downloaded assets,
checksums, and signed provenance all passed.

## Severity summary

- P0: 0;
- P1: 0;
- P2: 0;
- P3: 0;
- release-scoped `needs_evidence`: none.

## Remote release evidence

- PR #5 squash-merged as
  `e5a62d7c133449f3f37d5fc9f2dd5faa9e88c273`;
- protected-main CI run `29206091369`: success;
- annotated `v0.6.0` tag and release run `29206248400`: success, including the
  full matrix, installer, OpenClaw stable/beta, clean archive build,
  attestation, and publication;
- immutable release:
  `https://github.com/Olli0103/rightout/releases/tag/v0.6.0`;
- downloaded archive:
  `olli0103-openclaw-rightout-0.6.0.tgz`, SHA-256
  `cd65f557918f0f320a30917104001f3ae9e527aff1428742b9e24cad88f9a505`;
- downloaded `RELEASE-SHA256SUMS` verifies the archive; downloaded SBOM and
  catalog provenance are byte-identical to the tagged repository copies;
- `gh attestation verify` passes with repository, signer workflow,
  `refs/tags/v0.6.0`, source commit, and hosted-runner constraints.

## Independently reproduced local evidence

- TypeScript typecheck;
- 125/125 Node tests;
- 50/50 Python tests including installer mutation/rollback and workflow-parser adversarial cases;
- schema-v6 catalog validator with 56 entries and policy-matched channel
  evidence for executable controller emails;
- provenance digest with 61 primary-source fact records, catalog hash
  `4a3b373c7420cb4060d3ed91cc22cbf1f16c1fd010aa98f6063c01a210a49185`,
  and normalized source-fact hash
  `2d51eface0d87ab268f9484929c0bc995361325228d4fdd891a6867e34de9f42`;
- release checker across 116 files;
- production dependency audit with zero vulnerabilities;
- clean `git diff --check`.

The independent review found no open local P0/P1/P2/P3. It verified the final
Lead411 EU and Amplemarket US channels against their official policies. It did
not execute the cached OpenClaw beta package, mutate GitHub state, or perform
any live scan, email, form submission, broker write, or real-PII action.

After independent closeout, PR CI separately passed packaged runtime
inspection and plugin doctor on OpenClaw 2026.6.11 and 2026.7.1-beta.5, the
Ubuntu/macOS Node/Python matrix, and the isolated installer suite.

## Product boundary

The candidate has 21 Brave-index discovery lanes, 56 catalog targets, 23
reviewed EU processes, and 28 executable provider-write targets: 27 email and
one browser-form initiation. Human-only CAPTCHA, identity documents, DROP,
portal/device context, and legal-judgment steps remain explicit handoffs.

The full 18-area rating and its evidence boundary are recorded in
`docs/audit-v0.6.0-scorecard.md`.

Real-world broker response and removal effectiveness remain deployment
evidence outside this software-release verdict because the governing audit
prohibited real PII, live scans, emails, form submissions, and provider writes.
