# Release checklist: v0.8.1

- [x] Campaign-authorized live-scan reports are accepted by the case ledger and covered by a real runtime E2E.
- [x] Shared runtime/documentation coverage proves 56 code-enforced Brave lanes and preserves three `human_only` portal gates.
- [x] Country is mandatory and public-index/private-inventory/effectiveness limits are explicit in runtime reports and operator docs.
- [x] Mixed scan batches preserve all protected case workflow states and continue recording independent safe brokers.
- [x] Release workflow requires a GitHub-verified signed annotated tag and verifies artifact attestations before publication.
- [x] Browser-webmail verification binds one exact logged-in Gmail profile, recipient, authenticated sender domain, and allowlisted confirmation domain without returning raw mail or link values.
- [x] Static arithmetic and explicitly identified static text challenges have bounded paths; dynamic CAPTCHA, OTP, slider, security-question, ID, account, payment, phone, fax, and mail gates remain closed.
- [x] Machine evidence and a dedicated gate prove every pinned technical capability as `implemented` or `equivalent_or_stronger`; provider permission and default operational autonomy remain separate and closed.
- [x] Public README contains no reference-product comparison and keeps software coverage separate from provider permission and real-world effectiveness.
- [x] Rerun plugin, coverage, Python, installer, dummy E2E, dependency/security, workflow, package, and all non-publication release-check gates on the source-complete tree.
- [x] Complete an adversarial closing source-diff review with no open source P0/P1/P2/P3 findings.
- [x] Publish `release-correction-v0.8.0.md` as the v0.8.0 body with `prerelease:true` and verify the public readback exactly.

The historical unsigned v0.8.0 tag is immutable evidence and is not rewritten.
Publication of v0.8.1 remains an external signed-tag CI action; this checklist
must be complete before that action and does not claim that a GitHub release or
attestation already exists. Creating the new GitHub-verifiable signed annotated
v0.8.1 tag requires separate explicit authorization after protected-main
review. Post-publication archive, checksum, SBOM,
attestation, and release-evidence verification remains mandatory.
