# RightOut v0.8.0 — superseded prerelease

Status: **superseded prerelease; do not treat this artifact as the current
stable release.** Corrected v0.8.1 source remains subject to protected-main
review and a new GitHub-verified signed tag.

The original v0.8.0 release body made claims that a later independent audit did
not support. The historical archive and tag remain available as evidence, but
the following claims are withdrawn:

- The autonomous discovery campaign did not durably record campaign-gated scan
  reports, so the advertised finite global drain could loop instead of
  completing.
- The 59-lane statement included three controller portals that the catalog
  marks `human_only`. The corrected shared runtime contract proves 56
  code-enforced Brave public-index lanes: 30 people-search and 26
  controller/B2B lanes.
- Country localization was a technical Brave query setting, not proof of
  practical broker discovery, private-inventory visibility, identity, or
  absence.
- Mixed scan batches could abort when an existing broker was already in a
  protected removal state.
- The v0.8.0 annotated tag is not GitHub-verified as signed. Artifact
  attestation does not retroactively sign that tag.

The v0.8.1 remediation adds campaign/runtime regressions, an exhaustive
56-lane execution and fourteen-batch drain proof, mandatory ISO country
handling without implicit US defaults, protected-state audit history,
machine-readable coverage evidence, a subtree-stable upstream gate, and
pre-publication signed-tag plus attestation verification.

Until a corrected version is published, users should build only from reviewed
source and should not rely on v0.8.0's autonomous-campaign, 59-lane, or release
provenance claims.
