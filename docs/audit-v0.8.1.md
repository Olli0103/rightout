# Closing audit: RightOut v0.8.1 source candidate

Audit date: 2026-07-13. Status: F-1 through F-5 are closed in source and
regression evidence. F-6's preventive source gate and audited public v0.8.0
correction are also closed. Version 0.8.1 remains unpublished pending the
protected-main process and a separately authorized GitHub-verifiable signed
tag; that remaining publication action is not presented as completed evidence.

## Finding closure

| Finding | Source verdict | Evidence |
| --- | --- | --- |
| F-1 campaign scan persistence | closed | The case ledger accepts `campaign_gated_live_scan`; a real plugin-runtime E2E starts a finite discover campaign, executes `rightout_live_scan`, records the case, and reaches `done_for_now`. |
| F-2 scan-lane claim | closed | The audit's count of 21 covered only static core scan flags and missed the runtime overlay. The old overlay produced 59 but incorrectly promoted three `human_only` portal lanes. The shared builder now preserves every gate and proves exactly 56 executable lanes: 30 people-search plus 26 controller/B2B. Exhaustive tests run all 56 through `runLiveScan` and drain one exact campaign in fourteen bounded four-lane batches. |
| F-3 country/discovery meaning | closed as a claim defect | Reports and docs state public-index-only scope, selected localization, no private-inventory visibility, no identity/absence proof, and `discovery_effectiveness: needs_evidence`. Synthetic DE, JP, and BR negatives remain `inconclusive`. No real-world effectiveness claim is made. |
| F-4 implicit US default | closed | Profile `country` is mandatory; supported targets are localized and all other valid ISO countries use an explicit worldwide target. Missing country fails before provider I/O. |
| F-5 mixed-batch state loss | closed | Search observations preserve all in-flight and reviewed removal states while still recording the new observation and every independent safe broker in the batch. |
| F-6 release hygiene | closed for source prevention and v0.8.0 public correction | Release CI requires an annotated tag whose GitHub REST verification is true, verifies the generated GitHub artifact attestation before publication, and rejects final release notes carrying prerelease language. Authorized GitHub write plus independent readback set v0.8.0 to `prerelease:true` and made its public body exactly match `release-correction-v0.8.0.md`. The historical tag remains immutable and unsigned; the corrected body says so explicitly. |

## Current source evidence

- Plugin suite: 295 tests pass, including campaign/runtime, all-lane execution,
  protected-state, missing-country, and non-US semantics regressions.
- Coverage thresholds pass at 90.32% lines, 76.69% branches, and 91.30%
  functions.
- Python core/workflow tests: 44/44 pass. Network-enabled installer mutation,
  rollback, containment, and lock tests: 6/6 pass.
- Offline scan-only and state-machine dummy E2Es pass with no live network or
  provider write.
- Production dependency tree is valid; current npm audit reports zero
  vulnerabilities.
- Official npm dist-tags remain OpenClaw stable `2026.6.11` and beta
  `2026.7.1-beta.6`; the candidate passes the plugin/build check under both and
  isolated runtime installation under the beta.
- The machine coverage gate reports 65 combined entries, 56 code-enforced scan
  lanes, 30 people-search lanes, 26 controller/B2B lanes, and three preserved
  human-only controller portals.
- A fresh Hermes main check observed commit
  `f6d1fd511ca8173f634fd42a582e43c3d6181762`; the Unbroker subtree remains
  exactly the pinned tree `f8145c8318a398f0d12dbbd27bb88175ce19519b`.
- Current managed-service primary claims were rechecked and separated from
  runtime evidence. The benchmark records relevant peer-reviewed 2025 market
  measurements and their limitations without projecting them onto RightOut.
- The closing loop found and removed an upstream-gate flake: live verification
  is now pinned to the exact Unbroker subtree, not unrelated Hermes `main`
  movement. A changed subtree remains fail-closed for manual review.
- A repository-wide US-default search found the same anti-pattern in nested
  removal addresses. Scan and removal now share one ISO set, and nested values
  inherit only the explicit top-level country.

## Explicit non-claims

- Public-index discovery does not establish private broker inventory coverage,
  identity, absence, or practical discovery effectiveness. Those remain
  `needs_evidence`.
- Complete 22/22 normalized Unbroker contract coverage is not exact
  provider-playbook choreography or default autonomous form execution.
- Tests use synthetic identities and mocks and do not prove real-provider
  removal effectiveness.
- The source workflow can enforce future release provenance; it cannot
  retroactively sign the immutable historical v0.8.0 tag.

## Remaining external release action

The authorized v0.8.0 release correction is complete and its public readback
matches the reviewed repository document. The v0.8.1 candidate must still pass
the normal protected-main process. Creating its newly signed,
GitHub-verifiable annotated tag requires separate explicit authorization. The
pre-tag checklist does not claim that v0.8.1 publication happened. The tag
workflow must then produce and verify the archive, checksum, SBOM, provenance
attestation, and release evidence.
