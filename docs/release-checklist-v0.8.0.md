# Release checklist: v0.8.0

- [x] Exact pinned Unbroker normalized contract/capability baseline and current subtree hash recorded.
- [x] All 22 broker IDs and 20-form / one-email / one-phone method/route/input contracts represented; generic fixtures tested and PeopleConnect staged separately.
- [x] Current primary provider terms reviewed for all 22 routes: 8 explicit prohibitions, 14 `needs_evidence`, zero public permissions.
- [x] Current written provider authorization, contract digest, review/expiry, and default-deny runtime gates implemented.
- [x] Brave POST live scan keeps query/results/result URLs transient and enforces current query limits.
- [x] Campaign scope binds profile, catalogs, provider terms, browser, transports, permission records, expiry, revocation, and budget.
- [x] Staged PeopleConnect/DOB, same-profile verification, strong record matching, intent-before-click, observed transition, and redacted semantic-state receipt tested.
- [x] Browser-only inbound mail is zero-I/O human handoff; authenticated Gmail IMAP remains autonomous.
- [x] Documentation distinguishes normalized contract coverage from exact playbook/capability parity, current autonomous executability, and managed-service gaps.
- [x] ClustrMaps/PeekYou route evidence, current unavailability, and independent rescue methods preserved without false success.
- [x] Rerun plugin/coverage, Python/installer, dummy E2E, dependency/security, source-refresh, package, stable/beta OpenClaw, and release-check gates on the source-complete tree.
- [x] Receive a fresh independent closing review with no open P0/P1 and resolve every actionable lower finding.
- [x] Date the changelog, close the candidate audit, verify the local archive/checksum/SBOM inputs and release-evidence workflow, and authorize annotated-tag CI from protected `main`.

Post-publication verification of the GitHub archive, checksum, SBOM, attestation,
and release evidence remains mandatory before the project goal may be marked
complete; it is not falsely claimed by this pre-tag checklist.
