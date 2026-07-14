# RightOut v0.8.1

RightOut 0.8.1 is an audit-remediation release for autonomous Brave discovery,
case-state safety, technical feature coverage, country handling, and release provenance.

- A scan report created under a finite campaign grant is now accepted by the
  durable case ledger. A real runtime regression starts a discover-only
  campaign, executes `rightout_live_scan`, records the case, and proves that the
  next campaign step terminates.
- Runtime and documentation now share one scan-catalog builder. The enforced
  surface is 56 Brave Web Search POST lanes: 30 people-search and 26
  controller/B2B lanes. Three reviewed controller portals remain `human_only`;
  they are not silently promoted into automation.
- Country is mandatory in live-scan profiles. Reports expose the selected
  localization and state that results cover only the public web-search index.
  Private broker inventory visibility, identity proof, absence proof, and
  real-world discovery effectiveness remain `needs_evidence`.
- Scan and removal profiles now share one ISO-country set. Nested current/prior
  addresses inherit the explicit top-level country rather than silently
  defaulting to US.
- Scan observations no longer overwrite protected removal states. A mixed
  batch records all safe observations while preserving brokers already in
  approval, submission, verification, partial-removal, or rejection workflows.
- Release automation now requires a GitHub-verified signed annotated tag and
  verifies the generated GitHub artifact attestation before publishing the
  release archive.
- The managed-service benchmark now separates repository-enforced facts,
  vendor-published claims, and independently measured evidence. Inventory size
  is not presented as an effectiveness proxy, and RightOut's own real-provider
  effectiveness remains `needs_evidence`.
- The live Hermes gate now compares the security-relevant Unbroker subtree
  directly with the pinned tree. Unrelated upstream commits no longer create a
  false release failure; any change inside the subtree still stops for review.
- Browser-webmail verification now uses one exact logged-in Gmail profile. It
  requires the intended recipient, an allowlisted `signed-by`/`mailed-by`
  domain, and one HTTPS confirmation control on an allowlisted broker domain;
  raw mail, PII, and link tokens never enter public tool output.
- Explicit static arithmetic remains host-computed, and an explicitly
  identified static text challenge can accept only its one short snapshot-bound value.
  Dynamic CAPTCHA, OTP, sliders, security questions, ID, account, payment,
  phone, fax, and mail gates remain human-only.
- The machine evidence now separates technical capability from operational
  availability. Every pinned capability is implemented or reached through an
  equivalent-and-stricter path, while provider permission and default live
  autonomy remain fail-closed.
- The public README removes the reference-product comparison and presents only
  independently verifiable RightOut coverage and limitations.

The historical v0.8.0 tag remains unsigned and is not rewritten. Version 0.8.1
can be published only from a newly signed, GitHub-verified annotated tag after
all source, package, security, and attestation gates pass.
