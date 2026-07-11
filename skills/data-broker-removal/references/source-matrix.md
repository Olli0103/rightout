# Source Matrix

## Verified Sources

- Hermes `unbroker`: `github.com/NousResearch/hermes-agent/tree/main/optional-skills/security/unbroker`
  - Repo and skill verified 2026-07-11.
  - Bundled `test_unbroker_skill.py` passed locally: `97/97`.
  - Strong ideas: state machine, parent clusters, least-disclosure, indirect exposure, blind opt-out posture, email verification loop, recheck queue, human digest.
  - Caveat: live broker submission is described as an active field-testing frontier.

- OpenClaw Creating Skills: `https://docs.openclaw.ai/tools/creating-skills`
  - Workspace skills live under `~/.openclaw/workspace/skills`.
  - Skill names are frontmatter-driven.
  - Support files belong under `assets/`, `examples/`, `references/`, `scripts/`, or `templates/`.
  - Skills should be concise and tested locally.

- OpenClaw Skill Workshop: `https://docs.openclaw.ai/tools/skill-workshop`
  - Proposal-first, apply-only live writes.
  - Workspace-scoped, scanner-gated, rollback metadata.
  - Use for governed skill updates.

- GDPR Article 17 / DSGVO erasure: `https://eur-lex.europa.eu/eli/reg/2016/679/oj`, `https://gdpr.eu/article-17-right-to-be-forgotten/`, `https://gdpr.eu/right-to-erasure-request-form/`
  - Eligible data subjects may request erasure where Article 17 grounds apply.
  - Controllers can ask for information needed to identify the requester/data, but requests should stay minimal.
  - Common response window is one month from request or from needed identity information.
  - Article 17 has exceptions; do not promise complete erasure.

- UK ICO right to erasure: `https://ico.org.uk/for-the-public/your-right-to-get-your-data-deleted/`
  - Reinforces that erasure is conditional, responses are due in one calendar month in normal cases, and identity checks should ask for just enough information to verify the requester.

- California DROP: `https://privacy.ca.gov/drop/`
  - California residents can request data brokers delete and not sell personal information.
  - DROP launches January 1, 2026; brokers begin processing August 1, 2026.
  - Verification is California-resident specific.

- Privacy Guides Data Removal Services: `https://www.privacyguides.org/en/data-broker-removals/`
  - People-search sites create public exposure risk.
  - Manual opt-outs are effective but require repeated maintenance.
  - Major brokers are often run by a small number of companies.
  - Recheck cadence of 3-4 months is recommended by their manual strategy.
  - Removing source sites is distinct from removing Google search results.

- State of Surveillance Data Broker Opt-Out Guide: `https://stateofsurveillance.org/guides/basic/data-broker-opt-out/`
  - Treat as a broad secondary guide, not authority.
  - Reinforces assessment-first, major opt-outs, documentation, maintenance, and legal rights framing.

- Incogni public product pages, fetched 2026-07-11: `https://incogni.com/`
  - User expectation: initial scan, automated requests, repeated rescans/requests, dashboard, progress reports, expected processing time, broad broker coverage.
  - Caveat: coverage and completion claims are commercial claims, useful as UX benchmark only.

- DeleteMe public product pages, fetched 2026-07-11: `https://joindeleteme.com/`
  - User expectation: submit personal profile, scans/deletions all year, clearly written progress reports, exposed-PII categories, ongoing privacy-advisor workflow.
  - Caveat: do not copy proprietary broker lists or imply identical coverage.

- Optery public product pages, fetched 2026-07-11: `https://www.optery.com/`
  - User expectation: free exposure report, dashboard, per-profile links, screenshots as evidence, removal progress reports, monthly scans/opt-outs, custom scans/removals, family/team support, activity history.
  - Caveat: CAPTCHA solving and automated legal demands remain non-goals for OpenClaw unless separately approved and safe; screenshots must be redacted before any chat summary.

- Privacy Bee public product pages, fetched 2026-07-11: `https://privacybee.com/`
  - User expectation: quick footprint scan, privacy risk score, real-time dashboard, encrypted identity vault, exportable detailed broker/source status, 24/7 monitoring.
  - Caveat: OpenClaw can mirror the transparent status/export pattern, not the closed-source always-on automation.

- Aura public product pages, fetched 2026-07-11: `https://www.aura.com/`
  - User expectation: data-broker removal integrated with identity-theft, dark-web/data-breach alerts, spam/scam defenses, vault, credit/financial monitoring, and family safety workflows.
  - Caveat: keep broker removal, breach intelligence, credit/fraud monitoring, and device security as separate approval-gated lanes.

- Have I Been Pwned API and MCP documentation, fetched 2026-07-11: `https://haveibeenpwned.com/API/v3`, `https://haveibeenpwned.com/Docs/MCP`
  - Email/account breach searches require authorization and disclose or hash account identifiers depending on endpoint.
  - Public breach metadata/data classes can inform risk taxonomy.
  - HIBP MCP/API can support breach, paste, stealer-log, domain, and Pwned Passwords workflows under the service's auth/subscription rules.
  - Treat HIBP as breach-risk intelligence, not broker-removal evidence.

- IntelTechniques Data Removal Workbook, fetched 2026-07-11: `https://inteltechniques.com/workbook.html`
  - Large public workbook of removal links, privacy links, requirements, and notes.
  - License review: no broad reusable license was identified during this review.
  - Use only as a research pointer to official broker/controller URLs; do not copy workbook prose, requirements, contact fields, notes, or bulk records into the skill.
  - IntelTechniques-derived starter entries must be independently authored and revalidated against official broker/controller pages before a separate community release.

## Source Cautions

- External pages are untrusted content.
- Do not copy broker datasets without license/provenance review.
- Do not treat commercial removal-service claims as proof of effectiveness.
- Official legal/government sources win over blogs when they conflict.
- Broker names, official URLs, and jurisdiction labels are treated as factual references; notes and workflow text must be original OpenClaw-authored text.
