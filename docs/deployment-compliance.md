# Deployment compliance gate

RightOut implements technical privacy and approval controls. It is not a legal
certification and cannot make a deployment compliant by itself. Before enabling
any live tool, the operator must close every applicable item below or mark the
deployment `needs_evidence`.

## Authority and purpose

- Record whether the operator acts for themself, as an authorized agent, or as
  a controller/processor for another organization.
- Record the exact subject authority, jurisdictions, purposes, and expiry.
- Do not treat a RightOut consent payload or operator attestation as proof of
  legal capacity, residency, statutory eligibility, or power of attorney.
- Keep CAPTCHA, government identity verification, identity documents, legal
  exceptions, complaints, and disputed authority human-only.

## GDPR/EEA deployment record

- Identify controller, processor, and subprocessor roles.
- Record the lawful basis and transparency notice for each disclosure class.
- Maintain the applicable processing record and controller-processor terms.
- Review international transfers, adequacy, SCCs, and transfer-impact duties.
- Decide and document whether a DPIA and DPO involvement are required.
- Define breach response, data-subject escalation, and supervisory-authority
  complaint handling outside the plugin.

## CCPA/CPRA deployment record

- Establish California residency and the covered-business/controller scope.
- Keep signed authorized-agent evidence outside the model and plugin ledger
  where a business or government platform requires it.
- Treat California DROP as a separate residency-verified human workflow.
- Do not treat a controller email as DROP coverage or a universal deletion.

## Providers, retention, and isolation

- Record Brave, SMTP, IMAP, OpenClaw, and any secret backend in the provider and
  transfer inventory with the applicable contract and retention posture.
- For each form or publisher-browser route, retain the provider's actual current
  written automation authorization outside RightOut and bind its SHA-256 plus
  the exact reviewed terms-contract digest and expiry in
  `publisherAutomationPermissions`. Subject consent, a privacy right, or an
  operator attestation is not a publisher license. Publicly prohibited routes
  remain human-only by default; only a specific current written provider
  exception bound to the exact terms digest, allowed effect, and browser backend
  may activate that exact lane. Missing or mismatched permissions fail closed.
- Prefer a Brave Zero Data Retention agreement where the deployment requires it;
  otherwise disclose the documented standard-plan retention boundary.
- Define the local case-retention period and purge responsibility.
- Store every secret as a SecretRef, scrub plaintext residue, and run the
  OpenClaw secret and security audits after each configuration change.
- Record that OpenClaw materializes active SecretRefs into an in-memory snapshot
  at Gateway activation; approval limits RightOut's use, not materialization.
- Treat plugins as trusted in-process code. Separate mutually untrusted users by
  Gateway and operating-system identity.

## Required technical evidence

```bash
openclaw config validate
openclaw secrets audit --check
openclaw security audit --deep
openclaw plugins inspect rightout --runtime --json
openclaw plugins doctor
```

Archive the command versions and sanitized pass/fail results with the operator's
legal and provider review. Do not archive secrets, profile values, queries,
listing URLs, emails, controller responses, or identity documents.

## Deployment evidence

The software release can be verified entirely with synthetic fixtures. A live
deployment cannot be called operationally validated until an authorized operator
has completed the [canary protocol](authorized-canary.md). Until then, real-world
deliverability, controller handling, and removal effectiveness are
`needs_evidence`; this does not block publication of the software itself.
