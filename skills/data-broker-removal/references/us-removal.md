# US and California data-broker removal

Last reviewed: 2026-07-12. This is operational product guidance, not legal advice.

## Process boundary

RightOut supports ten executable US targets: BeenVerified email, the Intelius/PeopleConnect browser-form initiation, and eight controller-email lanes for Amplemarket, SalesIntel, LeadIQ, Wiza, SignalHire, Hunter, Seamless.AI, and ContactOut.

The eight data-broker emails use only full name, a subject-controlled contact email, region, and country. They are limited to an attested California profile and use each company's current official privacy-policy contact. A successful SMTP handoff means only `submitted`; it is not controller receipt, deletion, suppression, or proof that other identifiers were located.

## California DROP

[California DROP](https://privacy.ca.gov/drop/) is a separate government platform. RightOut keeps login, eligibility, identity/profile verification, filing, and status inspection human-only. After human attestation it records the filing phase, ordinary 90-day deadline, 45-day checkpoints, and literal portal status. Even `deleted` remains `deletion_confirmed: false`; an email request to one controller does not prove DROP coverage, and DROP does not authorize RightOut to upload identity documents.

GPC may be recorded only as a human-verified browser preference. RightOut does
not enable it, contact a site, or claim receipt/compliance. It is not deletion.

## Follow-up

- Track the catalog's 45-day operational recheck window; it is not a legal deadline calculator.
- Review any controller response personally, then use the separately approved `rightout_record_controller_outcome` tool to record only the outcome category.
- Never send an attachment or identity document automatically. SignalHire and other controllers may request identity evidence; minimize it or route it to human/legal review.
- Keep `controller_response_only` as the confirmation scope. Other identifiers, sources, affiliates, DROP participation, and future reappearance remain coverage gaps.
- Use `rightout_reconcile_submission` before any retry when the SMTP effect was ambiguous.
