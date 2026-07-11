# Release Checklist

Before publishing a release:

- Run `make test`.
- Run `make scan-only-dummy`.
- Run `make e2e-dummy`.
- Confirm no real PII appears in fixtures, reports, logs, or screenshots.
- Review `THIRD_PARTY_NOTICES.md`.
- Check every new broker entry for official URL, provenance, jurisdiction, lane, and license posture.
- Confirm GDPR/DSGVO, CCPA/CPRA, DROP, HIBP, provider-write, and human-task boundaries are still documented.
- Confirm the README still says the catalog is extensible and not complete.

