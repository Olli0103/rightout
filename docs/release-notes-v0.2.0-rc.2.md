# RightOut v0.2.0-rc.2

This safety prerelease supersedes `v0.2.0-rc.1` while stable-release evidence is completed.

## Safety corrections

- disables automated Spokeo scanning because Spokeo's published consumer terms prohibit automated queries, scraping, crawling, data mining, and automatic devices;
- keeps only conditional TruePeopleSearch live scanning and requires an exact operator broker-access attestation because public automated-access permission remains `needs_evidence`;
- requires exact-profile operator attestations plus accepted Brave Search API terms before approval and network access;
- discloses Brave's published standard-plan query-log maximum of 90 days in the native approval, unless the operator has an applicable Zero Data Retention agreement;
- binds the normalized complete attestation snapshot to the single-use approval and independently rechecks the actual object inside the live-scan library boundary.

## Release hardening

- atomic cross-process installer lock with fail-closed concurrent-run behavior and cleanup tests;
- GitHub Actions dependencies pinned to full commit SHAs;
- catalog and release gates prevent a published automation prohibition from being live-enabled;
- provider access and retention review added from official sources.

## Scope

- read-only discovery only;
- no removal submission, email, form, CAPTCHA, verification link, scheduler, or provider write;
- no real PII, production key, or live subject scan used for release testing;
- stable release remains `NO-GO` until conditional broker authority and operational behavior are evidenced under an explicitly authorized deployment.
