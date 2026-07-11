# Privacy and data-protection posture

Review date: 2026-07-11. This document describes product behavior, not legal advice or certification.

## Data flow

| Stage | Data | Recipient | RightOut retention |
| --- | --- | --- | --- |
| Tool selection | opaque profile ID, broker IDs | model/OpenClaw transcript | no RightOut storage |
| Approval | action, broker count, field categories, provider, no-write scope | configured OpenClaw approval surface | no raw values |
| Secret materialization | full name, city, region, US country | OpenClaw Gateway/plugin-process memory | from plugin config load until reload/restart; no RightOut disk persistence |
| Search | full name and location in HTTPS POST body | Brave Search API | none by RightOut; Brave publishes up to 90-day standard query-log retention unless an applicable ZDR agreement exists |
| Verification | candidate URL request | selected official broker domain | none by RightOut |
| Result | state, reason code, opaque proof ref, disclosure categories, gaps | OpenClaw/tool transcript | no raw PII/URL/body/query/key |

RightOut sets guarded HTTP capture to false and sanitizes thrown network/provider errors. Brave's privacy notice, updated 2025-12-04, states that standard Search API query logs may be retained for up to 90 days and that Zero Data Retention is an enterprise option. Broker servers may independently process or log authorized requests. RightOut cannot override their terms, retention, or legal role.

## Data minimization

The only supported live profile fields are `fullName`, `city`, `region`, and fixed country `US`. Email, phone, street address, date of birth, relatives, identity documents, credentials, verification tokens, and listing URLs are rejected or absent. The public tool does not carry profile values.

## Authorization and purpose

The operator must have a lawful basis and subject authorization before provisioning a profile. Live readiness requires explicit operator-owned attestations listing every authorized opaque profile ID, accepted Brave terms, and every broker whose automated access is independently authorized. The normalized complete attestation snapshot is part of the single-use approval binding and is independently revalidated by the live library. These attestations are fail-closed gates, not legal proof supplied by RightOut. The native per-call approval covers only read-only people-search discovery for selected brokers. It does not cover deletion, objection, opt-out, email, form submission, identity proof, monitoring, or any other reuse.

## GDPR/DSGVO posture

The current live scanner is US-only and is not a GDPR erasure workflow. Where GDPR applies, the deployer remains responsible for controller/processor roles, lawful basis, transparency, data-processing terms, international transfers, retention, access/deletion rights, and records of processing. The generic Article 17 catalog reference is human-only and cannot be scanned or submitted by RightOut.

## CCPA/CPRA posture

RightOut does not determine California residency, consumer eligibility, authorized-agent status, verification requirements, or whether a broker is subject to a particular request. California DROP and Google Results About You entries are references only; the plugin cannot submit to them.

## SecretRef limitation

OpenClaw SecretRefs protect supported config persistence and keep values out of the tool schema, but they are not a process-isolation or call-lifetime boundary. OpenClaw materializes the resolved plugin config before registration, so the Gateway/plugin process may hold the private profile and key from config load until reload or restart. RightOut accesses those values only after a valid single-use approval binding and does not write or return them. A deployment where an agent can inspect the Gateway process, secret-provider files, environment, or same-privilege memory requires additional OS/container/user separation.

Readiness requires clean `openclaw secrets audit --check` and resolution of RightOut's plaintext-profile/key security findings.
