# RightOut

RightOut is an approval-gated OpenClaw plugin and skill for read-only people-search discovery with privacy-safe reports. Version: `0.2.0-rc.2`.

It is conditionally live-scan capable for the US catalog entry `truepeoplesearch` only when the operator has independently verified and attested the exact profile ID, Brave terms acceptance, and broker-specific automated-access authority. Automated Spokeo scanning is disabled because its published terms prohibit automated queries, scraping, and crawling. RightOut does **not** submit removals, send email, fill forms, solve CAPTCHAs, schedule monitoring, or write to providers.

## Security boundary

The optional `rightout_live_scan` tool accepts only:

- an opaque operator-configured `profileId`;
- one or two supported catalog broker IDs.

The private subject profile and Brave Search key live in OpenClaw SecretRef-backed plugin config, not chat or tool arguments. Before offering approval, the plugin also requires operator-owned attestations for subject authorization, accepted Brave terms, and every selected broker. After the model selects the tool, a native `before_tool_call` hook requires `allow-once` or `deny`; denial, timeout, cancellation, missing attestations, hook failure, or no approval route fails closed. `allow-always` is not offered.

The scan sends full name and US location to Brave Search in a POST body. Brave's published privacy notice states that standard-plan query logs may be retained for up to 90 days; Zero Data Retention is an enterprise option. RightOut then fetches only operator-authorized, query-free HTTPS candidate URLs whose host and profile-path shape match the catalog policy through OpenClaw's SSRF-guarded runtime. A `found` result requires one structured JSON-LD `Person` record containing the exact normalized full name and matching city/region. Loose page text, reflected query pages, and search-index absence are always `inconclusive`, never proof of presence or absence.

Reports contain per-scan HMAC-derived opaque proof references, broker states, disclosure categories, and coverage gaps. They exclude raw PII, API keys, queries, candidate URLs, and raw responses. RightOut performs zero submissions, emails, local PII writes, or provider writes.

See [approval boundary](docs/approval-boundary.md), [privacy posture](docs/privacy-posture.md), and [security policy](SECURITY.md).

## Install

Prerequisites: Node.js 22.19+, npm, Python 3, and OpenClaw 2026.6.11+.

```bash
git clone https://github.com/Olli0103/rightout.git
cd rightout
npm ci --ignore-scripts
./install.sh
```

The installer validates the source, creates a minimal npm archive with compiled JavaScript, installs it through the official OpenClaw plugin installer, loads the runtime, verifies the live tool and approval hook, and runs `openclaw plugins doctor`.

Live readiness additionally requires operator-created SecretRefs, optional-tool allowlisting, an approval route, and clean secret/security audits. Follow [INSTALL.md](INSTALL.md); never paste a real profile into chat or a repository file.

## Offline validation runner

The bundled Python runner remains deliberately dummy-only. It cannot read real subject files or invoke the live plugin.

```bash
make test
make scan-only-dummy
make e2e-dummy
```

It exercises report v3, catalog policy, filesystem hardening, and the synthetic removal-state matrix. All synthetic results are labeled `fixture_only`; catalog lanes remain `not_checked` in dummy output.

## Product scope

RightOut currently provides a narrow live discovery capability and a broader reporting/state model. It is not feature-equivalent to Incogni, DeleteMe, Optery, Privacy Bee, or Aura: autonomous removals, recurring monitoring, dashboards, screenshots, custom-removal teams, family plans, Google cleanup, identity vaults, and dark-web/credit protection are not implemented. The source-backed comparison is in [docs/feature-benchmark.md](docs/feature-benchmark.md).

## Catalog and evidence policy

Every catalog entry must use independently authored notes plus official URLs, domains, jurisdiction, lane, minimum field categories, prerequisites, freshness, and structured provenance. Do not copy commercial broker lists, Privacy Guides, IntelTechniques, BADBOOL, screenshots, or proprietary reports.

The exact independent v0.1.0 audit artifact was not found in the repository, releases, issues, pull requests, release assets, or supplied attachments. Its exact wording and IDs remain `needs_evidence`; [the current audit](docs/audit-2026-07-11.md) preserves only evidenced baseline facts.
