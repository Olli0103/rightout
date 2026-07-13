# Install and enable RightOut

## 1. Prerequisites and verified install

Use OpenClaw `2026.6.11+`, Node.js `22.19+`, Python `3.11+`, GitHub CLI, and a
SHA-256 utility. Install the versioned, attested release archive rather than moving
`main`:

```bash
VERSION=0.8.1
mkdir "rightout-${VERSION}" && cd "rightout-${VERSION}"
gh release download "v${VERSION}" --repo Olli0103/rightout
shasum -a 256 -c RELEASE-SHA256SUMS
gh attestation verify "olli0103-openclaw-rightout-${VERSION}.tgz" \
  --repo Olli0103/rightout \
  --signer-workflow Olli0103/rightout/.github/workflows/release.yml \
  --source-ref "refs/tags/v${VERSION}" \
  --deny-self-hosted-runners
openclaw plugins install "./olli0103-openclaw-rightout-${VERSION}.tgz"
openclaw plugins enable rightout
openclaw plugins inspect rightout --runtime --json
openclaw plugins doctor
```

Use `sha256sum -c RELEASE-SHA256SUMS` on Linux. Inspect
`RELEASE-EVIDENCE.json`, `SBOM.spdx.json`, and `catalog-provenance.json` before
activation. A managed Gateway normally reloads the recorded install; restart an
unmanaged Gateway before live use. For source development, clone the repository, run
`npm ci --ignore-scripts`, and use `./install.sh`; `--force` updates an existing
registration and `--link` is development-only. The source installer stages the
packed archive in an isolated OpenClaw home, verifies the complete manifest/runtime tool set plus
the approval hook and plugin doctor, and only then mutates the target with
rollback and serialization.

## 2. Create SecretRefs out of band

Never ask an agent to create or display a real subject profile. A full logical profile may contain:

```json
{
  "fullName": "Avery Example",
  "alsoKnownAs": ["A. Example"],
  "city": "Exampleville",
  "region": "CA",
  "country": "US",
  "priorLocations": [{"city":"Oldtown","region":"WA","country":"US"}],
  "contactEmail": "avery@example.invalid",
  "emails": ["avery.old@example.invalid"],
  "phones": ["+1 202 555 0100"],
  "jurisdictions": ["US", "US-CA"],
  "consent": {
    "authorized": true,
    "recordedAt": "2026-07-12T08:00:00.000Z",
    "validUntil": "2026-10-10T08:00:00.000Z",
    "scope": ["scan", "broker_removal"],
    "method": "self"
  }
}
```

For an EU/EEA controller lane, use the applicable ISO country in both `country` and `jurisdictions`, include `EU` or `EEA`, and keep the same recorded `broker_removal` consent. The currently supported lanes require contact email and country; Lead411, 6sense, Cognism, and Lusha additionally require full name:

```json
{"fullName":"Avery Example","city":"Berlin","region":"BE","country":"DE","contactEmail":"avery@example.invalid","jurisdictions":["DE","EU","EEA"],"consent":{"authorized":true,"recordedAt":"2026-07-12T08:00:00.000Z","validUntil":"2026-10-10T08:00:00.000Z","scope":["broker_removal"],"method":"self"}}
```

Do not add extra identifiers unless a later human follow-up is proportionate and independently authorized. Never put either profile into chat or tool parameters.

`validUntil` is mandatory, must be later than `recordedAt`, must still be in the future when the action executes, and may be at most 365 days after `recordedAt`. Shorter purpose-specific periods are preferable. Revocation is performed out of band by disabling/removing the SecretRef profile or replacing its consent payload; a cached approval never overrides the execute-time check.

Configure the profile, Brave key, and a random durable-state encryption key of at least 32 characters as SecretRefs:

```bash
openclaw config set plugins.entries.rightout.config.braveApiKey \
  --ref-provider rightout_secrets --ref-source file --ref-id /braveApiKey
openclaw config set plugins.entries.rightout.config.stateEncryptionKey \
  --ref-provider rightout_secrets --ref-source file --ref-id /stateEncryptionKey
openclaw config set plugins.entries.rightout.config.profiles.profile_a1b2c3d4e5f60718.payload \
  --ref-provider rightout_secrets --ref-source file --ref-id /profiles/profile_a1b2c3d4e5f60718
openclaw config set plugins.entries.rightout.config.stateRetentionDays --strict-json '365'
```

SMTP supports Gmail, Yahoo, iCloud, and Fastmail on pinned TLS ports. IMAP verification is intentionally Gmail-only because RightOut pins receiver-added `mx.google.com` authentication results; other providers require a future evidence-backed authserv/OAuth contract. Arbitrary hosts, plaintext, port 25, proxy-selected destinations, or custom TLS overrides are rejected. Configure host/port/TLS as public facts and username/password/from-address/mailbox-address as SecretRefs. SMTP `fromAddress` and IMAP `address` must equal the profile `contactEmail`.

Authorized forms and outbound webmail compose support two production OpenClaw
browser transports. Prefer OpenClaw's production sandbox browser bridge when
the agent runs with `agents.defaults.sandbox.browser` enabled; OpenClaw supplies
`toolContext.browser.sandboxBridgeUrl` for that browser container, including its
`autoStart` lifecycle. No standalone host API setting is needed in that mode.

For an unsandboxed agent or an explicitly selected host browser profile, enable
OpenClaw's standalone browser-control HTTP server:

1. Set `OPENCLAW_EAGER_BROWSER_CONTROL_SERVER=1` in the **Gateway service
   environment**, then restart the Gateway. Setting it only in an interactive
   shell does not change an already running launchd/systemd/container service.
2. Read `gateway.port` (`openclaw config get gateway.port`). The browser-control
   port is `gateway.port + 2` (default `18791` for Gateway `18789`), so configure
   `browserControlBaseUrl` as `http://127.0.0.1:<derived-port>` with no `/browser`
   suffix.
3. Use stable shared-secret auth. With Gateway token auth, configure the same
   token as the `browserControlToken` SecretRef; RightOut sends bearer auth and
   does not support trusted-proxy/Tailscale identity on this loopback API.
4. Ensure the bundled Playwright runtime and a compatible Chromium-based browser
   are installed. RightOut requires AI snapshots and `/act`, which do not work
   without Playwright. For Docker, bake the browser with
   `OPENCLAW_INSTALL_BROWSER=1 ./scripts/docker/setup.sh`, or use the documented
   bundled installer:

   ```bash
   docker compose run --rm openclaw-cli \
     node /app/node_modules/playwright-core/cli.js install chromium
   ```

5. Start and verify the exact profile, then restart/verify the plugin:

   ```bash
   openclaw browser --browser-profile <name> start
   openclaw browser --browser-profile <name> status
   openclaw browser --browser-profile <name> doctor --deep
   openclaw plugins inspect rightout --runtime --json
   ```

Configure `browserProfile` for host/remote profile lanes and explicitly set
`browserBackendMode` to `managed_openclaw`, `remote_cloud_cdp`, or
`existing_logged_in_cdp`. `managed_openclaw` is the backend class for an
OpenClaw-managed browser reached through either the production sandbox bridge
or the standalone host transport; `browser_control_transport` distinguishes
them. Outbound
webmail is enabled only for the last mode, preventing an ordinary form browser
from being mistaken for a logged-in mailbox. Optionally set
`remoteCloudBrowserProfile` to a distinct named OpenClaw remote-CDP profile.
When the primary profile is blocked, the campaign may retry once through that
profile; a second failure becomes one consolidated human task. Gmail compose
requires a named profile already signed in by the operator. RightOut never reads
browser cookies, passwords, or profile storage and returns only privacy-redacted
semantic snapshots.
Browser-only inbound verification is intentionally disabled because the normal
Gmail UI does not provide a structured receiver-authentication contract. Use the
pinned authenticated Gmail IMAP lane or verify manually; the browser-mail
verification handoff performs zero mailbox I/O.
Active browser sessions are memory-only. After an unclean Gateway/browser
restart, manually inspect the configured profile, discard any autosaved Gmail
draft, close residual broker/discovery tabs, reconcile any durable pending
submission intent, and rerun the deep browser doctor. RightOut resumes encrypted
campaign/case state, but it cannot rediscover or close a lost in-memory tab
handle after restart.
Run `rightout_doctor({})` after configuration. It calls the official
`/doctor?deep=true&profile=...` endpoint and requires both an operational result
and a deep snapshot. `browser_control_transport` must be
either `openclaw_sandbox_browser_bridge` or
`standalone_loopback_http_opt_in`, matching the chosen deployment. A reachable
transport without Playwright/Chromium/deep-snapshot support is not
live-form-ready.

## 3. Compute bindings

After `npm run build`, use private mode-0600 local exports that exactly match the SecretRefs:

```bash
chmod 600 /secure/profile.json /secure/smtp.json /secure/imap.json
node scripts/compute-removal-bindings.mjs \
  profile_a1b2c3d4e5f60718 /secure/profile.json /secure/smtp.json /secure/imap.json
```

The helper prints only scan/removal profile digests plus SMTP/IMAP transport digests. Scan digests support profiles with an explicit ISO country, including EU profiles that use a member-country code such as `DE`. RightOut sends a directly supported Brave country/language target where available (for example `DE/de`) and otherwise uses explicit worldwide targeting; it never silently falls back to US. Treat all digests as sensitive pseudonymous configuration metadata, delete temporary exports, and recompute after any profile/transport change.

Back up the state encryption key through the secret provider. RightOut 0.8.1
keeps the v1 encrypted-store schema and forced upgrades preserve it. Encrypted
subject cases expire after `stateRetentionDays` without an update; the range is
30-730 days and the default is 365. Verification/listing/dedupe records retain
their shorter fixed TTLs. On first access, an untouched legacy v1 case without
an expiry is migrated under lock to `createdAt + stateRetentionDays`; an already
expired case is removed immediately. A missing key fails closed.

To rotate the key, configure a new active `stateEncryptionKey` and up to three
temporary old-key SecretRefs under `previousStateEncryptionKeys`, reload the
configuration, and explicitly approve `rightout_rotate_state_key({})`. Each
store remains readable throughout an interrupted rotation and is rewritten
under the active key. Only after the success report may the previous-key refs be
removed and secrets reloaded. Run the full readiness gate after both changes.

## 4. Configure exact attestations

Use the helper outputs instead of the zeros below.

Scan scope, after reviewing Brave terms revision `2026-02-11`, retention, subject authority, and disclosure vectors:

```json
{"braveTermsAccepted":true,"braveTermsVersion":"2026-02-11","braveCustomerResponsibilitiesAccepted":true,"subjectConsentReviewed":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedProfileDigests":{"profile_a1b2c3d4e5f60718":"0000000000000000000000000000000000000000000000000000000000000000"},"authorizedBrokerIds":["truepeoplesearch","beenverified"]}
```

Direct recheck scope, only after independently reviewing publisher terms and establishing access authority:

```json
{"rightoutDirectScanPolicyAccepted":true,"rightoutDirectScanPolicyVersion":"2026-07-12","subjectConsentReviewed":true,"publisherAccessAuthorized":true,"publisherTermsReviewed":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedProfileDigests":{"profile_a1b2c3d4e5f60718":"0000000000000000000000000000000000000000000000000000000000000000"},"authorizedBrokerIds":["truepeoplesearch","beenverified"]}
```

Email removal scope (example authorizing BeenVerified plus selected EU controller lanes):

```json
{"rightoutRemovalPolicyAccepted":true,"rightoutRemovalPolicyVersion":"2026-07-12-eu1","subjectConsentReviewed":true,"smtpAccountAuthorized":true,"minimumDisclosureAccepted":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedProfileDigests":{"profile_a1b2c3d4e5f60718":"0000000000000000000000000000000000000000000000000000000000000000"},"authorizedBrokerIds":["fullenrich_eu","beenverified","emetriq_eu"],"authorizedRequestKinds":["delete_and_opt_out","gdpr_erasure_objection"],"smtpTransportDigest":"0000000000000000000000000000000000000000000000000000000000000000"}
```

Browser-form scope (currently Intelius/PeopleConnect initiation):

```json
{"rightoutFormPolicyAccepted":true,"rightoutFormPolicyVersion":"2026-07-12","subjectConsentReviewed":true,"browserFormAuthorized":true,"minimumDisclosureAccepted":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedProfileDigests":{"profile_a1b2c3d4e5f60718":"0000000000000000000000000000000000000000000000000000000000000000"},"authorizedBrokerIds":["intelius"]}
```

This attestation is necessary but never sufficient for form automation. Every
form broker also needs a current written provider authorization obtained out of
band. Hash the retained authorization document locally with SHA-256 and copy
the current `contract_digest` from
`rightout_unbroker_parity_health({}).provider_terms.contracts`:

```json
{
  "intelius": {
    "authorizationReferenceSha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "termsContractDigest": "0000000000000000000000000000000000000000000000000000000000000000",
    "reviewedAt": "2026-07-13T08:00:00.000Z",
    "validUntil": "2026-10-11T08:00:00.000Z",
    "allowedEffects": ["submit_form", "open_verification"],
    "allowedBrowserBackends": ["existing_logged_in_cdp"]
  }
}
```

Write this object to
`plugins.entries.rightout.config.publisherAutomationPermissions`. It must refer
to the provider's actual written exception or permission; do not hash subject
consent, an operator note, or this documentation. The review cannot be
future-dated, the authorization must still be valid, and the maximum interval is
365 days. `allowedEffects` must enumerate only the operations named by the
written authorization; browser effects additionally require the exact selected
backend class in `allowedBrowserBackends`. Source refresh, publisher discovery,
direct recheck, form submission, and verification opening are separate powers.
Any provider-terms catalog change invalidates the binding. Current
public evidence alone authorizes zero of the 20 form routes.

Inbox/link verification scope (currently BeenVerified):

```json
{"rightoutVerificationPolicyAccepted":true,"rightoutVerificationPolicyVersion":"2026-07-12","subjectConsentReviewed":true,"inboxReadAuthorized":true,"verificationLinkOpenAuthorized":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedProfileDigests":{"profile_a1b2c3d4e5f60718":"0000000000000000000000000000000000000000000000000000000000000000"},"authorizedBrokerIds":["beenverified"],"imapTransportDigest":"0000000000000000000000000000000000000000000000000000000000000000"}
```

Write each attestation JSON object to its matching config path: `operatorAttestations`, `directScanAttestations`, `removalAttestations`, `formAttestations`, or `verificationAttestations`, using `openclaw config set ... --strict-json`. These are exact deployment gates, not blanket authority and not substitutes for `publisherAutomationPermissions`. Core assisted tools require their own native `allow-once`. The generic-form/outbound-webmail queue is campaign-bound; every autonomous effect must match and consume a finite `rightout_start_campaign` grant, and DOB adds a separate exact approval.

## 5. Tool, Gateway, and Cron policy

Allow only needed RightOut tools in the applicable agent policy. Unless full-operator direct invocation is intended, deny every tool whose manifest metadata has `replaySafe: false`. In 0.8.1 that includes provider effects plus campaign creation/revocation, DROP attestation, purge, outcome/reconciliation, and key rotation. Keep the deny list synchronized from `openclaw.plugin.json`; do not copy a stale partial list.

```json5
{
  gateway: { tools: { deny: [
    "rightout_live_scan", "rightout_direct_rescan", "rightout_submit_removal",
    "rightout_submit_form_removal", "rightout_submit_parity_email",
    "rightout_begin_discovery_session", "rightout_discovery_session_step",
    "rightout_begin_form_session", "rightout_form_session_step",
    "rightout_begin_webmail_session", "rightout_webmail_session_step",
    "rightout_poll_verification", "rightout_open_verification",
    "rightout_start_campaign", "rightout_revoke_campaign", "rightout_refresh_registries",
    "rightout_refresh_parity_sources",
    "rightout_record_drop_filed",
    "rightout_purge_subject_state", "rightout_record_controller_outcome",
    "rightout_reconcile_submission", "rightout_rotate_state_key"
  ] } }
}
```

Configure an interactive plugin approval route; without one, calls fail closed.
For recurring work, create an official OpenClaw Cron job that first invokes
`rightout_catalog_health({})`, then `rightout_due_rechecks` for an exact opaque
profile, followed by `rightout_campaign_next` for an active campaign or
`rightout_next_actions` in assisted mode. Any stale catalog entry stops live
provider I/O. Assisted live actions request their own approval; autonomous ones
must match the still-active campaign. If
`campaign.resume_mode` is `reconcile_before_external_writes`, the operator must
inspect provider-side evidence and approve `rightout_reconcile_submission`;
the agent must not infer the result. The plugin cannot self-schedule.

Example weekly read-only campaign monitor (replace only the opaque profile and
agent IDs). Configure the named agent itself with a tool allow-list containing
only `rightout_catalog_health`, `rightout_due_rechecks`,
`rightout_campaign_next`, `rightout_next_actions`, `rightout_case_status`, and
`rightout_export_report`; Cron does not create that policy boundary for you:

```bash
openclaw cron add '17 9 * * 1' \
  'For profile_a1b2c3d4e5f60718, call RightOut catalog health first. If fresh, list due rechecks, current campaign next step or assisted next actions, current status, and the PII-safe report. Do not invoke provider-I/O or critical local-state tools in this turn.' \
  --name rightout-profile-a1b2c3d4 \
  --tz Europe/Berlin \
  --session isolated \
  --agent rightout-monitor \
  --no-deliver
```

This job performs no provider call. A later interactive turn may execute a live
action only through its own native approval or a still-active matching campaign.
Use `openclaw cron run <job-id> --wait --wait-timeout 10m` and
`openclaw cron runs --id <job-id> --limit 50` to validate sanitized output before
enabling delivery. A campaign expires after at most 720 hours; Cron never renews
it automatically.

## 6. Readiness gate

```bash
openclaw config validate
openclaw secrets audit --check
openclaw security audit --deep
openclaw plugins inspect rightout --runtime --json
openclaw plugins doctor
make test
```

Resolve every RightOut critical finding and every machine-readable parity/source blocker. Development/release validation uses only `.invalid` identities and mocked providers. Do not perform a real broker scan, form, mail, link open, or provider write as a release test; the first live action must come from the authorized subject and either its exact assisted approval or a finite campaign approval.
