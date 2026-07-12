# Install and enable RightOut

## 1. Prerequisites and install

Use OpenClaw `2026.6.11+`, Node.js `22.19+`, Python `3.11+`, npm, and git.

```bash
git clone https://github.com/Olli0103/rightout.git
cd rightout
npm ci --ignore-scripts
./install.sh
openclaw plugins inspect rightout --runtime --json
openclaw plugins doctor
```

`--force` updates an existing registration; `--link` is development-only. The installer packages and validates before installation, serializes concurrent changes, snapshots prior config/managed extension state, and rolls back if runtime inspection or plugin doctor fails.

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
    "scope": ["scan", "broker_removal"]
  }
}
```

Configure the profile, Brave key, and a random durable-state encryption key of at least 32 characters as SecretRefs:

```bash
openclaw config set plugins.entries.rightout.config.braveApiKey \
  --ref-provider rightout_secrets --ref-source file --ref-id /braveApiKey
openclaw config set plugins.entries.rightout.config.stateEncryptionKey \
  --ref-provider rightout_secrets --ref-source file --ref-id /stateEncryptionKey
openclaw config set plugins.entries.rightout.config.profiles.profile_a1b2c3d4e5f60718.payload \
  --ref-provider rightout_secrets --ref-source file --ref-id /profiles/profile_a1b2c3d4e5f60718
```

SMTP supports Gmail, Yahoo, iCloud, and Fastmail on pinned TLS ports. IMAP verification is intentionally Gmail-only because RightOut pins receiver-added `mx.google.com` authentication results; other providers require a future evidence-backed authserv/OAuth contract. Arbitrary hosts, plaintext, port 25, proxy-selected destinations, or custom TLS overrides are rejected. Configure host/port/TLS as public facts and username/password/from-address/mailbox-address as SecretRefs. SMTP `fromAddress` and IMAP `address` must equal the profile `contactEmail`.

## 3. Compute bindings

After `npm run build`, use private mode-0600 local exports that exactly match the SecretRefs:

```bash
chmod 600 /secure/profile.json /secure/smtp.json /secure/imap.json
node scripts/compute-removal-bindings.mjs \
  profile_a1b2c3d4e5f60718 /secure/profile.json /secure/smtp.json /secure/imap.json
```

The helper prints only scan/removal profile digests plus SMTP/IMAP transport digests. Treat them as sensitive pseudonymous configuration metadata, delete temporary exports, and recompute after any profile/transport change.

Back up the state encryption key through the secret provider. Changing or losing it intentionally makes existing cases, dedupe entries, and opaque handles unreadable; v0.4.0 has no key-rotation migration tool.

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

Email removal scope (currently BeenVerified `US-CA`):

```json
{"rightoutRemovalPolicyAccepted":true,"rightoutRemovalPolicyVersion":"2026-07-12","subjectConsentReviewed":true,"smtpAccountAuthorized":true,"minimumDisclosureAccepted":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedProfileDigests":{"profile_a1b2c3d4e5f60718":"0000000000000000000000000000000000000000000000000000000000000000"},"authorizedBrokerIds":["beenverified"],"authorizedRequestKinds":["delete_and_opt_out"],"smtpTransportDigest":"0000000000000000000000000000000000000000000000000000000000000000"}
```

Browser-form scope (currently Intelius/PeopleConnect initiation):

```json
{"rightoutFormPolicyAccepted":true,"rightoutFormPolicyVersion":"2026-07-12","subjectConsentReviewed":true,"browserFormAuthorized":true,"minimumDisclosureAccepted":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedProfileDigests":{"profile_a1b2c3d4e5f60718":"0000000000000000000000000000000000000000000000000000000000000000"},"authorizedBrokerIds":["intelius"]}
```

Inbox/link verification scope (currently BeenVerified):

```json
{"rightoutVerificationPolicyAccepted":true,"rightoutVerificationPolicyVersion":"2026-07-12","subjectConsentReviewed":true,"inboxReadAuthorized":true,"verificationLinkOpenAuthorized":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedProfileDigests":{"profile_a1b2c3d4e5f60718":"0000000000000000000000000000000000000000000000000000000000000000"},"authorizedBrokerIds":["beenverified"],"imapTransportDigest":"0000000000000000000000000000000000000000000000000000000000000000"}
```

Write each JSON object to its matching config path: `operatorAttestations`, `directScanAttestations`, `removalAttestations`, `formAttestations`, or `verificationAttestations`, using `openclaw config set ... --strict-json`. These authorize prompts, not actions; every live call still requires native `allow-once`.

## 5. Tool, Gateway, and Cron policy

Allow only needed RightOut tools in the applicable agent policy. Unless full-operator direct invocation is intended, deny all live tools:

```json5
{
  gateway: { tools: { deny: [
    "rightout_live_scan", "rightout_direct_rescan", "rightout_submit_removal",
    "rightout_submit_form_removal", "rightout_poll_verification", "rightout_open_verification",
    "rightout_purge_subject_state"
  ] } }
}
```

Configure an interactive plugin approval route; without one, calls fail closed. For recurring work, create an official OpenClaw Cron job that invokes `rightout_due_rechecks` for an exact opaque profile and lets later live actions request their own approvals. The plugin cannot and does not self-schedule.

## 6. Readiness gate

```bash
openclaw config validate
openclaw secrets audit --check
openclaw security audit --deep
openclaw plugins inspect rightout --runtime --json
openclaw plugins doctor
make test
```

Resolve every RightOut critical finding. Development/release validation uses only `.invalid` identities and mocked providers. Do not perform a real broker scan, form, mail, link open, or provider write as a release test; the first live action must come from the authorized subject and its exact native approval prompt.
