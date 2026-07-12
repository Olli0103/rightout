# Install and enable RightOut

## 1. Prerequisites

- OpenClaw `2026.6.11` or newer
- Node.js `22.19` or newer and npm
- Python 3 for catalog/package validation
- Brave Search API key for live scans
- an SMTP app password for a supported provider if live removal is enabled
- an operator-owned OpenClaw secret provider outside the agent workspace

Supported SMTP endpoints are pinned in code: Gmail, Yahoo, iCloud, and Fastmail on their reviewed TLS ports. Arbitrary hosts, IP literals, port 25, plaintext SMTP, custom TLS overrides, and proxy-controlled destinations are rejected. Microsoft 365 is intentionally excluded because this release does not implement OAuth 2.0 for SMTP AUTH.

## 2. Install

```bash
git clone https://github.com/Olli0103/rightout.git
cd rightout
npm ci --ignore-scripts
./install.sh
```

Use `./install.sh --force` for an existing registration. `./install.sh --link` is development-only.

Verify:

```bash
openclaw plugins inspect rightout --runtime --json
openclaw plugins doctor
```

Expected runtime evidence is status `loaded`, optional tools `rightout_live_scan` and `rightout_submit_removal`, and typed hook `before_tool_call`.

The installer stages and validates before swap, snapshots config and a prior managed extension, serializes concurrent installs with `.rightout-install.lock`, and restores the prior state if runtime inspection or plugin doctor fails.

## 3. Provision SecretRefs

Create the secret values out of band. A complete private profile has this logical shape:

```json
{
  "fullName": "Avery Example",
  "city": "Exampleville",
  "region": "CA",
  "country": "US",
  "contactEmail": "avery@example.invalid",
  "jurisdictions": ["US", "US-CA"],
  "consent": {
    "authorized": true,
    "recordedAt": "2026-07-12T08:00:00.000Z",
    "scope": ["scan", "broker_removal"]
  }
}
```

Do not create a real profile through an agent, commit it, or place it in the workspace. Configure refs, for example:

```bash
openclaw config set plugins.entries.rightout.config.braveApiKey \
  --ref-provider rightout_secrets --ref-source file --ref-id /braveApiKey

openclaw config set plugins.entries.rightout.config.profiles.profile_a1b2c3d4e5f60718.payload \
  --ref-provider rightout_secrets --ref-source file \
  --ref-id /profiles/profile_a1b2c3d4e5f60718
```

Configure public SMTP transport facts normally and every identity/credential value as a SecretRef:

```bash
openclaw config set plugins.entries.rightout.config.smtpTransport.host '"smtp.gmail.com"' --strict-json
openclaw config set plugins.entries.rightout.config.smtpTransport.port '465' --strict-json
openclaw config set plugins.entries.rightout.config.smtpTransport.secure 'true' --strict-json

openclaw config set plugins.entries.rightout.config.smtpTransport.username \
  --ref-provider rightout_secrets --ref-source file --ref-id /smtp/username
openclaw config set plugins.entries.rightout.config.smtpTransport.password \
  --ref-provider rightout_secrets --ref-source file --ref-id /smtp/password
openclaw config set plugins.entries.rightout.config.smtpTransport.fromAddress \
  --ref-provider rightout_secrets --ref-source file --ref-id /smtp/fromAddress
```

The resolved `fromAddress` must exactly equal the selected profile's `contactEmail`. Prefer a provider-specific app password rather than the account's primary password.

## 4. Compute snapshot bindings

Compute pseudonymous, non-plaintext SHA-256 bindings over the normalized logical scan/removal profile and resolved SMTP transport. Treat the digests as sensitive configuration metadata. Use protected local JSON inputs that contain the same values as the SecretRefs; the helper refuses files accessible by group/other and prints digests only:

```bash
chmod 600 /secure/rightout-profile.json /secure/rightout-smtp.json
node scripts/compute-removal-bindings.mjs \
  profile_a1b2c3d4e5f60718 \
  /secure/rightout-profile.json \
  /secure/rightout-smtp.json
```

Delete any temporary export immediately after use. Recompute all affected bindings whenever a profile field or SMTP value changes. These bindings are immutable configuration evidence, not approval tokens; only native OpenClaw `allow-once` authorizes the write.

## 5. Record scan attestations

After reviewing recorded scan consent, subject authority, Brave Search API Terms revision `2026-02-11`, Brave customer responsibilities, disclosure, and retention, configure the exact scan scope. Replace the example zero value with the helper's `scanProfileDigests` output:

```bash
openclaw config set plugins.entries.rightout.config.operatorAttestations \
  '{"braveTermsAccepted":true,"braveTermsVersion":"2026-02-11","braveCustomerResponsibilitiesAccepted":true,"subjectConsentReviewed":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedProfileDigests":{"profile_a1b2c3d4e5f60718":"0000000000000000000000000000000000000000000000000000000000000000"},"authorizedBrokerIds":["truepeoplesearch","beenverified"]}' \
  --strict-json
```

This permits approval prompts for scans only. It never authorizes a removal.

## 6. Record removal attestations

After separately reviewing recorded subject consent, the official broker channel, minimum disclosure, SMTP authority, and RightOut removal policy `2026-07-12`, configure the exact removal scope. Replace the two example zero values with the helper's 64-hex outputs:

```bash
openclaw config set plugins.entries.rightout.config.removalAttestations \
  '{"rightoutRemovalPolicyAccepted":true,"rightoutRemovalPolicyVersion":"2026-07-12","subjectConsentReviewed":true,"smtpAccountAuthorized":true,"minimumDisclosureAccepted":true,"authorizedProfileIds":["profile_a1b2c3d4e5f60718"],"authorizedProfileDigests":{"profile_a1b2c3d4e5f60718":"0000000000000000000000000000000000000000000000000000000000000000"},"authorizedBrokerIds":["beenverified"],"authorizedRequestKinds":["delete_and_opt_out"],"smtpTransportDigest":"0000000000000000000000000000000000000000000000000000000000000000"}' \
  --strict-json
```

The current automated removal lane requires `US-CA` in the private profile. The email asks for deletion and opt-out without asserting that completion has occurred. The broker may require additional human verification.

## 7. Tool and Gateway policy

Both tools are optional. Add only the needed tools to the applicable `tools.allow` policy without replacing unrelated entries.

Unless direct full-operator `/tools/invoke` access is intentional, deny both tools on that surface:

```json5
{
  gateway: {
    tools: {
      deny: ["rightout_live_scan", "rightout_submit_removal"]
    }
  }
}
```

Configure a local approval UI or explicit `approvals.plugin` route. With no route, calls fail closed. See OpenClaw's [plugin permission requests](https://docs.openclaw.ai/plugins/plugin-permission-requests).

## 8. Readiness gate

```bash
openclaw config validate
openclaw secrets audit --check
openclaw security audit --deep
openclaw plugins inspect rightout --runtime --json
openclaw plugins doctor
```

Resolve all `rightout.secretref.*`, scan-attestation, and removal-attestation critical findings. Resolve or consciously accept the `rightout.gateway.tools_invoke` warning.

Installation and release tests use only mocked providers and `.invalid` identities. Do not test SMTP against a real broker. The first real email must be initiated by the user and approved through the removal-specific native prompt.
