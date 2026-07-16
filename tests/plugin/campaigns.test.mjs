import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  campaignApprovalDescription,
  campaignScopeBinding,
  createCampaignLedger,
  validateCampaignStartInput,
} from "../../lib/campaigns.mjs";
import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";

const profileId = "profile_a1b2c3d4e5f60718";
const catalogDigest = "a".repeat(64);
const profileDigest = "b".repeat(64);
const runtimeScopeDigest = "c".repeat(64);
const approvalRoutingDigest = "d".repeat(64);
const marketPolicyDigest = "e".repeat(64);
const managedRouting = {
  browserBackendMode: "managed_openclaw",
  browserControlTransport: "openclaw_sandbox_browser_bridge",
  remoteCloudFallback: false,
};
const secret = "dummy-campaign-state-key-with-more-than-32-characters";
const input = {
  profileId,
  brokerIds: ["beenverified", "intelius"],
  effects: ["direct_recheck", "discover", "open_verification", "poll_verification", "submit_email", "submit_form"],
  durationHours: 24,
  maxEffects: 12,
};

test("campaign scope is canonical, bounded, and PII-free", () => {
  assert.deepEqual(validateCampaignStartInput(input), input);
  const description = campaignApprovalDescription(input);
  assert.match(description, new RegExp(`P=${profileId}`));
  assert.match(description, /B=beenverified,intelius/);
  assert.match(description, /Brave:terms,id\/contact,log<=90d\/ZDR/);
  assert.match(description, /pub\/proc:min=id\/contact/);
  assert.match(description, /IMAP:r<=30/);
  assert.match(description, /B=managed\/sandbox/);
  assert.match(description, /standing,no-reprompt/);
  assert.match(description, /fx=discover,email,form,poll,open,recheck/);
  assert.match(description, /cap12\/24h,revocable/);
  assert.equal(description.length <= 256, true);
  assert.doesNotMatch(description, /Avery|example@/);
  assert.equal(
    campaignScopeBinding(input, catalogDigest, approvalRoutingDigest, marketPolicyDigest),
    campaignScopeBinding({ ...input }, catalogDigest, approvalRoutingDigest, marketPolicyDigest),
  );
  assert.notEqual(
    campaignScopeBinding(input, catalogDigest, approvalRoutingDigest, marketPolicyDigest),
    campaignScopeBinding(input, catalogDigest, approvalRoutingDigest, "f".repeat(64)),
  );
  for (const bad of [
    { ...input, durationHours: 0 },
    { ...input, durationHours: 721 },
    { ...input, maxEffects: 0 },
    { ...input, brokerIds: ["intelius", "intelius"] },
    { ...input, effects: ["arbitrary_write"] },
    { ...input, extra: true },
  ]) assert.throws(() => validateCampaignStartInput(bad), /rightout_campaign_scope_invalid/);
});

test("campaign approval uses one schema-valid immutable alias for the exact Unbroker scope", async () => {
  const parity = JSON.parse(await readFile(new URL("../../skills/data-broker-removal/references/brokers/unbroker-parity.json", import.meta.url), "utf8"));
  const brokerIds = [
    ...parity.brokers.map((broker) => broker.id),
  ].sort();
  const description = campaignApprovalDescription({ ...input, brokerIds });
  assert.match(description, /U22/);
  assert.match(description, new RegExp(`P=${profileId}`));
  assert.equal(description.length <= 256, true);
  assert.doesNotMatch(description, /spokeo|intelius/);
  const widened = { ...input, brokerIds: [...brokerIds, "thatsthem_extra"].sort() };
  const widenedDescription = campaignApprovalDescription(widened);
  assert.doesNotMatch(widenedDescription, /U22/);
  assert.match(widenedDescription, /B23@[a-f0-9]{12}/);
  assert.notEqual(widenedDescription, description);
  assert.notEqual(
    campaignScopeBinding(widened, catalogDigest, approvalRoutingDigest, marketPolicyDigest),
    campaignScopeBinding({ ...input, brokerIds }, catalogDigest, approvalRoutingDigest, marketPolicyDigest),
  );
  const maximum = campaignApprovalDescription({
    profileId: `profile_${"f".repeat(32)}`,
    brokerIds,
    effects: ["discover", "publisher_discover", "submit_email", "submit_form", "poll_verification", "open_verification", "direct_recheck"],
    durationHours: 720,
    maxEffects: 2_000,
  });
  assert.match(maximum, /fx=discover,pub-discover,email,form,poll,open,recheck/);
  assert.match(maximum, /B=managed\/sandbox/);
  assert.equal(maximum.length <= 256, true);
  const maximumRemote = campaignApprovalDescription({
    profileId: `profile_${"f".repeat(32)}`, brokerIds,
    effects: ["discover", "publisher_discover", "submit_email", "submit_form", "poll_verification", "open_verification", "direct_recheck"],
    durationHours: 720, maxEffects: 2_000,
  }, { browserBackendMode: "remote_cloud_cdp", browserControlTransport: "standalone_loopback_http_opt_in", remoteCloudFallback: false });
  assert.equal(maximumRemote.length <= 256, true);
  const maximumFallback = campaignApprovalDescription({
    profileId: `profile_${"f".repeat(32)}`, brokerIds,
    effects: ["discover", "publisher_discover", "submit_email", "submit_form", "poll_verification", "open_verification", "direct_recheck"],
    durationHours: 720, maxEffects: 2_000,
  }, { browserBackendMode: "existing_logged_in_cdp", browserControlTransport: "standalone_loopback_http_opt_in", remoteCloudFallback: true });
  assert.equal(maximumFallback.length <= 256, true);
  const remote = campaignApprovalDescription({ ...input, brokerIds }, {
    browserBackendMode: "remote_cloud_cdp", browserControlTransport: "standalone_loopback_http_opt_in", remoteCloudFallback: false,
  });
  assert.match(remote, /B=remote\/loopback/);
  const withFallback = campaignApprovalDescription({ ...input, brokerIds }, {
    browserBackendMode: "existing_logged_in_cdp", browserControlTransport: "standalone_loopback_http_opt_in", remoteCloudFallback: true,
  });
  assert.match(withFallback, /B=login\+remote\/loopback/);
  assert.equal(withFallback.length <= 256, true);
  const nonStagedBrokerIds = brokerIds.filter((brokerId) => brokerId !== "intelius");
  const nonStaged = campaignApprovalDescription({ ...input, brokerIds: nonStagedBrokerIds });
  assert.match(nonStaged, /U21-minus-int/);
  assert.equal(nonStaged.length <= 256, true);
  const formOnly = campaignApprovalDescription({ ...input, effects: ["submit_form"] });
  assert.match(formOnly, /fx=form;/);
  const directAndOpen = campaignApprovalDescription({ ...input, effects: ["direct_recheck", "open_verification"] });
  assert.match(directAndOpen, /fx=open,recheck;/);
});

test("one standing campaign grant authorizes only its exact durable scope", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "rightout-campaign-"));
  let at = Date.parse("2026-07-13T08:00:00Z");
  try {
    const store = createEncryptedFileKeyedStore({
      stateDir,
      namespace: "rightout-campaigns-v1",
      maxEntries: 20,
      getSecret: () => secret,
      now: () => at,
    });
    const ledger = createCampaignLedger(store, {
      now: () => at,
      randomId: () => `campaign_${"1".repeat(32)}`,
    });
    const started = await ledger.start(input, { catalogDigest, profileDigest, runtimeScopeDigest, marketPolicyDigest });
    assert.equal(started.status, "active");
    assert.equal(started.budget_unit, "broker_effect_authorization_unit");
    assert.match(started.budget_unit_definition, /multiple protocol interactions/);
    assert.equal(started.used_effects, 0);
    assert.equal(started.remaining_effects, 12);
    assert.equal(started.market_policy_digest, marketPolicyDigest);
    assert.equal(started.market_policy_binding, "exact_current_contract");
    assert.equal(
      (await ledger.assertMarketPolicy(started.campaign_id, { marketPolicyDigest })).market_policy_digest,
      marketPolicyDigest,
    );
    await assert.rejects(
      ledger.assertMarketPolicy(started.campaign_id, { marketPolicyDigest: "f".repeat(64) }),
      /rightout_campaign_market_policy_changed/,
    );

    const consumed = await ledger.consume(started.campaign_id, {
      profileId,
      catalogDigest,
      profileDigest,
      runtimeScopeDigest,
      marketPolicyDigest,
      effects: [
        { brokerId: "beenverified", effect: "discover" },
        { brokerId: "intelius", effect: "submit_form" },
      ],
    });
    assert.equal(consumed.used_effects, 2);
    assert.equal(consumed.consumed_effects, 2);
    assert.match(consumed.effect_reference, /^effect_[a-f0-9]{24}$/);
    assert.equal(JSON.stringify(consumed).includes("dummy-campaign-state-key"), false);

    await assert.rejects(ledger.consume(started.campaign_id, {
      profileId,
      catalogDigest,
      profileDigest,
      runtimeScopeDigest,
      marketPolicyDigest,
      effects: [{ brokerId: "spokeo", effect: "submit_form" }],
    }), /rightout_campaign_scope_mismatch/);
    await assert.rejects(ledger.consume(started.campaign_id, {
      profileId: "profile_ffffffffffffffff",
      catalogDigest,
      profileDigest,
      runtimeScopeDigest,
      marketPolicyDigest,
      effects: [{ brokerId: "intelius", effect: "submit_form" }],
    }), /rightout_campaign_scope_mismatch/);
    await assert.rejects(ledger.consume(started.campaign_id, {
      profileId,
      catalogDigest: "b".repeat(64),
      profileDigest,
      runtimeScopeDigest,
      marketPolicyDigest,
      effects: [{ brokerId: "intelius", effect: "submit_form" }],
    }), /rightout_campaign_scope_mismatch/);
    await assert.rejects(ledger.consume(started.campaign_id, {
      profileId,
      catalogDigest,
      profileDigest,
      runtimeScopeDigest,
      marketPolicyDigest: "f".repeat(64),
      effects: [{ brokerId: "intelius", effect: "submit_form" }],
    }), /rightout_campaign_market_policy_changed/);

    const encrypted = await readFile(join(stateDir, "rightout-plugin-state-v1", "rightout-campaigns-v1.json.enc"));
    assert.equal(encrypted.includes(Buffer.from(profileId)), false);
    assert.equal(encrypted.includes(Buffer.from("intelius")), false);

    const revoked = await ledger.revoke(started.campaign_id);
    assert.equal(revoked.status, "revoked");
    await assert.rejects(ledger.consume(started.campaign_id, {
      profileId,
      catalogDigest,
      profileDigest,
      runtimeScopeDigest,
      marketPolicyDigest,
      effects: [{ brokerId: "intelius", effect: "submit_form" }],
    }), /rightout_campaign_not_active/);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("campaign effect budget and expiry fail closed", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "rightout-campaign-budget-"));
  let at = Date.parse("2026-07-13T08:00:00Z");
  try {
    const ledger = createCampaignLedger(createEncryptedFileKeyedStore({
      stateDir,
      namespace: "rightout-campaigns-v1",
      maxEntries: 20,
      getSecret: () => secret,
      now: () => at,
    }), {
      now: () => at,
      randomId: () => `campaign_${"2".repeat(32)}`,
    });
    const started = await ledger.start(
      { ...input, durationHours: 1, maxEffects: 1 },
      { catalogDigest, profileDigest, runtimeScopeDigest, marketPolicyDigest },
    );
    const completed = await ledger.consume(started.campaign_id, {
      profileId,
      catalogDigest,
      profileDigest,
      runtimeScopeDigest,
      marketPolicyDigest,
      effects: [{ brokerId: "beenverified", effect: "discover" }],
    });
    assert.equal(completed.status, "completed");
    await assert.rejects(ledger.consume(started.campaign_id, {
      profileId,
      catalogDigest,
      profileDigest,
      runtimeScopeDigest,
      marketPolicyDigest,
      effects: [{ brokerId: "beenverified", effect: "discover" }],
    }), /rightout_campaign_not_active/);

    const expiring = createCampaignLedger(createEncryptedFileKeyedStore({
      stateDir,
      namespace: "rightout-campaigns-expiry-v1",
      maxEntries: 20,
      getSecret: () => secret,
      now: () => at,
    }), {
      now: () => at,
      randomId: () => `campaign_${"3".repeat(32)}`,
    });
    const short = await expiring.start(
      { ...input, durationHours: 1 },
      { catalogDigest, profileDigest, runtimeScopeDigest, marketPolicyDigest },
    );
    at += 60 * 60_000 + 1;
    await assert.rejects(expiring.status(short.campaign_id), /rightout_campaign_not_found|rightout_campaign_expired/);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});
