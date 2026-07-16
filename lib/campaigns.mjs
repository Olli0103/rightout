import { createHash, randomBytes } from "node:crypto";

const SAFE_CAMPAIGN_ID = /^campaign_[a-f0-9]{32}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_BROKER_ID = /^[a-z0-9_]{2,80}$/;

export const CAMPAIGN_EFFECTS = Object.freeze([
  "discover",
  "publisher_discover",
  "submit_email",
  "submit_form",
  "poll_verification",
  "open_verification",
  "direct_recheck",
]);

const EFFECT_SET = new Set(CAMPAIGN_EFFECTS);
const UNBROKER_EXACT22 = Object.freeze([
  "addresses", "advancedbackgroundchecks", "beenverified", "clustal", "clustrmaps",
  "cyberbackgroundchecks", "familytreenow", "fastpeoplesearch", "intelius", "mylife", "nuwber",
  "peekyou", "peoplefinders", "radaris", "rehold", "searchpeoplefree", "socialcatfish", "spokeo",
  "thatsthem", "truepeoplesearch", "usphonebook", "whitepages",
]);

function uniqueSorted(values, pattern, { min = 1, max = 200, error = "rightout_campaign_scope_invalid" } = {}) {
  if (!Array.isArray(values) || values.length < min || values.length > max) throw new Error(error);
  if (values.some((value) => typeof value !== "string" || !pattern.test(value))) throw new Error(error);
  const result = [...new Set(values)].sort();
  if (result.length !== values.length) throw new Error(error);
  return result;
}

export function validateCampaignStartInput(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_campaign_scope_invalid");
  const allowed = new Set(["profileId", "brokerIds", "effects", "durationHours", "maxEffects"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error("rightout_campaign_scope_invalid");
  if (typeof value.profileId !== "string" || !SAFE_PROFILE_ID.test(value.profileId)) throw new Error("rightout_campaign_scope_invalid");
  const brokerIds = uniqueSorted(value.brokerIds, SAFE_BROKER_ID);
  const effects = uniqueSorted(value.effects, /^[a-z_]{3,32}$/, { max: CAMPAIGN_EFFECTS.length });
  if (effects.some((effect) => !EFFECT_SET.has(effect))) throw new Error("rightout_campaign_scope_invalid");
  if (!Number.isInteger(value.durationHours) || value.durationHours < 1 || value.durationHours > 720) {
    throw new Error("rightout_campaign_scope_invalid");
  }
  if (!Number.isInteger(value.maxEffects) || value.maxEffects < 1 || value.maxEffects > 2_000) {
    throw new Error("rightout_campaign_scope_invalid");
  }
  if (effects.length === 1 && effects[0] === "discover" && value.maxEffects < brokerIds.length) {
    throw new Error("rightout_campaign_scope_invalid");
  }
  return {
    profileId: value.profileId,
    brokerIds,
    effects,
    durationHours: value.durationHours,
    maxEffects: value.maxEffects,
  };
}

export function validateCampaignRef(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 1) {
    throw new Error("rightout_campaign_ref_invalid");
  }
  if (typeof value.campaignId !== "string" || !SAFE_CAMPAIGN_ID.test(value.campaignId)) {
    throw new Error("rightout_campaign_ref_invalid");
  }
  return { campaignId: value.campaignId };
}

function publicRecord(record) {
  return {
    campaign_id: record.campaignId,
    subject_ref: record.profileId,
    status: record.status,
    autonomy: "full_bounded_standing_authorization",
    broker_ids: [...record.brokerIds],
    effects: [...record.effects],
    created_at: record.createdAt,
    expires_at: record.expiresAt,
    max_effects: record.maxEffects,
    budget_unit: "broker_effect_authorization_unit",
    budget_unit_definition: "one broker/effect authorization; a bounded browser, Brave, mail, or verification session may contain multiple protocol interactions",
    used_effects: record.usedEffects,
    remaining_effects: Math.max(0, record.maxEffects - record.usedEffects),
    last_effect_at: record.lastEffectAt ?? null,
    last_effect_reference: record.lastEffectReference ?? null,
    revoked_at: record.revokedAt ?? null,
    market_policy_digest: record.marketPolicyDigest,
    market_policy_binding: "exact_current_contract",
  };
}

function validateStored(record, nowMs) {
  if (record?.schemaVersion === 1 && record?.marketPolicyDigest === undefined) {
    throw new Error("rightout_campaign_market_policy_binding_required");
  }
  if (
    !record || typeof record !== "object" || record.schemaVersion !== 2
    || !SAFE_CAMPAIGN_ID.test(record.campaignId)
    || !SAFE_PROFILE_ID.test(record.profileId)
    || !Array.isArray(record.brokerIds) || record.brokerIds.some((id) => !SAFE_BROKER_ID.test(id))
    || !Array.isArray(record.effects) || record.effects.some((effect) => !EFFECT_SET.has(effect))
    || !["active", "revoked", "completed"].includes(record.status)
    || !Number.isInteger(record.maxEffects) || !Number.isInteger(record.usedEffects)
    || record.maxEffects < 1 || record.usedEffects < 0 || record.usedEffects > record.maxEffects
    || !Number.isFinite(Date.parse(record.createdAt)) || !Number.isFinite(Date.parse(record.expiresAt))
    || typeof record.profileDigest !== "string" || !/^[a-f0-9]{64}$/.test(record.profileDigest)
    || typeof record.runtimeScopeDigest !== "string" || !/^[a-f0-9]{64}$/.test(record.runtimeScopeDigest)
    || typeof record.marketPolicyDigest !== "string" || !/^[a-f0-9]{64}$/.test(record.marketPolicyDigest)
  ) throw new Error("rightout_campaign_state_invalid");
  if (record.status === "active" && Date.parse(record.expiresAt) <= nowMs) throw new Error("rightout_campaign_expired");
  return record;
}

function validateRequestedEffects(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) throw new Error("rightout_campaign_effect_invalid");
  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("rightout_campaign_effect_invalid");
    if (Object.keys(item).some((key) => !["brokerId", "effect"].includes(key))) throw new Error("rightout_campaign_effect_invalid");
    if (typeof item.brokerId !== "string" || !SAFE_BROKER_ID.test(item.brokerId) || !EFFECT_SET.has(item.effect)) {
      throw new Error("rightout_campaign_effect_invalid");
    }
    return { brokerId: item.brokerId, effect: item.effect };
  });
}

export function campaignApprovalDescription(input, routingScope = {
  browserBackendMode: "managed_openclaw",
  browserControlTransport: "openclaw_sandbox_browser_bridge",
  remoteCloudFallback: false,
}) {
  const clean = validateCampaignStartInput(input);
  const { browserBackendMode, browserControlTransport, remoteCloudFallback } = routingScope;
  if (!["managed_openclaw", "remote_cloud_cdp", "existing_logged_in_cdp", "not_required"].includes(browserBackendMode)) {
    throw new Error("rightout_campaign_scope_invalid");
  }
  if (
    !["openclaw_sandbox_browser_bridge", "standalone_loopback_http_opt_in", "not_required"].includes(browserControlTransport)
    || typeof remoteCloudFallback !== "boolean"
  ) throw new Error("rightout_campaign_scope_invalid");
  const exactUnbroker = clean.brokerIds.length === UNBROKER_EXACT22.length
    && clean.brokerIds.every((id, index) => id === UNBROKER_EXACT22[index]);
  const scan21 = UNBROKER_EXACT22.filter((id) => id !== "spokeo");
  const exactScan21 = clean.brokerIds.length === scan21.length
    && clean.brokerIds.every((id, index) => id === scan21[index]);
  const nonStaged21 = UNBROKER_EXACT22.filter((id) => id !== "intelius");
  const exactNonStaged21 = clean.brokerIds.length === nonStaged21.length
    && clean.brokerIds.every((id, index) => id === nonStaged21[index]);
  const exactSetDigest = createHash("sha256").update(clean.brokerIds.join("\n")).digest("hex").slice(0, 12);
  const explicitTargets = clean.brokerIds.join(",");
  const boundedTargets = explicitTargets.length <= 96 ? `B=${explicitTargets}` : `B${clean.brokerIds.length}@${exactSetDigest}`;
  const targets = exactUnbroker
    ? "U22"
    : exactScan21
      ? "U21-scan"
      : exactNonStaged21
        ? "U21-minus-int"
        : boundedTargets;
  const effectLabels = {
    discover: "discover",
    publisher_discover: "pub-discover",
    submit_email: "email",
    submit_form: "form",
    poll_verification: "poll",
    open_verification: "open",
    direct_recheck: "recheck",
  };
  const effects = CAMPAIGN_EFFECTS.filter((effect) => clean.effects.includes(effect)).map((effect) => effectLabels[effect]).join(",");
  const hasBrave = clean.effects.includes("discover");
  const hasPublisher = clean.effects.some((effect) => ["publisher_discover", "submit_form", "open_verification", "direct_recheck"].includes(effect));
  const hasOutboundMail = clean.effects.includes("submit_email");
  const hasMailbox = clean.effects.includes("poll_verification");
  const browserBase = browserBackendMode === "managed_openclaw" ? "managed"
    : browserBackendMode === "remote_cloud_cdp" ? "remote"
    : browserBackendMode === "existing_logged_in_cdp" ? "login"
    : "n/a";
  const browser = remoteCloudFallback && browserBackendMode !== "remote_cloud_cdp"
    ? `${browserBase}+remote`
    : browserBase;
  const transport = browserControlTransport === "openclaw_sandbox_browser_bridge" ? "sandbox"
    : browserControlTransport === "standalone_loopback_http_opt_in" ? "loopback"
    : "n/a";
  const risks = [
    hasBrave ? "Brave:terms,id/contact,log<=90d/ZDR" : null,
    hasPublisher || hasOutboundMail ? "pub/proc:min=id/contact" : null,
    hasMailbox ? "IMAP:r<=30" : null,
    clean.effects.includes("open_verification") ? "open:write" : null,
  ].filter(Boolean);
  const browserRisk = browserBackendMode === "not_required" ? null : `B=${browser}/${transport}`;
  const text = [
    `P=${clean.profileId}`,
    targets,
    "standing,no-reprompt",
    `fx=${effects}`,
    ...risks,
    browserRisk,
    `cap${clean.maxEffects}/${clean.durationHours}h,revocable`,
  ].filter(Boolean).join(";");
  if (text.length > 256) throw new Error("rightout_campaign_scope_invalid");
  return text;
}

export function campaignScopeBinding(input, catalogDigest, routingDigest, marketPolicyDigest) {
  const clean = validateCampaignStartInput(input);
  if (
    typeof catalogDigest !== "string" || !/^[a-f0-9]{64}$/.test(catalogDigest)
    || typeof routingDigest !== "string" || !/^[a-f0-9]{64}$/.test(routingDigest)
    || typeof marketPolicyDigest !== "string" || !/^[a-f0-9]{64}$/.test(marketPolicyDigest)
  ) throw new Error("rightout_campaign_scope_invalid");
  return JSON.stringify(["rightout_campaign_approval_v5", clean, catalogDigest, routingDigest, marketPolicyDigest]);
}

export function campaignRevokeScopeBinding(input) {
  const clean = validateCampaignRef(input);
  return JSON.stringify(["rightout_campaign_revoke_v1", clean.campaignId]);
}

export function createCampaignLedger(store, {
  now = () => Date.now(),
  randomId = () => `campaign_${randomBytes(16).toString("hex")}`,
} = {}) {
  if (!store || typeof store.registerIfAbsent !== "function" || typeof store.lookup !== "function" || typeof store.update !== "function") {
    throw new Error("rightout_campaign_store_invalid");
  }

  async function start(input, { catalogDigest, profileDigest, runtimeScopeDigest, marketPolicyDigest }) {
    const clean = validateCampaignStartInput(input);
    if (typeof catalogDigest !== "string" || !/^[a-f0-9]{64}$/.test(catalogDigest)) throw new Error("rightout_campaign_scope_invalid");
    if (typeof profileDigest !== "string" || !/^[a-f0-9]{64}$/.test(profileDigest)) throw new Error("rightout_campaign_scope_invalid");
    if (typeof runtimeScopeDigest !== "string" || !/^[a-f0-9]{64}$/.test(runtimeScopeDigest)) throw new Error("rightout_campaign_scope_invalid");
    if (typeof marketPolicyDigest !== "string" || !/^[a-f0-9]{64}$/.test(marketPolicyDigest)) throw new Error("rightout_campaign_scope_invalid");
    const campaignId = randomId();
    if (!SAFE_CAMPAIGN_ID.test(campaignId)) throw new Error("rightout_campaign_state_invalid");
    const at = now();
    const expiresAtMs = at + clean.durationHours * 60 * 60_000;
    const record = {
      schemaVersion: 2,
      campaignId,
      profileId: clean.profileId,
      brokerIds: clean.brokerIds,
      effects: clean.effects,
      status: "active",
      createdAt: new Date(at).toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString(),
      maxEffects: clean.maxEffects,
      usedEffects: 0,
      catalogDigest,
      profileDigest,
      runtimeScopeDigest,
      marketPolicyDigest,
    };
    const created = await store.registerIfAbsent(campaignId, record, { ttlMs: clean.durationHours * 60 * 60_000 });
    if (!created) throw new Error("rightout_campaign_state_invalid");
    return publicRecord(record);
  }

  async function status(campaignId) {
    if (!SAFE_CAMPAIGN_ID.test(campaignId)) throw new Error("rightout_campaign_ref_invalid");
    const record = await store.lookup(campaignId);
    if (!record) throw new Error("rightout_campaign_not_found");
    return publicRecord(validateStored(record, now()));
  }

  async function assertMarketPolicy(campaignId, { marketPolicyDigest }) {
    if (!SAFE_CAMPAIGN_ID.test(campaignId) || typeof marketPolicyDigest !== "string" || !/^[a-f0-9]{64}$/.test(marketPolicyDigest)) {
      throw new Error("rightout_campaign_ref_invalid");
    }
    const record = validateStored(await store.lookup(campaignId), now());
    if (record.marketPolicyDigest !== marketPolicyDigest) throw new Error("rightout_campaign_market_policy_changed");
    return publicRecord(record);
  }

  async function assertScope(campaignId, { profileId, profileDigest, runtimeScopeDigest, marketPolicyDigest }) {
    if (!SAFE_CAMPAIGN_ID.test(campaignId) || !SAFE_PROFILE_ID.test(profileId)) throw new Error("rightout_campaign_ref_invalid");
    const record = validateStored(await store.lookup(campaignId), now());
    if (record.profileId !== profileId) throw new Error("rightout_campaign_scope_mismatch");
    if (record.profileDigest !== profileDigest) throw new Error("rightout_profile_snapshot_changed");
    if (record.runtimeScopeDigest !== runtimeScopeDigest) throw new Error("rightout_campaign_runtime_scope_changed");
    if (record.marketPolicyDigest !== marketPolicyDigest) throw new Error("rightout_campaign_market_policy_changed");
    return publicRecord(record);
  }

  async function consume(campaignId, { profileId, effects, catalogDigest, profileDigest, runtimeScopeDigest, marketPolicyDigest }) {
    if (!SAFE_CAMPAIGN_ID.test(campaignId) || !SAFE_PROFILE_ID.test(profileId)) throw new Error("rightout_campaign_effect_invalid");
    if (typeof catalogDigest !== "string" || !/^[a-f0-9]{64}$/.test(catalogDigest)) throw new Error("rightout_campaign_effect_invalid");
    if (typeof profileDigest !== "string" || !/^[a-f0-9]{64}$/.test(profileDigest)) throw new Error("rightout_campaign_effect_invalid");
    if (typeof runtimeScopeDigest !== "string" || !/^[a-f0-9]{64}$/.test(runtimeScopeDigest)) throw new Error("rightout_campaign_effect_invalid");
    if (typeof marketPolicyDigest !== "string" || !/^[a-f0-9]{64}$/.test(marketPolicyDigest)) throw new Error("rightout_campaign_effect_invalid");
    const requested = validateRequestedEffects(effects);
    let result;
    await store.update(campaignId, (current) => {
      if (!current) throw new Error("rightout_campaign_not_found");
      const record = validateStored(current, now());
      if (record.status !== "active") throw new Error("rightout_campaign_not_active");
      if (record.profileId !== profileId || record.catalogDigest !== catalogDigest) throw new Error("rightout_campaign_scope_mismatch");
      if (record.profileDigest !== profileDigest) throw new Error("rightout_profile_snapshot_changed");
      if (record.runtimeScopeDigest !== runtimeScopeDigest) throw new Error("rightout_campaign_runtime_scope_changed");
      if (record.marketPolicyDigest !== marketPolicyDigest) throw new Error("rightout_campaign_market_policy_changed");
      const allowedBrokers = new Set(record.brokerIds);
      const allowedEffects = new Set(record.effects);
      if (requested.some((item) => !allowedBrokers.has(item.brokerId) || !allowedEffects.has(item.effect))) {
        throw new Error("rightout_campaign_scope_mismatch");
      }
      if (record.usedEffects + requested.length > record.maxEffects) throw new Error("rightout_campaign_effect_budget_exhausted");
      const at = new Date(now()).toISOString();
      const effectReference = `effect_${createHash("sha256").update(JSON.stringify([campaignId, record.usedEffects, requested, at])).digest("hex").slice(0, 24)}`;
      const next = {
        ...record,
        usedEffects: record.usedEffects + requested.length,
        lastEffectAt: at,
        lastEffectReference: effectReference,
        ...(record.usedEffects + requested.length === record.maxEffects ? { status: "completed" } : {}),
      };
      result = { ...publicRecord(next), effect_reference: effectReference, consumed_effects: requested.length };
      return next;
    });
    return result;
  }

  async function revoke(campaignId) {
    if (!SAFE_CAMPAIGN_ID.test(campaignId)) throw new Error("rightout_campaign_ref_invalid");
    let result;
    await store.update(campaignId, (current) => {
      if (!current) throw new Error("rightout_campaign_not_found");
      const record = validateStored(current, now());
      const next = record.status === "revoked" ? record : {
        ...record,
        status: "revoked",
        revokedAt: new Date(now()).toISOString(),
      };
      result = publicRecord(next);
      return next;
    });
    return result;
  }

  return { start, status, assertMarketPolicy, assertScope, consume, revoke };
}

export const __test = { publicRecord, validateStored, validateRequestedEffects };
