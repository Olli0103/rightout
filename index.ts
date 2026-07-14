import { readFile } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { basename } from "node:path";
import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import type { PluginApprovalResolution } from "openclaw/plugin-sdk/types";
import {
  buildHostnameAllowlistPolicyFromSuffixAllowlist,
  fetchWithSsrFGuard,
} from "openclaw/plugin-sdk/ssrf-runtime";
import {
  BRAVE_TERMS_VERSION,
  approvalDescription,
  runLiveScan,
  scanProfileDigest,
  validateOperatorAttestations,
  validatePublicToolInput,
} from "./lib/live-scan.mjs";
import {
  RIGHTOUT_REMOVAL_POLICY_VERSION,
  removalApprovalDescription,
  removalScopeBinding,
  resolveRemovalCatalogEntry,
  runRemovalSubmission,
  parseRemovalProfile,
  removalProfileDigest,
  validateRemovalOperatorAttestations,
  validateRemovalPreflight,
  validateRemovalPublicToolInput,
} from "./lib/removal.mjs";
import { createSmtpSender } from "./lib/smtp.mjs";
import { createCaseLedger } from "./lib/cases.mjs";
import { createBrowserFormSubmitter, createBrowserSessionDriver } from "./lib/browser-form.mjs";
import { createControllerReplyPoller, createImapPoller, newVerificationHandle } from "./lib/imap.mjs";
import {
  RIGHTOUT_CONTROLLER_REPLY_POLICY_VERSION,
  classifyControllerReply,
  controllerReplyScopeBinding,
  validateControllerReplyAttestations,
  validateControllerReplyPreflight,
} from "./lib/controller-replies.mjs";
import { createListingTokenVault } from "./lib/listing-tokens.mjs";
import { createEncryptedFileKeyedStore } from "./lib/file-keyed-store.mjs";
import { createEvidenceVault } from "./lib/evidence-vault.mjs";
import { createCustomTargetVault } from "./lib/custom-targets.mjs";
import { assertFreshCatalogEntries, catalogPolicyHealth } from "./lib/catalog-health.mjs";
import {
  RIGHTOUT_DIRECT_SCAN_POLICY_VERSION,
  directScanApprovalDescription,
  directScanScopeBinding,
  resolveDirectScanCatalogEntry,
  runDirectRescan,
  validateDirectScanAttestations,
  validateDirectScanInput,
  validatePublisherAccessAttestations,
} from "./lib/direct-rescan.mjs";
import {
  RIGHTOUT_VERIFICATION_POLICY_VERSION,
  browserVerificationProfileDigest,
  resolveVerificationCatalogEntry,
  validateBrowserVerificationPreflight,
  validateVerificationAttestations,
  validateVerificationOpenInput,
  validateVerificationPollInput,
  validateVerificationPreflight,
  verificationOpenApprovalDescription,
  verificationOpenScopeBinding,
  verificationPollApprovalDescription,
  verificationPollScopeBinding,
} from "./lib/verification.mjs";
import {
  RIGHTOUT_FORM_POLICY_VERSION,
  formApprovalDescription,
  formScopeBinding,
  resolveFormCatalogEntry,
  runFormRemoval,
  validateFormAttestations,
  validateFormPreflight,
  validateFormRemovalInput,
} from "./lib/form-removal.mjs";
import {
  CAMPAIGN_EFFECTS,
  campaignApprovalDescription,
  campaignRevokeScopeBinding,
  campaignScopeBinding,
  createCampaignLedger,
  validateCampaignRef,
  validateCampaignStartInput,
} from "./lib/campaigns.mjs";
import {
  parseCaliforniaRegistryCsv,
  readBoundedText,
  REGISTRY_PORTALS,
  registrySummary,
} from "./lib/registry.mjs";
import {
  assertParityCatalogFresh,
  assertParityCatalogRouteFresh,
  parityCatalogHealth,
  resolveParityBroker,
  validateParityCatalog,
} from "./lib/parity-catalog.mjs";
import { buildParityMessage, runParityEmail } from "./lib/parity-email.mjs";
import { planGlobalScanCampaignNext, planParityCampaignNext } from "./lib/parity-autopilot.mjs";
import { buildCombinedScanCatalog } from "./lib/scan-catalog.mjs";
import {
  assertPublisherAutomationPermission,
  providerTermsHealth,
  validateProviderTermsCatalog,
} from "./lib/provider-terms.mjs";
import { createReportExport } from "./lib/report-export.mjs";
import { refreshParitySources } from "./lib/parity-source-refresh.mjs";
import {
  createAutonomyWorkerLedger,
  workerPolicyDigest,
  workerSessionBindingDigest,
} from "./lib/autonomy-worker.mjs";
import {
  assessRecipeSnapshot,
  compileBuiltinRecipePack,
  recipeDigest,
} from "./lib/recipes.mjs";
import { buildEffectivenessReport } from "./lib/effectiveness.mjs";
import {
  resolveTeamMember,
  teamSessionBindingDigest,
  validateTeamAccess,
} from "./lib/team-access.mjs";
import { exportLocalDashboard } from "./lib/dashboard.mjs";

type ScanAttestations = {
  braveTermsAccepted: boolean;
  braveTermsVersion: string;
  braveCustomerResponsibilitiesAccepted: boolean;
  subjectConsentReviewed: boolean;
  authorizedProfileIds: string[];
  authorizedProfileDigests: Record<string, string>;
  authorizedBrokerIds: string[];
};

type RemovalAttestations = {
  rightoutRemovalPolicyAccepted: boolean;
  rightoutRemovalPolicyVersion: string;
  subjectConsentReviewed: boolean;
  smtpAccountAuthorized: boolean;
  minimumDisclosureAccepted: boolean;
  authorizedProfileIds: string[];
  authorizedProfileDigests: Record<string, string>;
  authorizedBrokerIds: string[];
  authorizedRequestKinds: string[];
  smtpTransportDigest: string;
};

type PasswordSmtpTransportConfig = {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  fromAddress: string;
  authMode?: "password";
};

type OauthSmtpTransportConfig = {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  authMode: "oauth2";
  oauthAccessToken: string;
  oauthExpiresAt: string;
  fromAddress: string;
};

type SmtpTransportConfig = PasswordSmtpTransportConfig | OauthSmtpTransportConfig;

type PasswordImapTransportConfig = {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  address: string;
  authMode?: "password";
};

type OauthImapTransportConfig = {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  authMode: "oauth2";
  oauthAccessToken: string;
  oauthExpiresAt: string;
  address: string;
};

type ImapTransportConfig = PasswordImapTransportConfig | OauthImapTransportConfig;

type VerificationAttestations = {
  rightoutVerificationPolicyAccepted: boolean;
  rightoutVerificationPolicyVersion: string;
  subjectConsentReviewed: boolean;
  inboxReadAuthorized: boolean;
  verificationLinkOpenAuthorized: boolean;
  authorizedProfileIds: string[];
  authorizedProfileDigests: Record<string, string>;
  authorizedBrokerIds: string[];
  imapTransportDigest?: string;
  browserProfileDigest?: string;
};

type ControllerReplyAttestations = {
  rightoutControllerReplyPolicyAccepted: boolean;
  rightoutControllerReplyPolicyVersion: string;
  subjectConsentReviewed: boolean;
  inboxReadAuthorized: boolean;
  authorizedProfileIds: string[];
  authorizedProfileDigests: Record<string, string>;
  authorizedBrokerIds: string[];
  imapTransportDigest: string;
};

type FormAttestations = {
  rightoutFormPolicyAccepted: boolean;
  rightoutFormPolicyVersion: string;
  subjectConsentReviewed: boolean;
  browserFormAuthorized: boolean;
  minimumDisclosureAccepted: boolean;
  authorizedProfileIds: string[];
  authorizedProfileDigests: Record<string, string>;
  authorizedBrokerIds: string[];
};

type DirectScanAttestations = {
  rightoutDirectScanPolicyAccepted: boolean;
  rightoutDirectScanPolicyVersion: string;
  subjectConsentReviewed: boolean;
  publisherAccessAuthorized: boolean;
  publisherTermsReviewed: boolean;
  authorizedProfileIds: string[];
  authorizedProfileDigests: Record<string, string>;
  authorizedBrokerIds: string[];
};

type TeamAccessRecord = {
  role: "owner" | "manager" | "viewer";
  sessionBindingDigest: string;
  authorizedProfileIds: string[];
};

type EffectivenessCanary = {
  profileId: string;
  brokerId: string;
  kind: "submission_delivered" | "controller_confirmed" | "direct_absence" | "reappearance";
  observedAt: string;
  proofReference: string;
};

type RightOutConfig = {
  braveApiKey?: string;
  profiles?: Record<string, { payload: string }>;
  operatorAttestations?: ScanAttestations;
  smtpTransport?: SmtpTransportConfig;
  removalAttestations?: RemovalAttestations;
  imapTransport?: ImapTransportConfig;
  verificationAttestations?: VerificationAttestations;
  controllerReplyAttestations?: ControllerReplyAttestations;
  customTargetRecipePacks?: unknown[];
  customTargetTrustedKeys?: Record<string, string>;
  customTargetPermissions?: Record<string, unknown>;
  effectivenessCanaries?: Record<string, EffectivenessCanary[]>;
  teamAccess?: Record<string, TeamAccessRecord>;
  formAttestations?: FormAttestations;
  stateEncryptionKey?: string;
  previousStateEncryptionKeys?: string[];
  stateRetentionDays?: number;
  directScanAttestations?: DirectScanAttestations;
  browserControlBaseUrl?: string;
  browserProfile?: string;
  browserControlToken?: string;
  browserBackendMode?: "managed_openclaw" | "remote_cloud_cdp" | "existing_logged_in_cdp";
  remoteCloudBrowserProfile?: string;
  publisherAutomationPermissions?: Record<string, {
    authorizationReferenceSha256: string;
    termsContractDigest: string;
    reviewedAt: string;
    validUntil: string;
    allowedEffects: ("source_refresh" | "publisher_discover" | "direct_recheck" | "submit_form" | "open_verification")[];
    allowedBrowserBackends: ("managed_openclaw" | "remote_cloud_cdp" | "existing_logged_in_cdp")[];
  }>;
};

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function digestJson(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function resolveBrowserControl(
  toolContext: Record<string, any>,
  config: RightOutConfig | undefined,
  backendOverride?: "managed_openclaw" | "remote_cloud_cdp" | "existing_logged_in_cdp",
) {
  const explicit = config?.browserControlBaseUrl;
  if (explicit !== undefined && config?.browserBackendMode === undefined) {
    throw new Error("rightout_browser_backend_invalid");
  }
  if (explicit !== undefined && typeof config?.browserControlToken !== "string") {
    throw new Error("rightout_browser_control_token_required");
  }
  if (explicit === undefined && config?.browserBackendMode !== undefined && config.browserBackendMode !== "managed_openclaw") {
    throw new Error("rightout_browser_backend_invalid");
  }
  if (explicit !== undefined) {
    let url;
    try { url = new URL(explicit); } catch { throw new Error("rightout_browser_bridge_unavailable"); }
    if (
      url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
      || url.username || url.password || url.search || url.hash
    ) throw new Error("rightout_browser_bridge_unavailable");
  }
  if (config?.browserProfile !== undefined && !/^[A-Za-z0-9._-]{1,64}$/.test(config.browserProfile)) {
    throw new Error("rightout_browser_profile_invalid");
  }
  if (config?.remoteCloudBrowserProfile !== undefined && !/^[A-Za-z0-9._-]{1,64}$/.test(config.remoteCloudBrowserProfile)) {
    throw new Error("rightout_browser_profile_invalid");
  }
  if (config?.browserBackendMode !== undefined && !["managed_openclaw", "remote_cloud_cdp", "existing_logged_in_cdp"].includes(config.browserBackendMode)) {
    throw new Error("rightout_browser_backend_invalid");
  }
  if (
    backendOverride === "remote_cloud_cdp"
    && typeof config?.remoteCloudBrowserProfile === "string"
    && config.remoteCloudBrowserProfile === config.browserProfile
  ) throw new Error("rightout_remote_cloud_profile_not_distinct");
  return {
    bridgeUrl: explicit ?? toolContext.browser?.sandboxBridgeUrl,
    browserProfile: backendOverride === "remote_cloud_cdp" ? config?.remoteCloudBrowserProfile : config?.browserProfile,
    browserAuthToken: config?.browserControlToken,
  };
}

function resolveBrowserBackend(toolContext: Record<string, any>, config: RightOutConfig | undefined) {
  if (config?.browserControlBaseUrl && config.browserBackendMode === undefined) {
    return {
      bridgeUrl: config.browserControlBaseUrl,
      browserProfile: config.browserProfile,
      browserAuthToken: config.browserControlToken,
      selected: "backend_mode_required",
      configured: false,
      supported: ["managed_openclaw", "remote_cloud_cdp", "existing_logged_in_cdp"],
      webmail_ready: false,
      remote_cloud_fallback_ready: false,
    };
  }
  if (config?.browserControlBaseUrl && typeof config.browserControlToken !== "string") {
    return {
      bridgeUrl: config.browserControlBaseUrl,
      browserProfile: config.browserProfile,
      selected: "browser_control_token_required",
      configured: false,
      supported: ["managed_openclaw", "remote_cloud_cdp", "existing_logged_in_cdp"],
      webmail_ready: false,
      remote_cloud_fallback_ready: false,
    };
  }
  if (!config?.browserControlBaseUrl && config?.browserBackendMode !== undefined && config.browserBackendMode !== "managed_openclaw") {
    return {
      selected: "standalone_loopback_required_for_non_managed_backend",
      configured: false,
      supported: ["managed_openclaw", "remote_cloud_cdp", "existing_logged_in_cdp"],
      webmail_ready: false,
      remote_cloud_fallback_ready: false,
    };
  }
  const control = resolveBrowserControl(toolContext, config);
  const hasBridge = typeof control.bridgeUrl === "string";
  const selected = !hasBridge
    ? "unavailable"
    : config?.browserBackendMode
      ?? (config?.browserControlBaseUrl ? "named_profile_unspecified" : "managed_openclaw");
  const needsNamedProfile = ["remote_cloud_cdp", "existing_logged_in_cdp", "named_profile_unspecified"].includes(selected);
  return {
    ...control,
    selected,
    configured: hasBridge && (!needsNamedProfile || typeof control.browserProfile === "string"),
    supported: ["managed_openclaw", "remote_cloud_cdp", "existing_logged_in_cdp"],
    webmail_ready: hasBridge && selected === "existing_logged_in_cdp" && typeof control.browserProfile === "string",
    remote_cloud_fallback_ready: Boolean(config?.browserControlBaseUrl) && hasBridge && selected !== "remote_cloud_cdp"
      && typeof config?.remoteCloudBrowserProfile === "string"
      && config.remoteCloudBrowserProfile !== config.browserProfile,
  };
}

function resolveBrowserControlTransport(toolContext: Record<string, any>, config: RightOutConfig | undefined) {
  if (config?.browserControlBaseUrl) return "standalone_loopback_http_opt_in";
  if (typeof toolContext.browser?.sandboxBridgeUrl === "string") return "openclaw_sandbox_browser_bridge";
  return "unavailable";
}

type ApprovalRoutingScope = {
  browserBackendMode: "managed_openclaw" | "remote_cloud_cdp" | "existing_logged_in_cdp" | "not_required";
  browserControlTransport: "openclaw_sandbox_browser_bridge" | "standalone_loopback_http_opt_in" | "not_required";
  remoteCloudFallback: boolean;
  routingDigest: string;
};

function browserApprovalRoutingScope(
  config: RightOutConfig | undefined,
  { browserRequired, effects = [] }: { browserRequired: boolean; effects?: string[] },
): ApprovalRoutingScope {
  const publisherEffects = effects.some((effect) => ["publisher_discover", "submit_form", "open_verification", "direct_recheck"].includes(effect));
  if (!browserRequired) {
    return {
      browserBackendMode: "not_required",
      browserControlTransport: "not_required",
      remoteCloudFallback: false,
      routingDigest: digestJson({
        version: 1,
        browser: "not_required",
        smtpTransportDigest: effects.includes("submit_email") ? config?.removalAttestations?.smtpTransportDigest ?? null : null,
        imapTransportDigest: effects.includes("poll_verification") ? config?.verificationAttestations?.imapTransportDigest ?? null : null,
        publisherPermissionsDigest: publisherEffects ? digestJson(config?.publisherAutomationPermissions ?? null) : null,
      }),
    };
  }
  // Validate the same configuration contract used immediately before browser I/O.
  resolveBrowserControl({}, config);
  const browserBackendMode = config?.browserBackendMode ?? "managed_openclaw";
  const browserControlTransport = config?.browserControlBaseUrl
    ? "standalone_loopback_http_opt_in"
    : "openclaw_sandbox_browser_bridge";
  const remoteCloudFallback = Boolean(
    config?.browserControlBaseUrl
    && browserBackendMode !== "remote_cloud_cdp"
    && typeof config.remoteCloudBrowserProfile === "string"
    && config.remoteCloudBrowserProfile !== config.browserProfile,
  );
  return {
    browserBackendMode,
    browserControlTransport,
    remoteCloudFallback,
    routingDigest: digestJson({
      version: 1,
      browserControlBaseUrl: config?.browserControlBaseUrl ?? null,
      browserProfile: config?.browserProfile ?? null,
      browserBackendMode,
      remoteCloudBrowserProfile: remoteCloudFallback ? config?.remoteCloudBrowserProfile ?? null : null,
      smtpTransportDigest: effects.includes("submit_email") ? config?.removalAttestations?.smtpTransportDigest ?? null : null,
      imapTransportDigest: effects.includes("poll_verification") ? config?.verificationAttestations?.imapTransportDigest ?? null : null,
      publisherPermissionsDigest: publisherEffects ? digestJson(config?.publisherAutomationPermissions ?? null) : null,
    }),
  };
}

async function probeBrowserBackend(control: {
  bridgeUrl?: string;
  browserProfile?: string;
  browserAuthToken?: string;
}): Promise<{ reachable: boolean; operational: boolean; deep_snapshot: boolean }> {
  if (typeof control.bridgeUrl !== "string") return { reachable: false, operational: false, deep_snapshot: false };
  const url = new URL(control.bridgeUrl);
  url.pathname = `${url.pathname.replace(/\/$/, "")}/doctor`;
  url.search = "";
  url.searchParams.set("deep", "true");
  if (control.browserProfile) url.searchParams.set("profile", control.browserProfile);
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 12_000);
  try {
    const response = await globalThis.fetch(url, {
      method: "GET",
      redirect: "error",
      signal: abort.signal,
      headers: {
        Accept: "application/json",
        ...(control.browserAuthToken ? { Authorization: `Bearer ${control.browserAuthToken}` } : {}),
      },
    });
    if (!response.ok) return { reachable: true, operational: false, deep_snapshot: false };
    const declared = Number(response.headers.get("content-length") || "0");
    if (declared > 128_000) return { reachable: true, operational: false, deep_snapshot: false };
    const body = await response.text();
    if (Buffer.byteLength(body, "utf8") > 128_000) return { reachable: true, operational: false, deep_snapshot: false };
    const report = JSON.parse(body) as Record<string, any>;
    const checks = Array.isArray(report.checks) ? report.checks : [];
    const deep = checks.find((item: any) => item?.id === "live-snapshot");
    return {
      reachable: true,
      operational: report.ok === true && checks.every((item: any) => item?.status !== "fail"),
      deep_snapshot: deep?.status === "pass",
    };
  } catch {
    return { reachable: false, operational: false, deep_snapshot: false };
  } finally {
    clearTimeout(timer);
  }
}

const CampaignIdParameter = Type.Optional(Type.String({
  pattern: "^campaign_[a-f0-9]{32}$",
  description: "Optional bounded standing-authorization reference. When valid, this exact in-scope provider effect runs without another approval prompt.",
}));

const LiveScanParameters = Type.Object(
  {
    profileId: Type.String({
      pattern: "^profile_[a-f0-9]{16,32}$",
      description: "Opaque operator-configured profile reference. Contains no personal data.",
    }),
    brokerIds: Type.Array(Type.String({ pattern: "^[a-z0-9_]{2,24}$" }), { minItems: 1, maxItems: 100, uniqueItems: true }),
    campaignId: CampaignIdParameter,
  },
  { additionalProperties: false },
);

const RemovalParameters = Type.Object(
  {
    profileId: Type.String({
      pattern: "^profile_[a-f0-9]{16,32}$",
      description: "Opaque operator-configured profile reference. Contains no personal data.",
    }),
    brokerId: Type.String({
      pattern: "^[a-z0-9_]{2,24}$",
      description: "Catalog broker with a supported, official email-removal lane.",
    }),
    requestKind: Type.Union([
      Type.Literal("delete_and_opt_out"),
      Type.Literal("gdpr_erasure_objection"),
    ], {
      description: "Catalog-validated US delete/opt-out or EU GDPR erasure/objection request.",
    }),
    campaignId: CampaignIdParameter,
  },
  { additionalProperties: false },
);

const CaseParameters = Type.Object(
  {
    profileId: Type.String({
      pattern: "^profile_[a-f0-9]{16,32}$",
      description: "Opaque operator-configured profile reference. Contains no personal data.",
    }),
  },
  { additionalProperties: false },
);

const DashboardExportParameters = Type.Object(
  {
    format: Type.Union([Type.Literal("html"), Type.Literal("json")], {
      description: "Static private local artifact format. No server or remote asset is created.",
    }),
  },
  { additionalProperties: false },
);

const EmptyParameters = Type.Object({}, { additionalProperties: false });

const ControllerOutcomeParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$", description: "Opaque private profile reference." }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,24}$", description: "Catalog EU or US controller whose response was reviewed by the operator." }),
    outcome: Type.Union([
      Type.Literal("processing_acknowledged"),
      Type.Literal("erasure_confirmed"),
      Type.Literal("partial_erasure"),
      Type.Literal("deletion_confirmed"),
      Type.Literal("partial_deletion"),
      Type.Literal("identity_required"),
      Type.Literal("request_rejected"),
    ], { description: "Human-reviewed controller response outcome; never inferred from SMTP acceptance." }),
    candidateHandle: Type.Optional(Type.String({
      pattern: "^reply_[a-f0-9]{24}$",
      description: "Optional encrypted authenticated-reply candidate that the operator reviewed before approving this outcome.",
    })),
  },
  { additionalProperties: false },
);

const ControllerReplyPollParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$", description: "Opaque private profile reference." }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,24}$", description: "Catalog EU or US controller with an already submitted email request." }),
  },
  { additionalProperties: false },
);

const EvidenceSnapshotParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$" }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,80}$" }),
  },
  { additionalProperties: false },
);

const EvidenceRefParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$" }),
    evidenceRef: Type.String({ pattern: "^evidence_[a-f0-9]{64}$" }),
  },
  { additionalProperties: false },
);

const EvidenceExportParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$" }),
    evidenceRef: Type.String({ pattern: "^evidence_[a-f0-9]{64}$" }),
    format: Type.Union([Type.Literal("json"), Type.Literal("markdown")]),
  },
  { additionalProperties: false },
);

const CustomTargetRefParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$" }),
    customTargetHandle: Type.String({ pattern: "^custom_[a-f0-9]{24}$" }),
  },
  { additionalProperties: false },
);

const SubmissionReconciliationParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$", description: "Opaque private profile reference." }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,24}$", description: "Catalog broker with a durable ambiguous submission intent." }),
    outcome: Type.Union([
      Type.Literal("provider_write_not_started"),
      Type.Literal("provider_write_confirmed"),
    ], { description: "Operator-reviewed reconciliation result; never inferred by the agent." }),
  },
  { additionalProperties: false },
);

const VerificationPollParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$", description: "Opaque private profile reference." }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,24}$", description: "Catalog broker with a verified IMAP lane." }),
    campaignId: CampaignIdParameter,
  },
  { additionalProperties: false },
);

const VerificationOpenParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$", description: "Opaque private profile reference." }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,24}$", description: "Catalog broker bound to the verification handle." }),
    verificationHandle: Type.String({ pattern: "^verify_[a-f0-9]{24}$", description: "Opaque short-lived handle returned by RightOut inbox polling." }),
    campaignId: CampaignIdParameter,
  },
  { additionalProperties: false },
);

const DirectScanParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$", description: "Opaque private profile reference." }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,24}$", description: "Catalog broker bound to the encrypted listing handle." }),
    listingHandle: Type.String({ pattern: "^listing_[a-f0-9]{24}$", description: "Opaque encrypted candidate handle returned by a RightOut live scan." }),
    campaignId: CampaignIdParameter,
  },
  { additionalProperties: false },
);

const CampaignStartParameters = Type.Object(
  {
    profileId: Type.String({
      pattern: "^profile_[a-f0-9]{16,32}$",
      description: "Opaque operator-configured profile reference. Contains no personal data.",
    }),
    brokerIds: Type.Array(Type.String({ pattern: "^[a-z0-9_]{2,80}$" }), {
      minItems: 1,
      maxItems: 200,
      uniqueItems: true,
      description: "Exact catalog broker set covered by this autonomous campaign grant.",
    }),
    effects: Type.Array(Type.Union(CAMPAIGN_EFFECTS.map((value) => Type.Literal(value))), {
      minItems: 1,
      maxItems: CAMPAIGN_EFFECTS.length,
      uniqueItems: true,
      description: "Exact provider-effect classes authorized for autonomous execution.",
    }),
    durationHours: Type.Integer({ minimum: 1, maximum: 720, description: "Standing-authorization lifetime in hours." }),
    maxEffects: Type.Integer({ minimum: 1, maximum: 2000, description: "Hard cap in broker-effect authorization units. One unit authorizes one broker/effect session, which may contain multiple bounded protocol interactions." }),
  },
  { additionalProperties: false },
);

const CampaignRefParameters = Type.Object(
  {
    campaignId: Type.String({ pattern: "^campaign_[a-f0-9]{32}$", description: "Opaque durable autonomous-campaign reference." }),
  },
  { additionalProperties: false },
);

const CampaignNextParameters = Type.Object(
  {
    campaignId: Type.String({ pattern: "^campaign_[a-f0-9]{32}$", description: "Active bounded campaign to advance by one deterministic step." }),
  },
  { additionalProperties: false },
);

const WorkerEnableParameters = Type.Object(
  {
    campaignId: Type.String({ pattern: "^campaign_[a-f0-9]{32}$", description: "Active bounded campaign to advance durably." }),
    intervalMinutes: Type.Integer({ minimum: 5, maximum: 1440, description: "Minimum delay between idle worker turns." }),
    maxConsecutiveFailures: Type.Integer({ minimum: 1, maximum: 10, description: "Hard transient-failure budget before a human gate." }),
  },
  { additionalProperties: false },
);

const WorkerRefParameters = Type.Object(
  { workerId: Type.String({ pattern: "^worker_[a-f0-9]{32}$", description: "Opaque durable autonomy worker reference." }) },
  { additionalProperties: false },
);

const WorkerCompleteParameters = Type.Object(
  {
    workerId: Type.String({ pattern: "^worker_[a-f0-9]{32}$" }),
    leaseId: Type.String({ pattern: "^lease_[a-f0-9]{32}$" }),
    outcome: Type.Union([Type.Literal("action_succeeded"), Type.Literal("transient_failure"), Type.Literal("human_gate")]),
    reason: Type.Optional(Type.String({ pattern: "^[a-z0-9_]{3,120}$" })),
  },
  { additionalProperties: false },
);

const RegistrySearchParameters = Type.Object(
  {
    query: Type.String({ minLength: 2, maxLength: 80, pattern: "^[A-Za-z0-9 .&'_-]+$", description: "Public broker/company name or domain fragment." }),
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 50, default: 20 })),
  },
  { additionalProperties: false },
);

const FormSessionBeginParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$" }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,80}$" }),
    campaignId: Type.String({ pattern: "^campaign_[a-f0-9]{32}$" }),
    listingHandle: Type.Optional(Type.String({ pattern: "^listing_[a-f0-9]{24}$" })),
  },
  { additionalProperties: false },
);

const DiscoverySessionBeginParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$" }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,80}$" }),
    campaignId: Type.String({ pattern: "^campaign_[a-f0-9]{32}$" }),
    browserBackend: Type.Optional(Type.Literal("remote_cloud_cdp")),
  },
  { additionalProperties: false },
);

const FormSessionField = Type.Object({
  ref: Type.String({ pattern: "^[A-Za-z0-9._:-]{1,160}$" }),
  profile_field: Type.String({ pattern: "^[a-z_]{2,32}$" }),
  type: Type.Union([Type.Literal("text"), Type.Literal("email"), Type.Literal("tel"), Type.Literal("url"), Type.Literal("date")]),
}, { additionalProperties: false });

const FormSessionAction = Type.Union([
  Type.Object({ kind: Type.Literal("inspect") }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("fill"), fields: Type.Array(FormSessionField, { minItems: 1, maxItems: 12 }) }, { additionalProperties: false }),
  Type.Object({
    kind: Type.Literal("fill_challenge"),
    ref: Type.String({ pattern: "^[A-Za-z0-9._:-]{1,160}$" }),
  }, { additionalProperties: false }),
  Type.Object({
    kind: Type.Literal("fill_static_text_challenge"),
    ref: Type.String({ pattern: "^[A-Za-z0-9._:-]{1,160}$" }),
    answer: Type.String({ pattern: "^[A-Za-z0-9]{1,12}$" }),
  }, { additionalProperties: false }),
  Type.Object({
    kind: Type.Literal("click"),
    ref: Type.String({ pattern: "^[A-Za-z0-9._:-]{1,160}$" }),
    purpose: Type.Union([
      Type.Literal("continue"), Type.Literal("agree"), Type.Literal("select_record"), Type.Literal("submit"), Type.Literal("suppress"), Type.Literal("confirm"),
    ]),
  }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("record_redacted_state_receipt") }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("close") }, { additionalProperties: false }),
]);

const FormSessionStepParameters = Type.Object(
  {
    sessionId: Type.String({ pattern: "^formsession_[a-f0-9]{24}$" }),
    action: FormSessionAction,
  },
  { additionalProperties: false },
);

const DiscoverySessionAction = Type.Union([
  Type.Object({ kind: Type.Literal("inspect") }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("fill"), fields: Type.Array(FormSessionField, { minItems: 1, maxItems: 12 }) }, { additionalProperties: false }),
  Type.Object({
    kind: Type.Literal("click"),
    ref: Type.String({ pattern: "^[A-Za-z0-9._:-]{1,160}$" }),
    purpose: Type.Union([Type.Literal("continue"), Type.Literal("agree"), Type.Literal("select_record")]),
  }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("record_redacted_state_receipt") }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("capture_candidate") }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal("close") }, { additionalProperties: false }),
]);

const DiscoverySessionStepParameters = Type.Object(
  {
    sessionId: Type.String({ pattern: "^discoverysession_[a-f0-9]{24}$" }),
    action: DiscoverySessionAction,
  },
  { additionalProperties: false },
);

const ParityEmailParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$" }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,80}$" }),
    campaignId: Type.String({ pattern: "^campaign_[a-f0-9]{32}$" }),
    listingHandle: Type.Optional(Type.String({ pattern: "^listing_[a-f0-9]{24}$" })),
  },
  { additionalProperties: false },
);

const WebmailSessionStepParameters = Type.Object(
  {
    sessionId: Type.String({ pattern: "^webmailsession_[a-f0-9]{24}$" }),
    action: Type.Union([
      Type.Object({ kind: Type.Literal("inspect") }, { additionalProperties: false }),
      Type.Object({ kind: Type.Literal("fill"), fields: Type.Array(FormSessionField, { minItems: 1, maxItems: 3 }) }, { additionalProperties: false }),
      Type.Object({
        kind: Type.Literal("click"),
        ref: Type.String({ pattern: "^[A-Za-z0-9._:-]{1,160}$" }),
        purpose: Type.Union([
          Type.Literal("send"), Type.Literal("open_message"),
          Type.Literal("inspect_authentication"), Type.Literal("open_confirmation"),
        ]),
      }, { additionalProperties: false }),
      Type.Object({ kind: Type.Literal("record_redacted_state_receipt") }, { additionalProperties: false }),
      Type.Object({ kind: Type.Literal("close") }, { additionalProperties: false }),
    ]),
  },
  { additionalProperties: false },
);

const WebmailVerificationBeginParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$" }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,80}$" }),
    campaignId: Type.String({ pattern: "^campaign_[a-f0-9]{32}$" }),
  },
  { additionalProperties: false },
);

async function loadCatalog(path: string): Promise<Record<string, unknown>> {
  const text = await readFile(path, { encoding: "utf-8" });
  return JSON.parse(text) as Record<string, unknown>;
}

function catalogDigest(catalog: Record<string, unknown>): string {
  return createHash("sha256").update(JSON.stringify(catalog)).digest("hex");
}

function assertCampaignCatalogScope(catalog: Record<string, unknown>, input: PublicCampaignStartInput): void {
  const rows = Array.isArray(catalog.brokers) ? catalog.brokers : [];
  const known = new Set(rows.flatMap((row) => (
    row && typeof row === "object" && !Array.isArray(row) && typeof (row as Record<string, unknown>).id === "string"
      ? [(row as Record<string, unknown>).id as string]
      : []
  )));
  if (input.brokerIds.some((brokerId) => !known.has(brokerId))) throw new Error("rightout_campaign_scope_invalid");
}

type PublicScanInput = { profileId: string; brokerIds: string[] };
type PublicRemovalInput = { profileId: string; brokerId: string; requestKind: "delete_and_opt_out" | "gdpr_erasure_objection" };
type PublicCaseInput = { profileId: string };
type PublicDashboardExportInput = { format: "html" | "json" };
type PublicControllerOutcomeInput = PublicCaseInput & {
  brokerId: string;
  outcome: "processing_acknowledged" | "erasure_confirmed" | "partial_erasure" | "deletion_confirmed" | "partial_deletion" | "identity_required" | "request_rejected";
  candidateHandle?: string;
};
type PublicControllerReplyInput = PublicCaseInput & { brokerId: string };
type PublicEvidenceRefInput = PublicCaseInput & { evidenceRef: string };
type PublicEvidenceExportInput = PublicEvidenceRefInput & { format: "json" | "markdown" };
type PublicCustomTargetRefInput = PublicCaseInput & { customTargetHandle: string };
type PublicSubmissionReconciliationInput = PublicCaseInput & {
  brokerId: string;
  outcome: "provider_write_not_started" | "provider_write_confirmed";
};
type PublicVerificationPollInput = { profileId: string; brokerId: string };
type PublicVerificationOpenInput = PublicVerificationPollInput & { verificationHandle: string };
type PublicDirectScanInput = PublicVerificationPollInput & { listingHandle: string };
type PublicCampaignStartInput = {
  profileId: string;
  brokerIds: string[];
  effects: string[];
  durationHours: number;
  maxEffects: number;
};
type PublicCampaignRefInput = { campaignId: string };
type PublicWorkerEnableInput = { campaignId: string; intervalMinutes: number; maxConsecutiveFailures: number };
type PublicWorkerRefInput = { workerId: string };
type PublicWorkerCompleteInput = PublicWorkerRefInput & {
  leaseId: string;
  outcome: "action_succeeded" | "transient_failure" | "human_gate";
  reason?: string;
};
type PublicFormSessionBeginInput = {
  profileId: string;
  brokerId: string;
  campaignId: string;
  listingHandle?: string;
};
type PublicDiscoverySessionBeginInput = {
  profileId: string;
  brokerId: string;
  campaignId: string;
  browserBackend?: "remote_cloud_cdp";
};
type ScanAttestationSnapshot = {
  braveTermsAccepted: true;
  braveTermsVersion: string;
  braveCustomerResponsibilitiesAccepted: true;
  subjectConsentReviewed: true;
  authorizedProfileIds: string[];
  authorizedProfileDigests: Record<string, string>;
  authorizedBrokerIds: string[];
};
type RemovalAttestationSnapshot = {
  rightoutRemovalPolicyAccepted: true;
  rightoutRemovalPolicyVersion: string;
  subjectConsentReviewed: true;
  smtpAccountAuthorized: true;
  minimumDisclosureAccepted: true;
  authorizedProfileIds: string[];
  authorizedProfileDigests: Record<string, string>;
  authorizedBrokerIds: string[];
  authorizedRequestKinds: string[];
  smtpTransportDigest: string;
};
type ApprovalBinding = { binding: string; expiresAt: number; toolName: string };
type VerificationToken = {
  profileId: string;
  brokerId: string;
  url: string;
  allowedDomains: string[];
  messageReference: string;
  submissionAt: string;
  submissionReference: string;
  createdAt: string;
};
type ControllerReplyCandidate = {
  profileId: string;
  brokerId: string;
  outcome: PublicControllerOutcomeInput["outcome"];
  messageReference: string;
  submissionReference: string;
  terminal: boolean;
  evidenceSignals: string[];
  authenticationSignals: string[];
  createdAt: string;
};

type CampaignEffect = { brokerId: string; effect: string };

function validateWorkerEnableInput(value: unknown): PublicWorkerEnableInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_worker_input_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).length !== 3 || Object.keys(input).some((key) => !["campaignId", "intervalMinutes", "maxConsecutiveFailures"].includes(key))) {
    throw new Error("rightout_worker_input_invalid");
  }
  if (typeof input.campaignId !== "string" || !/^campaign_[a-f0-9]{32}$/.test(input.campaignId)) throw new Error("rightout_worker_input_invalid");
  if (!Number.isInteger(input.intervalMinutes) || Number(input.intervalMinutes) < 5 || Number(input.intervalMinutes) > 1_440) throw new Error("rightout_worker_input_invalid");
  if (!Number.isInteger(input.maxConsecutiveFailures) || Number(input.maxConsecutiveFailures) < 1 || Number(input.maxConsecutiveFailures) > 10) {
    throw new Error("rightout_worker_input_invalid");
  }
  return input as unknown as PublicWorkerEnableInput;
}

function validateWorkerRefInput(value: unknown): PublicWorkerRefInput {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 1) throw new Error("rightout_worker_ref_invalid");
  const input = value as Record<string, unknown>;
  if (typeof input.workerId !== "string" || !/^worker_[a-f0-9]{32}$/.test(input.workerId)) throw new Error("rightout_worker_ref_invalid");
  return input as PublicWorkerRefInput;
}

function validateWorkerCompleteInput(value: unknown): PublicWorkerCompleteInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_worker_completion_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["workerId", "leaseId", "outcome", "reason"].includes(key))) throw new Error("rightout_worker_completion_invalid");
  validateWorkerRefInput({ workerId: input.workerId });
  if (typeof input.leaseId !== "string" || !/^lease_[a-f0-9]{32}$/.test(input.leaseId)) throw new Error("rightout_worker_completion_invalid");
  if (!["action_succeeded", "transient_failure", "human_gate"].includes(String(input.outcome))) throw new Error("rightout_worker_completion_invalid");
  if (input.reason !== undefined && (typeof input.reason !== "string" || !/^[a-z0-9_]{3,120}$/.test(input.reason))) {
    throw new Error("rightout_worker_completion_invalid");
  }
  return input as unknown as PublicWorkerCompleteInput;
}

function splitCampaignParams(value: unknown): { campaignId?: string; params: Record<string, unknown> } {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_campaign_effect_invalid");
  const record = value as Record<string, unknown>;
  const { campaignId, ...params } = record;
  if (campaignId === undefined) return { params };
  if (typeof campaignId !== "string" || !/^campaign_[a-f0-9]{32}$/.test(campaignId)) {
    throw new Error("rightout_campaign_effect_invalid");
  }
  return { campaignId, params };
}

function assertSessionActionShape(action: unknown, mode: "form" | "discovery" | "webmail"): asserts action is Record<string, any> {
  const fail = () => { throw new Error(`rightout_${mode}_session_input_invalid`); };
  if (!action || typeof action !== "object" || Array.isArray(action)) fail();
  const value = action as Record<string, any>;
  if (typeof value.kind !== "string") fail();
  if (["inspect", "record_redacted_state_receipt", "close"].includes(value.kind)) {
    if (Object.keys(value).length !== 1) fail();
    return;
  }
  if (mode === "discovery" && value.kind === "capture_candidate") {
    if (Object.keys(value).length !== 1) fail();
    return;
  }
  if (value.kind === "fill") {
    if (Object.keys(value).length !== 2 || !Array.isArray(value.fields) || value.fields.length < 1 || value.fields.length > (mode === "webmail" ? 3 : 12)) fail();
    const refs = new Set<string>();
    const profileFields = new Set<string>();
    for (const field of value.fields) {
      if (
        !field || typeof field !== "object" || Array.isArray(field)
        || Object.keys(field).length !== 3 || Object.keys(field).some((key) => !["ref", "profile_field", "type"].includes(key))
        || typeof field.ref !== "string" || !/^[A-Za-z0-9._:-]{1,160}$/.test(field.ref)
        || typeof field.profile_field !== "string" || !/^[a-z_]{2,32}$/.test(field.profile_field)
        || !["text", "email", "tel", "url", "date"].includes(field.type)
        || refs.has(field.ref) || profileFields.has(field.profile_field)
      ) fail();
      refs.add(field.ref);
      profileFields.add(field.profile_field);
    }
    return;
  }
  if (mode === "form" && value.kind === "fill_challenge") {
    if (
      Object.keys(value).length !== 2 || typeof value.ref !== "string" || !/^[A-Za-z0-9._:-]{1,160}$/.test(value.ref)
    ) fail();
    return;
  }
  if (mode === "form" && value.kind === "fill_static_text_challenge") {
    if (
      Object.keys(value).length !== 3 || typeof value.ref !== "string" || !/^[A-Za-z0-9._:-]{1,160}$/.test(value.ref)
      || typeof value.answer !== "string" || !/^[A-Za-z0-9]{1,12}$/.test(value.answer)
    ) fail();
    return;
  }
  if (value.kind === "click") {
    const purposes = mode === "webmail" ? ["send", "open_message", "inspect_authentication", "open_confirmation"]
      : mode === "discovery" ? ["continue", "agree", "select_record"]
      : ["continue", "agree", "select_record", "submit", "suppress", "confirm"];
    if (
      Object.keys(value).length !== 3 || typeof value.ref !== "string" || !/^[A-Za-z0-9._:-]{1,160}$/.test(value.ref)
      || typeof value.purpose !== "string" || !purposes.includes(value.purpose)
    ) fail();
    return;
  }
  fail();
}

function validateFormSessionBeginInput(value: unknown): PublicFormSessionBeginInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_form_session_input_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["profileId", "brokerId", "campaignId", "listingHandle"].includes(key))) {
    throw new Error("rightout_form_session_input_invalid");
  }
  if (typeof input.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(input.profileId)) throw new Error("rightout_form_session_input_invalid");
  if (typeof input.brokerId !== "string" || !/^[a-z0-9_]{2,80}$/.test(input.brokerId)) throw new Error("rightout_form_session_input_invalid");
  if (typeof input.campaignId !== "string" || !/^campaign_[a-f0-9]{32}$/.test(input.campaignId)) throw new Error("rightout_form_session_input_invalid");
  if (input.listingHandle !== undefined && (typeof input.listingHandle !== "string" || !/^listing_[a-f0-9]{24}$/.test(input.listingHandle))) {
    throw new Error("rightout_form_session_input_invalid");
  }
  return input as PublicFormSessionBeginInput;
}

function validateFormSessionStepInput(value: unknown): { sessionId: string; action: Record<string, any> } {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_form_session_input_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["sessionId", "action"].includes(key)) || Object.keys(input).length !== 2) {
    throw new Error("rightout_form_session_input_invalid");
  }
  if (typeof input.sessionId !== "string" || !/^formsession_[a-f0-9]{24}$/.test(input.sessionId)) throw new Error("rightout_form_session_input_invalid");
  assertSessionActionShape(input.action, "form");
  return { sessionId: input.sessionId, action: input.action as Record<string, any> };
}

function validateDiscoverySessionBeginInput(value: unknown): PublicDiscoverySessionBeginInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_discovery_session_input_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["profileId", "brokerId", "campaignId", "browserBackend"].includes(key)) || ![3, 4].includes(Object.keys(input).length)) {
    throw new Error("rightout_discovery_session_input_invalid");
  }
  if (typeof input.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(input.profileId)) throw new Error("rightout_discovery_session_input_invalid");
  if (typeof input.brokerId !== "string" || !/^[a-z0-9_]{2,80}$/.test(input.brokerId)) throw new Error("rightout_discovery_session_input_invalid");
  if (typeof input.campaignId !== "string" || !/^campaign_[a-f0-9]{32}$/.test(input.campaignId)) throw new Error("rightout_discovery_session_input_invalid");
  if (input.browserBackend !== undefined && input.browserBackend !== "remote_cloud_cdp") throw new Error("rightout_discovery_session_input_invalid");
  return input as PublicDiscoverySessionBeginInput;
}

function validateDiscoverySessionStepInput(value: unknown): { sessionId: string; action: Record<string, any> } {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_discovery_session_input_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["sessionId", "action"].includes(key)) || Object.keys(input).length !== 2) {
    throw new Error("rightout_discovery_session_input_invalid");
  }
  if (typeof input.sessionId !== "string" || !/^discoverysession_[a-f0-9]{24}$/.test(input.sessionId)) throw new Error("rightout_discovery_session_input_invalid");
  assertSessionActionShape(input.action, "discovery");
  return { sessionId: input.sessionId, action: input.action as Record<string, any> };
}

function validateWebmailSessionStepInput(value: unknown): { sessionId: string; action: Record<string, any> } {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_webmail_session_input_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["sessionId", "action"].includes(key)) || Object.keys(input).length !== 2) {
    throw new Error("rightout_webmail_session_input_invalid");
  }
  if (typeof input.sessionId !== "string" || !/^webmailsession_[a-f0-9]{24}$/.test(input.sessionId)) throw new Error("rightout_webmail_session_input_invalid");
  assertSessionActionShape(input.action, "webmail");
  return { sessionId: input.sessionId, action: input.action as Record<string, any> };
}

function validateWebmailVerificationBeginInput(value: unknown): { profileId: string; brokerId: string; campaignId: string } {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_webmail_verification_input_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["profileId", "brokerId", "campaignId"].includes(key)) || Object.keys(input).length !== 3) throw new Error("rightout_webmail_verification_input_invalid");
  if (typeof input.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(input.profileId)) throw new Error("rightout_webmail_verification_input_invalid");
  if (typeof input.brokerId !== "string" || !/^[a-z0-9_]{2,80}$/.test(input.brokerId)) throw new Error("rightout_webmail_verification_input_invalid");
  if (typeof input.campaignId !== "string" || !/^campaign_[a-f0-9]{32}$/.test(input.campaignId)) throw new Error("rightout_webmail_verification_input_invalid");
  return input as { profileId: string; brokerId: string; campaignId: string };
}

function scanScopeBinding(input: PublicScanInput, attestations: ScanAttestationSnapshot): string {
  return JSON.stringify(["scan", input.profileId, input.brokerIds, attestations]);
}

function removalDedupeKey(input: PublicRemovalInput): string {
  return `dedupe_${createHash("sha256").update(JSON.stringify([input.profileId, input.brokerId, input.requestKind])).digest("hex")}`;
}

function validateCaseInput(value: unknown): PublicCaseInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_profile_ref");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).length !== 1 || typeof input.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(input.profileId)) {
    throw new Error("invalid_profile_ref");
  }
  return { profileId: input.profileId };
}

function validateDashboardExportInput(value: unknown): PublicDashboardExportInput {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 1) {
    throw new Error("rightout_dashboard_input_invalid");
  }
  const input = value as Record<string, unknown>;
  if (!new Set(["html", "json"]).has(String(input.format))) throw new Error("rightout_dashboard_input_invalid");
  return input as PublicDashboardExportInput;
}

function dashboardExportScopeBinding(input: PublicDashboardExportInput, member: Record<string, any>, sessionBindingDigest: string): string {
  const clean = validateDashboardExportInput(input);
  if (
    !/^member_[a-f0-9]{16,32}$/.test(member?.member_id ?? "")
    || !["owner", "manager"].includes(member?.role)
    || !Array.isArray(member?.authorized_profile_ids) || member.authorized_profile_ids.length < 1
    || member.authorized_profile_ids.some((profileId: unknown) => typeof profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(profileId))
    || !/^[a-f0-9]{64}$/.test(sessionBindingDigest)
  ) {
    throw new Error("rightout_team_session_unauthorized");
  }
  return JSON.stringify([
    "rightout_dashboard_export_v1",
    clean.format,
    member.member_id,
    member.role,
    [...member.authorized_profile_ids].sort(),
    sessionBindingDigest,
  ]);
}

function purgeScopeBinding(input: PublicCaseInput): string {
  return JSON.stringify(["purge_subject_state", validateCaseInput(input).profileId]);
}

function rotationScopeBinding(): string {
  return JSON.stringify(["rotate_state_key", "all_rightout_encrypted_state"]);
}

function workerEnableScopeBinding(input: PublicWorkerEnableInput, policyDigest: string, sessionBindingDigest: string): string {
  const clean = validateWorkerEnableInput(input);
  if (![policyDigest, sessionBindingDigest].every((value) => /^[a-f0-9]{64}$/.test(value))) throw new Error("rightout_worker_policy_invalid");
  return JSON.stringify(["rightout_worker_enable_v1", clean, policyDigest, sessionBindingDigest]);
}

function workerResumeScopeBinding(input: PublicWorkerRefInput, policyDigest: string, sessionBindingDigest: string): string {
  const clean = validateWorkerRefInput(input);
  if (![policyDigest, sessionBindingDigest].every((value) => /^[a-f0-9]{64}$/.test(value))) throw new Error("rightout_worker_policy_invalid");
  return JSON.stringify(["rightout_worker_resume_v1", clean.workerId, policyDigest, sessionBindingDigest]);
}

function sensitiveFormStepScopeBinding(session: Record<string, any>, input: { sessionId: string; action: Record<string, any> }): string {
  const fields = Array.isArray(input.action?.fields)
    ? input.action.fields.map((field: Record<string, any>) => session.fieldDisclosureMap?.[field.profile_field]).filter(Boolean).sort()
    : [];
  if (!fields.includes("date_of_birth")) throw new Error("rightout_sensitive_form_gate_not_required");
  return JSON.stringify([
    "sensitive_form_disclosure_v2",
    input.sessionId,
    session.profileId,
    session.brokerId,
    session.campaignId,
    session.stage ?? "generic",
    session.broker.action_url,
    fields,
  ]);
}

function dropFiledScopeBinding(profileId: string, registryCount: number): string {
  if (!/^profile_[a-f0-9]{16,32}$/.test(profileId) || !Number.isInteger(registryCount) || registryCount < 1) throw new Error("rightout_drop_attestation_invalid");
  return JSON.stringify(["california_drop_filed_v1", profileId, registryCount, "2026-08-01"]);
}

function assertSupportedBrokerScope(catalog: Record<string, unknown>, input: PublicScanInput): void {
  const brokers = Array.isArray(catalog.brokers) ? catalog.brokers : [];
  for (const brokerId of input.brokerIds) {
    const broker = brokers.find((value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) return false;
      const entry = value as Record<string, unknown>;
      const scan = entry.scan as Record<string, unknown> | undefined;
      return entry.id === brokerId
        && ["people_search", "data_broker"].includes(String(entry.category))
        && scan?.supported === true
        && scan.automated_access_policy === "search_index_only_no_publisher_access";
    });
    if (!broker) throw new Error("unsupported_broker");
  }
}

function scanAttestationSnapshot(config: RightOutConfig | undefined, input: PublicScanInput): ScanAttestationSnapshot {
  return validateOperatorAttestations(input, config?.operatorAttestations) as ScanAttestationSnapshot;
}

function removalAttestationSnapshot(config: RightOutConfig | undefined, input: PublicRemovalInput): RemovalAttestationSnapshot {
  return validateRemovalOperatorAttestations(input, config?.removalAttestations) as RemovalAttestationSnapshot;
}

function isSecretRef(value: unknown): boolean {
  if (typeof value === "string") return /^\$\{?[A-Z][A-Z0-9_]*\}?$/.test(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const ref = value as Record<string, unknown>;
  return ["env", "file", "exec"].includes(String(ref.source))
    && typeof ref.provider === "string"
    && typeof ref.id === "string";
}

function validateControllerOutcomeInput(value: unknown): PublicControllerOutcomeInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_controller_outcome");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["profileId", "brokerId", "outcome", "candidateHandle"].includes(key))) throw new Error("invalid_controller_outcome");
  if (typeof input.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(input.profileId)) throw new Error("invalid_controller_outcome");
  if (typeof input.brokerId !== "string" || !/^[a-z0-9_]{2,24}$/.test(input.brokerId)) throw new Error("invalid_controller_outcome");
  if (!["processing_acknowledged", "erasure_confirmed", "partial_erasure", "deletion_confirmed", "partial_deletion", "identity_required", "request_rejected"].includes(String(input.outcome))) {
    throw new Error("invalid_controller_outcome");
  }
  if (input.candidateHandle !== undefined && (typeof input.candidateHandle !== "string" || !/^reply_[a-f0-9]{24}$/.test(input.candidateHandle))) {
    throw new Error("invalid_controller_outcome");
  }
  return input as PublicControllerOutcomeInput;
}

function controllerOutcomeScopeBinding(input: PublicControllerOutcomeInput, broker: unknown, candidate?: ControllerReplyCandidate): string {
  return JSON.stringify(["controller-outcome", input, broker, candidate ?? null]);
}

function validateControllerReplyInput(value: unknown): PublicControllerReplyInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_controller_reply_input_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["profileId", "brokerId"].includes(key))) throw new Error("rightout_controller_reply_input_invalid");
  if (typeof input.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(input.profileId)) throw new Error("rightout_controller_reply_input_invalid");
  if (typeof input.brokerId !== "string" || !/^[a-z0-9_]{2,24}$/.test(input.brokerId)) throw new Error("rightout_controller_reply_input_invalid");
  return input as PublicControllerReplyInput;
}

function validateEvidenceRefInput(value: unknown, exporting = false): PublicEvidenceRefInput | PublicEvidenceExportInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("rightout_evidence_ref_invalid");
  const input = value as Record<string, unknown>;
  const allowed = exporting ? ["profileId", "evidenceRef", "format"] : ["profileId", "evidenceRef"];
  if (Object.keys(input).some((key) => !allowed.includes(key)) || Object.keys(input).length !== allowed.length) throw new Error("rightout_evidence_ref_invalid");
  if (typeof input.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(input.profileId)) throw new Error("rightout_evidence_ref_invalid");
  if (typeof input.evidenceRef !== "string" || !/^evidence_[a-f0-9]{64}$/.test(input.evidenceRef)) throw new Error("rightout_evidence_ref_invalid");
  if (exporting && !["json", "markdown"].includes(String(input.format))) throw new Error("rightout_evidence_ref_invalid");
  return input as PublicEvidenceRefInput | PublicEvidenceExportInput;
}

function validateEvidenceSnapshotInput(value: unknown): PublicControllerReplyInput {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 2) throw new Error("rightout_evidence_scope_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["profileId", "brokerId"].includes(key))) throw new Error("rightout_evidence_scope_invalid");
  if (typeof input.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(input.profileId)) throw new Error("rightout_evidence_scope_invalid");
  if (typeof input.brokerId !== "string" || !/^[a-z0-9_]{2,80}$/.test(input.brokerId)) throw new Error("rightout_evidence_scope_invalid");
  return input as PublicControllerReplyInput;
}

function validateCustomTargetRefInput(value: unknown): PublicCustomTargetRefInput {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 2) throw new Error("rightout_custom_target_ref_invalid");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["profileId", "customTargetHandle"].includes(key))) throw new Error("rightout_custom_target_ref_invalid");
  if (typeof input.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(input.profileId)) throw new Error("rightout_custom_target_ref_invalid");
  if (typeof input.customTargetHandle !== "string" || !/^custom_[a-f0-9]{24}$/.test(input.customTargetHandle)) throw new Error("rightout_custom_target_ref_invalid");
  return input as PublicCustomTargetRefInput;
}

function evidenceExportScopeBinding(input: PublicEvidenceExportInput): string {
  return JSON.stringify(["rightout-evidence-export-v1", input]);
}

function validateSubmissionReconciliationInput(value: unknown): PublicSubmissionReconciliationInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_submission_reconciliation");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["profileId", "brokerId", "outcome"].includes(key))) throw new Error("invalid_submission_reconciliation");
  if (typeof input.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(input.profileId)) throw new Error("invalid_submission_reconciliation");
  if (typeof input.brokerId !== "string" || !/^[a-z0-9_]{2,24}$/.test(input.brokerId)) throw new Error("invalid_submission_reconciliation");
  if (!["provider_write_not_started", "provider_write_confirmed"].includes(String(input.outcome))) throw new Error("invalid_submission_reconciliation");
  return input as PublicSubmissionReconciliationInput;
}

function resolveSubmissionReconciliationBroker(catalog: Record<string, unknown>, input: PublicSubmissionReconciliationInput) {
  const rows = Array.isArray(catalog.brokers) ? catalog.brokers : [];
  const raw = rows.find((value) => value && typeof value === "object" && !Array.isArray(value) && (value as Record<string, unknown>).id === input.brokerId) as Record<string, any> | undefined;
  if (!raw || raw.removal?.supported !== true || !["email", "browser_form"].includes(raw.removal.channel)) {
    throw new Error("unsupported_submission_reconciliation_lane");
  }
  return {
    id: raw.id as string,
    name: String(raw.name),
    channel: raw.removal.channel as "email" | "browser_form",
    requestKind: String(raw.removal.request_kinds?.[0]),
    processingDays: Number(raw.removal.processing_days ?? 14),
  };
}

function resolveControllerOutcomeBroker(catalog: Record<string, unknown>, input: PublicControllerOutcomeInput) {
  const rows = Array.isArray(catalog.brokers) ? catalog.brokers : [];
  const raw = rows.find((value) => value && typeof value === "object" && !Array.isArray(value) && (value as Record<string, unknown>).id === input.brokerId) as Record<string, any> | undefined;
  if (!raw || raw.removal?.confirmation_policy !== "submitted_until_controller_response") {
    throw new Error("unsupported_controller_outcome_lane");
  }
  const requestKind = raw.process_class === "eu_controller_email_erasure"
    ? "gdpr_erasure_objection"
    : raw.process_class === "us_data_broker_email_deletion"
      ? "delete_and_opt_out"
      : null;
  if (!requestKind) throw new Error("unsupported_controller_outcome_lane");
  const euOnly = new Set(["erasure_confirmed", "partial_erasure"]);
  const usOnly = new Set(["deletion_confirmed", "partial_deletion"]);
  if (
    (raw.process_class === "eu_controller_email_erasure" && usOnly.has(input.outcome))
    || (raw.process_class === "us_data_broker_email_deletion" && euOnly.has(input.outcome))
  ) throw new Error("unsupported_controller_outcome_lane");
  return resolveRemovalCatalogEntry(catalog, {
    profileId: input.profileId,
    brokerId: input.brokerId,
    requestKind,
  });
}

function submissionReconciliationScopeBinding(input: PublicSubmissionReconciliationInput, broker: unknown): string {
  return JSON.stringify(["submission-reconciliation", input, broker]);
}

function paritySourceRefreshScopeBinding(routeIds: string[], permissionDigest: string): string {
  if (
    !Array.isArray(routeIds) || routeIds.length < 1 || routeIds.some((id) => !/^[a-z0-9_]{2,80}$/.test(id))
    || typeof permissionDigest !== "string" || !/^[a-f0-9]{64}$/.test(permissionDigest)
  ) throw new Error("rightout_parity_source_refresh_scope_invalid");
  return JSON.stringify(["parity-source-refresh-v2", routeIds, permissionDigest, "bounded_https_get", "pii_free_local_health_write"]);
}

function registryRefreshScopeBinding(): string {
  return JSON.stringify(["registry-refresh-v1", "cppa.ca.gov", "bounded_https_get", 2025, new Date().getUTCFullYear(), "encrypted_local_snapshot_write"]);
}

function secretFinding(rightout: Record<string, any> | undefined, path: string, title: string) {
  const parts = path.split(".");
  let value: any = rightout;
  for (const part of parts) value = value?.[part];
  if (value === undefined || isSecretRef(value)) return undefined;
  return {
    checkId: `rightout.secretref.${path.replaceAll(".", "_")}`,
    severity: "critical" as const,
    title,
    detail: `The configured ${path} value is not an OpenClaw SecretRef.`,
    remediation: `Migrate plugins.entries.rightout.config.${path} to a SecretRef, scrub plaintext residue, and run openclaw secrets audit --check.`,
  };
}

export default definePluginEntry({
  id: "rightout",
  name: "RightOut",
  description: "Bounded autonomous and assisted data-broker discovery, removal, verification, registry, and recheck campaigns",
  register(api) {
    const approvalBindings = new Map<string, ApprovalBinding>();
    const workerEffectCalls = new Map<string, { workerId: string; leaseId: string; executionDigest: string }>();
    const submittedScopes = new Map<string, number>();
    const approvalTtlMs = 120_000;
    const duplicateCooldownMs = 24 * 60 * 60_000;
    const catalogPath = api.resolvePath("skills/data-broker-removal/references/brokers/core.json");
    const catalogPromise = loadCatalog(catalogPath);
    const parityCatalogPath = api.resolvePath("skills/data-broker-removal/references/brokers/unbroker-parity.json");
    const parityCatalogRawPromise = loadCatalog(parityCatalogPath);
    const parityCatalogPromise = parityCatalogRawPromise.then((value) => validateParityCatalog(value));
    const parityCatalogSourceShaPromise = readFile(parityCatalogPath)
      .then((value) => createHash("sha256").update(value).digest("hex"));
    const recipeManifestPath = api.resolvePath("skills/data-broker-removal/references/brokers/recipe-pack.json");
    let recipePackPromise: Promise<Record<string, any>> | undefined;
    const loadRecipePack = () => {
      recipePackPromise ??= Promise.all([
        parityCatalogRawPromise,
        loadCatalog(recipeManifestPath),
        parityCatalogSourceShaPromise,
      ]).then(([catalog, manifest, sourceSha256]) => compileBuiltinRecipePack(catalog, manifest, { sourceSha256 }));
      return recipePackPromise;
    };
    const providerTermsPath = api.resolvePath("skills/data-broker-removal/references/brokers/provider-terms.json");
    const providerTermsPromise = loadCatalog(providerTermsPath).then((value) => validateProviderTermsCatalog(value));
    const campaignCatalogDigestPromise = Promise.all([catalogPromise, parityCatalogPromise, providerTermsPromise])
      .then(([core, parity, providerTerms]) => createHash("sha256").update(JSON.stringify([core, parity, providerTerms])).digest("hex"));

    async function assertCampaignPublisherPermissions(input: PublicCampaignStartInput, routingScope: ApprovalRoutingScope): Promise<void> {
      const publisherAccessEffects = new Set(["publisher_discover", "submit_form", "open_verification", "direct_recheck"]);
      const requestedPublisherEffects = input.effects.filter((effect) => publisherAccessEffects.has(effect));
      if (!requestedPublisherEffects.length) return;
      const [parity, providerTerms] = await Promise.all([parityCatalogPromise, providerTermsPromise]);
      const config = api.pluginConfig as RightOutConfig | undefined;
      for (const brokerId of input.brokerIds) {
        const broker = resolveParityBroker(parity, brokerId);
        for (const effect of requestedPublisherEffects) {
          const browserEffect = ["publisher_discover", "submit_form"].includes(effect)
            || (effect === "open_verification" && broker.id === "intelius");
          if (browserEffect) {
            if (routingScope.browserBackendMode === "not_required") throw new Error("rightout_browser_backend_invalid");
            assertPublisherAutomationPermission(config, broker, providerTerms, effect, { browserBackend: routingScope.browserBackendMode });
            if (routingScope.remoteCloudFallback && routingScope.browserBackendMode !== "remote_cloud_cdp") {
              assertPublisherAutomationPermission(config, broker, providerTerms, effect, { browserBackend: "remote_cloud_cdp" });
            }
          } else {
            assertPublisherAutomationPermission(config, broker, providerTerms, effect);
          }
        }
      }
    }

    async function paritySourceApprovalScope(config: RightOutConfig | undefined): Promise<{ routeIds: string[]; permissionDigest: string }> {
      const [parity, providerTerms] = await Promise.all([parityCatalogPromise, providerTermsPromise]);
      const grants = [];
      for (const route of parity.brokers) {
        try {
          grants.push(assertPublisherAutomationPermission(config, route, providerTerms, "source_refresh"));
        } catch { /* unpermitted routes remain skipped */ }
      }
      const routeIds = grants.map((grant) => grant.broker_id).sort();
      if (!routeIds.length) throw new Error("rightout_publisher_automation_not_authorized");
      return { routeIds, permissionDigest: digestJson(grants.sort((a, b) => a.broker_id.localeCompare(b.broker_id))) };
    }

    async function providerAuthorizationHealth(config: RightOutConfig | undefined) {
      const [parity, providerTerms] = await Promise.all([parityCatalogPromise, providerTermsPromise]);
      let routingScope: ApprovalRoutingScope | undefined;
      try {
        routingScope = browserApprovalRoutingScope(config, {
          browserRequired: true,
          effects: ["publisher_discover", "submit_form", "open_verification"],
        });
      } catch { /* invalid browser routing leaves browser effects closed */ }
      const effects = ["source_refresh", "publisher_discover", "direct_recheck", "submit_form", "open_verification"];
      const brokerIdsByEffect: Record<string, string[]> = Object.fromEntries(effects.map((effect) => [effect, []]));
      for (const route of parity.brokers) {
        for (const effect of effects) {
          const sourceExecutable = !String(route.source_status).startsWith("needs_evidence")
            && route.source_status !== "observed_official_archive_external_unavailable";
          const applicable = effect === "source_refresh"
            || (effect === "submit_form" && route.method === "web_form" && sourceExecutable)
            || (effect === "publisher_discover" && sourceExecutable)
            || (effect === "direct_recheck" && sourceExecutable)
            || (effect === "open_verification" && route.verification === "email" && sourceExecutable);
          if (!applicable) continue;
          try {
            const browserEffect = ["publisher_discover", "submit_form"].includes(effect)
              || (effect === "open_verification" && route.id === "intelius");
            if (browserEffect) {
              if (!routingScope || routingScope.browserBackendMode === "not_required") throw new Error("rightout_browser_backend_invalid");
              assertPublisherAutomationPermission(config, route, providerTerms, effect, { browserBackend: routingScope.browserBackendMode });
              if (routingScope.remoteCloudFallback && routingScope.browserBackendMode !== "remote_cloud_cdp") {
                assertPublisherAutomationPermission(config, route, providerTerms, effect, { browserBackend: "remote_cloud_cdp" });
              }
            } else {
              assertPublisherAutomationPermission(config, route, providerTerms, effect);
            }
            brokerIdsByEffect[effect].push(route.id);
          } catch { /* closed lane */ }
        }
      }
      const authorizedRouteCounts = Object.fromEntries(effects.map((effect) => [effect, brokerIdsByEffect[effect].length]));
      return {
        selected_browser_backend: routingScope?.browserBackendMode ?? "invalid_or_unconfigured",
        remote_cloud_fallback_bound: routingScope?.remoteCloudFallback ?? false,
        authorized_route_counts: authorizedRouteCounts,
        authorized_broker_ids_by_effect: brokerIdsByEffect,
        any_publisher_lane_authorized: Object.values(authorizedRouteCounts).some((count) => count > 0),
        public_provider_authorizations_bundled: 0,
        subject_consent_is_not_provider_authorization: true,
      };
    }

    function paritySourceApprovalDescription(scope: { routeIds: string[]; permissionDigest: string }): string {
      const prefix = "GET public publisher pages for source_refresh only: ";
      const suffix = ". No subject data/body capture/write; store PII-free health. Permission-set changes require new approval.";
      const explicitTargets = scope.routeIds.join(",");
      const compactTargets = scope.routeIds.length === 22
        ? "all 22 pinned routes"
        : `${scope.routeIds.length} pinned routes@${scope.permissionDigest.slice(0, 12)}`;
      const targets = `${prefix}${explicitTargets}${suffix}`.length <= 256 ? explicitTargets : compactTargets;
      const text = `${prefix}${targets}${suffix}`;
      if (text.length > 256) throw new Error("rightout_parity_source_refresh_scope_invalid");
      return text;
    }

    async function combinedScanCatalog(): Promise<Record<string, any>> {
      const [core, parity] = await Promise.all([catalogPromise, parityCatalogPromise]);
      return buildCombinedScanCatalog(core, parity);
    }

    async function assertAutonomousCampaignScope(input: PublicCampaignStartInput): Promise<void> {
      if (input.effects.length === 1 && input.effects[0] === "discover") {
        assertCampaignCatalogScope(await combinedScanCatalog(), input);
        return;
      }
      assertCampaignCatalogScope(await parityCatalogPromise, input);
    }

    async function combinedVerificationCatalog(): Promise<Record<string, any>> {
      const [core, parity] = await Promise.all([catalogPromise, parityCatalogPromise]);
      const rows = new Map<string, Record<string, any>>();
      for (const row of Array.isArray(core.brokers) ? core.brokers : []) {
        if (row && typeof row === "object" && !Array.isArray(row) && typeof (row as Record<string, any>).id === "string") {
          rows.set((row as Record<string, any>).id, row as Record<string, any>);
        }
      }
      for (const route of parity.brokers) {
        if (route.verification !== "email") continue;
        const existing = rows.get(route.id);
        if (existing?.verification?.supported === true) continue;
        const providerOpenRestricted = route.source_status === "observed_official_archive_external_unavailable"
          || String(route.source_status).startsWith("needs_evidence");
        rows.set(route.id, {
          id: route.id,
          name: route.name,
          category: "people_search",
          official_domains: route.official_domains,
          verification: {
            supported: true,
            channel: "imap",
            sender_domains: route.official_domains,
            link_domains: route.official_domains,
            processing_days: 14,
            open_link: route.id === "intelius"
              ? "browser_same_profile_required"
              : providerOpenRestricted ? "human_only" : "approval_gated_https_get",
          },
        });
      }
      return { schema_version: 1, brokers: [...rows.values()] };
    }

    async function combinedDirectCatalog(): Promise<Record<string, any>> {
      const [core, parity] = await Promise.all([catalogPromise, parityCatalogPromise]);
      const rows = new Map<string, Record<string, any>>();
      for (const row of Array.isArray(core.brokers) ? core.brokers : []) {
        if (row && typeof row === "object" && !Array.isArray(row) && typeof (row as Record<string, any>).id === "string") {
          rows.set((row as Record<string, any>).id, row as Record<string, any>);
        }
      }
      for (const route of parity.brokers) {
        if (
          String(route.source_status).startsWith("needs_evidence")
          || route.source_status === "observed_official_archive_external_unavailable"
        ) continue;
        const existing = rows.get(route.id);
        if (existing?.direct_rescan?.supported === true) continue;
        rows.set(route.id, {
          id: route.id,
          name: route.name,
          category: "people_search",
          official_domains: route.official_domains,
          direct_rescan: {
            supported: true,
            strategy: "exact_encrypted_index_candidate_urls",
            publisher_terms_gate: "current_written_provider_authorization",
          },
        });
      }
      return { schema_version: 1, brokers: [...rows.values()] };
    }

    async function assertScanScopeFresh(input: PublicScanInput): Promise<void> {
      const [core, parity] = await Promise.all([catalogPromise, parityCatalogPromise]);
      const coreIds = new Set((Array.isArray(core.brokers) ? core.brokers : []).map((row: any) => row?.id).filter(Boolean));
      const firstCoreId = input.brokerIds.find((id) => coreIds.has(id));
      if (firstCoreId) assertFreshCatalogEntries(core, [firstCoreId]);
      assertParityCatalogFresh(parity);
    }

    async function assertParityRouteFresh(brokerId: string): Promise<void> {
      const [core, parity] = await Promise.all([catalogPromise, parityCatalogPromise]);
      const coreEntry = (Array.isArray(core.brokers) ? core.brokers : []).find((row: any) => row?.id === brokerId);
      if (coreEntry) assertFreshCatalogEntries(core, [brokerId]);
      assertParityCatalogRouteFresh(parity, brokerId);
    }

    async function assertParityRescueFresh(brokerId: string): Promise<void> {
      const parity = await parityCatalogPromise;
      const route = parity.brokers.find((row: any) => row.id === brokerId);
      const checked = Date.parse(`${route?.rescue_last_checked ?? ""}T00:00:00Z`);
      if (
        !route || typeof route.rescue_email !== "string" || typeof route.rescue_source_url !== "string"
        || !Array.isArray(route.rescue_disclosure_fields) || !Number.isFinite(checked)
        || checked > Date.now()
        || Date.now() - checked > 180 * 24 * 60 * 60_000
      ) throw new Error("rightout_catalog_lane_stale");
    }
    const sendSmtpMail = createSmtpSender();
    const pollImapVerification = createImapPoller();
    const pollControllerReply = createControllerReplyPoller({ classifier: classifyControllerReply });
    const submitBrowserForm = createBrowserFormSubmitter();
    const browserSessionDriver = createBrowserSessionDriver();
    const browserSessions = new Map<string, Record<string, any>>();
    const browserSessionTimers = new Map<string, ReturnType<typeof setTimeout>>();

    function deleteBrowserSession(sessionId: string): boolean {
      const timer = browserSessionTimers.get(sessionId);
      if (timer) clearTimeout(timer);
      browserSessionTimers.delete(sessionId);
      return Map.prototype.delete.call(browserSessions, sessionId);
    }

    function storeBrowserSession(sessionId: string, session: Record<string, any>): void {
      deleteBrowserSession(sessionId);
      Map.prototype.set.call(browserSessions, sessionId, session);
      const delay = Math.max(0, Math.min(2_147_483_647, Number(session.expiresAt) - Date.now()));
      const timer = setTimeout(() => {
        const current = browserSessions.get(sessionId);
        if (current !== session) return;
        void invalidateBrowserSession(sessionId, session, "verified_portal_session_expired").catch(() => {
          api.logger.warn("RightOut timed browser-session cleanup failed; manual browser cleanup may be required");
        });
      }, delay);
      timer.unref?.();
      browserSessionTimers.set(sessionId, timer);
    }
    const stateDir = api.runtime.state.resolveStateDir(process.env);
    const configuredRetentionDays = (api.pluginConfig as RightOutConfig | undefined)?.stateRetentionDays;
    const stateRetentionDays = Number.isInteger(configuredRetentionDays) && configuredRetentionDays! >= 30 && configuredRetentionDays! <= 730
      ? configuredRetentionDays!
      : 365;
    const openRightOutStore = <T>(options: { namespace: string; maxEntries: number; defaultTtlMs?: number }) =>
      createEncryptedFileKeyedStore({
        stateDir,
        ...options,
        getSecret: () => (api.pluginConfig as RightOutConfig | undefined)?.stateEncryptionKey,
        getPreviousSecrets: () => (api.pluginConfig as RightOutConfig | undefined)?.previousStateEncryptionKeys ?? [],
      }) as any;
    const caseStore = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-cases-v1",
      maxEntries: 100,
      defaultTtlMs: stateRetentionDays * 24 * 60 * 60_000,
    });
    const profileSnapshotStore = openRightOutStore<{ profileId: string; digest: string; createdAt: string }>({
      namespace: "rightout-profile-snapshots-v1",
      maxEntries: 100,
      defaultTtlMs: stateRetentionDays * 24 * 60 * 60_000,
    });
    const caseLedger = createCaseLedger(caseStore);
    const verificationTokens = openRightOutStore<VerificationToken>({
      namespace: "rightout-verification-tokens-v1",
      maxEntries: 200,
      defaultTtlMs: 7 * 24 * 60 * 60_000,
    });
    const controllerReplyCandidates = openRightOutStore<ControllerReplyCandidate>({
      namespace: "rightout-controller-reply-candidates-v1",
      maxEntries: 500,
      defaultTtlMs: 30 * 24 * 60 * 60_000,
    });
    const evidenceStore = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-evidence-vault-v1",
      maxEntries: 500,
    });
    const evidenceExportStore = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-evidence-export-index-v1",
      maxEntries: 1_000,
    });
    const evidenceVault = createEvidenceVault(evidenceStore, { exportStore: evidenceExportStore, exportRoot: stateDir });
    void evidenceVault.cleanupExpiredEvidence().catch(() => {
      api.logger?.warn?.("RightOut evidence retention cleanup failed; evidence export is blocked until cleanup succeeds");
    });
    const customTargetStore = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-custom-targets-v1",
      maxEntries: 500,
      defaultTtlMs: 365 * 24 * 60 * 60_000,
    });
    const customTargetVault = createCustomTargetVault(customTargetStore);
    const verificationOpenDedupe = openRightOutStore<{ createdAt: string; profileId: string; brokerId: string; submissionReference: string; phase: string }>({
      namespace: "rightout-verification-open-dedupe-v1",
      maxEntries: 200,
      defaultTtlMs: 30 * 24 * 60 * 60_000,
    });
    const submissionDedupe = openRightOutStore<{ createdAt: string; channel: string; profileId: string; brokerId: string; phase?: string }>({
      namespace: "rightout-submission-dedupe-v1",
      maxEntries: 500,
      defaultTtlMs: duplicateCooldownMs,
    });
    const listingTokens = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-listing-tokens-v1",
      maxEntries: 500,
      defaultTtlMs: 180 * 24 * 60 * 60_000,
    });
    const campaignStore = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-campaigns-v1",
      maxEntries: 100,
      defaultTtlMs: 30 * 24 * 60 * 60_000,
    });
    const campaignLedger = createCampaignLedger(campaignStore);
    const workerStore = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-autonomy-workers-v1",
      maxEntries: 100,
      defaultTtlMs: 30 * 24 * 60 * 60_000,
    });
    const workerLedger = createAutonomyWorkerLedger(workerStore);
    const registryStore = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-registry-v1",
      maxEntries: 20,
      defaultTtlMs: 45 * 24 * 60 * 60_000,
    });
    const paritySourceStore = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-parity-source-health-v1",
      maxEntries: 2,
      defaultTtlMs: 30 * 24 * 60 * 60_000,
    });
    const portalFlowStore = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-verified-portal-flows-v1",
      maxEntries: 100,
      defaultTtlMs: 24 * 60 * 60_000,
    });

    function portalFlowKey(profileId: string, brokerId: string): string {
      return `portal_${createHash("sha256").update(JSON.stringify([profileId, brokerId])).digest("hex")}`;
    }

    function configuredProfileDigest(profileId: string): string {
      const config = api.pluginConfig as RightOutConfig | undefined;
      const payload = config?.profiles?.[profileId]?.payload;
      if (!stateEncryptionReady(config) || typeof payload !== "string") throw new Error("rightout_not_configured");
      let profile: unknown;
      try { profile = JSON.parse(payload); }
      catch { throw new Error("invalid_profile"); }
      if (!profile || typeof profile !== "object" || Array.isArray(profile)) throw new Error("invalid_profile");
      return digestJson(profile);
    }

    function configuredRuntimeScopeDigest(): string {
      const config = api.pluginConfig as RightOutConfig | undefined;
      return digestJson({
        smtpTransport: config?.smtpTransport ?? null,
        imapTransport: config?.imapTransport ?? null,
        browserControlBaseUrl: config?.browserControlBaseUrl ?? null,
        browserProfile: config?.browserProfile ?? null,
        browserBackendMode: config?.browserBackendMode ?? "managed_openclaw",
        remoteCloudBrowserProfile: config?.remoteCloudBrowserProfile ?? null,
        browserControlToken: config?.browserControlToken ?? null,
        publisherAutomationPermissions: config?.publisherAutomationPermissions ?? null,
        operatorAttestations: config?.operatorAttestations ?? null,
        removalAttestations: config?.removalAttestations ?? null,
        verificationAttestations: config?.verificationAttestations ?? null,
        formAttestations: config?.formAttestations ?? null,
        directScanAttestations: config?.directScanAttestations ?? null,
      });
    }

    function trustedWorkerSession(context: Record<string, any>): { sessionKey: string; agentId: string; sessionBindingDigest: string } {
      const sessionKey = context.sessionKey;
      const agentId = context.agentId;
      if (typeof sessionKey !== "string" || typeof agentId !== "string") throw new Error("rightout_worker_session_required");
      return { sessionKey, agentId, sessionBindingDigest: workerSessionBindingDigest({ sessionKey, agentId }) };
    }

    function configuredProfileIds(config = api.pluginConfig as RightOutConfig | undefined): string[] {
      return Object.keys(config?.profiles ?? {}).filter((profileId) => /^profile_[a-f0-9]{16,32}$/.test(profileId)).sort();
    }

    function teamContext(context: Record<string, any>): { sessionKey: string; agentId: string } {
      const sessionKey = context?.sessionKey;
      const agentId = context?.agentId;
      if (typeof sessionKey !== "string" || typeof agentId !== "string") throw new Error("rightout_team_session_required");
      return { sessionKey, agentId };
    }

    function currentTeamMember(config: RightOutConfig | undefined, context: Record<string, any>) {
      if (config?.teamAccess === undefined) return undefined;
      return resolveTeamMember(config.teamAccess, configuredProfileIds(config), teamContext(context));
    }

    function assertTeamProfileScope(member: Record<string, any>, profileId: string): void {
      if (!member.authorized_profile_ids.includes(profileId)) throw new Error("rightout_team_profile_unauthorized");
    }

    async function eventProfileScope(params: unknown): Promise<string | undefined> {
      if (!params || typeof params !== "object" || Array.isArray(params)) return undefined;
      const value = params as Record<string, unknown>;
      if (typeof value.profileId === "string") return value.profileId;
      if (typeof value.campaignId === "string" && /^campaign_[a-f0-9]{32}$/.test(value.campaignId)) {
        const campaign = await campaignStore.lookup(value.campaignId);
        if (!campaign || typeof campaign.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(campaign.profileId)) {
          throw new Error("rightout_team_campaign_scope_unknown");
        }
        return campaign.profileId;
      }
      if (typeof value.workerId === "string" && /^worker_[a-f0-9]{32}$/.test(value.workerId)) {
        const worker = await workerStore.lookup(value.workerId);
        if (!worker || typeof worker.profileId !== "string" || !/^profile_[a-f0-9]{16,32}$/.test(worker.profileId)) {
          throw new Error("rightout_team_worker_scope_unknown");
        }
        return worker.profileId;
      }
      if (typeof value.sessionId === "string") {
        const session = browserSessions.get(value.sessionId);
        if (!session || typeof session.profileId !== "string") throw new Error("rightout_team_session_scope_unknown");
        return session.profileId;
      }
      return undefined;
    }

    function effectivenessCanaries(config: RightOutConfig | undefined, profileId: string): EffectivenessCanary[] | undefined {
      return config?.effectivenessCanaries?.[profileId];
    }

    async function effectivenessForProfile(profileId: string): Promise<Record<string, any>> {
      assertConfiguredProfile(profileId);
      await ensureImmutableProfileSnapshot(profileId);
      const status = await caseLedger.status(profileId);
      return buildEffectivenessReport(status, effectivenessCanaries(api.pluginConfig as RightOutConfig | undefined, profileId));
    }

    async function teamDashboardModel(member: Record<string, any>): Promise<Record<string, any>> {
      const config = api.pluginConfig as RightOutConfig | undefined;
      const profiles = [];
      const effectiveness = [];
      for (const profileId of member.authorized_profile_ids) {
        const status = await caseLedger.status(profileId);
        const measured = buildEffectivenessReport(status, effectivenessCanaries(config, profileId));
        profiles.push({
          subject_ref: status.subject_ref,
          counts: status.counts,
          cases: status.cases.map((item: Record<string, any>) => ({
            broker_id: item.broker_id,
            state: item.state,
            next_recheck_at: item.next_recheck_at,
          })),
        });
        effectiveness.push({
          subject_ref: measured.subject_ref,
          operational_effectiveness: measured.operational_effectiveness,
          discovery: measured.discovery,
          submission: measured.submission,
          provider_confirmation: measured.provider_confirmation,
          reappearance: measured.reappearance,
          uncertainty: measured.uncertainty,
          human_handoff: measured.human_handoff,
        });
      }
      const authorized = new Set(member.authorized_profile_ids);
      const evidenceReferenceCount = (await evidenceStore.entries()).filter((entry: Record<string, any>) => authorized.has(entry?.value?.profileId)).length;
      const health = catalogPolicyHealth(await catalogPromise);
      const dueNow = profiles.flatMap((profile) => profile.cases).filter((item) => (
        typeof item.next_recheck_at === "string" && Date.parse(item.next_recheck_at) <= Date.now()
      )).length;
      const evidencedCount = effectiveness.filter((item) => item.operational_effectiveness === "evidenced_by_authorized_canaries").length;
      return {
        dashboard_version: 1,
        generated_at: new Date().toISOString(),
        member: {
          member_id: member.member_id,
          role: member.role,
          authorized_profile_count: member.authorized_profile_ids.length,
        },
        profiles,
        effectiveness,
        operational_effectiveness: evidencedCount === effectiveness.length && evidencedCount > 0
          ? "evidenced_by_authorized_canaries"
          : evidencedCount > 0 ? "partially_evidenced_by_authorized_canaries" : "needs_evidence",
        due_now: dueNow,
        evidence_reference_count: evidenceReferenceCount,
        route_health: {
          summary: health.summary,
          live_provider_io_allowed: health.live_provider_io_allowed,
          next_action: health.next_action,
        },
        invariants: { raw_pii_in_report: false, network_requests: 0, browser_service_started: false },
      };
    }

    async function currentWorkerPolicyDigest(): Promise<string> {
      const recipePack = await loadRecipePack();
      return workerPolicyDigest({
        catalogDigest: await campaignCatalogDigestPromise,
        recipeDigest: recipePack.recipe_digest,
        runtimeScopeDigest: configuredRuntimeScopeDigest(),
      });
    }

    async function workerExecutionContext(workerId: string, context: Record<string, any>) {
      const worker = await workerLedger.status(workerId);
      const campaign = await campaignLedger.status(worker.campaign_id);
      if (campaign.status === "active") {
        const profileDigest = await ensureImmutableProfileSnapshot(campaign.subject_ref);
        await campaignLedger.assertScope(campaign.campaign_id, {
          profileId: campaign.subject_ref,
          profileDigest,
          runtimeScopeDigest: configuredRuntimeScopeDigest(),
        });
      }
      const session = trustedWorkerSession(context);
      return { worker, campaign, policyDigest: await currentWorkerPolicyDigest(), ...session };
    }

    async function currentRecipeForBroker(brokerId: string): Promise<Record<string, any>> {
      const pack = await loadRecipePack();
      const matches = pack.recipes.filter((recipe: Record<string, any>) => recipe.broker_id === brokerId);
      if (matches.length !== 1) throw new Error("rightout_recipe_not_found");
      return matches[0];
    }

    async function assessFormRecipeSession(
      sessionId: string,
      session: Record<string, any>,
      snapshot: Record<string, any>,
    ): Promise<Record<string, any>> {
      const recipe = await currentRecipeForBroker(session.brokerId);
      const currentDigest = recipeDigest(recipe);
      if (
        session.recipeId !== recipe.recipe_id
        || session.recipeDigest !== currentDigest
        || session.recipePackDigest !== (await loadRecipePack()).recipe_digest
      ) {
        await invalidateBrowserSession(sessionId, session, "signed_recipe_policy_changed");
        throw new Error("rightout_recipe_policy_changed");
      }
      const assessment = assessRecipeSnapshot(recipe, snapshot) as Record<string, any>;
      if (assessment.state !== "compatible") {
        await caseLedger.recordLifecycle(session.profileId, session.brokerId, "blocked", {
          evidenceKind: "human_task",
          reason: assessment.reason,
        }).catch(() => undefined);
        await invalidateBrowserSession(sessionId, session, assessment.reason);
        throw new Error(assessment.state === "human_gate" ? "rightout_recipe_human_gate" : "rightout_recipe_drift_quarantined");
      }
      return assessment;
    }

    function workerScheduleMessage(workerId: string): string {
      if (!/^worker_[a-f0-9]{32}$/.test(workerId)) throw new Error("rightout_worker_ref_invalid");
      return `Advance ${workerId}: call rightout_worker_tick with exactly this workerId. If action_ready, execute exactly command.tool with command.parameters, then call rightout_worker_complete with the returned workerId and leaseId. Use action_succeeded only after a successful tool result; otherwise use transient_failure or human_gate. Never invent tools or parameters.`;
    }

    const interactiveWorkerTools = new Set([
      "rightout_begin_discovery_session",
      "rightout_begin_webmail_session",
      "rightout_begin_form_session",
      "rightout_begin_webmail_verification",
    ]);

    function workerExecutionReceipt(toolName: string, result: unknown, error?: string): { state: "completed" | "human_gate"; resultState: string } {
      if (typeof error === "string" && error.length > 0) return { state: "human_gate", resultState: "tool_error" };
      const details = result && typeof result === "object" && !Array.isArray(result)
        ? (result as Record<string, any>).details
        : undefined;
      if (!details || typeof details !== "object" || Array.isArray(details)) return { state: "human_gate", resultState: "missing_structured_result" };
      const resultState = typeof details.state === "string"
        ? details.state
        : typeof details.mode === "string" ? details.mode : "unclassified_result";
      if (!/^[a-z0-9_]{2,120}$/.test(resultState)) return { state: "human_gate", resultState: "invalid_result_state" };
      if (
        details.retry_blocked === true || details.tracking?.durable_case_recorded === false
        || /(?:blocked|uncertain|human_gate|manual|failed|error|cancelled)/u.test(resultState)
      ) return { state: "human_gate", resultState };
      if (toolName === "rightout_live_scan") {
        return Array.isArray(details.results)
          ? { state: "completed", resultState }
          : { state: "human_gate", resultState: "live_scan_result_incomplete" };
      }
      if (toolName === "rightout_submit_removal" || toolName === "rightout_submit_parity_email") {
        return resultState === "submitted"
          ? { state: "completed", resultState }
          : { state: "human_gate", resultState };
      }
      if (toolName === "rightout_poll_verification") {
        return ["verification_pending", "verification_not_observed"].includes(resultState)
          ? { state: "completed", resultState }
          : { state: "human_gate", resultState };
      }
      if (toolName === "rightout_open_verification") {
        return resultState === "awaiting_processing"
          ? { state: "completed", resultState }
          : { state: "human_gate", resultState };
      }
      if (toolName === "rightout_direct_rescan") return { state: "completed", resultState };
      return { state: "human_gate", resultState: "non_terminal_worker_tool" };
    }

    async function scheduleWorkerRoute(
      session: { sessionKey: string; agentId: string },
      workerId: string,
      delayMs: number,
    ): Promise<Record<string, unknown>> {
      const boundedDelay = Math.max(1_000, Math.min(30 * 24 * 60 * 60_000, Math.ceil(delayMs)));
      const tag = `rightout-worker-${workerId.slice("worker_".length)}`;
      let replaced = { removed: 0, failed: 0 };
      try {
        replaced = await api.session.workflow.unscheduleSessionTurnsByTag({ sessionKey: session.sessionKey, tag });
        const handle = await api.session.workflow.scheduleSessionTurn({
          sessionKey: session.sessionKey,
          agentId: session.agentId,
          delayMs: boundedDelay,
          deleteAfterRun: true,
          deliveryMode: "none",
          name: `RightOut worker ${workerId.slice(-8)}`,
          tag,
          message: workerScheduleMessage(workerId),
        });
        if (handle) {
          return {
            scheduler_state: "host_scheduled",
            scheduled_job_registered: true,
            scheduled_delay_ms: boundedDelay,
            replaced_scheduled_turns: replaced.removed,
            raw_session_key_in_report: false,
          };
        }
      } catch {
        api.logger.warn("RightOut host scheduler handoff failed; explicit handoff is required");
      }
      return {
        scheduler_state: "explicit_handoff_required",
        scheduled_job_registered: false,
        scheduled_delay_ms: boundedDelay,
        replaced_scheduled_turns: replaced.removed,
        cron_handoff: {
          target: "current_trusted_session",
          delay_ms: boundedDelay,
          delete_after_run: true,
          delivery_mode: "none",
          message: workerScheduleMessage(workerId),
        },
        next_action: `call_rightout_worker_tick_with_${workerId}_from_the_same_openclaw_session`,
        raw_session_key_in_report: false,
      };
    }

    async function scheduleWorkerTurn(context: Record<string, any>, workerId: string, delayMs: number): Promise<Record<string, unknown>> {
      const session = trustedWorkerSession(context);
      return scheduleWorkerRoute(session, workerId, delayMs);
    }

    async function recoverWorkerSchedules(): Promise<void> {
      for (const worker of await workerLedger.recoverable()) {
        const wakeAt = worker.lease_expires_at ?? worker.next_wake_at;
        if (typeof wakeAt !== "string" || !Number.isFinite(Date.parse(wakeAt))) continue;
        await scheduleWorkerRoute(
          { sessionKey: worker.session_key, agentId: worker.agent_id },
          worker.worker_id,
          Math.max(1_000, Date.parse(wakeAt) - Date.now() + (worker.unresolved_action ? 1_000 : 0)),
        );
      }
    }

    void recoverWorkerSchedules().catch(() => {
      api.logger?.warn?.("RightOut worker schedule recovery failed; durable workers remain fail-closed until an operator resumes them");
    });

    function browserVerificationTransportReady(config: RightOutConfig | undefined, browser: Record<string, any>): boolean {
      if (!browser.webmail_ready || typeof config?.verificationAttestations?.browserProfileDigest !== "string") return false;
      try {
        return config.verificationAttestations.browserProfileDigest === browserVerificationProfileDigest({
          browserControlBaseUrl: config.browserControlBaseUrl,
          browserProfile: config.browserProfile,
          browserBackendMode: config.browserBackendMode,
        });
      } catch { return false; }
    }

    async function ensureImmutableProfileSnapshot(profileId: string): Promise<string> {
      const digest = configuredProfileDigest(profileId);
      const record = { profileId, digest, createdAt: new Date().toISOString() };
      if (!await profileSnapshotStore.registerIfAbsent(profileId, record)) {
        const existing = await profileSnapshotStore.lookup(profileId);
        if (!existing || existing.profileId !== profileId || existing.digest !== digest) {
          throw new Error("rightout_profile_snapshot_changed");
        }
      }
      return digest;
    }

    async function saveRegistrySnapshot(snapshot: Record<string, any>): Promise<void> {
      const records = Array.isArray(snapshot.records) ? snapshot.records : [];
      const chunks = [];
      for (let index = 0; index < records.length; index += 100) chunks.push(records.slice(index, index + 100));
      await registryStore.clear();
      for (let index = 0; index < chunks.length; index += 1) {
        await registryStore.register(`registry_chunk_${String(index).padStart(3, "0")}`, { records: chunks[index] });
      }
      await registryStore.register("registry_meta", {
        ...registrySummary(snapshot),
        state: "registry_ready",
        chunk_count: chunks.length,
      });
    }

    async function registryMeta(): Promise<Record<string, any>> {
      const meta = await registryStore.lookup("registry_meta") as Record<string, any> | undefined;
      if (!meta || !Number.isInteger(meta.chunk_count) || meta.chunk_count < 1 || meta.chunk_count > 10) {
        return {
          report_version: 1,
          state: "registry_not_initialized",
          record_count: 0,
          portals: REGISTRY_PORTALS,
          next_action: "call_rightout_refresh_registries",
          raw_contact_addresses_in_report: false,
        };
      }
      return meta;
    }

    async function registryRecords(): Promise<Record<string, any>[]> {
      const meta = await registryMeta();
      if (meta.state !== "registry_ready") throw new Error("rightout_registry_not_refreshed");
      const records = [];
      for (let index = 0; index < meta.chunk_count; index += 1) {
        const chunk = await registryStore.lookup(`registry_chunk_${String(index).padStart(3, "0")}`) as Record<string, any> | undefined;
        if (!chunk || !Array.isArray(chunk.records)) throw new Error("rightout_registry_state_invalid");
        records.push(...chunk.records);
      }
      if (records.length !== meta.record_count) throw new Error("rightout_registry_state_invalid");
      return records;
    }

    function formProfileValues(profile: Record<string, any>, listingUrl?: string): Record<string, string> {
      const fullName = String(profile.fullName ?? "").trim();
      const nameParts = fullName.split(/\s+/u).filter(Boolean);
      const listingPathParts = listingUrl
        ? new URL(listingUrl).pathname.split("/").filter(Boolean)
        : [];
      const listingId = listingPathParts.at(-1);
      const values: Record<string, string> = {
        full_name: profile.fullName,
        contact_email: profile.contactEmail,
        contact_email_confirm: profile.contactEmail,
        ...(nameParts[0] ? { first_name: nameParts[0] } : {}),
        ...(nameParts.length > 1 ? { last_name: nameParts.slice(1).join(" ") } : {}),
        ...(profile.dateOfBirth ? { date_of_birth: profile.dateOfBirth } : {}),
        ...(profile.currentAddress?.line1 ? { street: profile.currentAddress.line1 } : {}),
        city: profile.currentAddress?.city ?? profile.city,
        region: profile.currentAddress?.region ?? profile.region,
        ...(profile.currentAddress?.postal ? { postal: profile.currentAddress.postal } : {}),
        ...(profile.phones?.[0] ? { phone: profile.phones[0] } : {}),
        ...(listingUrl ? { listing_url: listingUrl } : {}),
        ...(listingId && /^[A-Za-z0-9_-]{1,160}$/.test(listingId) ? { listing_id: listingId } : {}),
      };
      return Object.fromEntries(Object.entries(values).filter(([, value]) => typeof value === "string" && value.length > 0));
    }

    function formFieldDisclosureMap(disclosureFields: string[], values: Record<string, string>): Record<string, string> {
      const aliases: Record<string, string> = {
        first_name: "full_name",
        last_name: "full_name",
        contact_email_confirm: "contact_email",
        listing_id: "listing_url",
      };
      const permitted = new Set(disclosureFields);
      return Object.fromEntries(
        Object.keys(values)
          .map((field) => [field, aliases[field] ?? field])
          .filter(([, disclosure]) => permitted.has(disclosure)),
      );
    }

    function discoveryProfileValues(profile: Record<string, any>): Record<string, string> {
      const values = formProfileValues(profile);
      return Object.fromEntries(
        ["full_name", "contact_email", "street", "city", "region", "postal", "phone"]
          .filter((field) => typeof values[field] === "string" && values[field].length > 0)
          .map((field) => [field, values[field]]),
      );
    }

    function activeFormSession(sessionId: string): Record<string, any> {
      const session = browserSessions.get(sessionId);
      if (!session || session.sessionType !== "form") throw new Error("rightout_form_session_expired");
      return session;
    }

    function activeWebmailSession(sessionId: string): Record<string, any> {
      const session = browserSessions.get(sessionId);
      if (!session || session.sessionType !== "webmail") throw new Error("rightout_webmail_session_expired");
      return session;
    }

    function activeDiscoverySession(sessionId: string): Record<string, any> {
      const session = browserSessions.get(sessionId);
      if (!session || session.kind !== "publisher_discovery") throw new Error("rightout_discovery_session_expired");
      return session;
    }

    async function authorizeCampaignEffects(
      campaignId: string | undefined,
      profileId: string,
      effects: CampaignEffect[],
      catalog: Record<string, unknown>,
      consume: boolean,
    ): Promise<boolean> {
      const profileDigest = await ensureImmutableProfileSnapshot(profileId);
      const runtimeScopeDigest = configuredRuntimeScopeDigest();
      if (!campaignId) return false;
      if (consume) {
        await campaignLedger.consume(campaignId, {
          profileId, effects, catalogDigest: await campaignCatalogDigestPromise, profileDigest, runtimeScopeDigest,
        });
        return true;
      }
      const status = await campaignLedger.assertScope(campaignId, { profileId, profileDigest, runtimeScopeDigest });
      if (
        status.status !== "active" || status.subject_ref !== profileId
        || effects.some((item) => !status.broker_ids.includes(item.brokerId) || !status.effects.includes(item.effect))
      ) throw new Error("rightout_campaign_scope_mismatch");
      return true;
    }

    async function revalidateConsumedSessionEffect(session: Record<string, any>, effect: CampaignEffect["effect"]): Promise<void> {
      const profileDigest = await ensureImmutableProfileSnapshot(session.profileId);
      const runtimeScopeDigest = configuredRuntimeScopeDigest();
      const status = await campaignLedger.assertScope(session.campaignId, {
        profileId: session.profileId, profileDigest, runtimeScopeDigest,
      });
      if (
        !["active", "completed"].includes(status.status)
        || Date.parse(status.expires_at) <= Date.now()
        || status.subject_ref !== session.profileId
        || !status.broker_ids.includes(session.brokerId)
        || !status.effects.includes(effect)
      ) throw new Error("rightout_campaign_not_active");
    }

    async function cleanupAndCloseBrowserSession(session: Record<string, any>): Promise<Record<string, unknown>> {
      let draftCleanup = "not_applicable";
      let providerIntentCleanup = "not_applicable";
      let tabCleanup = "closed";
      if (
        session.sessionType === "webmail"
        && (session.draftMayContainPii === true || (Array.isArray(session.filledFields) && session.filledFields.length > 0))
        && !session.sendCompleted
      ) {
        try {
          const result = await browserSessionDriver.discardDraft({
            ...session.browserControl,
            targetId: session.targetId,
            allowedDomains: ["mail.google.com"],
            allowedFields: Object.keys(session.values ?? {}),
            values: session.values ?? {},
            privacyMode: "webmail",
          });
          draftCleanup = result.discarded === true ? "discard_control_activated" : "needs_manual_cleanup";
        } catch { draftCleanup = "needs_manual_cleanup"; }
      }
      if (session.sessionType === "form" && session.submissionIntentReserved === true) {
        providerIntentCleanup = "submission_uncertain_recorded";
        await caseLedger.recordSubmissionUncertain(session.profileId, session.brokerId, {
          channel: "browser_form", reason: "form_session_invalidated_with_pending_provider_intent",
        }).catch(() => { providerIntentCleanup = "needs_manual_reconciliation"; });
      }
      if (session.stage === "peopleconnect_guided_identity") {
        await portalFlowStore.delete(portalFlowKey(session.profileId, session.brokerId)).catch(() => undefined);
      }
      try { await browserSessionDriver.closeSession({ ...session.browserControl, targetId: session.targetId }); }
      catch { tabCleanup = "needs_manual_cleanup"; }
      if (draftCleanup === "needs_manual_cleanup" || tabCleanup === "needs_manual_cleanup") {
        await caseLedger.recordLifecycle(session.profileId, session.brokerId, "human_task_queued", {
          evidenceKind: "human_task",
          reason: draftCleanup === "needs_manual_cleanup"
            ? "webmail_draft_cleanup_required"
            : "browser_tab_cleanup_required",
        }).catch(() => undefined);
      }
      return { draft_cleanup: draftCleanup, provider_intent_cleanup: providerIntentCleanup, tab_cleanup: tabCleanup };
    }

    async function invalidateBrowserSession(
      sessionId: string,
      session: Record<string, any>,
      humanTaskReason?: string,
    ): Promise<Record<string, unknown>> {
      deleteBrowserSession(sessionId);
      const cleanup = await cleanupAndCloseBrowserSession(session);
      if (humanTaskReason && session.stage === "peopleconnect_guided_identity") {
        await caseLedger.recordLifecycle(session.profileId, session.brokerId, "human_task_queued", {
          evidenceKind: "human_task", reason: humanTaskReason,
        }).catch(() => undefined);
      }
      return cleanup;
    }

    async function revalidatePublisherBrowserSession(
      sessionId: string,
      session: Record<string, any>,
      effect: CampaignEffect["effect"],
    ): Promise<void> {
      try {
        if (effect === "submit_form") {
          parityFormAttestationSnapshot(api.pluginConfig as RightOutConfig | undefined, session.profileId, session.brokerId);
        }
        if (effect === "publisher_discover") {
          const config = api.pluginConfig as RightOutConfig | undefined;
          const attestations = validatePublisherAccessAttestations(
            { profileId: session.profileId, brokerId: session.brokerId },
            config?.directScanAttestations,
          ) as DirectScanAttestations;
          const payload = config?.profiles?.[session.profileId]?.payload;
          if (typeof payload !== "string" || scanProfileDigest(payload) !== attestations.authorizedProfileDigests[session.profileId]) {
            throw new Error("rightout_direct_scan_profile_snapshot_changed");
          }
        }
        assertPublisherAutomationPermission(
          api.pluginConfig as RightOutConfig | undefined,
          session.broker,
          await providerTermsPromise,
          effect,
          { browserBackend: session.browserBackend },
        );
        await revalidateConsumedSessionEffect(session, effect);
      } catch (error) {
        await invalidateBrowserSession(sessionId, session);
        throw error;
      }
    }

    async function invalidateBrowserSessions(predicate: (session: Record<string, any>) => boolean): Promise<Record<string, number>> {
      const closing = [];
      let invalidated = 0;
      for (const [sessionId, session] of browserSessions) {
        if (!predicate(session)) continue;
        deleteBrowserSession(sessionId);
        invalidated += 1;
        closing.push(cleanupAndCloseBrowserSession(session));
      }
      const cleanup = await Promise.all(closing);
      return {
        invalidated,
        drafts_discarded: cleanup.filter((item) => item.draft_cleanup === "discard_control_activated").length,
        drafts_needing_manual_cleanup: cleanup.filter((item) => item.draft_cleanup === "needs_manual_cleanup").length,
        provider_intents_marked_uncertain: cleanup.filter((item) => item.provider_intent_cleanup === "submission_uncertain_recorded").length,
        provider_intents_needing_manual_reconciliation: cleanup.filter((item) => item.provider_intent_cleanup === "needs_manual_reconciliation").length,
        tabs_closed: cleanup.filter((item) => item.tab_cleanup === "closed").length,
        tabs_needing_manual_cleanup: cleanup.filter((item) => item.tab_cleanup === "needs_manual_cleanup").length,
      };
    }

    async function invalidatePortalFlows(
      predicate: (flow: Record<string, any>) => boolean,
      humanTaskReason?: string,
    ): Promise<number> {
      let invalidated = 0;
      for (const entry of await portalFlowStore.entries()) {
        const flow = entry?.value as Record<string, any> | undefined;
        if (!flow || !predicate(flow)) continue;
        await portalFlowStore.delete(entry.key);
        invalidated += 1;
        if (typeof flow.bridgeUrl === "string" && typeof flow.targetId === "string") {
          await browserSessionDriver.closeSession({
            bridgeUrl: flow.bridgeUrl, targetId: flow.targetId,
            browserProfile: flow.browserProfile ?? undefined,
            browserAuthToken: (api.pluginConfig as RightOutConfig | undefined)?.browserControlToken,
          }).catch(() => undefined);
        }
        if (humanTaskReason && typeof flow.profileId === "string" && typeof flow.brokerId === "string") {
          await caseLedger.recordLifecycle(flow.profileId, flow.brokerId, "human_task_queued", {
            evidenceKind: "human_task", reason: humanTaskReason,
          }).catch(() => undefined);
        }
      }
      return invalidated;
    }

    async function purgeProfileEntries(store: any, profileId: string): Promise<number> {
      let deleted = 0;
      for (const entry of await store.entries()) {
        if (entry?.value?.profileId === profileId && await store.delete(entry.key)) deleted += 1;
      }
      return deleted;
    }

    function verificationOpenDedupeKey(profileId: string, brokerId: string, submissionReference: string): string {
      return `verification_${createHash("sha256").update(JSON.stringify([profileId, brokerId, submissionReference])).digest("hex")}`;
    }

    async function acquireSubmissionDedupe(
      dedupeKey: string,
      input: PublicRemovalInput,
      channel: "smtp_email" | "browser_webmail" | "browser_form",
    ): Promise<void> {
      const record = {
        createdAt: new Date().toISOString(), channel, profileId: input.profileId, brokerId: input.brokerId,
        phase: "dedupe_reserved_before_case_intent",
      };
      if (await submissionDedupe.registerIfAbsent(dedupeKey, record)) return;
      const existing = await submissionDedupe.lookup(dedupeKey);
      const profile = await caseLedger.load(input.profileId);
      const brokerCase = profile.brokers?.[input.brokerId];
      const state = brokerCase?.state;
      const preIntentOrphan = existing?.phase === "dedupe_reserved_before_case_intent"
        && !["submission_pending", "submission_uncertain", "submitted", "verification_pending", "awaiting_processing", "confirmed_removed"].includes(state);
      const reconciledNotStarted = existing?.phase === "durable_case_intent_reserved"
        && state === "action_selected"
        && brokerCase?.submission_outcome === "human_reviewed_not_started";
      if (preIntentOrphan || reconciledNotStarted) {
        await submissionDedupe.delete(dedupeKey);
        if (await submissionDedupe.registerIfAbsent(dedupeKey, record)) return;
      }
      throw new Error("rightout_duplicate_removal_request");
    }

    async function markSubmissionDedupeIntentReserved(
      dedupeKey: string,
      input: PublicRemovalInput,
      channel: "smtp_email" | "browser_webmail" | "browser_form",
    ): Promise<void> {
      await submissionDedupe.register(dedupeKey, {
        createdAt: new Date().toISOString(), channel, profileId: input.profileId, brokerId: input.brokerId,
        phase: "durable_case_intent_reserved",
      });
    }

    function assertConfiguredProfile(profileId: string): void {
      if (!/^profile_[a-f0-9]{16,32}$/.test(profileId)) throw new Error("invalid_profile_ref");
      const config = api.pluginConfig as RightOutConfig | undefined;
      if (typeof config?.stateEncryptionKey !== "string" || config.stateEncryptionKey.length < 32 || typeof config?.profiles?.[profileId]?.payload !== "string") {
        throw new Error("rightout_not_configured");
      }
    }

    function stateEncryptionReady(config: RightOutConfig | undefined): config is RightOutConfig & { stateEncryptionKey: string } {
      return typeof config?.stateEncryptionKey === "string" && config.stateEncryptionKey.length >= 32;
    }

    function stateRotationReady(config: RightOutConfig | undefined): config is RightOutConfig & { stateEncryptionKey: string; previousStateEncryptionKeys: string[] } {
      return stateEncryptionReady(config)
        && Array.isArray(config.previousStateEncryptionKeys)
        && config.previousStateEncryptionKeys.length >= 1
        && config.previousStateEncryptionKeys.length <= 3
        && config.previousStateEncryptionKeys.every((key) => typeof key === "string" && key.length >= 32 && key.length <= 4_096 && key !== config.stateEncryptionKey);
    }

    function verificationAttestationSnapshot(
      config: RightOutConfig | undefined,
      input: PublicVerificationPollInput,
    ): VerificationAttestations {
      return validateVerificationAttestations(input, config?.verificationAttestations) as VerificationAttestations;
    }

    function controllerReplyAttestationSnapshot(
      config: RightOutConfig | undefined,
      input: PublicControllerReplyInput,
    ): ControllerReplyAttestations {
      return validateControllerReplyAttestations(input, config?.controllerReplyAttestations) as ControllerReplyAttestations;
    }

    async function controllerCandidateForOutcome(input: PublicControllerOutcomeInput): Promise<ControllerReplyCandidate | undefined> {
      if (!input.candidateHandle) return undefined;
      const candidate = await controllerReplyCandidates.lookup(input.candidateHandle);
      if (
        !candidate || candidate.profileId !== input.profileId || candidate.brokerId !== input.brokerId
        || candidate.outcome !== input.outcome || !/^mail_[a-f0-9]{24}$/.test(candidate.messageReference)
        || !/^(?:smtp|webmail)_[a-f0-9]{16,64}$/.test(candidate.submissionReference)
      ) throw new Error("rightout_controller_reply_candidate_invalid");
      return candidate;
    }

    function formAttestationSnapshot(config: RightOutConfig | undefined, input: PublicRemovalInput): FormAttestations {
      return validateFormAttestations(input, config?.formAttestations) as FormAttestations;
    }

    function parityFormAttestationSnapshot(
      config: RightOutConfig | undefined,
      profileId: string,
      brokerId: string,
    ): FormAttestations {
      const payload = config?.profiles?.[profileId]?.payload;
      const attestations = formAttestationSnapshot(config, { profileId, brokerId, requestKind: "delete_and_opt_out" });
      if (typeof payload !== "string" || removalProfileDigest(payload) !== attestations.authorizedProfileDigests[profileId]) {
        throw new Error("rightout_form_snapshot_changed");
      }
      return attestations;
    }

    function directScanAttestationSnapshot(config: RightOutConfig | undefined, input: PublicDirectScanInput): DirectScanAttestations {
      return validateDirectScanAttestations(input, config?.directScanAttestations) as DirectScanAttestations;
    }

    function pruneApprovalState(now = Date.now()): void {
      for (const [toolCallId, approval] of approvalBindings) {
        if (approval.expiresAt <= now) approvalBindings.delete(toolCallId);
      }
      for (const [scope, expiresAt] of submittedScopes) {
        if (expiresAt <= now) submittedScopes.delete(scope);
      }
    }

    async function pruneTransientState(now = Date.now()): Promise<void> {
      pruneApprovalState(now);
      for (const [sessionId, session] of browserSessions) {
        if (session.expiresAt <= now) {
          const cleanup = await invalidateBrowserSession(sessionId, session, "verified_portal_session_expired");
          if (cleanup.draft_cleanup === "needs_manual_cleanup") api.logger.warn("RightOut expired webmail draft needs manual cleanup");
        }
      }
      if (stateEncryptionReady(api.pluginConfig as RightOutConfig | undefined)) {
        await invalidatePortalFlows(
          (flow) => Number.isFinite(flow.expiresAt) && flow.expiresAt <= now,
          "verified_portal_flow_expired_after_restart",
        );
      }
    }

    api.registerSecurityAuditCollector(({ config, sourceConfig }) => {
      const findings = [];
      const source = sourceConfig as Record<string, any>;
      const rightout = source.plugins?.entries?.rightout?.config as Record<string, any> | undefined;
      for (const candidate of [
        secretFinding(rightout, "braveApiKey", "RightOut Brave key is stored as plaintext"),
        secretFinding(rightout, "smtpTransport.username", "RightOut SMTP username is stored as plaintext"),
        secretFinding(rightout, "smtpTransport.password", "RightOut SMTP password is stored as plaintext"),
        secretFinding(rightout, "smtpTransport.oauthAccessToken", "RightOut SMTP OAuth access token is stored as plaintext"),
        secretFinding(rightout, "smtpTransport.fromAddress", "RightOut sender address is stored as plaintext"),
        secretFinding(rightout, "imapTransport.username", "RightOut IMAP username is stored as plaintext"),
        secretFinding(rightout, "imapTransport.password", "RightOut IMAP password is stored as plaintext"),
        secretFinding(rightout, "imapTransport.oauthAccessToken", "RightOut IMAP OAuth access token is stored as plaintext"),
        secretFinding(rightout, "imapTransport.address", "RightOut IMAP mailbox address is stored as plaintext"),
        secretFinding(rightout, "stateEncryptionKey", "RightOut durable-state encryption key is stored as plaintext"),
        secretFinding(rightout, "browserControlToken", "RightOut browser-control token is stored as plaintext"),
      ]) {
        if (candidate) findings.push(candidate);
      }
      for (const [profileId, profile] of Object.entries(rightout?.profiles ?? {})) {
        if (!isSecretRef((profile as Record<string, unknown>)?.payload)) {
          findings.push({
            checkId: `rightout.secretref.profile.${profileId}`,
            severity: "critical" as const,
            title: "RightOut subject profile is stored as plaintext",
            detail: "A private subject profile is not an OpenClaw SecretRef.",
            remediation: "Migrate every profiles.*.payload value to a SecretRef, scrub plaintext residue, and run openclaw secrets audit --check.",
          });
        }
      }
      for (const [index, previousKey] of (rightout?.previousStateEncryptionKeys ?? []).entries()) {
        if (!isSecretRef(previousKey)) {
          findings.push({
            checkId: `rightout.secretref.previous_state_key.${index}`,
            severity: "critical" as const,
            title: "RightOut previous state key is stored as plaintext",
            detail: "A temporary previous key used for state rotation is not an OpenClaw SecretRef.",
            remediation: "Migrate every previousStateEncryptionKeys item to a SecretRef, complete rotation, remove the old refs, and run openclaw secrets audit --check.",
          });
        }
      }
      if (rightout?.profiles !== undefined && rightout?.stateEncryptionKey === undefined) {
        findings.push({
          checkId: "rightout.state_encryption_key",
          severity: "critical" as const,
          title: "RightOut durable state encryption key is missing",
          detail: "Durable cases, dedupe records, and opaque URL handles require an operator SecretRef encryption key.",
          remediation: "Configure plugins.entries.rightout.config.stateEncryptionKey as a SecretRef with at least 32 random characters.",
        });
      }
      const scanAttestations = rightout?.operatorAttestations;
      if (rightout?.braveApiKey !== undefined && (
        scanAttestations?.braveTermsAccepted !== true
        || scanAttestations?.braveTermsVersion !== BRAVE_TERMS_VERSION
        || scanAttestations?.braveCustomerResponsibilitiesAccepted !== true
        || scanAttestations?.subjectConsentReviewed !== true
        || !Array.isArray(scanAttestations?.authorizedProfileIds)
        || scanAttestations.authorizedProfileIds.length < 1
        || !scanAttestations?.authorizedProfileDigests
        || typeof scanAttestations.authorizedProfileDigests !== "object"
        || scanAttestations.authorizedProfileIds.some((profileId: string) => !/^[a-f0-9]{64}$/.test(scanAttestations.authorizedProfileDigests?.[profileId]))
        || !Array.isArray(scanAttestations?.authorizedBrokerIds)
        || scanAttestations.authorizedBrokerIds.length < 1
      )) {
        findings.push({
          checkId: "rightout.scan_operator_attestations",
          severity: "critical" as const,
          title: "RightOut scan attestations are incomplete",
          detail: `Live scans require exact scope plus Brave terms version ${BRAVE_TERMS_VERSION} and customer responsibilities.`,
          remediation: "Review the cited Brave terms and privacy notice, then set revision-bound operatorAttestations out of band.",
        });
      }
      const removalAttestations = rightout?.removalAttestations;
      if (rightout?.smtpTransport !== undefined && (
        removalAttestations?.rightoutRemovalPolicyAccepted !== true
        || removalAttestations?.rightoutRemovalPolicyVersion !== RIGHTOUT_REMOVAL_POLICY_VERSION
        || removalAttestations?.subjectConsentReviewed !== true
        || removalAttestations?.smtpAccountAuthorized !== true
        || removalAttestations?.minimumDisclosureAccepted !== true
        || !Array.isArray(removalAttestations?.authorizedProfileIds)
        || removalAttestations.authorizedProfileIds.length < 1
        || !removalAttestations?.authorizedProfileDigests
        || typeof removalAttestations.authorizedProfileDigests !== "object"
        || removalAttestations.authorizedProfileIds.some((profileId: string) => !/^[a-f0-9]{64}$/.test(removalAttestations.authorizedProfileDigests?.[profileId]))
        || !Array.isArray(removalAttestations?.authorizedBrokerIds)
        || removalAttestations.authorizedBrokerIds.length < 1
        || !Array.isArray(removalAttestations?.authorizedRequestKinds)
        || !removalAttestations.authorizedRequestKinds.some((kind: string) => ["delete_and_opt_out", "gdpr_erasure_objection"].includes(kind))
        || typeof removalAttestations?.smtpTransportDigest !== "string"
        || !/^[a-f0-9]{64}$/.test(removalAttestations.smtpTransportDigest)
      )) {
        findings.push({
          checkId: "rightout.removal_operator_attestations",
          severity: "critical" as const,
          title: "RightOut removal attestations are incomplete",
          detail: `Removal writes require consent, SMTP authority, minimum-disclosure acceptance, exact scope, and policy ${RIGHTOUT_REMOVAL_POLICY_VERSION}.`,
          remediation: "Review the removal policy and configure exact revision-bound removalAttestations out of band.",
        });
      }
      const verificationAttestations = rightout?.verificationAttestations;
      const verificationImapBindingValid = typeof verificationAttestations?.imapTransportDigest === "string"
        && /^[a-f0-9]{64}$/.test(verificationAttestations.imapTransportDigest);
      let verificationBrowserBindingValid = false;
      try {
        verificationBrowserBindingValid = typeof verificationAttestations?.browserProfileDigest === "string"
          && verificationAttestations.browserProfileDigest === browserVerificationProfileDigest({
            browserControlBaseUrl: rightout?.browserControlBaseUrl,
            browserProfile: rightout?.browserProfile,
            browserBackendMode: rightout?.browserBackendMode,
          });
      } catch { /* an invalid or absent logged-in browser binding is not ready */ }
      if (verificationAttestations !== undefined && (
        verificationAttestations?.rightoutVerificationPolicyAccepted !== true
        || verificationAttestations?.rightoutVerificationPolicyVersion !== RIGHTOUT_VERIFICATION_POLICY_VERSION
        || verificationAttestations?.subjectConsentReviewed !== true
        || verificationAttestations?.inboxReadAuthorized !== true
        || verificationAttestations?.verificationLinkOpenAuthorized !== true
        || !Array.isArray(verificationAttestations?.authorizedProfileIds)
        || verificationAttestations.authorizedProfileIds.length < 1
        || !verificationAttestations?.authorizedProfileDigests
        || typeof verificationAttestations.authorizedProfileDigests !== "object"
        || verificationAttestations.authorizedProfileIds.some((profileId: string) => !/^[a-f0-9]{64}$/.test(verificationAttestations.authorizedProfileDigests?.[profileId]))
        || !Array.isArray(verificationAttestations?.authorizedBrokerIds)
        || verificationAttestations.authorizedBrokerIds.length < 1
        || (!verificationImapBindingValid && !verificationBrowserBindingValid)
      )) {
        findings.push({
          checkId: "rightout.verification_operator_attestations",
          severity: "critical" as const,
          title: "RightOut inbox-verification attestations are incomplete",
          detail: `Inbox reads and confirmation-link opens require exact scope and policy ${RIGHTOUT_VERIFICATION_POLICY_VERSION}.`,
          remediation: "Review the verification policy and configure exact revision-bound verificationAttestations out of band.",
        });
      }
      const controllerReplyAttestations = rightout?.controllerReplyAttestations;
      if (controllerReplyAttestations !== undefined && (
        controllerReplyAttestations?.rightoutControllerReplyPolicyAccepted !== true
        || controllerReplyAttestations?.rightoutControllerReplyPolicyVersion !== RIGHTOUT_CONTROLLER_REPLY_POLICY_VERSION
        || controllerReplyAttestations?.subjectConsentReviewed !== true
        || controllerReplyAttestations?.inboxReadAuthorized !== true
        || !Array.isArray(controllerReplyAttestations?.authorizedProfileIds)
        || controllerReplyAttestations.authorizedProfileIds.length < 1
        || !controllerReplyAttestations?.authorizedProfileDigests
        || typeof controllerReplyAttestations.authorizedProfileDigests !== "object"
        || controllerReplyAttestations.authorizedProfileIds.some((profileId: string) => !/^[a-f0-9]{64}$/.test(controllerReplyAttestations.authorizedProfileDigests?.[profileId]))
        || !Array.isArray(controllerReplyAttestations?.authorizedBrokerIds)
        || controllerReplyAttestations.authorizedBrokerIds.length < 1
        || typeof controllerReplyAttestations?.imapTransportDigest !== "string"
        || !/^[a-f0-9]{64}$/.test(controllerReplyAttestations.imapTransportDigest)
      )) {
        findings.push({
          checkId: "rightout.controller_reply_attestations",
          severity: "critical" as const,
          title: "RightOut controller-reply attestations are incomplete",
          detail: `Authenticated reply candidates require exact subject, broker, IMAP, and policy scope ${RIGHTOUT_CONTROLLER_REPLY_POLICY_VERSION}.`,
          remediation: "Review the read-only controller-reply policy and configure exact revision-bound controllerReplyAttestations out of band.",
        });
      }
      const formAttestations = rightout?.formAttestations;
      if (formAttestations !== undefined && (
        formAttestations?.rightoutFormPolicyAccepted !== true
        || formAttestations?.rightoutFormPolicyVersion !== RIGHTOUT_FORM_POLICY_VERSION
        || formAttestations?.subjectConsentReviewed !== true
        || formAttestations?.browserFormAuthorized !== true
        || formAttestations?.minimumDisclosureAccepted !== true
        || !Array.isArray(formAttestations?.authorizedProfileIds)
        || formAttestations.authorizedProfileIds.length < 1
        || !formAttestations?.authorizedProfileDigests
        || typeof formAttestations.authorizedProfileDigests !== "object"
        || formAttestations.authorizedProfileIds.some((profileId: string) => !/^[a-f0-9]{64}$/.test(formAttestations.authorizedProfileDigests?.[profileId]))
        || !Array.isArray(formAttestations?.authorizedBrokerIds)
        || formAttestations.authorizedBrokerIds.length < 1
      )) {
        findings.push({
          checkId: "rightout.form_operator_attestations",
          severity: "critical" as const,
          title: "RightOut browser-form attestations are incomplete",
          detail: `Browser form writes require exact profile/broker scope, minimum disclosure, and policy ${RIGHTOUT_FORM_POLICY_VERSION}.`,
          remediation: "Review the browser-form policy and configure exact revision-bound formAttestations out of band.",
        });
      }
      const directScanAttestations = rightout?.directScanAttestations;
      if (directScanAttestations !== undefined && (
        directScanAttestations?.rightoutDirectScanPolicyAccepted !== true
        || directScanAttestations?.rightoutDirectScanPolicyVersion !== RIGHTOUT_DIRECT_SCAN_POLICY_VERSION
        || directScanAttestations?.subjectConsentReviewed !== true
        || directScanAttestations?.publisherAccessAuthorized !== true
        || directScanAttestations?.publisherTermsReviewed !== true
        || !Array.isArray(directScanAttestations?.authorizedProfileIds)
        || directScanAttestations.authorizedProfileIds.length < 1
        || !directScanAttestations?.authorizedProfileDigests
        || typeof directScanAttestations.authorizedProfileDigests !== "object"
        || directScanAttestations.authorizedProfileIds.some((profileId: string) => !/^[a-f0-9]{64}$/.test(directScanAttestations.authorizedProfileDigests?.[profileId]))
        || !Array.isArray(directScanAttestations?.authorizedBrokerIds)
        || directScanAttestations.authorizedBrokerIds.length < 1
      )) {
        findings.push({
          checkId: "rightout.direct_scan_operator_attestations",
          severity: "critical" as const,
          title: "RightOut direct-rescan attestations are incomplete",
          detail: `Direct publisher reads require exact scope, terms review, and policy ${RIGHTOUT_DIRECT_SCAN_POLICY_VERSION}.`,
          remediation: "Review publisher terms and configure exact revision-bound directScanAttestations out of band.",
        });
      }
      const customTargetConfigured = [
        rightout?.customTargetRecipePacks,
        rightout?.customTargetTrustedKeys,
        rightout?.customTargetPermissions,
      ].filter((value) => value !== undefined).length;
      if (customTargetConfigured > 0 && customTargetConfigured < 3) {
        findings.push({
          checkId: "rightout.custom_target_trust",
          severity: "critical" as const,
          title: "RightOut custom-target trust configuration is incomplete",
          detail: "Custom targets remain quarantined unless signed recipe packs, allowlisted Ed25519 public keys, and exact handle-bound current permissions are all configured.",
          remediation: "Configure all three custom-target trust inputs or remove the partial configuration; raw targets remain encrypted local state.",
        });
      }
      if (rightout?.teamAccess !== undefined) {
        try {
          validateTeamAccess(rightout.teamAccess, Object.keys(rightout?.profiles ?? {}));
        } catch {
          findings.push({
            checkId: "rightout.team_access",
            severity: "critical" as const,
            title: "RightOut team access configuration is invalid",
            detail: "Team mode requires unique session bindings, at least one owner, exact roles, and configured per-member subject scopes.",
            remediation: "Generate session bindings with rightout_team_session_binding and configure unique owner, manager, or viewer records with exact profile IDs.",
          });
        }
      }
      const runtime = config as Record<string, any>;
      const httpDeny = runtime.gateway?.tools?.deny;
      const privilegedGatewayTools = [
        "rightout_live_scan",
        "rightout_submit_removal",
        "rightout_submit_form_removal",
        "rightout_poll_verification",
        "rightout_poll_controller_reply",
        "rightout_open_verification",
        "rightout_direct_rescan",
        "rightout_purge_subject_state",
        "rightout_record_controller_outcome",
        "rightout_create_evidence_snapshot",
        "rightout_export_evidence",
        "rightout_export_dashboard",
        "rightout_reconcile_submission",
        "rightout_rotate_state_key",
        "rightout_start_campaign",
        "rightout_revoke_campaign",
        "rightout_refresh_registries",
        "rightout_refresh_parity_sources",
        "rightout_record_drop_filed",
        "rightout_submit_parity_email",
        "rightout_begin_webmail_session",
        "rightout_webmail_session_step",
        "rightout_begin_webmail_verification",
        "rightout_begin_discovery_session",
        "rightout_discovery_session_step",
        "rightout_begin_form_session",
        "rightout_form_session_step",
        "rightout_worker_enable",
        "rightout_worker_tick",
        "rightout_worker_complete",
        "rightout_worker_resume",
        "rightout_worker_revoke",
      ];
      const missingDeny = privilegedGatewayTools.filter((tool) => !Array.isArray(httpDeny) || !httpDeny.includes(tool));
      if (missingDeny.length) {
        findings.push({
          checkId: "rightout.gateway.tools_invoke",
          severity: "warn" as const,
          title: "RightOut tools are reachable through direct Gateway tool invoke",
          detail: `The following tools are not denied on the full-operator /tools/invoke surface: ${missingDeny.join(", ")}.`,
          remediation: "Add all live RightOut tools to gateway.tools.deny unless direct operator invocation is explicitly required.",
        });
      }
      if (rightout?.teamAccess !== undefined) {
        const teamGatewayTools = [...new Set([
          ...privilegedGatewayTools,
          "rightout_evidence_status",
          "rightout_custom_target_status",
          "rightout_effectiveness",
          "rightout_team_session_binding",
          "rightout_team_overview",
          "rightout_next_actions",
          "rightout_case_status",
          "rightout_export_report",
          "rightout_catalog_health",
          "rightout_setup",
          "rightout_doctor",
          "rightout_due_rechecks",
          "rightout_campaign_status",
          "rightout_campaign_next",
          "rightout_worker_status",
          "rightout_registry_status",
          "rightout_registry_search",
          "rightout_unbroker_parity_health",
        ])];
        const exposed = teamGatewayTools.filter((tool) => !Array.isArray(httpDeny) || !httpDeny.includes(tool));
        if (exposed.length) {
          findings.push({
            checkId: "rightout.team_access.gateway_boundary",
            severity: "critical" as const,
            title: "RightOut team roles are bypassable through full-operator direct tool invoke",
            detail: `Team mode requires every RightOut tool to be denied on /tools/invoke; missing: ${exposed.join(", ")}.`,
            remediation: "Add every RightOut contract tool to gateway.tools.deny so all family/team use stays inside session-bound agent hooks.",
          });
        }
      }
      return findings;
    });

    api.on("before_tool_call", async (event, hookContext) => {
      const config = api.pluginConfig as RightOutConfig | undefined;
      if (config?.teamAccess !== undefined && event.toolName.startsWith("rightout_")) {
        if (event.toolName !== "rightout_team_session_binding") {
          try {
            const member = currentTeamMember(config, hookContext as Record<string, any>);
            if (!member) throw new Error("rightout_team_access_not_configured");
            const profileId = await eventProfileScope(event.params);
            if (profileId) assertTeamProfileScope(member, profileId);
            const teamReadOnlyTools = new Set([
              "rightout_next_actions",
              "rightout_case_status",
              "rightout_export_report",
              "rightout_catalog_health",
              "rightout_setup",
              "rightout_doctor",
              "rightout_due_rechecks",
              "rightout_registry_status",
              "rightout_registry_search",
              "rightout_unbroker_parity_health",
              "rightout_evidence_status",
              "rightout_custom_target_status",
              "rightout_effectiveness",
              "rightout_team_overview",
            ]);
            const dashboardAllowed = event.toolName === "rightout_export_dashboard" && ["owner", "manager"].includes(member.role);
            if (!teamReadOnlyTools.has(event.toolName) && !dashboardAllowed && member.role !== "owner") {
              throw new Error("rightout_team_role_unauthorized");
            }
          } catch {
            return { block: true, blockReason: "RightOut team access requires an exact bound session, authorized profile scope, and sufficient role" };
          }
        }
      }
      if (event.toolCallId && event.toolName.startsWith("rightout_") && typeof hookContext?.sessionKey === "string" && typeof hookContext?.agentId === "string") {
        try {
          const session = trustedWorkerSession(hookContext as Record<string, any>);
          const matched = await workerLedger.matchExecution(event.toolName, event.params, session.sessionBindingDigest);
          if (matched) {
            workerEffectCalls.set(event.toolCallId, {
              workerId: matched.worker_id,
              leaseId: matched.lease_id,
              executionDigest: matched.execution_digest,
            });
          }
        } catch {
          return { block: true, blockReason: "RightOut could not bind this provider action to the exact pending durable-worker command" };
        }
      }
      const approvalTools = new Set([
        "rightout_live_scan",
        "rightout_submit_removal",
        "rightout_submit_form_removal",
        "rightout_poll_verification",
        "rightout_poll_controller_reply",
        "rightout_open_verification",
        "rightout_direct_rescan",
        "rightout_purge_subject_state",
        "rightout_record_controller_outcome",
        "rightout_export_evidence",
        "rightout_export_dashboard",
        "rightout_reconcile_submission",
        "rightout_rotate_state_key",
        "rightout_start_campaign",
        "rightout_revoke_campaign",
        "rightout_refresh_registries",
        "rightout_refresh_parity_sources",
        "rightout_record_drop_filed",
        "rightout_form_session_step",
        "rightout_worker_enable",
        "rightout_worker_resume",
      ]);
      if (!approvalTools.has(event.toolName)) return;
      if (!event.toolCallId) return { block: true, blockReason: "RightOut requires a host-authoritative tool call ID" };
      const catalog = await catalogPromise;
      pruneApprovalState();
      approvalBindings.delete(event.toolCallId);
      if (event.toolName === "rightout_worker_enable") {
        try {
          const input = validateWorkerEnableInput(event.params);
          const campaign = await campaignLedger.status(input.campaignId);
          if (campaign.status !== "active") throw new Error("rightout_worker_campaign_invalid");
          const profileDigest = await ensureImmutableProfileSnapshot(campaign.subject_ref);
          await campaignLedger.assertScope(campaign.campaign_id, {
            profileId: campaign.subject_ref,
            profileDigest,
            runtimeScopeDigest: configuredRuntimeScopeDigest(),
          });
          const session = trustedWorkerSession(hookContext as Record<string, any>);
          const policyDigest = await currentWorkerPolicyDigest();
          const binding = workerEnableScopeBinding(input, policyDigest, session.sessionBindingDigest);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Enable durable RightOut worker",
              description: `Advance ${input.campaignId} in this exact trusted session every ${input.intervalMinutes}m when idle; stop after ${input.maxConsecutiveFailures} transient failures, scope drift, revocation, or any human gate.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "Durable RightOut autonomy requires an active immutable campaign, current recipe policy, exact trusted session, and native allow-once approval" };
        }
      }
      if (event.toolName === "rightout_export_evidence") {
        try {
          const input = validateEvidenceRefInput(event.params, true) as PublicEvidenceExportInput;
          const binding = evidenceExportScopeBinding(input);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Export redacted local evidence",
              description: `P ${input.profileId}; ${input.evidenceRef}. Write one ${input.format} artifact into the private local RightOut export directory after the evidence-vault redaction scan.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid RightOut evidence-export scope" };
        }
      }
      if (event.toolName === "rightout_export_dashboard") {
        try {
          const input = validateDashboardExportInput(event.params);
          const member = currentTeamMember(config, hookContext as Record<string, any>);
          if (!member || !["owner", "manager"].includes(member.role)) throw new Error("rightout_team_role_unauthorized");
          const session = teamContext(hookContext as Record<string, any>);
          const binding = dashboardExportScopeBinding(input, member, teamSessionBindingDigest(session));
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Export private local RightOut dashboard",
              description: `Write one static ${input.format} dashboard for ${member.member_id} and only its authorized subject scopes. No server, scripts, remote assets, or network request.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "Private dashboard export requires a configured owner or manager session and native allow-once approval" };
        }
      }
      if (event.toolName === "rightout_worker_resume") {
        try {
          const input = validateWorkerRefInput(event.params);
          const context = await workerExecutionContext(input.workerId, hookContext as Record<string, any>);
          if (context.campaign.status !== "active") throw new Error("rightout_worker_campaign_invalid");
          const binding = workerResumeScopeBinding(input, context.policyDigest, context.sessionBindingDigest);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Resume durable RightOut worker",
              description: `Resume ${input.workerId} only in its original trusted session and unchanged campaign, runtime, catalog, and signed-recipe scope.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "RightOut worker resume requires the original trusted session, unchanged policy, active campaign, and native allow-once approval" };
        }
      }
      if (event.toolName === "rightout_form_session_step") {
        try {
          const input = validateFormSessionStepInput(event.params);
          await pruneTransientState();
          const session = activeFormSession(input.sessionId);
          if (input.action.kind !== "fill") return;
          const fields = input.action.fields.map((field: Record<string, any>) => session.fieldDisclosureMap?.[field.profile_field]).filter(Boolean);
          if (!fields.includes("date_of_birth")) return;
          await revalidatePublisherBrowserSession(input.sessionId, session, "submit_form");
          const binding = sensitiveFormStepScopeBinding(session, input);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Authorize sensitive DOB disclosure",
              description: `P ${session.profileId}; ${session.broker.id} (${session.broker.name}); host ${new URL(session.broker.action_url).hostname}; fields ${[...new Set(fields)].sort().join(",")}; campaign ${session.campaignId}; allow once.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "Sensitive form disclosure requires an exact active session, immutable subject snapshot, and native human allow-once approval" };
        }
      }
      if (event.toolName === "rightout_start_campaign") {
        try {
          const input = validateCampaignStartInput(event.params) as PublicCampaignStartInput;
          await assertAutonomousCampaignScope(input);
          const routingScope = browserApprovalRoutingScope(config, {
            browserRequired: input.effects.some((effect) => ["publisher_discover", "submit_form"].includes(effect))
              || (input.effects.includes("open_verification") && input.brokerIds.includes("intelius")),
            effects: input.effects,
          });
          await assertCampaignPublisherPermissions(input, routingScope);
          const digest = await campaignCatalogDigestPromise;
          const binding = campaignScopeBinding(input, digest, routingScope.routingDigest);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Authorize autonomous RightOut campaign",
              description: campaignApprovalDescription(input, routingScope),
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid, unconfigured, or unsupported RightOut autonomous campaign scope" };
        }
      }
      if (event.toolName === "rightout_revoke_campaign") {
        try {
          const input = validateCampaignRef(event.params) as PublicCampaignRefInput;
          const binding = campaignRevokeScopeBinding(input);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Revoke autonomous RightOut campaign",
              description: `Permanently revoke ${input.campaignId}. No further autonomous provider effect can use this standing authorization.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid RightOut campaign revocation scope" };
        }
      }
      if (event.toolName === "rightout_record_drop_filed") {
        try {
          const input = validateCaseInput(event.params);
          assertConfiguredProfile(input.profileId);
          const profile = parseRemovalProfile((config?.profiles?.[input.profileId] as any)?.payload);
          if (!profile.jurisdictions.includes("US-CA")) throw new Error("rightout_drop_ineligible");
          const registry = await registryMeta();
          if (registry.state !== "registry_ready" || !Number.isInteger(registry.record_count) || registry.record_count < 1) throw new Error("rightout_drop_registry_invalid");
          const binding = dropFiledScopeBinding(input.profileId, registry.record_count);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Record California DROP filing",
              description: `P ${input.profileId}; attest the human-verified DROP request was filed for the current ${registry.record_count}-broker official registry snapshot. No provider write.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "California DROP filing requires an eligible profile, current official registry snapshot, and operator attestation" };
        }
      }
      if (event.toolName === "rightout_rotate_state_key") {
        try {
          if (!event.params || typeof event.params !== "object" || Array.isArray(event.params) || Object.keys(event.params).length !== 0) {
            throw new Error("invalid_state_rotation_scope");
          }
          const binding = rotationScopeBinding();
          const toolCallId = event.toolCallId;
          return {
            params: {},
            requireApproval: {
              title: "Rotate RightOut state encryption key",
              description: "Re-encrypt all local RightOut state with the active SecretRef key. No provider call or PII output. Keep previous keys configured until this operation succeeds.",
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid or unconfigured RightOut state-key rotation" };
        }
      }
      if (event.toolName === "rightout_purge_subject_state") {
        try {
          const input = validateCaseInput(event.params);
          const binding = purgeScopeBinding(input);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Purge RightOut subject state",
              description: `P ${input.profileId}. Permanently delete this subject's encrypted RightOut cases, handles, and dedupe records. Provider data and OpenClaw config are unchanged.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid RightOut subject-state purge scope" };
        }
      }
      if (event.toolName === "rightout_record_controller_outcome") {
        try {
          const input = validateControllerOutcomeInput(event.params);
          const broker = resolveControllerOutcomeBroker(catalog, input);
          if (!["eu_controller_email_erasure", "us_data_broker_email_deletion"].includes(broker.processClass) || broker.confirmationPolicy !== "submitted_until_controller_response") {
            throw new Error("unsupported_controller_outcome_lane");
          }
          const candidate = await controllerCandidateForOutcome(input);
          const binding = controllerOutcomeScopeBinding(input, broker, candidate);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Record reviewed controller outcome",
              description: `P ${input.profileId}; ${broker.name}. Confirm you personally reviewed the official controller response${candidate ? " behind the authenticated encrypted candidate" : ""} and record '${input.outcome}'. This can change removal status; no provider write.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid, unsupported, or unreviewed RightOut controller outcome" };
        }
      }
      if (event.toolName === "rightout_reconcile_submission") {
        try {
          const input = validateSubmissionReconciliationInput(event.params);
          const broker = resolveSubmissionReconciliationBroker(catalog, input);
          const binding = submissionReconciliationScopeBinding(input, broker);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Reconcile uncertain provider write",
              description: `P ${input.profileId}; ${broker.name}. Confirm you personally reviewed provider-side evidence and record '${input.outcome}'. This changes retry safety; no provider write.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid, unsupported, or unreviewed RightOut submission reconciliation" };
        }
      }
      if (event.toolName === "rightout_refresh_parity_sources" || event.toolName === "rightout_refresh_registries") {
        try {
          if (!event.params || typeof event.params !== "object" || Array.isArray(event.params) || Object.keys(event.params).length !== 0) {
            throw new Error("invalid_refresh_scope");
          }
          const parityRefresh = event.toolName === "rightout_refresh_parity_sources";
          const parityScope = parityRefresh ? await paritySourceApprovalScope(config) : undefined;
          const binding = parityScope
            ? paritySourceRefreshScopeBinding(parityScope.routeIds, parityScope.permissionDigest)
            : registryRefreshScopeBinding();
          const toolCallId = event.toolCallId;
          return {
            params: {},
            requireApproval: {
              title: parityRefresh ? "Refresh broker source health" : "Refresh official registry snapshot",
              description: parityRefresh
                ? paritySourceApprovalDescription(parityScope!)
                : "Read the newest available CPPA registry CSV (2025-current) and replace the encrypted local registry snapshot. No subject data or controller write.",
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "RightOut refresh requires an exact empty input and native allow-once approval" };
        }
      }
      if (event.toolName === "rightout_live_scan") {
        try {
          const scoped = splitCampaignParams(event.params);
          const input = validatePublicToolInput(scoped.params) as PublicScanInput;
          const scanCatalog = await combinedScanCatalog();
          assertSupportedBrokerScope(scanCatalog, input);
          await assertScanScopeFresh(input);
          const attestations = scanAttestationSnapshot(config, input);
          if (scoped.campaignId) {
            await authorizeCampaignEffects(
              scoped.campaignId,
              input.profileId,
              input.brokerIds.map((brokerId) => ({ brokerId, effect: "discover" })),
              catalog,
              false,
            );
            return { params: { ...input, campaignId: scoped.campaignId } };
          }
          if (input.brokerIds.length > 2) throw new Error("per_effect_scan_scope_too_large");
          const binding = scanScopeBinding(input, attestations);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Run live data-broker scan",
              description: approvalDescription(input),
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") {
                  approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                } else {
                  approvalBindings.delete(toolCallId);
                }
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid, unsupported, or unattested RightOut scan scope" };
        }
      }

      if (event.toolName === "rightout_submit_removal") {
        try {
          const scoped = splitCampaignParams(event.params);
          const input = validateRemovalPublicToolInput(scoped.params) as PublicRemovalInput;
          const broker = resolveRemovalCatalogEntry(catalog, input);
          assertFreshCatalogEntries(catalog, [input.brokerId]);
          const attestations = removalAttestationSnapshot(config, input);
          const dedupeKey = removalDedupeKey(input);
          if (submittedScopes.has(dedupeKey)) return { block: true, blockReason: "duplicate RightOut removal request is cooling down" };
          if (scoped.campaignId) {
            await authorizeCampaignEffects(scoped.campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "submit_email" }], catalog, false);
            return { params: { ...input, campaignId: scoped.campaignId } };
          }
          const binding = removalScopeBinding(input, attestations, broker);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Submit broker removal request",
              description: removalApprovalDescription(input, broker),
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") {
                  approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                } else {
                  approvalBindings.delete(toolCallId);
                }
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid, unsupported, unconsented, or unattested RightOut removal scope" };
        }
      }

      if (event.toolName === "rightout_submit_form_removal") {
        try {
          const scoped = splitCampaignParams(event.params);
          const input = validateFormRemovalInput(scoped.params) as PublicRemovalInput;
          const broker = resolveFormCatalogEntry(catalog, input);
          const browserScope = browserApprovalRoutingScope(config, { browserRequired: true, effects: ["submit_form"] });
          if (browserScope.browserBackendMode === "not_required") throw new Error("rightout_browser_backend_invalid");
          assertPublisherAutomationPermission(
            config, { id: input.brokerId, method: "web_form" }, await providerTermsPromise, "submit_form",
            { browserBackend: browserScope.browserBackendMode },
          );
          assertFreshCatalogEntries(catalog, [input.brokerId]);
          const attestations = formAttestationSnapshot(config, input);
          const dedupeKey = removalDedupeKey(input);
          if (submittedScopes.has(dedupeKey)) return { block: true, blockReason: "duplicate RightOut form removal is cooling down" };
          if (scoped.campaignId) {
            await authorizeCampaignEffects(scoped.campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "submit_form" }], catalog, false);
            return { params: { ...input, campaignId: scoped.campaignId } };
          }
          const binding = formScopeBinding(input, attestations, broker, browserScope);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Submit broker suppression form",
              description: formApprovalDescription(input, broker, browserScope),
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid, unsupported, unconsented, or unattested RightOut browser-form scope" };
        }
      }

      if (event.toolName === "rightout_poll_verification") {
        try {
          const scoped = splitCampaignParams(event.params);
          const input = validateVerificationPollInput(scoped.params) as PublicVerificationPollInput;
          const verificationCatalog = await combinedVerificationCatalog();
          const broker = resolveVerificationCatalogEntry(verificationCatalog, { profileId: input.profileId, brokerId: input.brokerId });
          await assertParityRouteFresh(input.brokerId);
          const attestations = verificationAttestationSnapshot(config, input);
          if (scoped.campaignId) {
            await authorizeCampaignEffects(scoped.campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "poll_verification" }], catalog, false);
            return { params: { ...input, campaignId: scoped.campaignId } };
          }
          const binding = verificationPollScopeBinding(input, attestations, broker);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Poll broker verification mail",
              description: verificationPollApprovalDescription(input, broker),
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid, unsupported, or unattested RightOut inbox-verification scope" };
        }
      }

      if (event.toolName === "rightout_poll_controller_reply") {
        try {
          const input = validateControllerReplyInput(event.params);
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string" || !config.imapTransport) {
            throw new Error("rightout_not_configured");
          }
          assertFreshCatalogEntries(catalog, [input.brokerId]);
          const attestations = controllerReplyAttestationSnapshot(config, input);
          const preflight = validateControllerReplyPreflight({
            input,
            catalog,
            profilePayload: config.profiles[input.profileId].payload,
            imapTransport: config.imapTransport,
            attestations,
          });
          const binding = controllerReplyScopeBinding(input, attestations, preflight.broker);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Poll authenticated controller reply",
              description: `P ${input.profileId}; ${input.brokerId}. Read up to 30 recent INBOX messages, accept only exact-recipient, aligned-DKIM, official-domain, exact-thread replies; return no body or address.`,
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid, unsupported, unconsented, or unattested RightOut controller-reply scope" };
        }
      }

      if (event.toolName === "rightout_direct_rescan") {
        try {
          const scoped = splitCampaignParams(event.params);
          const input = validateDirectScanInput(scoped.params) as PublicDirectScanInput;
          const directCatalog = await combinedDirectCatalog();
          const broker = resolveDirectScanCatalogEntry(directCatalog, input);
          assertPublisherAutomationPermission(config, broker, await providerTermsPromise, "direct_recheck");
          await assertParityRouteFresh(input.brokerId);
          const attestations = directScanAttestationSnapshot(config, input);
          if (scoped.campaignId) {
            await authorizeCampaignEffects(scoped.campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "direct_recheck" }], catalog, false);
            return { params: { ...input, campaignId: scoped.campaignId } };
          }
          const binding = directScanScopeBinding(input, attestations, broker);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Directly recheck known broker listing",
              description: directScanApprovalDescription(input, broker),
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              onResolution(decision: PluginApprovalResolution) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid, expired, unsupported, or unattested RightOut direct-rescan scope" };
        }
      }

      try {
        const scoped = splitCampaignParams(event.params);
        const input = validateVerificationOpenInput(scoped.params) as PublicVerificationOpenInput;
        const verificationCatalog = await combinedVerificationCatalog();
        const broker = resolveVerificationCatalogEntry(verificationCatalog, input);
        if (broker.openLinkMode === "browser_same_profile_required" && !scoped.campaignId) {
          return { block: true, blockReason: "Same-profile verification requires a finite campaign grant; assisted mode remains a manual human gate" };
        }
        const openRoutingScope = browserApprovalRoutingScope(config, {
          browserRequired: broker.openLinkMode === "browser_same_profile_required",
          effects: ["open_verification"],
        });
        if (broker.openLinkMode === "browser_same_profile_required") {
          if (openRoutingScope.browserBackendMode === "not_required") throw new Error("rightout_browser_backend_invalid");
          assertPublisherAutomationPermission(config, broker, await providerTermsPromise, "open_verification", { browserBackend: openRoutingScope.browserBackendMode });
        } else {
          assertPublisherAutomationPermission(config, broker, await providerTermsPromise, "open_verification");
        }
        await assertParityRouteFresh(input.brokerId);
        const attestations = verificationAttestationSnapshot(config, input);
        if (scoped.campaignId) {
          await authorizeCampaignEffects(scoped.campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "open_verification" }], catalog, false);
          return { params: { ...input, campaignId: scoped.campaignId } };
        }
        const binding = verificationOpenScopeBinding(input, attestations, broker);
        const toolCallId = event.toolCallId;
        return {
          params: input,
          requireApproval: {
            title: "Open broker confirmation link",
            description: verificationOpenApprovalDescription(input, broker),
            severity: "critical" as const,
            allowedDecisions: ["allow-once", "deny"] as const,
            timeoutMs: approvalTtlMs,
            onResolution(decision: PluginApprovalResolution) {
              if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
              else approvalBindings.delete(toolCallId);
            },
          },
        };
      } catch {
        return { block: true, blockReason: "invalid, expired, mismatched, or unattested RightOut verification-link scope" };
      }
    });

    api.on("after_tool_call", async (event) => {
      if (!event.toolCallId) return;
      const pending = workerEffectCalls.get(event.toolCallId);
      if (!pending) return;
      workerEffectCalls.delete(event.toolCallId);
      const receipt = workerExecutionReceipt(event.toolName, event.result, event.error);
      try {
        await workerLedger.recordExecutionResult(pending.workerId, pending.leaseId, {
          executionDigest: pending.executionDigest,
          state: receipt.state,
          resultState: receipt.resultState,
        });
      } catch {
        api.logger?.warn?.("RightOut could not persist an exact durable-worker execution receipt; completion will fail closed");
      }
    });

    api.registerTool(
      (toolContext) => ({
        name: "rightout_live_scan",
        label: "RightOut live scan",
        description: "Run a read-only live Brave index scan of supported catalog brokers under an assisted native allow-once approval or a matching finite campaign grant. Never authorizes or submits a removal.",
        parameters: LiveScanParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicScanInput;
          let campaignId: string | undefined;
          try {
            const scoped = splitCampaignParams(params);
            campaignId = scoped.campaignId;
            input = validatePublicToolInput(scoped.params) as PublicScanInput;
          } catch {
            throw new Error("rightout_approval_binding_failed");
          }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await combinedScanCatalog();
          assertSupportedBrokerScope(catalog, input);
          await assertScanScopeFresh(input);
          let attestations: ScanAttestationSnapshot | undefined;
          try {
            attestations = scanAttestationSnapshot(config, input);
          } catch {
            // Missing or changed attestations invalidate the approval binding.
          }
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!attestations || (!campaignId && (!approval || approval.toolName !== "rightout_live_scan" || approval.binding !== scanScopeBinding(input, attestations)))) {
            throw new Error("rightout_approval_binding_failed");
          }
          if (!stateEncryptionReady(config) || typeof config.braveApiKey !== "string" || typeof config.profiles?.[input.profileId]?.payload !== "string") {
            throw new Error("rightout_not_configured");
          }
          await authorizeCampaignEffects(
            campaignId,
            input.profileId,
            input.brokerIds.map((brokerId) => ({ brokerId, effect: "discover" })),
            catalog,
            true,
          );
          const guardedFetch = async ({ url, allowedHosts, ...options }: {
            url: string;
            allowedHosts: string[];
            timeoutMs?: number;
            maxRedirects?: number;
            signal?: AbortSignal;
            init?: RequestInit;
          }) => fetchWithSsrFGuard({
            url,
            fetchImpl: globalThis.fetch,
            ...options,
            requireHttps: true,
            capture: false,
            policy: buildHostnameAllowlistPolicyFromSuffixAllowlist(allowedHosts),
            auditContext: "rightout_live_scan",
          });
          const report = await runLiveScan({
            input: { ...input, subject: config.profiles[input.profileId].payload },
            catalog,
            apiKey: config.braveApiKey,
            guardedFetch,
            signal,
            operatorAttestations: attestations,
            approvalBoundary: campaignId ? "finite_campaign_grant" : "assisted_allow_once",
          });
          let durableCaseRecorded = true;
          try {
            await caseLedger.recordScan(report);
          } catch {
            durableCaseRecorded = false;
            api.logger.error("RightOut live scan completed but its PII-safe case update failed");
          }
          const trackedReport = { ...report, tracking: { durable_case_recorded: durableCaseRecorded } };
          return { content: [{ type: "text", text: JSON.stringify(trackedReport) }], details: trackedReport };
        },
      }),
      { name: "rightout_live_scan", optional: true },
    );

    api.registerTool(
      {
        name: "rightout_direct_rescan",
        label: "RightOut direct rescan",
        description: "Directly recheck only encrypted broker-domain listing URLs captured by separately authorized discovery. Requires current written provider authorization and exact attestations. Assisted calls use native allow-once; campaign calls use a matching finite grant. Never submits a request.",
        parameters: DirectScanParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicDirectScanInput;
          let campaignId: string | undefined;
          try {
            const scoped = splitCampaignParams(params);
            campaignId = scoped.campaignId;
            input = validateDirectScanInput(scoped.params) as PublicDirectScanInput;
          }
          catch { throw new Error("rightout_approval_binding_failed"); }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await combinedDirectCatalog();
          const broker = resolveDirectScanCatalogEntry(catalog, input);
          assertPublisherAutomationPermission(config, broker, await providerTermsPromise, "direct_recheck");
          await assertParityRouteFresh(input.brokerId);
          let attestations: DirectScanAttestations | undefined;
          try { attestations = directScanAttestationSnapshot(config, input); } catch { /* fail below */ }
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !attestations || (!campaignId && (
              !approval || approval.toolName !== "rightout_direct_rescan"
              || approval.binding !== directScanScopeBinding(input, attestations, broker)
            ))
          ) throw new Error("rightout_approval_binding_failed");
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string") {
            throw new Error("rightout_not_configured");
          }
          await authorizeCampaignEffects(campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "direct_recheck" }], catalog, true);
          const token = await createListingTokenVault(listingTokens, config.stateEncryptionKey).lookup(
            input.listingHandle, input.profileId, input.brokerId,
          );
          const guardedFetch = async ({ url, allowedHosts, ...options }: {
            url: string;
            allowedHosts: string[];
            timeoutMs?: number;
            maxRedirects?: number;
            signal?: AbortSignal;
            init?: RequestInit;
          }) => fetchWithSsrFGuard({
            url,
            fetchImpl: globalThis.fetch,
            ...options,
            requireHttps: true,
            capture: false,
            policy: buildHostnameAllowlistPolicyFromSuffixAllowlist(allowedHosts),
            auditContext: "rightout_direct_rescan",
          });
          const report = await runDirectRescan({
            input,
            catalog,
            profilePayload: config.profiles[input.profileId].payload,
            attestations,
            token,
            guardedFetch,
            signal,
          });
          let durableCaseRecorded = true;
          let state = report.observation;
          try {
            await caseLedger.recordDirectRescan(report);
            const stored = await caseLedger.load(input.profileId);
            state = stored.brokers?.[input.brokerId]?.state ?? state;
          } catch {
            durableCaseRecorded = false;
            api.logger.error("RightOut direct rescan completed but its PII-safe case update failed");
          }
          const trackedReport = {
            ...report,
            state,
            approval_boundary: campaignId ? "finite_campaign_grant" : "assisted_allow_once",
            tracking: { durable_case_recorded: durableCaseRecorded },
          };
          return { content: [{ type: "text", text: JSON.stringify(trackedReport) }], details: trackedReport };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_submit_removal",
        label: "RightOut submit removal",
        description: "Send one catalog-locked US delete/opt-out or EU GDPR erasure/objection email through the approved SMTP account. Assisted calls use native allow-once; campaign calls use a matching finite grant. Submission is never reported as confirmed removal.",
        parameters: RemovalParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicRemovalInput;
          let campaignId: string | undefined;
          try {
            const scoped = splitCampaignParams(params);
            campaignId = scoped.campaignId;
            input = validateRemovalPublicToolInput(scoped.params) as PublicRemovalInput;
          } catch {
            throw new Error("rightout_approval_binding_failed");
          }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await catalogPromise;
          const broker = resolveRemovalCatalogEntry(catalog, input);
          assertFreshCatalogEntries(catalog, [input.brokerId]);
          let attestations: RemovalAttestationSnapshot | undefined;
          try {
            attestations = removalAttestationSnapshot(config, input);
          } catch {
            // Missing or changed attestations invalidate the approval binding.
          }
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!attestations || (!campaignId && (!approval || approval.toolName !== "rightout_submit_removal" || approval.binding !== removalScopeBinding(input, attestations, broker)))) {
            throw new Error("rightout_approval_binding_failed");
          }
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string" || !config.smtpTransport) {
            throw new Error("rightout_not_configured");
          }
          validateRemovalPreflight({
            input,
            catalog,
            profilePayload: config.profiles[input.profileId].payload,
            smtpConfig: config.smtpTransport,
            operatorAttestations: attestations,
          });
          await authorizeCampaignEffects(campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "submit_email" }], catalog, true);
          if ((broker as Record<string, any>).discoveryRequirement !== "not_required_for_data_subject_request") {
            await caseLedger.removalContext(input.profileId, input.brokerId);
          }
          const dedupeKey = removalDedupeKey(input);
          if (submittedScopes.has(dedupeKey)) throw new Error("rightout_duplicate_removal_request");
          await acquireSubmissionDedupe(dedupeKey, input, "smtp_email");
          try {
            await caseLedger.reserveSubmission(input.profileId, input.brokerId, {
              channel: "smtp_email",
              discoveryRequirement: (broker as Record<string, any>).discoveryRequirement,
            });
            await markSubmissionDedupeIntentReserved(dedupeKey, input, "smtp_email");
          } catch (error) {
            await submissionDedupe.delete(dedupeKey);
            throw error;
          }
          submittedScopes.set(dedupeKey, Number.POSITIVE_INFINITY);
          try {
            const report = await runRemovalSubmission({
              input,
              catalog,
              profilePayload: config.profiles[input.profileId].payload,
              smtpConfig: config.smtpTransport,
              operatorAttestations: attestations,
              approvalBoundary: campaignId ? "finite_campaign_grant" : "assisted_allow_once",
              signal,
              sendMail: sendSmtpMail,
            });
            submittedScopes.set(dedupeKey, Date.now() + duplicateCooldownMs);
            let durableCaseRecorded = true;
            let durableSubmissionFinalized = true;
            try {
              const processingDays = Number((broker as Record<string, any>).processingDays ?? 14);
              await caseLedger.recordRemoval(report, processingDays);
            } catch {
              durableSubmissionFinalized = false;
              try {
                await caseLedger.recordSubmissionUncertain(input.profileId, input.brokerId, {
                  channel: "smtp_email",
                  reason: "accepted_write_ledger_finalize_failed",
                });
              } catch { durableCaseRecorded = false; }
              api.logger.error("RightOut removal was submitted but its PII-safe case update failed");
            }
            const trackedReport = {
              ...report,
              state: durableSubmissionFinalized ? report.state : "submission_uncertain",
              tracking: { durable_case_recorded: durableCaseRecorded, submission_finalized: durableSubmissionFinalized },
            };
            return { content: [{ type: "text", text: JSON.stringify(trackedReport) }], details: trackedReport };
          } catch (error) {
            const code = error instanceof Error ? error.message : "";
            const possibleWrite = code === "rightout_removal_transport_failed" || code === "rightout_removal_not_accepted";
            if (possibleWrite) {
              submittedScopes.set(dedupeKey, Date.now() + duplicateCooldownMs);
              await caseLedger.recordSubmissionUncertain(input.profileId, input.brokerId, {
                channel: "smtp_email",
                reason: code,
              }).catch(() => api.logger.error("RightOut ambiguous email write could not be persisted"));
            } else {
              submittedScopes.delete(dedupeKey);
              await caseLedger.releaseSubmission(input.profileId, input.brokerId, code || "provider_write_not_started")
                .catch(() => api.logger.error("RightOut unused email write intent could not be released"));
              await submissionDedupe.delete(dedupeKey);
            }
            throw error;
          }
        },
      },
      { optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_unbroker_parity_health",
        label: "RightOut Unbroker parity health",
        description: "Report the exact normalized 22-broker, 20-form/one-email/one-phone surface, exact form preflight state, and unresolved blockers. Performs no provider request; it may run one PII-free local browser deep-health probe.",
        parameters: EmptyParameters,
        async execute(_toolCallId, params) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length !== 0) {
            throw new Error("rightout_parity_health_input_invalid");
          }
          const parityHealth = parityCatalogHealth(await parityCatalogPromise);
          const termsHealth = providerTermsHealth(await providerTermsPromise);
          const config = api.pluginConfig as RightOutConfig | undefined;
          const authorization = await providerAuthorizationHealth(config);
          const exactFormPairs: Array<{ profile_id: string; broker_id: string }> = [];
          for (const brokerId of authorization.authorized_broker_ids_by_effect.submit_form) {
            for (const profileId of Object.keys(config?.profiles ?? {})) {
              try {
                parityFormAttestationSnapshot(config, profileId, brokerId);
                exactFormPairs.push({ profile_id: profileId, broker_id: brokerId });
              } catch { /* non-overlapping or stale attestations remain closed */ }
            }
          }
          const browser = resolveBrowserBackend(toolContext as Record<string, any>, config);
          const browserProbe = browser.configured
            ? await probeBrowserBackend(browser)
            : { reachable: false, operational: false, deep_snapshot: false };
          const formPolicyConfigurationReady = exactFormPairs.length > 0;
          const formExecutionReady = formPolicyConfigurationReady
            && browser.configured && browserProbe.operational && browserProbe.deep_snapshot;
          const formBlockers = [
            ...(formPolicyConfigurationReady ? [] : ["no_exact_profile_broker_form_attestation_and_provider_permission_overlap"]),
            ...(browser.configured ? [] : ["browser_backend_not_configured"]),
            ...(browserProbe.operational ? [] : ["browser_backend_not_operational"]),
            ...(browserProbe.deep_snapshot ? [] : ["browser_deep_snapshot_not_verified"]),
          ];
          const report = {
            ...parityHealth,
            release_ready: parityHealth.release_ready,
            software_release_ready: parityHealth.release_ready,
            autonomous_form_policy_configuration_ready: formPolicyConfigurationReady,
            autonomous_form_execution_ready: formExecutionReady,
            autonomous_form_readiness_scope: "exact_local_preflight_and_browser_deep_health_provider_effectiveness_not_canaried",
            autonomous_form_execution_blockers: formBlockers,
            exact_form_authorized_profile_broker_pairs: exactFormPairs,
            browser_readiness: {
              selected: browser.selected,
              configured: browser.configured,
              reachable: browserProbe.reachable,
              operational: browserProbe.operational,
              deep_snapshot: browserProbe.deep_snapshot,
            },
            provider_effectiveness_verified: false,
            exact_provider_playbook_choreography_complete: false,
            provider_terms: termsHealth,
            provider_authorization: authorization,
            latest_live_source_refresh: await paritySourceStore.lookup("latest") ?? null,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_unbroker_parity_health", optional: true },
    );

    api.registerTool(
      {
        name: "rightout_refresh_parity_sources",
        label: "RightOut refresh official parity sources",
        description: "Probe only Unbroker-parity publisher URLs covered by current written publisher authorization, without subject data or response-body capture. Unpermitted routes are skipped; findings are quarantined and never mutate the catalog automatically. Requires native allow-once approval.",
        parameters: EmptyParameters,
        async execute(toolCallId, params, signal) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length !== 0) {
            throw new Error("rightout_parity_source_refresh_input_invalid");
          }
          pruneApprovalState();
          const config = api.pluginConfig as RightOutConfig | undefined;
          const refreshScope = await paritySourceApprovalScope(config);
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !approval || approval.toolName !== "rightout_refresh_parity_sources"
            || approval.binding !== paritySourceRefreshScopeBinding(refreshScope.routeIds, refreshScope.permissionDigest)
          ) {
            throw new Error("rightout_approval_binding_failed");
          }
          if (!stateEncryptionReady(config)) throw new Error("rightout_not_configured");
          const catalog = await parityCatalogPromise;
          const guardedFetch = async ({ url, allowedHosts, ...options }: {
            url: string; allowedHosts: string[]; timeoutMs?: number; maxRedirects?: number; signal?: AbortSignal; init?: RequestInit;
          }) => fetchWithSsrFGuard({
            url,
            fetchImpl: globalThis.fetch,
            ...options,
            requireHttps: true,
            capture: false,
            policy: buildHostnameAllowlistPolicyFromSuffixAllowlist(allowedHosts),
            auditContext: "rightout_refresh_parity_sources",
          });
          const providerTerms = await providerTermsPromise;
          const report = await refreshParitySources({
            catalog,
            guardedFetch,
            signal,
            permissionForRoute(route: Record<string, any>) {
              try { return assertPublisherAutomationPermission(config, route, providerTerms, "source_refresh"); }
              catch { return null; }
            },
          });
          await paritySourceStore.register("latest", report);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_submit_parity_email",
        label: "RightOut submit parity rescue email",
        description: "Send one official-source, catalog-locked deletion and opt-out request for an Unbroker broker whose form, phone, identity, or published automation boundary requires the compliant email rescue lane. Requires an active bounded campaign.",
        parameters: ParityEmailParameters,
        async execute(toolCallId, params, signal) {
          const input = validateFormSessionBeginInput(params);
          const config = api.pluginConfig as RightOutConfig | undefined;
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string" || !config.smtpTransport) {
            throw new Error("rightout_not_configured");
          }
          const parityCatalog = await parityCatalogPromise;
          const broker = resolveParityBroker(parityCatalog, input.brokerId);
          if (typeof broker.rescue_email !== "string") throw new Error("rightout_parity_email_lane_invalid");
          await assertParityRescueFresh(input.brokerId);
          const coreCatalog = await catalogPromise;
          await authorizeCampaignEffects(input.campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "submit_email" }], coreCatalog, false);
          let listingUrl;
          if (broker.rescue_disclosure_fields.includes("listing_url")) {
            if (!input.listingHandle) throw new Error("rightout_form_listing_handle_required");
            const token = await createListingTokenVault(listingTokens, config.stateEncryptionKey).lookup(input.listingHandle, input.profileId, input.brokerId);
            listingUrl = token.urls[0];
          }
          const removalInput: PublicRemovalInput = { profileId: input.profileId, brokerId: input.brokerId, requestKind: "delete_and_opt_out" };
          const dedupeKey = removalDedupeKey(removalInput);
          await authorizeCampaignEffects(input.campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "submit_email" }], coreCatalog, true);
          await acquireSubmissionDedupe(dedupeKey, removalInput, "smtp_email");
          try {
            await caseLedger.reserveSubmission(input.profileId, input.brokerId, {
              channel: "smtp_email",
              discoveryRequirement: "not_required_for_data_subject_request",
            });
            await markSubmissionDedupeIntentReserved(dedupeKey, removalInput, "smtp_email");
          } catch (error) {
            await submissionDedupe.delete(dedupeKey);
            throw error;
          }
          let report;
          try {
            report = await runParityEmail({
              input: { profileId: input.profileId, brokerId: input.brokerId },
              broker,
              profilePayload: config.profiles[input.profileId].payload,
              smtpConfig: config.smtpTransport,
              listingUrl,
              sendMail: sendSmtpMail,
              signal,
            });
          } catch (error) {
            const code = error instanceof Error ? error.message : "rightout_removal_transport_failed";
            const possibleWrite = ["rightout_removal_transport_failed", "rightout_removal_not_accepted"].includes(code);
            if (possibleWrite) {
              await caseLedger.recordSubmissionUncertain(input.profileId, input.brokerId, { channel: "smtp_email", reason: code }).catch(() => undefined);
            } else {
              await caseLedger.releaseSubmission(input.profileId, input.brokerId, code).catch(() => undefined);
              await submissionDedupe.delete(dedupeKey);
            }
            throw error;
          }
          let durableCaseRecorded = true;
          let durableSubmissionFinalized = true;
          try {
            await caseLedger.recordRemoval(report, 45);
          } catch {
            durableSubmissionFinalized = false;
            try {
              await caseLedger.recordSubmissionUncertain(input.profileId, input.brokerId, {
                channel: "smtp_email",
                reason: "accepted_write_ledger_finalize_failed",
              });
            } catch { durableCaseRecorded = false; }
            api.logger.error("RightOut parity rescue was accepted but its PII-safe case update failed");
          }
          const details = {
            ...report,
            state: durableSubmissionFinalized ? report.state : "submission_uncertain",
            campaign_id: input.campaignId,
            tracking: { durable_case_recorded: durableCaseRecorded, submission_finalized: durableSubmissionFinalized },
          };
          return { content: [{ type: "text", text: JSON.stringify(details) }], details };
        },
      },
      { optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_begin_webmail_session",
        label: "RightOut begin browser webmail send",
        description: "Open a privacy-redacted Gmail compose session in the configured logged-in OpenClaw browser profile for an official parity rescue address. Recipient, subject, and body stay inside the plugin/browser control plane.",
        parameters: ParityEmailParameters,
        async execute(toolCallId, params, signal) {
          const input = validateFormSessionBeginInput(params);
          const config = api.pluginConfig as RightOutConfig | undefined;
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string") throw new Error("rightout_not_configured");
          const parityCatalog = await parityCatalogPromise;
          const broker = resolveParityBroker(parityCatalog, input.brokerId);
          if (typeof broker.rescue_email !== "string") throw new Error("rightout_parity_email_lane_invalid");
          await assertParityRescueFresh(input.brokerId);
          const coreCatalog = await catalogPromise;
          await authorizeCampaignEffects(input.campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "submit_email" }], coreCatalog, true);
          let listingUrl;
          if (broker.rescue_disclosure_fields.includes("listing_url")) {
            if (!input.listingHandle) throw new Error("rightout_form_listing_handle_required");
            const token = await createListingTokenVault(listingTokens, config.stateEncryptionKey).lookup(input.listingHandle, input.profileId, input.brokerId);
            listingUrl = token.urls[0];
          }
          const built = buildParityMessage({
            input: { profileId: input.profileId, brokerId: input.brokerId },
            broker,
            profilePayload: config.profiles[input.profileId].payload,
            listingUrl,
          });
          const browserControl = resolveBrowserControl(toolContext as Record<string, any>, config);
          const browserBackend = resolveBrowserBackend(toolContext as Record<string, any>, config);
          if (!browserBackend.webmail_ready || typeof browserControl.bridgeUrl !== "string" || !browserControl.browserProfile) throw new Error("rightout_browser_webmail_profile_required");
          const values = { recipient: built.recipient, message_subject: built.subject, message_body: built.text };
          const opened = await browserSessionDriver.openSession({
            ...browserControl,
            formUrl: "https://mail.google.com/mail/u/0/#compose",
            allowedDomains: ["mail.google.com"],
            allowedFields: Object.keys(values),
            values,
            privacyMode: "webmail",
            signal,
          });
          const sessionId = `webmailsession_${randomBytes(12).toString("hex")}`;
          storeBrowserSession(sessionId, {
            sessionId, sessionType: "webmail", webmailMode: "send", targetId: opened.targetId,
            profileId: input.profileId, brokerId: input.brokerId, campaignId: input.campaignId,
            broker, values, disclosureFields: built.disclosureFields, browserControl,
            filledFields: [], effectConsumed: true, expiresAt: Date.now() + 30 * 60_000,
          });
          const report = {
            report_version: 1, session_id: sessionId, subject_ref: input.profileId, broker_id: input.brokerId,
            state: "webmail_session_ready", provider: "gmail_openclaw_browser_profile", snapshot: opened.snapshot,
            disclosures_allowed: Object.keys(values), provider_reads: 1, provider_writes: 0, raw_mailbox_content_in_report: false, raw_pii_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_begin_webmail_session", optional: true },
    );

    api.registerTool(
      {
        name: "rightout_webmail_session_step",
        label: "RightOut browser webmail step",
        description: "Fill or send one catalog-built privacy request in an active redacted webmail session. The model selects only ARIA refs and field names; it never supplies or receives message values.",
        parameters: WebmailSessionStepParameters,
        async execute(_toolCallId, params, signal) {
          const input = validateWebmailSessionStepInput(params);
          await pruneTransientState();
          const session = activeWebmailSession(input.sessionId);
          const coreCatalog = await catalogPromise;
          if (session.webmailMode === "verification") {
            if (input.action.kind === "fill" || (input.action.kind === "click" && input.action.purpose === "send")) {
              throw new Error("rightout_webmail_session_input_invalid");
            }
            const verificationCatalog = await combinedVerificationCatalog();
            const driverOptions = {
              ...session.browserControl,
              targetId: session.targetId,
              allowedDomains: ["mail.google.com", ...session.broker.linkDomains],
              allowedFields: [],
              values: session.values,
              privacyMode: "webmail_verification",
              brokerMessageDomains: session.broker.senderDomains,
              brokerMessageNames: [session.broker.name],
              verificationRecipient: session.values.contact_email,
              verificationLinkDomains: session.broker.linkDomains,
              signal,
            };
            if (input.action.kind === "close") {
              deleteBrowserSession(input.sessionId);
              const cleanup = await cleanupAndCloseBrowserSession(session);
              const report = {
                session_id: input.sessionId, broker_id: session.brokerId, state: "webmail_verification_session_closed",
                provider_writes: 0, tab_cleanup: cleanup.tab_cleanup, raw_mailbox_content_in_report: false,
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            await revalidateConsumedSessionEffect(session, "poll_verification").catch(async (error) => {
              await invalidateBrowserSession(input.sessionId, session);
              throw error;
            });
            if (input.action.kind === "inspect") {
              const snapshot = await browserSessionDriver.inspect(driverOptions);
              session.messageAuthenticated = snapshot.snapshot.includes("verification_message_authenticated");
              const report = {
                session_id: input.sessionId, broker_id: session.brokerId, state: "webmail_verification_session_active",
                snapshot, message_authenticated: session.messageAuthenticated === true,
                raw_mailbox_content_in_report: false, raw_link_in_report: false,
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            if (input.action.kind === "record_redacted_state_receipt") {
              const receipt = await browserSessionDriver.redactedStateReceipt(driverOptions);
              const report = { session_id: input.sessionId, broker_id: session.brokerId, state: "redacted_state_receipt_recorded", ...receipt };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            const openingConfirmation = input.action.kind === "click" && input.action.purpose === "open_confirmation";
            if (!openingConfirmation) {
              if (!input.action || input.action.kind !== "click" || !["open_message", "inspect_authentication"].includes(input.action.purpose)) {
                throw new Error("rightout_webmail_session_input_invalid");
              }
              const snapshot = await browserSessionDriver.act({ ...driverOptions, action: input.action });
              session.messageAuthenticated = snapshot.snapshot.includes("verification_message_authenticated");
              const report = {
                session_id: input.sessionId, broker_id: session.brokerId, state: "webmail_verification_session_active",
                snapshot, message_authenticated: session.messageAuthenticated === true,
                raw_mailbox_content_in_report: false, raw_link_in_report: false, provider_writes: 0,
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            if (session.messageAuthenticated !== true) throw new Error("rightout_webmail_message_not_authenticated");
            assertPublisherAutomationPermission(
              api.pluginConfig as RightOutConfig | undefined,
              session.parityBroker,
              await providerTermsPromise,
              "open_verification",
              { browserBackend: "existing_logged_in_cdp" },
            );
            await authorizeCampaignEffects(
              session.campaignId,
              session.profileId,
              [{ brokerId: session.brokerId, effect: "open_verification" }],
              verificationCatalog,
              false,
            );
            const openDedupeKey = verificationOpenDedupeKey(
              session.profileId,
              session.brokerId,
              session.caseContext.submission_proof_reference,
            );
            const openIntentCreated = await verificationOpenDedupe.registerIfAbsent(openDedupeKey, {
              createdAt: new Date().toISOString(),
              profileId: session.profileId,
              brokerId: session.brokerId,
              submissionReference: session.caseContext.submission_proof_reference,
              phase: "browser_webmail_provider_request_intent",
            });
            if (!openIntentCreated) throw new Error("rightout_verification_open_unresolved");
            try {
              await authorizeCampaignEffects(
                session.campaignId,
                session.profileId,
                [{ brokerId: session.brokerId, effect: "open_verification" }],
                verificationCatalog,
                true,
              );
            } catch (error) {
              await verificationOpenDedupe.delete(openDedupeKey);
              throw error;
            }
            let snapshot;
            let failedStage = "browser_confirmation_action";
            try {
              snapshot = await browserSessionDriver.act({ ...driverOptions, action: input.action });
              if (!snapshot.snapshot.includes("verification_destination_opened_observed")) {
                throw new Error("rightout_verification_open_failed");
              }
              failedStage = "durable_case_transition";
              if (session.brokerId === "intelius") {
                const config = api.pluginConfig as RightOutConfig | undefined;
                const profile = parseRemovalProfile(config!.profiles![session.profileId].payload) as Record<string, any>;
                const values = formProfileValues(profile);
                const disclosureFields = ["full_name", "date_of_birth"];
                const fieldDisclosureMap = formFieldDisclosureMap(disclosureFields, values);
                const expiresAt = Date.now() + 30 * 60_000;
                const formSnapshot = await browserSessionDriver.inspect({
                  ...session.browserControl,
                  targetId: session.targetId,
                  allowedDomains: session.broker.linkDomains,
                  allowedFields: Object.keys(fieldDisclosureMap),
                  values,
                  privacyMode: "peopleconnect_guided",
                  signal,
                });
                const formSessionId = `formsession_${randomBytes(12).toString("hex")}`;
                const formRecipe = await currentRecipeForBroker(session.brokerId);
                const formRecipeDigest = recipeDigest(formRecipe);
                const formRecipePackDigest = (await loadRecipePack()).recipe_digest;
                await portalFlowStore.register(portalFlowKey(session.profileId, session.brokerId), {
                  profileId: session.profileId, brokerId: session.brokerId, campaignId: session.campaignId,
                  targetId: session.targetId, browserProfile: session.browserControl.browserProfile ?? null,
                  bridgeUrl: session.browserControl.bridgeUrl, browserBackend: "existing_logged_in_cdp",
                  stage: "peopleconnect_guided_identity", expiresAt,
                });
                storeBrowserSession(formSessionId, {
                  sessionId: formSessionId, sessionType: "form", stage: "peopleconnect_guided_identity", targetId: session.targetId,
                  profileId: session.profileId, brokerId: session.brokerId, campaignId: session.campaignId,
                  broker: session.parityBroker, values, fieldDisclosureMap, browserControl: session.browserControl,
                  recipeId: formRecipe.recipe_id, recipeDigest: formRecipeDigest, recipePackDigest: formRecipePackDigest,
                  browserBackend: "existing_logged_in_cdp", filledFields: [], recordSelected: false,
                  effectConsumed: true, submissionIntentReserved: false, expiresAt,
                });
                const formRecipeAssessment = await assessFormRecipeSession(formSessionId, activeFormSession(formSessionId), formSnapshot);
                deleteBrowserSession(input.sessionId);
                await verificationOpenDedupe.delete(openDedupeKey);
                const report = {
                  report_version: 1, session_id: formSessionId, subject_ref: session.profileId, broker_id: session.brokerId,
                  state: "guided_suppression_ready", same_browser_profile_retained: true,
                  authenticated_browser_message_bound: true, disclosures_allowed: disclosureFields,
                  form_fields_available: Object.keys(fieldDisclosureMap), snapshot: formSnapshot,
                  recipe_policy: { recipe_id: formRecipe.recipe_id, recipe_digest: formRecipeDigest, assessment: formRecipeAssessment.state },
                  raw_mailbox_content_in_report: false, raw_link_in_report: false, raw_pii_in_report: false, provider_writes: 1,
                };
                return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
              }
              await caseLedger.recordLifecycle(session.profileId, session.brokerId, "awaiting_processing", {
                evidenceKind: "broker_verification_link",
                processingDays: session.broker.processingDays,
                proofReference: `verify_${createHash("sha256").update(input.sessionId).digest("hex").slice(0, 24)}`,
              });
              failedStage = "durable_retry_guard_finalize";
              await verificationOpenDedupe.delete(openDedupeKey);
              failedStage = "redacted_receipt";
              const receipt = await browserSessionDriver.redactedStateReceipt(driverOptions);
              await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
              deleteBrowserSession(input.sessionId);
              const report = {
                report_version: 1, subject_ref: session.profileId, broker_id: session.brokerId,
                state: "awaiting_processing", campaign_id: session.campaignId,
                authenticated_browser_message_bound: true, same_browser_profile_retained: true,
                proof_references: [receipt.receipt_reference], redacted_state_receipt: receipt,
                raw_mailbox_content_in_report: false, raw_link_in_report: false, raw_pii_in_report: false, provider_writes: 1,
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            } catch (error) {
              const errorCode = error instanceof Error && /^rightout_[a-z0-9_]+$/.test(error.message)
                ? error.message : "rightout_verification_open_failed";
              await caseLedger.recordLifecycle(session.profileId, session.brokerId, "human_task_queued", {
                evidenceKind: "human_task", reason: "browser_webmail_verification_open_uncertain",
              }).catch(() => undefined);
              await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
              deleteBrowserSession(input.sessionId);
              const report = {
                report_version: 1, subject_ref: session.profileId, broker_id: session.brokerId,
                state: "human_task_queued", reason: "browser_webmail_verification_open_uncertain",
                error_code: errorCode,
                failed_stage: failedStage,
                retry_blocked: true, campaign_id: session.campaignId,
                raw_mailbox_content_in_report: false, raw_link_in_report: false, raw_pii_in_report: false,
                provider_writes_possible: true,
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
          }
          if (session.webmailMode !== "send") throw new Error("rightout_webmail_session_expired");
          if (input.action.kind === "click" && input.action.purpose !== "send") throw new Error("rightout_webmail_session_input_invalid");
          const driverOptions = {
            ...session.browserControl, targetId: session.targetId, allowedDomains: ["mail.google.com"],
            allowedFields: Object.keys(session.values), values: session.values, privacyMode: "webmail", signal,
          };
          if (input.action.kind === "close") {
            deleteBrowserSession(input.sessionId);
            const cleanup = await cleanupAndCloseBrowserSession(session);
            const draftPossible = session.draftMayContainPii === true || session.filledFields.length > 0;
            const report = {
              session_id: input.sessionId, broker_id: session.brokerId, state: "webmail_session_closed",
              provider_writes: 0, provider_write_possible: draftPossible,
              draft_cleanup: cleanup.draft_cleanup,
              tab_cleanup: cleanup.tab_cleanup,
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          try {
            if (session.effectConsumed) await revalidateConsumedSessionEffect(session, "submit_email");
            else await authorizeCampaignEffects(session.campaignId, session.profileId, [{ brokerId: session.brokerId, effect: "submit_email" }], coreCatalog, false);
          } catch (error) {
            await invalidateBrowserSession(input.sessionId, session);
            throw error;
          }
          if (input.action.kind === "inspect") {
            const snapshot = await browserSessionDriver.inspect(driverOptions);
            const report = { session_id: input.sessionId, broker_id: session.brokerId, state: "webmail_session_active", snapshot, raw_mailbox_content_in_report: false };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (input.action.kind === "record_redacted_state_receipt") {
            const receipt = await browserSessionDriver.redactedStateReceipt(driverOptions);
            const report = { session_id: input.sessionId, broker_id: session.brokerId, state: "redacted_state_receipt_recorded", ...receipt };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (input.action.kind === "fill" && !session.effectConsumed) {
            await authorizeCampaignEffects(session.campaignId, session.profileId, [{ brokerId: session.brokerId, effect: "submit_email" }], coreCatalog, true);
            session.effectConsumed = true;
          }
          const finalSend = input.action.kind === "click" && input.action.purpose === "send";
          let dedupeKey;
          let reserved = false;
          if (finalSend) {
            if (!session.effectConsumed || Object.keys(session.values).some((field) => !session.filledFields.includes(field))) throw new Error("rightout_webmail_fields_incomplete");
            const removalInput: PublicRemovalInput = { profileId: session.profileId, brokerId: session.brokerId, requestKind: "delete_and_opt_out" };
            dedupeKey = removalDedupeKey(removalInput);
            await acquireSubmissionDedupe(dedupeKey, removalInput, "browser_webmail");
            await caseLedger.reserveSubmission(session.profileId, session.brokerId, { channel: "browser_webmail", discoveryRequirement: "not_required_for_data_subject_request" });
            await markSubmissionDedupeIntentReserved(dedupeKey, removalInput, "browser_webmail");
            reserved = true;
          }
          try {
            const snapshot = await browserSessionDriver.act({ ...driverOptions, action: input.action });
            if (input.action.kind === "fill") {
              session.draftMayContainPii = true;
              for (const field of input.action.fields) session.filledFields.push(field.profile_field);
              session.filledFields = [...new Set(session.filledFields)];
            }
            if (!finalSend) {
              const report = {
                session_id: input.sessionId, broker_id: session.brokerId, state: "webmail_session_active", snapshot,
                provider_write_possible: input.action.kind === "fill",
                draft_retention: input.action.kind === "fill" ? "gmail_autosave_possible_until_send_or_discard" : "unchanged",
                raw_mailbox_content_in_report: false,
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            if (!snapshot.observed_transitions?.includes("message_sent_observed")) throw new Error("rightout_webmail_send_unconfirmed");
            session.sendCompleted = true;
            const receipt = await browserSessionDriver.redactedStateReceipt(driverOptions);
            const generatedAt = new Date().toISOString();
            const proof = `webmail_${createHash("sha256").update(JSON.stringify([input.sessionId, session.brokerId, generatedAt])).digest("hex").slice(0, 24)}`;
            const report = {
              report_version: 1, subject_ref: session.profileId, broker_id: session.brokerId, state: "submitted", generated_at: generatedAt,
              delivery: { channel: "openclaw_browser_webmail", webmail_sent: true, broker_receipt_confirmed: false, removal_confirmed: false },
              disclosures: { to_broker: session.disclosureFields, values_in_report: false, attachments: 0, identity_documents: 0 },
              proof_references: [proof, receipt.receipt_reference], redacted_state_receipt: receipt, campaign_id: session.campaignId,
              raw_mailbox_content_in_report: false, raw_message_in_report: false, raw_pii_in_report: false,
            };
            await caseLedger.recordRemoval(report, 45);
            await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
            deleteBrowserSession(input.sessionId);
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          } catch (error) {
            if (reserved) {
              const code = error instanceof Error ? error.message : "rightout_webmail_send_failed";
              await caseLedger.recordSubmissionUncertain(session.profileId, session.brokerId, { channel: "browser_webmail", reason: code }).catch(() => undefined);
            }
            if (input.action.kind === "fill" && error instanceof Error && error.message === "rightout_browser_action_uncertain") {
              session.draftMayContainPii = true;
              const cleanup = await invalidateBrowserSession(input.sessionId, session);
              await caseLedger.recordLifecycle(session.profileId, session.brokerId, "human_task_queued", {
                evidenceKind: "human_task", reason: "webmail_fill_outcome_uncertain",
              }).catch(() => undefined);
              const report = {
                session_id: input.sessionId, broker_id: session.brokerId, state: "human_task_queued",
                reason: "webmail_fill_outcome_uncertain", automatic_retry_allowed: false,
                provider_write_possible: true, draft_cleanup: cleanup.draft_cleanup, tab_cleanup: cleanup.tab_cleanup,
                raw_mailbox_content_in_report: false, raw_pii_in_report: false,
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            if (finalSend) await invalidateBrowserSession(input.sessionId, session);
            throw error;
          }
        },
      },
      { optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_begin_webmail_verification",
        label: "RightOut begin browser-mail verification",
        description: "Open a broker-scoped Gmail search in the configured logged-in browser. Only a recipient-bound message with an allowed signed-by/mailed-by domain can expose one allowlisted confirmation control; raw mail and link values never leave the browser control plane.",
        parameters: WebmailVerificationBeginParameters,
        async execute(_toolCallId, params, signal) {
          const input = validateWebmailVerificationBeginInput(params);
          const config = api.pluginConfig as RightOutConfig | undefined;
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string") throw new Error("rightout_not_configured");
          const verificationCatalog = await combinedVerificationCatalog();
          const broker = resolveVerificationCatalogEntry(verificationCatalog, { profileId: input.profileId, brokerId: input.brokerId });
          const parityCatalog = await parityCatalogPromise;
          const parityBroker = resolveParityBroker(parityCatalog, input.brokerId);
          await assertParityRouteFresh(input.brokerId);
          const browserControl = resolveBrowserControl(toolContext as Record<string, any>, config);
          const browserBackend = resolveBrowserBackend(toolContext as Record<string, any>, config);
          if (!browserBackend.webmail_ready || typeof browserControl.bridgeUrl !== "string" || !browserControl.browserProfile) {
            throw new Error("rightout_browser_webmail_profile_required");
          }
          const attestations = validateVerificationAttestations(input, config.verificationAttestations, { transport: "browser_webmail" }) as VerificationAttestations;
          const preflight = validateBrowserVerificationPreflight({
            input,
            catalog: verificationCatalog,
            profilePayload: config.profiles[input.profileId].payload,
            browserControl: {
              browserControlBaseUrl: config.browserControlBaseUrl,
              browserProfile: config.browserProfile,
              browserBackendMode: config.browserBackendMode,
            },
            attestations,
          });
          const caseContext = await caseLedger.verificationContext(input.profileId, input.brokerId, ["submitted", "verification_pending"]);
          const unresolvedOpen = await verificationOpenDedupe.lookup(verificationOpenDedupeKey(
            input.profileId,
            input.brokerId,
            caseContext.submission_proof_reference,
          ));
          if (unresolvedOpen) throw new Error("rightout_verification_open_unresolved");
          await authorizeCampaignEffects(
            input.campaignId,
            input.profileId,
            [{ brokerId: input.brokerId, effect: "poll_verification" }],
            verificationCatalog,
            false,
          );
          await authorizeCampaignEffects(
            input.campaignId,
            input.profileId,
            [{ brokerId: input.brokerId, effect: "poll_verification" }],
            verificationCatalog,
            true,
          );
          const query = `newer_than:14d {${broker.senderDomains.map((domain) => `from:${domain}`).join(" ")}} {verify confirm removal optout privacy}`;
          const webmailUrl = `https://mail.google.com/mail/u/0/#search/${encodeURIComponent(query)}`;
          const values = { contact_email: preflight.profile.contactEmail };
          const opened = await browserSessionDriver.openSession({
            ...browserControl,
            formUrl: webmailUrl,
            allowedDomains: ["mail.google.com", ...broker.linkDomains],
            allowedFields: [],
            values,
            privacyMode: "webmail_verification",
            brokerMessageDomains: broker.senderDomains,
            brokerMessageNames: [broker.name],
            verificationRecipient: preflight.profile.contactEmail,
            verificationLinkDomains: broker.linkDomains,
            label: "rightout-webmail-verification",
            signal,
          });
          const sessionId = `webmailsession_${randomBytes(12).toString("hex")}`;
          storeBrowserSession(sessionId, {
            sessionId, sessionType: "webmail", webmailMode: "verification", targetId: opened.targetId,
            profileId: input.profileId, brokerId: input.brokerId, campaignId: input.campaignId,
            broker, parityBroker, values, browserControl, caseContext,
            messageAuthenticated: false, effectConsumed: true, expiresAt: Date.now() + 30 * 60_000,
          });
          const report = {
            report_version: 1, session_id: sessionId, subject_ref: input.profileId, broker_id: input.brokerId,
            state: "webmail_verification_session_ready", provider: "gmail_openclaw_browser_profile",
            snapshot: opened.snapshot,
            sender_domains_allowed: broker.senderDomains,
            link_domains_allowed: broker.linkDomains,
            authentication_required: ["recipient_match", "signed_by_or_mailed_by_allowed_domain"],
            next_actions: ["open_one_broker_message", "inspect_authentication", "open_one_confirmation_control_or_close"],
            provider_reads: 1, provider_writes: 0,
            raw_mailbox_content_in_report: false, raw_link_in_report: false, raw_pii_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_begin_webmail_verification", optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_submit_form_removal",
        label: "RightOut submit form removal",
        description: "Initiate a catalog-locked broker suppression flow through the configured OpenClaw browser backend. PII is resolved inside the plugin and CAPTCHA/ID fails closed. Assisted calls require native allow-once; campaign calls require a matching finite grant.",
        parameters: RemovalParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicRemovalInput;
          let campaignId: string | undefined;
          try {
            const scoped = splitCampaignParams(params);
            campaignId = scoped.campaignId;
            input = validateFormRemovalInput(scoped.params) as PublicRemovalInput;
          }
          catch { throw new Error("rightout_approval_binding_failed"); }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await catalogPromise;
          const broker = resolveFormCatalogEntry(catalog, input);
          const permissionRoutingScope = browserApprovalRoutingScope(config, { browserRequired: true, effects: ["submit_form"] });
          if (permissionRoutingScope.browserBackendMode === "not_required") throw new Error("rightout_browser_backend_invalid");
          assertPublisherAutomationPermission(
            config, { id: input.brokerId, method: "web_form" }, await providerTermsPromise, "submit_form",
            { browserBackend: permissionRoutingScope.browserBackendMode },
          );
          assertFreshCatalogEntries(catalog, [input.brokerId]);
          let attestations: FormAttestations | undefined;
          try { attestations = formAttestationSnapshot(config, input); } catch { /* fail below */ }
          let browserScope: ApprovalRoutingScope | undefined;
          try { browserScope = browserApprovalRoutingScope(config, { browserRequired: true, effects: ["submit_form"] }); } catch { /* fail below */ }
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!attestations || !browserScope || (!campaignId && (!approval || approval.toolName !== "rightout_submit_form_removal" || approval.binding !== formScopeBinding(input, attestations, broker, browserScope)))) {
            throw new Error("rightout_approval_binding_failed");
          }
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string") throw new Error("rightout_not_configured");
          validateFormPreflight({ input, catalog, profilePayload: config.profiles[input.profileId].payload, attestations });
          await authorizeCampaignEffects(campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "submit_form" }], catalog, true);
          await caseLedger.removalContext(input.profileId, input.brokerId);
          const dedupeKey = removalDedupeKey(input);
          if (submittedScopes.has(dedupeKey)) throw new Error("rightout_duplicate_removal_request");
          await acquireSubmissionDedupe(dedupeKey, input, "browser_form");
          try {
            await caseLedger.reserveSubmission(input.profileId, input.brokerId, {
              channel: "browser_form",
              discoveryRequirement: (broker as Record<string, any>).discoveryRequirement,
            });
            await markSubmissionDedupeIntentReserved(dedupeKey, input, "browser_form");
          } catch (error) {
            await submissionDedupe.delete(dedupeKey);
            throw error;
          }
          submittedScopes.set(dedupeKey, Number.POSITIVE_INFINITY);
          try {
            const browserControl = resolveBrowserControl(toolContext as Record<string, any>, config);
            const report = await runFormRemoval({
              input,
              catalog,
              profilePayload: config.profiles[input.profileId].payload,
              attestations,
              ...browserControl,
              browserBackend: browserScope.browserBackendMode,
              browserControlTransport: resolveBrowserControlTransport(toolContext as Record<string, any>, config),
              approvalBoundary: campaignId ? "finite_campaign_grant" : "assisted_allow_once",
              submitForm: submitBrowserForm,
              signal,
            });
            submittedScopes.set(dedupeKey, Date.now() + duplicateCooldownMs);
            let durableCaseRecorded = true;
            let durableSubmissionFinalized = true;
            try { await caseLedger.recordFormSubmission(report); }
            catch {
              durableSubmissionFinalized = false;
              try {
                await caseLedger.recordSubmissionUncertain(input.profileId, input.brokerId, {
                  channel: "browser_form",
                  reason: "accepted_write_ledger_finalize_failed",
                });
              } catch { durableCaseRecorded = false; }
              api.logger.error("RightOut submitted a browser form but its PII-safe case update failed");
            }
            const trackedReport = {
              ...report,
              state: durableSubmissionFinalized ? report.state : "submission_uncertain",
              tracking: { durable_case_recorded: durableCaseRecorded, submission_finalized: durableSubmissionFinalized },
            };
            return { content: [{ type: "text", text: JSON.stringify(trackedReport) }], details: trackedReport };
          } catch (error) {
            const code = error instanceof Error ? error.message : "rightout_form_failed";
            const safeCodes = new Set([
              "rightout_browser_bridge_unavailable", "rightout_browser_bridge_failed",
              "rightout_browser_snapshot_invalid", "rightout_form_contract_mismatch",
              "rightout_form_human_gate_required", "rightout_form_profile_field_missing",
              "rightout_form_submission_unconfirmed", "rightout_form_submission_uncertain", "rightout_form_cancelled",
            ]);
            const reason = safeCodes.has(code) ? code : "rightout_form_failed";
            const possibleWrite = ["rightout_browser_bridge_failed", "rightout_form_submission_unconfirmed", "rightout_form_submission_uncertain"].includes(reason);
            if (possibleWrite) {
              submittedScopes.set(dedupeKey, Date.now() + duplicateCooldownMs);
              await caseLedger.recordSubmissionUncertain(input.profileId, input.brokerId, {
                channel: "browser_form",
                reason,
              }).catch(() => api.logger.error("RightOut ambiguous form write could not be persisted"));
            }
            else {
              submittedScopes.delete(dedupeKey);
              await caseLedger.releaseSubmission(input.profileId, input.brokerId, reason)
                .catch(() => api.logger.error("RightOut unused form write intent could not be released"));
              await submissionDedupe.delete(dedupeKey);
            }
            let durableCaseRecorded = true;
            if (!possibleWrite) {
              try {
                await caseLedger.recordLifecycle(input.profileId, input.brokerId, "human_task_queued", {
                  evidenceKind: "human_task",
                  reason,
                });
              } catch { durableCaseRecorded = false; }
            }
            const report = {
              report_version: 1,
              subject_ref: input.profileId,
              broker_id: input.brokerId,
              state: possibleWrite ? "submission_uncertain" : "human_task_queued",
              reason,
              possible_form_write: possibleWrite,
              generated_at: new Date().toISOString(),
              tracking: { durable_case_recorded: durableCaseRecorded },
              invariants: { raw_pii_in_report: false, captcha_bypasses: 0, identity_documents_uploaded: 0 },
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
        },
      }),
      { name: "rightout_submit_form_removal", optional: true },
    );

    api.registerTool(
      {
        name: "rightout_poll_verification",
        label: "RightOut poll verification",
        description: "Read recent mail from the approved IMAP account and find a broker-domain confirmation link without returning raw mail or link values. Assisted calls use native allow-once; campaign calls use a matching finite grant.",
        parameters: VerificationPollParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicVerificationPollInput;
          let campaignId: string | undefined;
          try {
            const scoped = splitCampaignParams(params);
            campaignId = scoped.campaignId;
            input = validateVerificationPollInput(scoped.params) as PublicVerificationPollInput;
          } catch {
            throw new Error("rightout_approval_binding_failed");
          }
          const approvalBoundary = campaignId ? "finite_campaign_grant" : "assisted_allow_once";
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await combinedVerificationCatalog();
          const broker = resolveVerificationCatalogEntry(catalog, input);
          await assertParityRouteFresh(input.brokerId);
          await pruneTransientState();
          if (broker.openLinkMode === "browser_same_profile_required" && await portalFlowStore.lookup(portalFlowKey(input.profileId, input.brokerId))) {
            throw new Error("rightout_verified_portal_flow_already_open");
          }
          let attestations: VerificationAttestations | undefined;
          try { attestations = verificationAttestationSnapshot(config, input); } catch { /* fail below */ }
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!attestations || (!campaignId && (!approval || approval.toolName !== "rightout_poll_verification" || approval.binding !== verificationPollScopeBinding(input, attestations, broker)))) {
            throw new Error("rightout_approval_binding_failed");
          }
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string" || !config.imapTransport) {
            throw new Error("rightout_not_configured");
          }
          const caseContext = await caseLedger.verificationContext(input.profileId, input.brokerId, ["submitted", "verification_pending"]);
          const unresolvedOpen = await verificationOpenDedupe.lookup(verificationOpenDedupeKey(
            input.profileId,
            input.brokerId,
            caseContext.submission_proof_reference,
          ));
          if (unresolvedOpen) throw new Error("rightout_verification_open_unresolved");
          const preflight = validateVerificationPreflight({
            input,
            catalog,
            profilePayload: config.profiles[input.profileId].payload,
            imapTransport: config.imapTransport,
            attestations,
          });
          await authorizeCampaignEffects(campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "poll_verification" }], catalog, true);
          const result = await pollImapVerification({
            transport: preflight.imap,
            expectedAddress: preflight.profile.contactEmail,
            broker: preflight.broker.raw,
            notBefore: caseContext.submitted_at,
            sinceDays: 14,
            signal,
          });
          if (!result.found) {
            const deferred = await caseLedger.deferRecheck(input.profileId, input.brokerId, {
              reason: "verification_mail_not_observed",
              days: 1,
            });
            const report = {
              report_version: 1,
              subject_ref: input.profileId,
              broker_id: input.brokerId,
              state: "verification_not_observed",
              approval_boundary: approvalBoundary,
              generated_at: new Date().toISOString(),
              next_recheck_at: deferred.next_recheck_at,
              retry_deferred: true,
              raw_mail_in_report: false,
              provider_writes: 0,
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (
            typeof result.link !== "string"
            || typeof result.message_reference !== "string"
            || !Array.isArray(result.allowed_link_domains)
          ) throw new Error("rightout_verification_poll_failed");
          if (broker.openLinkMode === "browser_same_profile_required" && !campaignId) {
            const deferred = await caseLedger.deferRecheck(input.profileId, input.brokerId, {
              reason: "same_profile_verification_requires_finite_campaign",
              days: 1,
            });
            const report = {
              report_version: 1,
              subject_ref: input.profileId,
              broker_id: input.brokerId,
              state: "requires_finite_campaign",
              approval_boundary: approvalBoundary,
              reason: "same_profile_verified_portal_cannot_start_from_assisted_allow_once",
              message_reference: result.message_reference,
              next_recheck_at: deferred.next_recheck_at,
              next_action: "start_a_finite_campaign_with_poll_verification_open_verification_and_submit_form_or_open_the_verified_message_manually",
              raw_mail_in_report: false,
              raw_link_in_report: false,
              raw_pii_in_report: false,
              provider_writes: 0,
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (broker.openLinkMode === "human_only") {
            await caseLedger.recordLifecycle(input.profileId, input.brokerId, "human_task_queued", {
              evidenceKind: "human_task",
              reason: "verification_link_open_human_only",
              proofReference: result.message_reference,
            });
            const report = {
              report_version: 1,
              subject_ref: input.profileId,
              broker_id: input.brokerId,
              state: "human_task_queued",
              approval_boundary: approvalBoundary,
              reason: "verification_link_open_human_only",
              message_reference: result.message_reference,
              generated_at: new Date().toISOString(),
              next_action: "operator_opens_the_verified_broker_message_and_confirmation_control_manually",
              invariants: { raw_mail_in_report: false, raw_link_in_report: false, raw_pii_in_report: false, provider_writes: 0 },
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          const verificationHandle = newVerificationHandle();
          const token: VerificationToken = {
            profileId: input.profileId,
            brokerId: input.brokerId,
            url: result.link,
            allowedDomains: result.allowed_link_domains,
            messageReference: result.message_reference,
            submissionAt: caseContext.submitted_at,
            submissionReference: caseContext.submission_proof_reference,
            createdAt: new Date().toISOString(),
          };
          try {
            await caseLedger.recordLifecycle(input.profileId, input.brokerId, "verification_pending", {
              evidenceKind: "broker_verification_link",
              proofReference: result.message_reference,
            });
          } catch {
            api.logger.error("RightOut found a verification link but its PII-safe case update failed");
            throw new Error("rightout_verification_tracking_failed");
          }
          await verificationTokens.register(verificationHandle, token);
          const report = {
            report_version: 1,
            subject_ref: input.profileId,
            broker_id: input.brokerId,
            state: "verification_pending",
            approval_boundary: approvalBoundary,
            verification_handle: verificationHandle,
            message_reference: result.message_reference,
            link_security: result.link_security,
            generated_at: token.createdAt,
            next_action: broker.openLinkMode === "browser_same_profile_required"
              ? "open_the_opaque_handle_in_the_same_configured_browser_profile"
              : "separately_approve_rightout_open_verification",
            next_command: {
              tool: "rightout_open_verification",
              parameters: {
                profileId: input.profileId,
                brokerId: input.brokerId,
                verificationHandle,
                ...(campaignId ? { campaignId } : {}),
              },
              approval_boundary: campaignId ? "finite_campaign_grant" : "assisted_allow_once_required",
            },
            tracking: { durable_case_recorded: true, bound_to_submission: true },
            invariants: { raw_mail_in_report: false, raw_link_in_report: false, raw_pii_in_report: false, provider_writes: 0 },
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_open_verification",
        label: "RightOut open verification",
        description: "Consume one short-lived broker-bound handle and open its stored HTTPS confirmation link. This external write uses assisted native allow-once or a matching finite campaign grant; same-profile portals require the campaign path.",
        parameters: VerificationOpenParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicVerificationOpenInput;
          let campaignId: string | undefined;
          try {
            const scoped = splitCampaignParams(params);
            campaignId = scoped.campaignId;
            input = validateVerificationOpenInput(scoped.params) as PublicVerificationOpenInput;
          }
          catch { throw new Error("rightout_approval_binding_failed"); }
          const approvalBoundary = campaignId ? "finite_campaign_grant" : "assisted_allow_once";
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await combinedVerificationCatalog();
          const broker = resolveVerificationCatalogEntry(catalog, input);
          const openPermissionScope = browserApprovalRoutingScope(config, {
            browserRequired: broker.openLinkMode === "browser_same_profile_required",
            effects: ["open_verification"],
          });
          if (broker.openLinkMode === "browser_same_profile_required") {
            if (openPermissionScope.browserBackendMode === "not_required") throw new Error("rightout_browser_backend_invalid");
            assertPublisherAutomationPermission(config, broker, await providerTermsPromise, "open_verification", { browserBackend: openPermissionScope.browserBackendMode });
          } else {
            assertPublisherAutomationPermission(config, broker, await providerTermsPromise, "open_verification");
          }
          await assertParityRouteFresh(input.brokerId);
          let sameProfileBrowserControl: Record<string, any> | undefined;
          if (broker.openLinkMode === "browser_same_profile_required") {
            sameProfileBrowserControl = resolveBrowserControl(toolContext as Record<string, any>, config);
            if (
              typeof sameProfileBrowserControl.bridgeUrl !== "string"
              || typeof sameProfileBrowserControl.browserProfile !== "string"
              || !sameProfileBrowserControl.bridgeUrl.trim()
              || !sameProfileBrowserControl.browserProfile.trim()
            ) {
              throw new Error("rightout_peopleconnect_named_browser_profile_required");
            }
          }
          await pruneTransientState();
          if (broker.openLinkMode === "browser_same_profile_required" && await portalFlowStore.lookup(portalFlowKey(input.profileId, input.brokerId))) {
            throw new Error("rightout_verified_portal_flow_already_open");
          }
          let attestations: VerificationAttestations | undefined;
          try { attestations = verificationAttestationSnapshot(config, input); } catch { /* fail below */ }
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !attestations || (!campaignId && (
              !approval
              || approval.toolName !== "rightout_open_verification"
              || approval.binding !== verificationOpenScopeBinding(input, attestations, broker)
            ))
          ) {
            throw new Error("rightout_approval_binding_failed");
          }
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string" || !config.imapTransport) {
            throw new Error("rightout_not_configured");
          }
          const context = await caseLedger.verificationContext(input.profileId, input.brokerId, ["verification_pending"]);
          const token = await verificationTokens.lookup(input.verificationHandle);
          if (
            !token || token.profileId !== input.profileId || token.brokerId !== input.brokerId
            || token.submissionAt !== context.submitted_at
            || token.submissionReference !== context.submission_proof_reference
          ) throw new Error("rightout_verification_handle_expired");
          validateVerificationPreflight({
            input,
            catalog,
            profilePayload: config.profiles[input.profileId].payload,
            imapTransport: config.imapTransport,
            attestations,
          });
          if (broker.openLinkMode === "browser_same_profile_required" && !campaignId) {
            throw new Error("rightout_peopleconnect_campaign_required");
          }
          await authorizeCampaignEffects(campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "open_verification" }], catalog, true);
          const openDedupeKey = verificationOpenDedupeKey(input.profileId, input.brokerId, context.submission_proof_reference);
          const openIntentCreated = await verificationOpenDedupe.registerIfAbsent(openDedupeKey, {
            createdAt: new Date().toISOString(),
            profileId: input.profileId,
            brokerId: input.brokerId,
            submissionReference: context.submission_proof_reference,
            phase: "provider_request_intent",
          });
          if (!openIntentCreated) throw new Error("rightout_verification_open_unresolved");
          let consumed;
          try {
            consumed = await verificationTokens.consume(input.verificationHandle);
            if (!consumed || consumed.url !== token.url) throw new Error("rightout_verification_handle_expired");
          } catch (error) {
            await verificationOpenDedupe.delete(openDedupeKey);
            throw error;
          }
          if (broker.openLinkMode === "browser_same_profile_required") {
            let opened: Record<string, any> | undefined;
            let flowStored = false;
            let sessionId: string | undefined;
            try {
              const browserControl = sameProfileBrowserControl!;
              const parity = await parityCatalogPromise;
              const portalBroker = resolveParityBroker(parity, input.brokerId) as Record<string, any>;
              const profile = parseRemovalProfile(config.profiles[input.profileId].payload) as Record<string, any>;
              const values = formProfileValues(profile);
              const disclosureFields = ["full_name", "date_of_birth"];
              const fieldDisclosureMap = formFieldDisclosureMap(disclosureFields, values);
              opened = await browserSessionDriver.openSession({
                ...browserControl, formUrl: consumed.url, allowedDomains: consumed.allowedDomains,
                allowedFields: Object.keys(fieldDisclosureMap), values, privacyMode: "peopleconnect_guided", signal,
              });
              const expiresAt = Date.now() + 30 * 60_000;
              await portalFlowStore.register(portalFlowKey(input.profileId, input.brokerId), {
                profileId: input.profileId, brokerId: input.brokerId, campaignId,
                targetId: opened.targetId, browserProfile: browserControl.browserProfile ?? null,
                bridgeUrl: browserControl.bridgeUrl,
                browserBackend: config?.browserBackendMode ?? "managed_openclaw",
                stage: "peopleconnect_guided_identity", expiresAt,
              });
              flowStored = true;
              sessionId = `formsession_${randomBytes(12).toString("hex")}`;
              const formRecipe = await currentRecipeForBroker(input.brokerId);
              const formRecipeDigest = recipeDigest(formRecipe);
              const formRecipePackDigest = (await loadRecipePack()).recipe_digest;
              storeBrowserSession(sessionId, {
                sessionId, sessionType: "form", stage: "peopleconnect_guided_identity", targetId: opened.targetId,
                profileId: input.profileId, brokerId: input.brokerId, campaignId,
                broker: portalBroker, values, fieldDisclosureMap, browserControl,
                recipeId: formRecipe.recipe_id, recipeDigest: formRecipeDigest, recipePackDigest: formRecipePackDigest,
                browserBackend: config?.browserBackendMode ?? "managed_openclaw",
                filledFields: [], recordSelected: false, effectConsumed: true,
                submissionIntentReserved: false, expiresAt,
              });
              const formRecipeAssessment = await assessFormRecipeSession(sessionId, activeFormSession(sessionId), opened.snapshot);
              await verificationOpenDedupe.delete(openDedupeKey);
              const report = {
                report_version: 1, session_id: sessionId, subject_ref: input.profileId, broker_id: input.brokerId,
                state: "guided_suppression_ready", generated_at: new Date().toISOString(),
                approval_boundary: approvalBoundary,
                same_browser_profile_retained: true, authenticated_imap_message_bound: true,
                verification_handle_consumed: true, disclosures_allowed: disclosureFields,
                form_fields_available: Object.keys(fieldDisclosureMap), snapshot: opened.snapshot,
                recipe_policy: { recipe_id: formRecipe.recipe_id, recipe_digest: formRecipeDigest, assessment: formRecipeAssessment.state },
                next_action: "fill_identity_then_select_one_strongly_corroborated_record_then_click_suppress",
                invariants: { raw_link_in_report: false, raw_pii_in_report: false, provider_writes: 1 },
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            } catch (error) {
              if (sessionId) deleteBrowserSession(sessionId);
              if (flowStored) await portalFlowStore.delete(portalFlowKey(input.profileId, input.brokerId)).catch(() => undefined);
              if (opened?.targetId && sameProfileBrowserControl) {
                await browserSessionDriver.closeSession({ ...sameProfileBrowserControl, targetId: opened.targetId }).catch(() => undefined);
              }
              await caseLedger.recordLifecycle(input.profileId, input.brokerId, "human_task_queued", {
                evidenceKind: "human_task", reason: "same_profile_verification_open_uncertain",
              }).catch(() => undefined);
              const report = {
                report_version: 1, subject_ref: input.profileId, broker_id: input.brokerId,
                state: "human_task_queued", reason: "same_profile_verification_open_uncertain",
                approval_boundary: approvalBoundary,
                verification_handle_consumed: true, retry_blocked: true,
                tracking: { durable_retry_guard_recorded: true },
                invariants: { raw_link_in_report: false, raw_pii_in_report: false, provider_writes_possible: true },
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
          }
          let request;
          let openFailure;
          try {
            request = await fetchWithSsrFGuard({
              url: consumed.url,
              fetchImpl: globalThis.fetch,
              requireHttps: true,
              capture: false,
              timeoutMs: 20_000,
              maxRedirects: 3,
              signal,
              policy: buildHostnameAllowlistPolicyFromSuffixAllowlist(consumed.allowedDomains),
              auditContext: "rightout_open_verification",
              init: { method: "GET", redirect: "follow", headers: { Accept: "text/html,application/xhtml+xml" } },
            });
            if (!request.response.ok) throw new Error("rightout_verification_open_failed");
          } catch (error) {
            openFailure = signal?.aborted ? "rightout_verification_cancelled" : "rightout_verification_open_failed";
          } finally {
            await request?.release?.();
          }
          if (openFailure) {
            let durableCaseRecorded = true;
            try {
              await caseLedger.recordLifecycle(input.profileId, input.brokerId, "human_task_queued", {
                evidenceKind: "human_task",
                reason: "verification_open_outcome_uncertain",
              });
            } catch { durableCaseRecorded = false; }
            const report = {
              report_version: 1,
              subject_ref: input.profileId,
              broker_id: input.brokerId,
              state: durableCaseRecorded ? "human_task_queued" : "verification_opened_tracking_failed",
              approval_boundary: approvalBoundary,
              reason: "verification_open_outcome_uncertain",
              generated_at: new Date().toISOString(),
              verification_handle_consumed: true,
              removal_confirmed: false,
              retry_blocked: true,
              next_action: "manual_provider_status_check_required",
              tracking: { durable_case_recorded: durableCaseRecorded, durable_retry_guard_recorded: true },
              invariants: { raw_link_in_report: false, raw_pii_in_report: false, provider_writes_possible: true },
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          let durableCaseRecorded = true;
          try {
            await caseLedger.recordLifecycle(input.profileId, input.brokerId, "awaiting_processing", {
              evidenceKind: "broker_verification_link",
              processingDays: broker.processingDays,
              proofReference: `verify_${createHash("sha256").update(input.verificationHandle).digest("hex").slice(0, 24)}`,
            });
          } catch {
            durableCaseRecorded = false;
            api.logger.error("RightOut opened a verification link but its PII-safe case update failed");
          }
          if (!durableCaseRecorded) {
            const report = {
              report_version: 1,
              subject_ref: input.profileId,
              broker_id: input.brokerId,
              state: "verification_opened_tracking_failed",
              approval_boundary: approvalBoundary,
              generated_at: new Date().toISOString(),
              verification_handle_consumed: true,
              removal_confirmed: false,
              next_action: "manual_provider_status_check_required",
              retry_blocked: true,
              tracking: { durable_case_recorded: false, durable_retry_guard_recorded: true },
              invariants: { raw_link_in_report: false, raw_pii_in_report: false, provider_writes: 1 },
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          await verificationOpenDedupe.delete(openDedupeKey);
          const report = {
            report_version: 1,
            subject_ref: input.profileId,
            broker_id: input.brokerId,
            state: "awaiting_processing",
            approval_boundary: approvalBoundary,
            generated_at: new Date().toISOString(),
            verification_handle_consumed: true,
            removal_confirmed: false,
            tracking: { durable_case_recorded: durableCaseRecorded },
            invariants: { raw_link_in_report: false, raw_pii_in_report: false, provider_writes: 1 },
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_open_verification", optional: true },
    );

    api.registerTool(
      {
        name: "rightout_poll_controller_reply",
        label: "RightOut poll controller reply",
        description: "Read recent approved IMAP mail for an exact thread-bound, receiver-authenticated official controller reply. Returns only a bounded outcome candidate; never records a legal or terminal outcome automatically.",
        parameters: ControllerReplyPollParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicControllerReplyInput;
          try { input = validateControllerReplyInput(params); }
          catch { throw new Error("rightout_approval_binding_failed"); }
          await pruneTransientState();
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await catalogPromise;
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string" || !config.imapTransport) {
            throw new Error("rightout_not_configured");
          }
          assertFreshCatalogEntries(catalog, [input.brokerId]);
          const attestations = controllerReplyAttestationSnapshot(config, input);
          const preflight = validateControllerReplyPreflight({
            input,
            catalog,
            profilePayload: config.profiles[input.profileId].payload,
            imapTransport: config.imapTransport,
            attestations,
          });
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !approval || approval.toolName !== "rightout_poll_controller_reply"
            || approval.binding !== controllerReplyScopeBinding(input, attestations, preflight.broker)
          ) throw new Error("rightout_approval_binding_failed");
          const caseContext = await caseLedger.verificationContext(input.profileId, input.brokerId, [
            "submitted", "awaiting_processing", "identity_verification_required", "partially_removed",
          ]);
          const result = await pollControllerReply({
            transport: preflight.imap,
            expectedAddress: preflight.profile.contactEmail,
            broker: preflight.broker.raw,
            expectedMessageId: preflight.expectedMessageId,
            notBefore: caseContext.submitted_at,
            sinceDays: 30,
            signal,
          });
          if (!result.found) {
            const deferred = await caseLedger.deferRecheck(input.profileId, input.brokerId, {
              reason: "authenticated_controller_reply_not_observed",
              days: 1,
            });
            const report = {
              report_version: 1,
              subject_ref: input.profileId,
              broker_id: input.brokerId,
              state: "controller_reply_not_observed",
              generated_at: new Date().toISOString(),
              next_recheck_at: deferred.next_recheck_at,
              provider_writes: 0,
              invariants: { raw_mail_in_report: false, raw_pii_in_report: false, inferred_controller_outcome: false },
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (
            typeof result.message_reference !== "string" || !/^mail_[a-f0-9]{24}$/.test(result.message_reference)
            || !Array.isArray(result.authentication_signals) || !Array.isArray(result.evidence_signals)
          ) throw new Error("rightout_controller_reply_poll_failed");
          if (result.outcome_candidate === "needs_manual_check") {
            const report = {
              report_version: 1,
              subject_ref: input.profileId,
              broker_id: input.brokerId,
              state: "controller_reply_needs_manual_check",
              message_reference: result.message_reference,
              authentication_signals: result.authentication_signals,
              classifier_signals: result.evidence_signals,
              generated_at: new Date().toISOString(),
              next_action: "inspect_the_exact_message_in_the_authorized_mailbox_then_record_only_a_personally_reviewed_outcome",
              provider_writes: 0,
              invariants: { raw_mail_in_report: false, raw_pii_in_report: false, inferred_controller_outcome: false },
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          const allowedOutcomes = new Set(["processing_acknowledged", "erasure_confirmed", "partial_erasure", "deletion_confirmed", "partial_deletion", "identity_required", "request_rejected"]);
          if (!allowedOutcomes.has(result.outcome_candidate) || result.confidence !== "high") throw new Error("rightout_controller_reply_poll_failed");
          const candidateHandle = `reply_${randomBytes(12).toString("hex")}`;
          const candidate: ControllerReplyCandidate = {
            profileId: input.profileId,
            brokerId: input.brokerId,
            outcome: result.outcome_candidate as ControllerReplyCandidate["outcome"],
            messageReference: result.message_reference,
            submissionReference: caseContext.submission_proof_reference,
            terminal: result.terminal === true,
            evidenceSignals: result.evidence_signals,
            authenticationSignals: result.authentication_signals,
            createdAt: new Date().toISOString(),
          };
          await controllerReplyCandidates.register(candidateHandle, candidate);
          const report = {
            report_version: 1,
            subject_ref: input.profileId,
            broker_id: input.brokerId,
            state: "authenticated_controller_reply_candidate",
            candidate_handle: candidateHandle,
            outcome_candidate: candidate.outcome,
            terminal_candidate: candidate.terminal,
            confidence: "high",
            message_reference: candidate.messageReference,
            authentication_signals: candidate.authenticationSignals,
            classifier_signals: candidate.evidenceSignals,
            generated_at: candidate.createdAt,
            next_action: "personally_review_the_exact_mailbox_message_then_call_rightout_record_controller_outcome_with_this_candidate_handle",
            provider_writes: 0,
            invariants: { raw_mail_in_report: false, raw_pii_in_report: false, outcome_recorded_automatically: false },
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_create_evidence_snapshot",
        label: "RightOut create evidence snapshot",
        description: "Store one sanitized case-transition snapshot in the encrypted, retention-bound, content-addressed local evidence vault. Returns metadata only and performs no provider request or external write.",
        parameters: EvidenceSnapshotParameters,
        async execute(_toolCallId, params) {
          const input = validateEvidenceSnapshotInput(params);
          assertConfiguredProfile(input.profileId);
          const status = await caseLedger.status(input.profileId);
          const item = status.cases.find((candidate: Record<string, any>) => candidate.broker_id === input.brokerId);
          if (!item) throw new Error("rightout_evidence_case_not_found");
          const content = {
            schema_version: 1,
            subject_ref: input.profileId,
            broker_id: input.brokerId,
            state: item.state,
            proof_references: item.proof_references,
            submission_channel: item.submission_channel,
            submission_started_at: item.submission_started_at,
            submission_outcome: item.submission_outcome,
            next_recheck_at: item.next_recheck_at,
            removal_confirmed_at: item.removal_confirmed_at,
            removal_confirmation_scope: item.removal_confirmation_scope,
            coverage_gap: item.coverage_gap,
            human_task_reason: item.human_task_reason,
            raw_pii_in_snapshot: false,
          };
          const report = await evidenceVault.put({
            profileId: input.profileId,
            brokerId: input.brokerId,
            kind: "case_transition_snapshot",
            retentionDays: stateRetentionDays,
            content,
          });
          const details = { report_version: 1, state: "encrypted_evidence_snapshot_created", ...report, provider_reads: 0, provider_writes: 0 };
          return { content: [{ type: "text", text: JSON.stringify(details) }], details };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_evidence_status",
        label: "RightOut evidence status",
        description: "Read metadata for one exact subject-bound encrypted evidence reference without returning its content or performing a network request.",
        parameters: EvidenceRefParameters,
        async execute(_toolCallId, params) {
          const input = validateEvidenceRefInput(params) as PublicEvidenceRefInput;
          const report = { report_version: 1, state: "encrypted_evidence_available", ...(await evidenceVault.metadata(input.evidenceRef, input.profileId)), provider_reads: 0, provider_writes: 0 };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_export_evidence",
        label: "RightOut export redacted evidence",
        description: "Export one exact encrypted evidence record into the private local RightOut export directory after redaction. Requires native allow-once approval and performs no provider request.",
        parameters: EvidenceExportParameters,
        async execute(toolCallId, params) {
          const input = validateEvidenceRefInput(params, true) as PublicEvidenceExportInput;
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_export_evidence" || approval.binding !== evidenceExportScopeBinding(input)) {
            throw new Error("rightout_approval_binding_failed");
          }
          assertConfiguredProfile(input.profileId);
          const exported = await evidenceVault.exportRedacted(input.evidenceRef, input.profileId, stateDir, input.format);
          const { artifact_path: artifactPath, ...exportMetadata } = exported;
          const report = {
            report_version: 1,
            ...exportMetadata,
            artifact_name: basename(artifactPath),
            artifact_location: "private_rightout_state_evidence_export_directory",
            approval_boundary: "native_openclaw_allow_once_redacted_local_export",
            provider_reads: 0,
            provider_writes: 0,
            raw_pii_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_custom_target_status",
        label: "RightOut custom target status",
        description: "Inspect one subject-bound opaque custom-target handle. Raw URL/domain/source facts remain encrypted; readiness requires one exact trusted external recipe and current handle-bound permission.",
        parameters: CustomTargetRefParameters,
        async execute(_toolCallId, params) {
          const input = validateCustomTargetRefInput(params);
          assertConfiguredProfile(input.profileId);
          const config = api.pluginConfig as RightOutConfig;
          const metadata = await customTargetVault.metadata(input.customTargetHandle, input.profileId);
          let state = "quarantined";
          let reason = "signed_recipe_and_current_permission_required";
          let recipeId: string | null = null;
          let recipeDigestValue: string | null = null;
          try {
            const resolved = await customTargetVault.resolveAuthorized(input.customTargetHandle, input.profileId, {
              recipePacks: config.customTargetRecipePacks,
              trustedKeys: config.customTargetTrustedKeys,
              permission: config.customTargetPermissions?.[input.customTargetHandle],
            });
            state = "authorized_recipe_and_permission_bound";
            reason = "ready_for_separately_approved_custom_provider_session";
            recipeId = resolved.metadata.recipe_id;
            recipeDigestValue = resolved.metadata.recipe_digest;
          } catch (error) {
            const code = error instanceof Error ? error.message : "rightout_custom_target_recipe_required";
            reason = code === "rightout_custom_target_permission_expired"
              ? "permission_expired"
              : code === "rightout_custom_target_scope_mismatch"
                ? "subject_scope_mismatch"
                : "signed_recipe_and_current_permission_required";
          }
          const report = {
            report_version: 1,
            ...metadata,
            state,
            reason,
            recipe_id: recipeId,
            recipe_digest: recipeDigestValue,
            provider_action_available: false,
            next_action: state === "authorized_recipe_and_permission_bound"
              ? "custom_provider_execution_remains_disabled_until_a_dedicated_approval_gated_session_is_implemented"
              : "install_a_trusted_signed_recipe_and_current_handle_bound_permission",
            provider_reads: 0,
            provider_writes: 0,
            raw_target_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_rotate_state_key",
        label: "RightOut rotate state key",
        description: "Re-encrypt all local RightOut state under the active SecretRef key while temporary previous SecretRef keys remain configured. Requires native allow-once approval and performs no provider call.",
        parameters: EmptyParameters,
        async execute(toolCallId, params) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length !== 0) {
            throw new Error("rightout_approval_binding_failed");
          }
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_rotate_state_key" || approval.binding !== rotationScopeBinding()) {
            throw new Error("rightout_approval_binding_failed");
          }
          const config = api.pluginConfig as RightOutConfig | undefined;
          if (!stateRotationReady(config)) throw new Error("rightout_state_rotation_not_configured");
          const [cases, profileSnapshots, verificationHandles, controllerReplyHandles, evidenceEntries, evidenceExportEntries, customTargetEntries, verificationOpenGuards, portalFlows, listingHandles, dedupeRecords, campaigns, workers, registryEntries, paritySourceEntries] = await Promise.all([
            caseStore.reencrypt(),
            profileSnapshotStore.reencrypt(),
            verificationTokens.reencrypt(),
            controllerReplyCandidates.reencrypt(),
            evidenceStore.reencrypt(),
            evidenceExportStore.reencrypt(),
            customTargetStore.reencrypt(),
            verificationOpenDedupe.reencrypt(),
            portalFlowStore.reencrypt(),
            listingTokens.reencrypt(),
            submissionDedupe.reencrypt(),
            campaignStore.reencrypt(),
            workerStore.reencrypt(),
            registryStore.reencrypt(),
            paritySourceStore.reencrypt(),
          ]);
          const report = {
            report_version: 1,
            state: "local_state_key_rotated",
            generated_at: new Date().toISOString(),
            reencrypted_entries: {
              cases,
              profile_snapshots: profileSnapshots,
              verification_handles: verificationHandles,
              controller_reply_candidates: controllerReplyHandles,
              evidence_entries: evidenceEntries,
              evidence_export_index_entries: evidenceExportEntries,
              custom_target_entries: customTargetEntries,
              verification_open_guards: verificationOpenGuards,
              verified_portal_flows: portalFlows,
              listing_handles: listingHandles,
              dedupe_records: dedupeRecords,
              campaigns,
              autonomy_workers: workers,
              registry_entries: registryEntries,
              parity_source_entries: paritySourceEntries,
            },
            previous_key_count: config.previousStateEncryptionKeys.length,
            provider_writes: 0,
            raw_pii_in_report: false,
            next_action: "remove_previousStateEncryptionKeys_from_config_reload_then_run_openclaw_security_audits",
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_purge_subject_state",
        label: "RightOut purge subject state",
        description: "Permanently delete one opaque subject's encrypted RightOut cases, verification/listing handles, and dedupe records. Requires native allow-once approval and does not alter providers or OpenClaw configuration.",
        parameters: CaseParameters,
        async execute(toolCallId, params) {
          let input: PublicCaseInput;
          try { input = validateCaseInput(params); }
          catch { throw new Error("rightout_approval_binding_failed"); }
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_purge_subject_state" || approval.binding !== purgeScopeBinding(input)) {
            throw new Error("rightout_approval_binding_failed");
          }
          const config = api.pluginConfig as RightOutConfig | undefined;
          if (!stateEncryptionReady(config)) throw new Error("rightout_not_configured");
          const activeSessionsInvalidated = await invalidateBrowserSessions((session) => session.profileId === input.profileId);
          const activePortalFlowsInvalidated = await invalidatePortalFlows((flow) => flow.profileId === input.profileId);
          const [caseDeleted, profileSnapshotDeleted, verificationHandles, controllerReplyHandles, evidenceExports, evidenceEntries, customTargetEntries, verificationOpenGuards, portalFlows, listingHandles, dedupeRecords, campaigns, workers] = await Promise.all([
            caseLedger.purge(input.profileId),
            profileSnapshotStore.delete(input.profileId),
            purgeProfileEntries(verificationTokens, input.profileId),
            purgeProfileEntries(controllerReplyCandidates, input.profileId),
            evidenceVault.purgeExports(input.profileId),
            purgeProfileEntries(evidenceStore, input.profileId),
            purgeProfileEntries(customTargetStore, input.profileId),
            purgeProfileEntries(verificationOpenDedupe, input.profileId),
            purgeProfileEntries(portalFlowStore, input.profileId),
            purgeProfileEntries(listingTokens, input.profileId),
            purgeProfileEntries(submissionDedupe, input.profileId),
            purgeProfileEntries(campaignStore, input.profileId),
            purgeProfileEntries(workerStore, input.profileId),
          ]);
          submittedScopes.clear();
          const report = {
            report_version: 1,
            subject_ref: input.profileId,
            state: "local_subject_state_purged",
            generated_at: new Date().toISOString(),
            deleted: {
              case_record: caseDeleted ? 1 : 0,
              profile_snapshot: profileSnapshotDeleted ? 1 : 0,
              verification_handles: verificationHandles,
              controller_reply_candidates: controllerReplyHandles,
              evidence_exports: evidenceExports,
              evidence_entries: evidenceEntries,
              custom_target_entries: customTargetEntries,
              verification_open_guards: verificationOpenGuards,
              verified_portal_flows: portalFlows,
              listing_handles: listingHandles,
              dedupe_records: dedupeRecords,
              campaigns,
              autonomy_workers: workers,
              active_sessions: activeSessionsInvalidated.invalidated,
              active_verified_portal_flows: activePortalFlowsInvalidated,
              webmail_drafts_discarded: activeSessionsInvalidated.drafts_discarded,
              webmail_drafts_needing_manual_cleanup: activeSessionsInvalidated.drafts_needing_manual_cleanup,
              form_provider_intents_marked_uncertain: activeSessionsInvalidated.provider_intents_marked_uncertain,
              form_provider_intents_needing_manual_reconciliation: activeSessionsInvalidated.provider_intents_needing_manual_reconciliation,
              browser_tabs_closed: activeSessionsInvalidated.tabs_closed,
              browser_tabs_needing_manual_cleanup: activeSessionsInvalidated.tabs_needing_manual_cleanup,
            },
            config_profile_deleted: false,
            provider_writes: 0,
            next_action: "remove_the_subject_profile_secretref_from_openclaw_config_if_full_erasure_is_required",
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_record_controller_outcome",
        label: "RightOut record controller outcome",
        description: "Record one operator-reviewed EU or US controller response in the encrypted case ledger. Requires native allow-once approval and performs no provider write. SMTP acceptance alone is never sufficient.",
        parameters: ControllerOutcomeParameters,
        async execute(toolCallId, params) {
          let input: PublicControllerOutcomeInput;
          try { input = validateControllerOutcomeInput(params); }
          catch { throw new Error("rightout_approval_binding_failed"); }
          const catalog = await catalogPromise;
          const broker = resolveControllerOutcomeBroker(catalog, input);
          const candidate = await controllerCandidateForOutcome(input);
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !approval || approval.toolName !== "rightout_record_controller_outcome"
            || approval.binding !== controllerOutcomeScopeBinding(input, broker, candidate)
          ) throw new Error("rightout_approval_binding_failed");
          assertConfiguredProfile(input.profileId);
          await ensureImmutableProfileSnapshot(input.profileId);
          const outcome = await caseLedger.recordControllerOutcome(input.profileId, input.brokerId, input.outcome, {
            id: broker.id,
            process_class: broker.processClass,
            removal: { confirmation_policy: broker.confirmationPolicy, processing_days: broker.processingDays },
          });
          if (input.candidateHandle) await controllerReplyCandidates.delete(input.candidateHandle);
          const report = {
            report_version: 1,
            subject_ref: input.profileId,
            broker_id: input.brokerId,
            state: outcome.state,
            controller_outcome: input.outcome,
            generated_at: new Date().toISOString(),
            proof_references: [outcome.proof_reference],
            removal_confirmation_scope: outcome.confirmation_scope ?? null,
            operator_attestation: "native_openclaw_allow_once_human_review",
            authenticated_candidate_consumed: Boolean(input.candidateHandle),
            provider_writes: 0,
            invariants: { raw_controller_response_in_report: false, raw_pii_in_report: false, smtp_acceptance_used_as_outcome: false },
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_reconcile_submission",
        label: "RightOut reconcile submission",
        description: "Record an operator-reviewed outcome for a durable pending or uncertain provider write. Requires native allow-once approval, performs no provider write, and is the only safe path back to retry eligibility.",
        parameters: SubmissionReconciliationParameters,
        async execute(toolCallId, params) {
          let input: PublicSubmissionReconciliationInput;
          try { input = validateSubmissionReconciliationInput(params); }
          catch { throw new Error("rightout_approval_binding_failed"); }
          const catalog = await catalogPromise;
          const broker = resolveSubmissionReconciliationBroker(catalog, input);
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !approval || approval.toolName !== "rightout_reconcile_submission"
            || approval.binding !== submissionReconciliationScopeBinding(input, broker)
          ) throw new Error("rightout_approval_binding_failed");
          assertConfiguredProfile(input.profileId);
          await ensureImmutableProfileSnapshot(input.profileId);
          const outcome = await caseLedger.reconcileSubmission(input.profileId, input.brokerId, input.outcome, {
            processingDays: broker.processingDays,
          });
          if (input.outcome === "provider_write_not_started") {
            const dedupeKey = removalDedupeKey({
              profileId: input.profileId,
              brokerId: input.brokerId,
              requestKind: broker.requestKind as PublicRemovalInput["requestKind"],
            });
            submittedScopes.delete(dedupeKey);
            await submissionDedupe.delete(dedupeKey);
          }
          const report = {
            report_version: 1,
            subject_ref: input.profileId,
            broker_id: input.brokerId,
            state: outcome.state,
            submission_channel: outcome.channel,
            reconciliation_outcome: input.outcome,
            generated_at: new Date().toISOString(),
            proof_references: [outcome.proof_reference],
            operator_attestation: "native_openclaw_allow_once_human_review",
            retry_allowed: input.outcome === "provider_write_not_started",
            provider_writes: 0,
            invariants: { raw_provider_evidence_in_report: false, raw_pii_in_report: false, agent_inference_used: false },
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_begin_discovery_session",
        label: "RightOut begin publisher browser discovery",
        description: "Open one official-domain broker search surface after Brave was inconclusive. Requires a separately authorized publisher-discovery campaign effect and publisher-terms attestation; returns only a PII-redacted snapshot.",
        parameters: DiscoverySessionBeginParameters,
        async execute(_toolCallId, params, signal) {
          const input = validateDiscoverySessionBeginInput(params);
          const config = api.pluginConfig as RightOutConfig | undefined;
          const parityCatalog = await parityCatalogPromise;
          const broker = resolveParityBroker(parityCatalog, input.brokerId);
          const selectedBackend = input.browserBackend ?? config?.browserBackendMode ?? "managed_openclaw";
          assertPublisherAutomationPermission(config, broker, await providerTermsPromise, "publisher_discover", { browserBackend: selectedBackend });
          const profilePayload = config?.profiles?.[input.profileId]?.payload;
          if (!stateEncryptionReady(config) || typeof profilePayload !== "string") throw new Error("rightout_not_configured");
          if (
            String(broker.source_status).startsWith("needs_evidence")
            || broker.source_status === "observed_official_archive_external_unavailable"
          ) {
            throw new Error("rightout_publisher_discovery_not_executable");
          }
          await assertParityRouteFresh(input.brokerId);
          const attestations = validatePublisherAccessAttestations(
            { profileId: input.profileId, brokerId: input.brokerId },
            config?.directScanAttestations,
          ) as DirectScanAttestations;
          if (scanProfileDigest(profilePayload) !== attestations.authorizedProfileDigests[input.profileId]) {
            throw new Error("rightout_direct_scan_profile_snapshot_changed");
          }
          const profile = parseRemovalProfile(profilePayload) as Record<string, any>;
          const values = discoveryProfileValues(profile);
          if (typeof values.full_name !== "string") throw new Error("rightout_discovery_profile_field_missing");
          const browserControl = resolveBrowserControl(toolContext as Record<string, any>, config, selectedBackend);
          if (typeof browserControl.bridgeUrl !== "string") throw new Error("rightout_browser_bridge_unavailable");
          if (selectedBackend === "remote_cloud_cdp" && !browserControl.browserProfile) {
            throw new Error("rightout_remote_cloud_browser_unavailable");
          }
          if (selectedBackend === "remote_cloud_cdp") {
            const caseStatus = await caseLedger.status(input.profileId);
            const brokerCase = caseStatus.cases.find((item: any) => item.broker_id === input.brokerId);
            if (brokerCase?.state !== "blocked") throw new Error("rightout_remote_cloud_retry_not_eligible");
          }
          await authorizeCampaignEffects(
            input.campaignId,
            input.profileId,
            [{ brokerId: input.brokerId, effect: "publisher_discover" }],
            await catalogPromise,
            true,
          );
          if (selectedBackend === "remote_cloud_cdp") {
            await caseLedger.recordLifecycle(input.profileId, input.brokerId, "human_task_queued", {
              evidenceKind: "human_task",
              reason: "remote_cloud_browser_retry_in_progress",
            });
          }
          const discoveryStartUrl = `https://${broker.official_domains[0]}/`;
          let opened;
          try {
            opened = await browserSessionDriver.openSession({
              ...browserControl,
              formUrl: discoveryStartUrl,
              discoveryStartUrl,
              allowedDomains: broker.official_domains,
              allowedFields: Object.keys(values),
              values,
              privacyMode: "publisher_discovery",
              label: selectedBackend === "remote_cloud_cdp"
                ? "rightout-remote-cloud-retry"
                : "rightout-publisher-discovery",
              signal,
            });
          } catch (error) {
            if (selectedBackend === "remote_cloud_cdp") {
              await caseLedger.recordLifecycle(input.profileId, input.brokerId, "human_task_queued", {
                evidenceKind: "human_task",
                reason: "remote_cloud_browser_retry_failed",
              }).catch(() => undefined);
            } else {
              await caseLedger.recordLifecycle(input.profileId, input.brokerId, "blocked", {
                evidenceKind: "human_task",
                reason: "primary_browser_access_blocked",
              }).catch(() => undefined);
            }
            throw error;
          }
          if (["hard_human_gate", "access_blocked"].includes(opened.snapshot.challenge)) {
            await browserSessionDriver.closeSession({ ...browserControl, targetId: opened.targetId }).catch(() => undefined);
            await caseLedger.recordLifecycle(input.profileId, input.brokerId, selectedBackend === "remote_cloud_cdp" ? "human_task_queued" : "blocked", {
              evidenceKind: "human_task",
              reason: selectedBackend === "remote_cloud_cdp" ? "remote_cloud_browser_retry_failed" : "primary_browser_access_blocked",
            });
            throw new Error("rightout_form_human_gate_required");
          }
          const sessionId = `discoverysession_${randomBytes(12).toString("hex")}`;
          storeBrowserSession(sessionId, {
            kind: "publisher_discovery",
            sessionId,
            targetId: opened.targetId,
            profileId: input.profileId,
            brokerId: input.brokerId,
            campaignId: input.campaignId,
            broker,
            values,
            discoveryStartUrl,
            browserControl,
            privacyMode: "publisher_discovery",
            browserBackend: selectedBackend,
            expiresAt: Date.now() + 30 * 60_000,
          });
          const report = {
            report_version: 1,
            session_id: sessionId,
            subject_ref: input.profileId,
            broker_id: input.brokerId,
            state: "publisher_discovery_session_ready",
            snapshot: opened.snapshot,
            disclosures_allowed: Object.keys(values),
            next_actions: ["inspect", "fill_search_fields", "select_record", "capture_candidate_or_close"],
            provider_reads: 1,
            provider_writes: 0,
            browser_backend: input.browserBackend ?? resolveBrowserBackend(toolContext as Record<string, any>, config).selected,
            raw_pii_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_begin_discovery_session", optional: true },
    );

    api.registerTool(
      {
        name: "rightout_discovery_session_step",
        label: "RightOut publisher browser discovery step",
        description: "Inspect or drive one bounded official-domain discovery session. Candidate capture encrypts the current broker URL and records only an indirect signal for later direct verification.",
        parameters: DiscoverySessionStepParameters,
        async execute(_toolCallId, params, signal) {
          const input = validateDiscoverySessionStepInput(params);
          pruneApprovalState();
          await pruneTransientState();
          const session = activeDiscoverySession(input.sessionId);
          if (input.action.kind !== "close") {
            await revalidatePublisherBrowserSession(input.sessionId, session, "publisher_discover");
          }
          const driverOptions = {
            ...session.browserControl,
            targetId: session.targetId,
            allowedDomains: session.broker.official_domains,
            allowedFields: Object.keys(session.values),
            values: session.values,
            discoveryStartUrl: session.discoveryStartUrl,
            privacyMode: session.privacyMode,
            signal,
          };
          const guardedBrowserStep = async <T>(operation: () => Promise<T>): Promise<T> => {
            try { return await operation(); }
            catch (error) {
              if (session.browserBackend === "remote_cloud_cdp") {
                await caseLedger.recordLifecycle(session.profileId, session.brokerId, "human_task_queued", {
                  evidenceKind: "human_task",
                  reason: "remote_cloud_browser_retry_failed",
                }).catch(() => undefined);
                await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
                deleteBrowserSession(input.sessionId);
              } else {
                const code = error instanceof Error ? error.message : "rightout_browser_bridge_failed";
                if (![
                  "rightout_discovery_candidate_not_selected", "rightout_form_ref_invalid",
                  "rightout_form_action_not_allowed", "rightout_form_profile_field_missing",
                ].includes(code)) {
                  await caseLedger.recordLifecycle(session.profileId, session.brokerId, "blocked", {
                    evidenceKind: "human_task",
                    reason: "primary_browser_access_blocked",
                  }).catch(() => undefined);
                  await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
                  deleteBrowserSession(input.sessionId);
                }
              }
              throw error;
            }
          };
          if (input.action.kind === "inspect") {
            const snapshot = await guardedBrowserStep(() => browserSessionDriver.inspect(driverOptions));
            const report = { session_id: input.sessionId, broker_id: session.brokerId, state: "publisher_discovery_session_active", snapshot };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (input.action.kind === "record_redacted_state_receipt") {
            const receipt = await guardedBrowserStep(() => browserSessionDriver.redactedStateReceipt(driverOptions));
            const report = { session_id: input.sessionId, broker_id: session.brokerId, state: "redacted_state_receipt_recorded", ...receipt };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (input.action.kind === "close") {
            await browserSessionDriver.closeSession(driverOptions);
            deleteBrowserSession(input.sessionId);
            await caseLedger.recordLifecycle(session.profileId, session.brokerId, "human_task_queued", {
              evidenceKind: "human_task",
              reason: session.browserBackend === "remote_cloud_cdp"
                ? "remote_cloud_browser_retry_closed_without_candidate"
                : "publisher_discovery_closed_without_candidate",
            });
            const report = {
              session_id: input.sessionId,
              broker_id: session.brokerId,
              state: "human_task_queued",
              reason: session.browserBackend === "remote_cloud_cdp"
                ? "remote_cloud_browser_retry_closed_without_candidate"
                : "publisher_discovery_closed_without_candidate",
              provider_writes: 0,
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (input.action.kind === "capture_candidate") {
            const candidate = await guardedBrowserStep(() => browserSessionDriver.captureCandidate(driverOptions));
            const observedAt = new Date().toISOString();
            const listingHandle = await createListingTokenVault(listingTokens, (api.pluginConfig as RightOutConfig).stateEncryptionKey!).storeCandidate({
              profileId: session.profileId,
              brokerId: session.brokerId,
              urls: [candidate.candidateUrl],
              officialDomains: session.broker.official_domains,
              observedAt,
            });
            const receipt = await guardedBrowserStep(() => browserSessionDriver.redactedStateReceipt(driverOptions));
            const report = {
              report_version: 1,
              mode: "operator_authorized_browser_discovery",
              subject_ref: session.profileId,
              broker_id: session.brokerId,
              state: "indirect_exposure",
              listing_handle: listingHandle,
              generated_at: observedAt,
              proof_references: [receipt.receipt_reference],
              redacted_state_receipt: receipt,
              candidate_requires_direct_verification: true,
              provider_reads: 1,
              provider_writes: 0,
              raw_url_in_report: false,
              raw_pii_in_report: false,
            };
            await caseLedger.recordBrowserDiscovery(report);
            await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
            deleteBrowserSession(input.sessionId);
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          const snapshot = await guardedBrowserStep(() => browserSessionDriver.act({ ...driverOptions, action: input.action }));
          const report = { session_id: input.sessionId, broker_id: session.brokerId, state: "publisher_discovery_session_active", snapshot };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_begin_form_session",
        label: "RightOut begin autonomous form session",
        description: "Open one independently sourced Unbroker-parity opt-out route inside an approved bounded campaign. Returns a PII-redacted interactive snapshot; secret values remain inside the plugin and browser control plane.",
        parameters: FormSessionBeginParameters,
        async execute(_toolCallId, params, signal) {
          const input = validateFormSessionBeginInput(params);
          await pruneTransientState();
          const config = api.pluginConfig as RightOutConfig | undefined;
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string") {
            throw new Error("rightout_not_configured");
          }
          const parityCatalog = await parityCatalogPromise;
          const broker = resolveParityBroker(parityCatalog, input.brokerId);
          if (
            broker.method !== "web_form"
            || [
              "needs_evidence",
              "observed_official_archive_external_unavailable",
            ].includes(broker.source_status)
          ) {
            throw new Error("rightout_parity_route_not_executable");
          }
          parityFormAttestationSnapshot(config, input.profileId, input.brokerId);
          const selectedBackend = config?.browserBackendMode ?? "managed_openclaw";
          assertPublisherAutomationPermission(config, broker, await providerTermsPromise, "submit_form", { browserBackend: selectedBackend });
          await assertParityRouteFresh(input.brokerId);
          const recipe = await currentRecipeForBroker(input.brokerId);
          if (recipe.method !== "web_form") throw new Error("rightout_recipe_method_mismatch");
          const currentRecipeDigest = recipeDigest(recipe);
          const currentRecipePackDigest = (await loadRecipePack()).recipe_digest;
          await ensureImmutableProfileSnapshot(input.profileId);
          const coreCatalog = await catalogPromise;
          const profile = parseRemovalProfile(config.profiles[input.profileId].payload) as Record<string, any>;
          let listingUrl;
          if (broker.disclosure_fields.includes("listing_url")) {
            if (!input.listingHandle) throw new Error("rightout_form_listing_handle_required");
            const token = await createListingTokenVault(listingTokens, config.stateEncryptionKey).lookup(input.listingHandle, input.profileId, input.brokerId);
            listingUrl = token.urls[0];
          }
          const values = formProfileValues(profile, listingUrl);
          const browserControl = resolveBrowserControl(toolContext as Record<string, any>, config);
          if (typeof browserControl.bridgeUrl !== "string") throw new Error("rightout_browser_bridge_unavailable");
          if (broker.id === "intelius" && typeof browserControl.browserProfile !== "string") {
            throw new Error("rightout_peopleconnect_named_browser_profile_required");
          }
          if (broker.id === "intelius") {
            const flowKey = portalFlowKey(input.profileId, input.brokerId);
            const flow = await portalFlowStore.lookup(flowKey) as Record<string, any> | undefined;
            if (flow) {
              if (
                flow.profileId !== input.profileId || flow.brokerId !== input.brokerId || flow.campaignId !== input.campaignId
                || flow.stage !== "peopleconnect_guided_identity" || !Number.isFinite(flow.expiresAt) || flow.expiresAt <= Date.now()
                || flow.browserProfile !== (browserControl.browserProfile ?? null)
              ) throw new Error("rightout_verified_portal_flow_invalid");
              try {
                await revalidateConsumedSessionEffect({ ...flow, profileId: input.profileId, brokerId: input.brokerId }, "submit_form");
              } catch (error) {
                await portalFlowStore.delete(flowKey);
                await browserSessionDriver.closeSession({
                  bridgeUrl: flow.bridgeUrl,
                  targetId: flow.targetId,
                  browserProfile: flow.browserProfile ?? undefined,
                  browserAuthToken: config.browserControlToken,
                }).catch(() => undefined);
                throw error;
              }
              const disclosureFields = ["full_name", "date_of_birth"];
              const fieldDisclosureMap = formFieldDisclosureMap(disclosureFields, values);
              const driverOptions = {
                ...browserControl, targetId: flow.targetId, allowedDomains: broker.official_domains,
                allowedFields: Object.keys(fieldDisclosureMap), values, privacyMode: "peopleconnect_guided", signal,
              };
              let snapshot;
              try {
                snapshot = await browserSessionDriver.inspect(driverOptions);
              } catch {
                await portalFlowStore.delete(flowKey).catch(() => undefined);
                await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
                await caseLedger.recordLifecycle(input.profileId, input.brokerId, "human_task_queued", {
                  evidenceKind: "human_task",
                  reason: "verified_portal_target_lost_after_restart",
                }).catch(() => undefined);
                const report = {
                  report_version: 1, subject_ref: input.profileId, broker_id: input.brokerId,
                  state: "human_task_queued", reason: "verified_portal_target_lost_after_restart",
                  verification_link_reopened: false, provider_writes: 0, raw_pii_in_report: false,
                };
                return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
              }
              const sessionId = `formsession_${randomBytes(12).toString("hex")}`;
              storeBrowserSession(sessionId, {
                sessionId, sessionType: "form", stage: "peopleconnect_guided_identity", targetId: flow.targetId,
                profileId: input.profileId, brokerId: input.brokerId, campaignId: input.campaignId,
                broker, values, fieldDisclosureMap, browserControl,
                recipeId: recipe.recipe_id, recipeDigest: currentRecipeDigest, recipePackDigest: currentRecipePackDigest,
                browserBackend: config?.browserBackendMode ?? "managed_openclaw",
                filledFields: [], recordSelected: false,
                effectConsumed: true, submissionIntentReserved: false, expiresAt: flow.expiresAt,
              });
              const recipeAssessment = await assessFormRecipeSession(sessionId, activeFormSession(sessionId), snapshot);
              const report = {
                report_version: 1, session_id: sessionId, subject_ref: input.profileId, broker_id: input.brokerId,
                method: "web_form", state: "guided_suppression_ready", snapshot,
                disclosures_allowed: disclosureFields, form_fields_available: Object.keys(fieldDisclosureMap),
                same_browser_profile_retained: true, resumed_from_encrypted_flow_state: true,
                recipe_policy: { recipe_id: recipe.recipe_id, recipe_digest: currentRecipeDigest, assessment: recipeAssessment.state },
                provider_reads: 1, provider_writes: 0, raw_pii_in_report: false,
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            const currentCase = (await caseLedger.load(input.profileId)).brokers?.[input.brokerId];
            if (["human_task_queued", "blocked"].includes(currentCase?.state)) {
              throw new Error("rightout_peopleconnect_manual_reconciliation_required");
            }
            if (["submitted", "verification_pending", "submission_pending", "submission_uncertain", "awaiting_processing"].includes(currentCase?.state)) {
              throw new Error("rightout_peopleconnect_verification_resume_required");
            }
          }
          const stage = broker.id === "intelius" ? "peopleconnect_email_entry" : "generic";
          const disclosureFields = stage === "peopleconnect_email_entry" ? ["contact_email"] : broker.disclosure_fields;
          if (disclosureFields.some((field: string) => typeof values[field] !== "string" || !values[field])) {
            throw new Error("rightout_form_profile_field_missing");
          }
          const fieldDisclosureMap = formFieldDisclosureMap(disclosureFields, values);
          await authorizeCampaignEffects(input.campaignId, input.profileId, [{ brokerId: input.brokerId, effect: "submit_form" }], coreCatalog, true);
          let opened;
          try {
            opened = await browserSessionDriver.openSession({
              ...browserControl,
              formUrl: broker.action_url,
              allowedDomains: broker.official_domains,
              allowedFields: Object.keys(fieldDisclosureMap),
              values,
              signal,
            });
          } catch {
            await caseLedger.recordLifecycle(input.profileId, input.brokerId, "blocked", {
              evidenceKind: "human_task",
              reason: "primary_browser_open_failed_after_effect_consumed",
            }).catch(() => undefined);
            const report = {
              report_version: 1, subject_ref: input.profileId, broker_id: input.brokerId,
              state: "blocked", reason: "primary_browser_open_failed_after_effect_consumed",
              effect_consumed: true, automatic_retry_allowed: false,
              provider_writes: 0, raw_pii_in_report: false,
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (["hard_human_gate", "access_blocked"].includes(opened.snapshot.challenge)) {
            await browserSessionDriver.closeSession({ ...browserControl, targetId: opened.targetId }).catch(() => undefined);
            await caseLedger.recordLifecycle(input.profileId, input.brokerId, "blocked", {
              evidenceKind: "human_task",
              reason: "primary_browser_access_blocked",
            }).catch(() => undefined);
            throw new Error(opened.snapshot.challenge === "access_blocked" ? "rightout_browser_access_blocked" : "rightout_form_human_gate_required");
          }
          const sessionId = `formsession_${randomBytes(12).toString("hex")}`;
          storeBrowserSession(sessionId, {
            sessionId,
            sessionType: "form",
            stage,
            targetId: opened.targetId,
            profileId: input.profileId,
            brokerId: input.brokerId,
            campaignId: input.campaignId,
            broker,
            recipeId: recipe.recipe_id,
            recipeDigest: currentRecipeDigest,
            recipePackDigest: currentRecipePackDigest,
            values,
            fieldDisclosureMap,
            browserControl,
            browserBackend: config?.browserBackendMode ?? "managed_openclaw",
            filledFields: [],
            consentAgreed: false,
            effectConsumed: true,
            submissionIntentReserved: false,
            expiresAt: Date.now() + 30 * 60_000,
          });
          const recipeAssessment = await assessFormRecipeSession(sessionId, activeFormSession(sessionId), opened.snapshot);
          const report = {
            report_version: 1,
            session_id: sessionId,
            subject_ref: input.profileId,
            broker_id: input.brokerId,
            method: "web_form",
            state: "form_session_ready",
            snapshot: opened.snapshot,
            disclosures_allowed: disclosureFields,
            flow_stage: stage,
            recipe_policy: { recipe_id: recipe.recipe_id, recipe_digest: currentRecipeDigest, assessment: recipeAssessment.state },
            form_fields_available: Object.keys(fieldDisclosureMap),
            provider_reads: 1,
            provider_writes: 0,
            raw_pii_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_begin_form_session", optional: true },
    );

    api.registerTool(
      {
        name: "rightout_form_session_step",
        label: "RightOut autonomous form step",
        description: "Inspect or perform one bounded action in an active parity form session. Profile values are selected only by catalog field name, never supplied by the model. Final submission requires the campaign scope and every required field.",
        parameters: FormSessionStepParameters,
        async execute(toolCallId, params, signal) {
          const input = validateFormSessionStepInput(params);
          pruneApprovalState();
          await pruneTransientState();
          const session = activeFormSession(input.sessionId);
          if (input.action.kind !== "close") {
            await revalidatePublisherBrowserSession(input.sessionId, session, "submit_form");
          }
          if (["fill_challenge", "fill_static_text_challenge"].includes(input.action.kind) && session.stage !== "generic") {
            throw new Error("rightout_form_session_input_invalid");
          }
          if (input.action.kind === "click") {
            const allowedPurposes = session.stage === "peopleconnect_email_entry"
              ? ["agree", "continue"]
              : session.stage === "peopleconnect_guided_identity"
                ? ["continue", "select_record", "suppress"]
                : ["continue", "agree", "select_record", "confirm", "submit"];
            if (!allowedPurposes.includes(input.action.purpose)) throw new Error("rightout_form_session_input_invalid");
          }
          const driverOptions = {
            ...session.browserControl,
            targetId: session.targetId,
            allowedDomains: session.broker.official_domains,
            allowedFields: Object.keys(session.fieldDisclosureMap),
            values: session.values,
            ...(session.stage === "peopleconnect_guided_identity" ? { privacyMode: "peopleconnect_guided" } : {}),
            beforeActionGuard: (snapshot: Record<string, any>) => assessFormRecipeSession(input.sessionId, session, snapshot),
            signal,
          };
          if (input.action.kind === "close") {
            await browserSessionDriver.closeSession(driverOptions);
            deleteBrowserSession(input.sessionId);
            const pendingProviderIntent = session.submissionIntentReserved === true;
            if (pendingProviderIntent) {
              await caseLedger.recordSubmissionUncertain(session.profileId, session.brokerId, {
                channel: "browser_form", reason: "form_session_closed_with_pending_provider_intent",
              }).catch(() => undefined);
            }
            if (session.stage === "peopleconnect_guided_identity") {
              await portalFlowStore.delete(portalFlowKey(session.profileId, session.brokerId));
              if (!pendingProviderIntent) {
                await caseLedger.recordLifecycle(session.profileId, session.brokerId, "human_task_queued", {
                  evidenceKind: "human_task", reason: "verified_portal_closed_before_suppression",
                });
              }
            }
            const report = {
              session_id: input.sessionId, broker_id: session.brokerId,
              state: pendingProviderIntent ? "submission_uncertain"
                : session.stage === "peopleconnect_guided_identity" ? "human_task_queued" : "form_session_closed",
              ...(pendingProviderIntent
                ? { reason: "pending_provider_intent_requires_reconciliation", next_action: "rightout_reconcile_submission" }
                : session.stage === "peopleconnect_guided_identity" ? { reason: "verified_portal_closed_before_suppression" } : {}),
              provider_writes_possible: pendingProviderIntent,
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (input.action.kind === "inspect") {
            const snapshot = await browserSessionDriver.inspect(driverOptions);
            const recipeAssessment = await assessFormRecipeSession(input.sessionId, session, snapshot);
            const report = {
              session_id: input.sessionId,
              broker_id: session.brokerId,
              state: "form_session_active",
              snapshot,
              recipe_policy: { recipe_id: session.recipeId, assessment: recipeAssessment.state },
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (input.action.kind === "record_redacted_state_receipt") {
            const receipt = await browserSessionDriver.redactedStateReceipt(driverOptions);
            const report = { session_id: input.sessionId, broker_id: session.brokerId, state: "redacted_state_receipt_recorded", ...receipt };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (input.action.kind === "fill") {
            const disclosures = (input.action.fields ?? []).map((field: Record<string, any>) => session.fieldDisclosureMap[field.profile_field]).filter(Boolean);
            if (disclosures.includes("date_of_birth")) {
              const approval = approvalBindings.get(toolCallId);
              approvalBindings.delete(toolCallId);
              if (
                !approval || approval.toolName !== "rightout_form_session_step"
                || approval.binding !== sensitiveFormStepScopeBinding(session, input)
              ) throw new Error("rightout_form_sensitive_field_human_gate");
            }
          }
          const initialVerificationRequest = session.stage === "peopleconnect_email_entry"
            && input.action.kind === "click" && input.action.purpose === "continue";
          const finalSuppression = session.stage === "peopleconnect_guided_identity"
            && input.action.kind === "click" && input.action.purpose === "suppress";
          const finalSubmit = session.stage === "generic"
            && input.action.kind === "click" && input.action.purpose === "submit";
          if (session.stage === "peopleconnect_email_entry" && input.action.kind === "click" && input.action.purpose === "submit") {
            throw new Error("rightout_peopleconnect_email_continue_required");
          }
          if (session.stage === "peopleconnect_guided_identity" && input.action.kind === "click" && input.action.purpose === "submit") {
            throw new Error("rightout_peopleconnect_suppression_control_required");
          }
          let dedupeKey = session.submissionDedupeKey as string | undefined;
          let submissionReserved = session.submissionIntentReserved === true;
          let reservedThisAction = false;
          const removalInput: PublicRemovalInput = { profileId: session.profileId, brokerId: session.brokerId, requestKind: "delete_and_opt_out" };
          const peopleConnectProviderClick = session.stage === "peopleconnect_email_entry" && input.action.kind === "click";
          const genericProviderClick = session.stage === "generic" && input.action.kind === "click";
          const guidedProviderClick = session.stage === "peopleconnect_guided_identity" && input.action.kind === "click"
            && ["continue", "suppress"].includes(input.action.purpose);
          if (initialVerificationRequest && session.consentAgreed !== true) throw new Error("rightout_peopleconnect_consent_required");
          if (peopleConnectProviderClick || finalSubmit) {
            const required = peopleConnectProviderClick ? ["contact_email"] : session.broker.disclosure_fields;
            if (required.some((field: string) => !session.filledFields.includes(field))) {
              throw new Error("rightout_form_required_fields_not_filled");
            }
          }
          if (finalSuppression || guidedProviderClick) {
            if (!["full_name", "date_of_birth"].every((field) => session.filledFields.includes(field))) {
              throw new Error("rightout_form_required_fields_not_filled");
            }
          }
          if (finalSuppression && session.recordSelected !== true) throw new Error("rightout_peopleconnect_record_not_corroborated");
          if ((peopleConnectProviderClick || genericProviderClick) && !submissionReserved) {
            dedupeKey = removalDedupeKey(removalInput);
            await acquireSubmissionDedupe(dedupeKey, removalInput, "browser_form");
            try {
              await caseLedger.reserveSubmission(session.profileId, session.brokerId, {
                channel: "browser_form",
                discoveryRequirement: "not_required_for_data_subject_request",
              });
              await markSubmissionDedupeIntentReserved(dedupeKey, removalInput, "browser_form");
              submissionReserved = true;
              reservedThisAction = true;
              session.submissionIntentReserved = true;
              session.submissionDedupeKey = dedupeKey;
            } catch (error) {
              await submissionDedupe.delete(dedupeKey);
              throw error;
            }
          } else if (guidedProviderClick && !submissionReserved) {
            dedupeKey = removalDedupeKey(removalInput);
            const existing = await submissionDedupe.lookup(dedupeKey);
            if (!existing || existing.phase !== "identity_portal_verification_requested") throw new Error("rightout_peopleconnect_flow_state_invalid");
            await caseLedger.reserveVerifiedPortalSubmission(session.profileId, session.brokerId);
            await submissionDedupe.register(dedupeKey, {
              createdAt: new Date().toISOString(), channel: "browser_form", profileId: session.profileId,
              brokerId: session.brokerId, phase: "durable_verified_portal_suppression_intent",
            });
            submissionReserved = true;
            reservedThisAction = true;
            session.submissionIntentReserved = true;
            session.submissionDedupeKey = dedupeKey;
          }
          try {
            const snapshot = await browserSessionDriver.act({ ...driverOptions, action: input.action });
            await assessFormRecipeSession(input.sessionId, session, snapshot);
            if (input.action.kind === "fill") {
              for (const field of input.action.fields ?? []) {
                const disclosure = session.fieldDisclosureMap[field.profile_field];
                if (disclosure) session.filledFields.push(disclosure);
              }
              session.filledFields = [...new Set(session.filledFields)];
            }
            if (session.stage === "peopleconnect_guided_identity" && input.action.kind === "click" && input.action.purpose === "select_record") {
              session.recordSelected = true;
            }
            if (session.stage === "peopleconnect_email_entry" && input.action.kind === "click" && input.action.purpose === "agree") {
              if (!snapshot.refs.some((item: Record<string, any>) => item.ref === input.action.ref && item.checked === true)) {
                throw new Error("rightout_peopleconnect_consent_unconfirmed");
              }
              session.consentAgreed = true;
            }
            const genericSuccessObserved = session.stage === "generic" && input.action.kind === "click"
              && snapshot.observed_transitions?.includes("submission_success_observed");
            if (genericSuccessObserved && session.broker.disclosure_fields.some((field: string) => !session.filledFields.includes(field))) {
              throw new Error("rightout_form_required_fields_not_filled_after_provider_action");
            }
            const completedGeneric = finalSubmit || genericSuccessObserved;
            if (!completedGeneric && !initialVerificationRequest && !finalSuppression) {
              const report = {
                session_id: input.sessionId, broker_id: session.brokerId,
                state: session.stage === "peopleconnect_guided_identity" ? "guided_suppression_active" : "form_session_active",
                snapshot, record_corroborated: session.recordSelected === true,
                durable_provider_intent: submissionReserved,
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            const confirmed = initialVerificationRequest
              ? snapshot.observed_transitions?.includes("verification_email_requested_observed")
              : finalSuppression
                ? snapshot.observed_transitions?.includes("suppression_success_observed")
                : snapshot.observed_transitions?.includes("submission_success_observed");
            if (!confirmed) throw new Error(finalSuppression ? "rightout_peopleconnect_suppression_unconfirmed" : "rightout_form_submission_unconfirmed");
            const receipt = await browserSessionDriver.redactedStateReceipt(driverOptions);
            const generatedAt = new Date().toISOString();
            const formProofReference = `form_${createHash("sha256")
              .update(JSON.stringify([session.sessionId, session.brokerId, generatedAt, initialVerificationRequest, finalSuppression]))
              .digest("hex").slice(0, 24)}`;
            if (initialVerificationRequest) {
              const report = {
                report_version: 1, subject_ref: session.profileId, broker_id: session.brokerId,
                state: "verification_pending", generated_at: generatedAt,
                delivery: { channel: "openclaw_browser_profile", verification_email_requested: true, removal_confirmed: false },
                disclosures: { to_broker: ["contact_email"], values_in_report: false, identity_documents: 0 },
                proof_references: [formProofReference, receipt.receipt_reference], redacted_state_receipt: receipt, campaign_id: session.campaignId,
                next_action: "open_authenticated_current_submission_message_in_same_browser_profile",
                raw_pii_in_report: false,
              };
              await caseLedger.recordVerificationRequested(report);
              await submissionDedupe.register(dedupeKey, {
                createdAt: generatedAt, channel: "browser_form", profileId: session.profileId,
                brokerId: session.brokerId, phase: "identity_portal_verification_requested",
              });
              await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
              deleteBrowserSession(input.sessionId);
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            if (finalSuppression) {
              const report = {
                report_version: 1, subject_ref: session.profileId, broker_id: session.brokerId,
                state: "awaiting_processing", generated_at: generatedAt,
                delivery: { channel: "openclaw_browser_profile", form_submitted: true, suppression_selected: true, removal_confirmed: false },
                disclosures: { to_broker: ["full_name", "date_of_birth"], values_in_report: false, identity_documents: 0 },
                proof_references: [formProofReference, receipt.receipt_reference], redacted_state_receipt: receipt, campaign_id: session.campaignId,
                provider_control_verified: "suppressed", delete_control_used: false, raw_pii_in_report: false,
              };
              await caseLedger.recordSuppressionSubmission(report);
              await portalFlowStore.delete(portalFlowKey(session.profileId, session.brokerId));
              await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
              deleteBrowserSession(input.sessionId);
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            const report = {
              report_version: 1,
              subject_ref: session.profileId,
              broker_id: session.brokerId,
              state: "verification_pending",
              generated_at: generatedAt,
              delivery: { channel: "openclaw_browser_profile", form_submitted: true, removal_confirmed: false },
              disclosures: { to_broker: session.broker.disclosure_fields, values_in_report: false, identity_documents: 0 },
              proof_references: [formProofReference, receipt.receipt_reference],
              redacted_state_receipt: receipt,
              campaign_id: session.campaignId,
              raw_pii_in_report: false,
            };
            await caseLedger.recordFormSubmission(report);
            await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
            deleteBrowserSession(input.sessionId);
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          } catch (error) {
            if (submissionReserved) {
              const code = error instanceof Error ? error.message : "rightout_form_failed";
              const definitelyNotStarted = new Set([
                "rightout_form_ref_invalid", "rightout_form_action_not_allowed", "rightout_form_human_gate_required",
                "rightout_form_domain_mismatch", "rightout_form_target_invalid", "rightout_form_action_ambiguous",
                "rightout_form_field_target_mismatch", "rightout_form_field_target_ambiguous",
                "rightout_form_field_mapping_ambiguous", "rightout_form_field_type_mismatch",
                "rightout_form_record_not_corroborated", "rightout_form_record_ambiguous",
              ]).has(code);
              if (definitelyNotStarted && reservedThisAction && session.stage !== "peopleconnect_guided_identity") {
                await caseLedger.releaseSubmission(session.profileId, session.brokerId, code).catch(() => undefined);
                if (dedupeKey) await submissionDedupe.delete(dedupeKey);
                session.submissionIntentReserved = false;
                delete session.submissionDedupeKey;
              } else if (!definitelyNotStarted) {
                await caseLedger.recordSubmissionUncertain(session.profileId, session.brokerId, { channel: "browser_form", reason: code })
                  .catch(() => undefined);
                if (session.stage === "peopleconnect_guided_identity") {
                  await portalFlowStore.delete(portalFlowKey(session.profileId, session.brokerId));
                }
                await browserSessionDriver.closeSession(driverOptions).catch(() => undefined);
                deleteBrowserSession(input.sessionId);
              }
            }
            throw error;
          }
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_start_campaign",
        label: "RightOut start autonomous campaign",
        description: "Create a finite, revocable standing authorization for an exact subject, broker set, effect set, lifetime, and effect budget. One native allow-once approval starts the campaign; subsequent in-scope effects can run without per-effect prompts.",
        parameters: CampaignStartParameters,
        async execute(toolCallId, params) {
          let input: PublicCampaignStartInput;
          try { input = validateCampaignStartInput(params) as PublicCampaignStartInput; }
          catch { throw new Error("rightout_approval_binding_failed"); }
          await assertAutonomousCampaignScope(input);
          const digest = await campaignCatalogDigestPromise;
          const config = api.pluginConfig as RightOutConfig | undefined;
          const routingScope = browserApprovalRoutingScope(config, {
            browserRequired: input.effects.some((effect) => ["publisher_discover", "submit_form"].includes(effect))
              || (input.effects.includes("open_verification") && input.brokerIds.includes("intelius")),
            effects: input.effects,
          });
          await assertCampaignPublisherPermissions(input, routingScope);
          pruneApprovalState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !approval || approval.toolName !== "rightout_start_campaign"
            || approval.binding !== campaignScopeBinding(input, digest, routingScope.routingDigest)
          ) throw new Error("rightout_approval_binding_failed");
          assertConfiguredProfile(input.profileId);
          const profilePayload = (api.pluginConfig as RightOutConfig).profiles![input.profileId].payload;
          if (input.effects.includes("discover")) scanProfileDigest(profilePayload);
          if (input.effects.some((effect) => effect !== "discover")) parseRemovalProfile(profilePayload);
          const profileDigest = await ensureImmutableProfileSnapshot(input.profileId);
          const runtimeScopeDigest = configuredRuntimeScopeDigest();
          const report = await campaignLedger.start(input, { catalogDigest: digest, profileDigest, runtimeScopeDigest });
          const details = {
            report_version: 1,
            ...report,
            approval_boundary: "native_openclaw_allow_once_bounded_standing_authorization",
            scope_widening_allowed: false,
            raw_pii_in_report: false,
            next_action: "call_rightout_campaign_next_then_execute_only_the_returned_campaign_scoped_command_until_done_for_now",
          };
          return { content: [{ type: "text", text: JSON.stringify(details) }], details };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_campaign_status",
        label: "RightOut campaign status",
        description: "Read one PII-safe autonomous campaign grant, remaining effect budget, expiry, and revocation state. Performs no provider request or write.",
        parameters: CampaignRefParameters,
        async execute(_toolCallId, params) {
          const input = validateCampaignRef(params) as PublicCampaignRefInput;
          const report = await campaignLedger.status(input.campaignId);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    async function campaignNextReport(toolContext: Record<string, any>, campaignId: string): Promise<Record<string, any>> {
      await pruneTransientState();
      const initial = await campaignLedger.status(campaignId);
      if (initial.status !== "active") {
        return {
          report_version: 1,
          campaign_id: campaignId,
          state: initial.status === "completed" ? "campaign_completed" : "campaign_revoked",
          terminal: true,
          reason: initial.status === "completed" ? "effect_budget_exhausted" : "standing_authorization_revoked",
          used_effects: initial.used_effects,
          max_effects: initial.max_effects,
          remaining_effects: initial.remaining_effects,
          next_action: initial.status === "completed"
            ? "review_outcomes_and_start_a_new_separately_approved_campaign_only_if_needed"
            : "none",
          deterministic_next_loop: true,
          provider_reads: 0,
          provider_writes: 0,
          raw_pii_in_report: false,
        };
      }
      const profileDigest = await ensureImmutableProfileSnapshot(initial.subject_ref);
      const campaign = await campaignLedger.assertScope(campaignId, {
        profileId: initial.subject_ref,
        profileDigest,
        runtimeScopeDigest: configuredRuntimeScopeDigest(),
      });
      const [caseStatus, parity, core] = await Promise.all([
        caseLedger.status(campaign.subject_ref),
        parityCatalogPromise,
        catalogPromise,
      ]);
      const config = api.pluginConfig as RightOutConfig | undefined;
      const browser = resolveBrowserBackend(toolContext, config);
      const emailMode = config?.smtpTransport ? "smtp" : browser.webmail_ready ? "webmail" : "unavailable";
      const verificationMode = config?.imapTransport ? "imap"
        : browserVerificationTransportReady(config, browser) ? "browser_webmail" : "unavailable";
      const globalScanOnly = campaign.effects.length === 1 && campaign.effects[0] === "discover";
      let planned = globalScanOnly
        ? planGlobalScanCampaignNext({ campaign, caseStatus, scanCatalog: await combinedScanCatalog() })
        : planParityCampaignNext({
          campaign, caseStatus, parityCatalog: parity, coreCatalog: core,
          emailMode, verificationMode, browserMode: browser.selected,
          remoteCloudRetryAvailable: browser.remote_cloud_fallback_ready,
        });
      for (const brokerId of campaign.broker_ids) {
        const flow = await portalFlowStore.lookup(portalFlowKey(campaign.subject_ref, brokerId)) as Record<string, any> | undefined;
        if (
          flow?.campaignId === campaignId && flow.stage === "peopleconnect_guided_identity"
          && Number.isFinite(flow.expiresAt) && flow.expiresAt > Date.now()
        ) {
          planned = {
            state: "action_ready",
            command: {
              kind: "execute_tool",
              tool: "rightout_begin_form_session",
              parameters: { profileId: campaign.subject_ref, brokerId, campaignId },
              reason: "resume_same_browser_profile_verified_portal_from_encrypted_flow_state",
            },
          } as any;
          break;
        }
      }
      return {
        report_version: 1,
        campaign_id: campaignId,
        ...planned,
        selected_email_mode: emailMode,
        selected_verification_mode: verificationMode,
        selected_browser_mode: browser.selected,
        remote_cloud_retry_available: browser.remote_cloud_fallback_ready,
        deterministic_next_loop: true,
        provider_reads: 0,
        provider_writes: 0,
        raw_pii_in_report: false,
      };
    }

    api.registerTool(
      (toolContext) => ({
        name: "rightout_campaign_next",
        label: "RightOut campaign next",
        description: "Return exactly one deterministic in-scope RightOut command, human/source gate, or done-for-now digest for an active autonomous campaign. Performs no network request or provider write.",
        parameters: CampaignNextParameters,
        async execute(_toolCallId, params) {
          const input = validateCampaignRef(params) as PublicCampaignRefInput;
          const report = await campaignNextReport(toolContext as Record<string, any>, input.campaignId);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_campaign_next", optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_worker_enable",
        label: "RightOut enable durable worker",
        description: "Bind one active finite campaign to this exact trusted OpenClaw session and schedule durable one-action-at-a-time turns. Requires native allow-once approval; recipe, runtime, or session drift stops execution.",
        parameters: WorkerEnableParameters,
        async execute(toolCallId, params) {
          let input: PublicWorkerEnableInput;
          try { input = validateWorkerEnableInput(params); }
          catch { throw new Error("rightout_approval_binding_failed"); }
          const campaign = await campaignLedger.status(input.campaignId);
          if (campaign.status !== "active") throw new Error("rightout_worker_campaign_invalid");
          const profileDigest = await ensureImmutableProfileSnapshot(campaign.subject_ref);
          await campaignLedger.assertScope(campaign.campaign_id, {
            profileId: campaign.subject_ref,
            profileDigest,
            runtimeScopeDigest: configuredRuntimeScopeDigest(),
          });
          const session = trustedWorkerSession(toolContext as Record<string, any>);
          const policyDigest = await currentWorkerPolicyDigest();
          pruneApprovalState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !approval || approval.toolName !== "rightout_worker_enable"
            || approval.binding !== workerEnableScopeBinding(input, policyDigest, session.sessionBindingDigest)
          ) throw new Error("rightout_approval_binding_failed");
          const worker = await workerLedger.create(input, {
            campaign,
            policyDigest,
            sessionBindingDigest: session.sessionBindingDigest,
            session: { sessionKey: session.sessionKey, agentId: session.agentId },
          });
          const scheduler = await scheduleWorkerTurn(toolContext as Record<string, any>, worker.worker_id, 1_000);
          const report = {
            report_version: 1,
            ...worker,
            recipe_pack_digest: (await loadRecipePack()).recipe_digest,
            durable_encrypted_state: true,
            one_action_per_lease: true,
            scope_widening_allowed: false,
            ...scheduler,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_worker_enable", optional: true },
    );

    api.registerTool(
      {
        name: "rightout_worker_status",
        label: "RightOut worker status",
        description: "Read one PII-safe durable worker checkpoint, failure budget, next wake, and unresolved-action state. Performs no network request or provider write.",
        parameters: WorkerRefParameters,
        async execute(_toolCallId, params) {
          const input = validateWorkerRefInput(params);
          const report = await workerLedger.status(input.workerId);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_worker_tick",
        label: "RightOut worker tick",
        description: "Claim one durable lease and return exactly one campaign-scoped allowlisted command, gate, or checkpoint. It performs no provider request or write itself and runs only in the originally bound trusted session.",
        parameters: WorkerRefParameters,
        async execute(_toolCallId, params) {
          const input = validateWorkerRefInput(params);
          const context = await workerExecutionContext(input.workerId, toolContext as Record<string, any>);
          const claim = await workerLedger.claim(input.workerId, {
            campaign: context.campaign,
            policyDigest: context.policyDigest,
            sessionBindingDigest: context.sessionBindingDigest,
          }) as unknown as Record<string, any>;
          if (claim.state === "not_due") {
            const wakeAt = Date.parse(claim.worker.next_wake_at);
            const scheduler = await scheduleWorkerTurn(toolContext as Record<string, any>, input.workerId, Math.max(1_000, wakeAt - Date.now()));
            const report = { report_version: 1, ...claim, ...scheduler };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (claim.state !== "claimed") {
            const report = { report_version: 1, ...claim, raw_pii_in_report: false };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          const planned = await campaignNextReport(toolContext as Record<string, any>, context.campaign.campaign_id);
          const safeReason = typeof planned.reason === "string" && /^[a-z0-9_]{3,120}$/.test(planned.reason)
            ? planned.reason
            : "campaign_human_gate";
          if (planned.state === "action_ready") {
            if (interactiveWorkerTools.has(planned.command?.tool)) {
              const completed = await workerLedger.complete(input.workerId, claim.lease_id, {
                outcome: "human_gate",
                reason: "interactive_session_requires_operator_continuation",
              }) as unknown as Record<string, any>;
              const report = {
                report_version: 1,
                ...completed,
                deferred_command_tool: planned.command.tool,
                provider_reads: 0,
                provider_writes: 0,
                raw_pii_in_report: false,
              };
              return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            }
            const baseline = await campaignLedger.status(context.campaign.campaign_id);
            const issued = await workerLedger.issue(input.workerId, claim.lease_id, planned.command, {
              campaignUsedEffects: baseline.used_effects,
              campaignLastEffectReference: baseline.last_effect_reference,
            }) as unknown as Record<string, any>;
            const watchdog = await scheduleWorkerTurn(
              toolContext as Record<string, any>,
              input.workerId,
              Math.max(1_000, Date.parse(claim.lease_expires_at) - Date.now() + 1_000),
            );
            const report = {
              report_version: 1,
              ...issued,
              recipe_pack_digest: (await loadRecipePack()).recipe_digest,
              lease_watchdog_registered: watchdog.scheduled_job_registered === true,
              ...watchdog,
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          const deferredHumanGates = Number(planned.consolidated_digest?.human_gates ?? 0);
          if (planned.state === "human_gate" || deferredHumanGates > 0) {
            const completed = await workerLedger.complete(input.workerId, claim.lease_id, {
              outcome: "human_gate",
              reason: planned.state === "human_gate" ? safeReason : "deferred_human_gates_present",
            }) as unknown as Record<string, any>;
            const report = {
              report_version: 1,
              ...completed,
              campaign_state: planned.state,
              deferred_human_gate_count: deferredHumanGates,
              raw_pii_in_report: false,
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          if (planned.state !== "done_for_now" && !planned.terminal) throw new Error("rightout_worker_plan_invalid");
          const nextWakeAt = typeof planned.next_wake_at === "string" ? planned.next_wake_at : null;
          const completed = await workerLedger.complete(input.workerId, claim.lease_id, {
            outcome: "done_for_now",
            nextWakeAt,
            reason: planned.terminal ? "campaign_terminal" : "done_for_now",
          }) as unknown as Record<string, any>;
          const scheduler = completed.state === "active" && completed.worker.next_wake_at
            ? await scheduleWorkerTurn(
              toolContext as Record<string, any>,
              input.workerId,
              Math.max(1_000, Date.parse(completed.worker.next_wake_at) - Date.now()),
            )
            : { scheduler_state: "not_scheduled_terminal" };
          const report = { report_version: 1, ...completed, ...scheduler, raw_pii_in_report: false };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_worker_tick", optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_worker_complete",
        label: "RightOut complete worker lease",
        description: "Complete one claimed worker lease. Success requires a newly consumed campaign effect; an observed effect paired with a reported failure becomes a non-retrying human gate.",
        parameters: WorkerCompleteParameters,
        async execute(_toolCallId, params) {
          const input = validateWorkerCompleteInput(params);
          const context = await workerExecutionContext(input.workerId, toolContext as Record<string, any>);
          const pending = await workerLedger.pending(input.workerId, input.leaseId);
          const receipt = pending.execution_receipt;
          const exactCommandCompleted = receipt?.state === "completed" && receipt.executionDigest === pending.execution_digest;
          if (input.outcome === "action_succeeded" && !exactCommandCompleted) throw new Error("rightout_worker_success_evidence_missing");
          const receiptRequiresHuman = receipt?.state === "human_gate" || (input.outcome !== "action_succeeded" && exactCommandCompleted);
          const outcome = receiptRequiresHuman ? "human_gate" : input.outcome;
          const reason = receipt?.state === "human_gate"
            ? `exact_command_${receipt.resultState}`.slice(0, 120)
            : input.outcome !== "action_succeeded" && exactCommandCompleted
              ? "exact_command_completed_outcome_uncertain"
              : input.reason;
          const completed = await workerLedger.complete(input.workerId, input.leaseId, { outcome, ...(reason ? { reason } : {}) }) as unknown as Record<string, any>;
          const scheduler = completed.state === "active" && completed.worker.next_wake_at
            ? await scheduleWorkerTurn(
              toolContext as Record<string, any>,
              input.workerId,
              Math.max(1_000, Date.parse(completed.worker.next_wake_at) - Date.now()),
            )
            : { scheduler_state: "not_scheduled_gate_or_terminal" };
          const report = {
            report_version: 1,
            ...completed,
            exact_command_receipt_observed: Boolean(receipt),
            exact_command_completed: exactCommandCompleted,
            completion_evidence: exactCommandCompleted ? "host_observed_exact_terminal_tool_result" : "no_exact_terminal_tool_result",
            policy_digest_current: context.policyDigest === await currentWorkerPolicyDigest(),
            ...scheduler,
            raw_pii_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_worker_complete", optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_worker_resume",
        label: "RightOut resume worker",
        description: "Resume a gated durable worker only in its original trusted session and unchanged campaign, runtime, catalog, and signed-recipe scope. Requires native allow-once approval.",
        parameters: WorkerRefParameters,
        async execute(toolCallId, params) {
          let input: PublicWorkerRefInput;
          try { input = validateWorkerRefInput(params); }
          catch { throw new Error("rightout_approval_binding_failed"); }
          const context = await workerExecutionContext(input.workerId, toolContext as Record<string, any>);
          if (context.campaign.status !== "active") throw new Error("rightout_worker_campaign_invalid");
          pruneApprovalState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !approval || approval.toolName !== "rightout_worker_resume"
            || approval.binding !== workerResumeScopeBinding(input, context.policyDigest, context.sessionBindingDigest)
          ) throw new Error("rightout_approval_binding_failed");
          const worker = await workerLedger.resume(input.workerId, {
            campaign: context.campaign,
            policyDigest: context.policyDigest,
            sessionBindingDigest: context.sessionBindingDigest,
          }) as unknown as Record<string, any>;
          const scheduler = await scheduleWorkerTurn(toolContext as Record<string, any>, input.workerId, 1_000);
          const report = { report_version: 1, ...worker, ...scheduler, raw_pii_in_report: false };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_worker_resume", optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_worker_revoke",
        label: "RightOut revoke worker",
        description: "Immediately revoke one durable worker. This can only reduce authority, performs no provider request, and leaves its finite campaign separately revocable.",
        parameters: WorkerRefParameters,
        async execute(_toolCallId, params) {
          const input = validateWorkerRefInput(params);
          const worker = await workerLedger.revoke(input.workerId) as unknown as Record<string, any>;
          let scheduler = { removed: 0, failed: 0 };
          try {
            const session = trustedWorkerSession(toolContext as Record<string, any>);
            scheduler = await api.session.workflow.unscheduleSessionTurnsByTag({
              sessionKey: session.sessionKey,
              tag: `rightout-worker-${input.workerId.slice("worker_".length)}`,
            });
          } catch { /* a queued turn remains harmless because the worker is revoked */ }
          const report = {
            report_version: 1,
            ...worker,
            scheduler_cleanup: scheduler,
            campaign_revoked: false,
            provider_reads: 0,
            provider_writes: 0,
            raw_pii_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_worker_revoke", optional: true },
    );

    api.registerTool(
      {
        name: "rightout_revoke_campaign",
        label: "RightOut revoke autonomous campaign",
        description: "Permanently revoke one bounded standing authorization so it cannot authorize further provider effects. Requires native allow-once approval and performs no provider request.",
        parameters: CampaignRefParameters,
        async execute(toolCallId, params) {
          let input: PublicCampaignRefInput;
          try { input = validateCampaignRef(params) as PublicCampaignRefInput; }
          catch { throw new Error("rightout_approval_binding_failed"); }
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !approval || approval.toolName !== "rightout_revoke_campaign"
            || approval.binding !== campaignRevokeScopeBinding(input)
          ) throw new Error("rightout_approval_binding_failed");
          const report = await campaignLedger.revoke(input.campaignId);
          const activeSessionsInvalidated = await invalidateBrowserSessions((session) => session.campaignId === input.campaignId);
          const portalFlowsInvalidated = await invalidatePortalFlows((flow) => flow.campaignId === input.campaignId);
          const details = {
            ...(report as unknown as Record<string, unknown>),
            active_sessions_invalidated: activeSessionsInvalidated.invalidated,
            webmail_drafts_discarded: activeSessionsInvalidated.drafts_discarded,
            webmail_drafts_needing_manual_cleanup: activeSessionsInvalidated.drafts_needing_manual_cleanup,
            form_provider_intents_marked_uncertain: activeSessionsInvalidated.provider_intents_marked_uncertain,
            form_provider_intents_needing_manual_reconciliation: activeSessionsInvalidated.provider_intents_needing_manual_reconciliation,
            browser_tabs_closed: activeSessionsInvalidated.tabs_closed,
            browser_tabs_needing_manual_cleanup: activeSessionsInvalidated.tabs_needing_manual_cleanup,
            verified_portal_flows_invalidated: portalFlowsInvalidated,
          };
          return { content: [{ type: "text", text: JSON.stringify(details) }], details };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_next_actions",
        label: "RightOut next actions",
        description: "Plan deterministic next actions for one opaque subject reference from the clean-room catalog and PII-safe durable case ledger. Performs no network request or provider write.",
        parameters: CaseParameters,
        async execute(_toolCallId, params) {
          const input = validateCaseInput(params);
          assertConfiguredProfile(input.profileId);
          await ensureImmutableProfileSnapshot(input.profileId);
          const catalog = await catalogPromise;
          const report = await caseLedger.plan(input.profileId, catalog);
          const health = catalogPolicyHealth(catalog);
          const enriched = {
            ...report,
            policy_health: health.summary,
            live_provider_io_allowed: health.live_provider_io_allowed,
            policy_next_action: health.next_action,
          };
          return { content: [{ type: "text", text: JSON.stringify(enriched) }], details: enriched };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_case_status",
        label: "RightOut case status",
        description: "Read the PII-safe durable case status for one opaque subject reference. Performs no network request or provider write.",
        parameters: CaseParameters,
        async execute(_toolCallId, params) {
          const input = validateCaseInput(params);
          assertConfiguredProfile(input.profileId);
          await ensureImmutableProfileSnapshot(input.profileId);
          const report = await caseLedger.status(input.profileId);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_export_report",
        label: "RightOut export status report",
        description: "Export one subject's PII-safe durable status as Markdown, structured JSON, and Google Sheets-compatible rows. Performs no network request or provider write.",
        parameters: CaseParameters,
        async execute(_toolCallId, params) {
          const input = validateCaseInput(params);
          assertConfiguredProfile(input.profileId);
          await ensureImmutableProfileSnapshot(input.profileId);
          const report = createReportExport(await caseLedger.status(input.profileId));
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_refresh_registries",
        label: "RightOut refresh official registries",
        description: "Fetch the newest complete California data-broker registry from the official CPPA source, validate and encrypt it locally, and surface official Vermont, Oregon, and Texas registry portals. Uses no subject data and performs no provider write.",
        parameters: EmptyParameters,
        async execute(toolCallId, params, signal) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length !== 0) {
            throw new Error("rightout_registry_refresh_input_invalid");
          }
          pruneApprovalState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_refresh_registries" || approval.binding !== registryRefreshScopeBinding()) {
            throw new Error("rightout_approval_binding_failed");
          }
          const config = api.pluginConfig as RightOutConfig | undefined;
          if (!stateEncryptionReady(config)) throw new Error("rightout_not_configured");
          let snapshot;
          let providerReadAttempts = 0;
          const currentYear = new Date().getUTCFullYear();
          for (let year = currentYear; year >= 2025; year -= 1) {
            const url = `https://cppa.ca.gov/data_broker_registry/registry${year}.csv`;
            let request;
            try {
              providerReadAttempts += 1;
              request = await fetchWithSsrFGuard({
                url,
                fetchImpl: globalThis.fetch,
                requireHttps: true,
                capture: false,
                timeoutMs: 60_000,
                maxRedirects: 0,
                signal,
                policy: buildHostnameAllowlistPolicyFromSuffixAllowlist(["cppa.ca.gov"]),
                auditContext: "rightout_refresh_registries",
                init: { method: "GET", redirect: "manual", headers: { Accept: "text/csv" } },
              });
              if (!request.response.ok) continue;
              const text = await readBoundedText(request.response);
              snapshot = parseCaliforniaRegistryCsv(text, { sourceUrl: url });
              break;
            } catch (error) {
              if (signal?.aborted) throw new Error("rightout_registry_refresh_cancelled");
              if (year === 2025) throw new Error("rightout_registry_refresh_failed");
            } finally {
              await request?.release?.();
            }
          }
          if (!snapshot) throw new Error("rightout_registry_refresh_failed");
          await saveRegistrySnapshot(snapshot);
          const report = {
            ...registrySummary(snapshot),
            state: "official_registry_refreshed",
            encrypted_local_snapshot: true,
            provider_reads: providerReadAttempts,
            provider_read_attempts: providerReadAttempts,
            successful_sources: 1,
            provider_writes: 0,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_registry_status",
        label: "RightOut registry status",
        description: "Read the PII-safe status and official portal coverage of the encrypted registry snapshot. Performs no network request.",
        parameters: EmptyParameters,
        async execute(_toolCallId, params) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length !== 0) {
            throw new Error("rightout_registry_status_input_invalid");
          }
          const report = await registryMeta();
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_record_drop_filed",
        label: "RightOut record California DROP filed",
        description: "Record an operator-verified California DROP filing as one durable registry-wide case. Requires native allow-once approval; performs no portal action and never automates state identity verification.",
        parameters: CaseParameters,
        async execute(toolCallId, params) {
          const input = validateCaseInput(params);
          const config = api.pluginConfig as RightOutConfig | undefined;
          assertConfiguredProfile(input.profileId);
          await ensureImmutableProfileSnapshot(input.profileId);
          const profile = parseRemovalProfile(config!.profiles![input.profileId].payload);
          if (!profile.jurisdictions.includes("US-CA")) throw new Error("rightout_drop_ineligible");
          const registry = await registryMeta();
          if (registry.state !== "registry_ready" || !Number.isInteger(registry.record_count) || registry.record_count < 1) throw new Error("rightout_drop_registry_invalid");
          await pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_record_drop_filed" || approval.binding !== dropFiledScopeBinding(input.profileId, registry.record_count)) {
            throw new Error("rightout_approval_binding_failed");
          }
          const outcome = await caseLedger.recordDropFiled(input.profileId, {
            registryCount: registry.record_count,
            processingStart: "2026-08-01T00:00:00.000Z",
          });
          const report = {
            report_version: 1, subject_ref: input.profileId, broker_id: "ca_drop", state: outcome.state,
            registry_scope: registry.record_count, proof_references: [outcome.proof_reference], next_recheck_at: outcome.next_recheck_at,
            portal_action_performed_by_rightout: false, human_identity_verification_required: true,
            coverage_gap: "nonregistered_brokers_and_fcra_exceptions_not_covered", provider_reads: 0, provider_writes: 0, raw_pii_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_registry_search",
        label: "RightOut registry search",
        description: "Search the encrypted official California registry snapshot by public broker/company name or domain and return PII-safe controller routing metadata.",
        parameters: RegistrySearchParameters,
        async execute(_toolCallId, params) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).some((key) => !["query", "limit"].includes(key))) {
            throw new Error("rightout_registry_search_input_invalid");
          }
          const value = params as Record<string, unknown>;
          const query = typeof value.query === "string" ? value.query.trim().toLowerCase() : "";
          const limitValue = value.limit === undefined ? 20 : value.limit;
          if (!/^[a-z0-9 .&'_-]{2,80}$/i.test(query) || typeof limitValue !== "number" || !Number.isInteger(limitValue) || limitValue < 1 || limitValue > 50) {
            throw new Error("rightout_registry_search_input_invalid");
          }
          const limit = limitValue;
          const matches = (await registryRecords()).filter((record) => [
            record.name,
            record.website_domain,
            record.contact_email_domain,
            record.rights_domain,
          ].some((value) => typeof value === "string" && value.toLowerCase().includes(query))).slice(0, limit);
          const report = {
            report_version: 1,
            query,
            match_count: matches.length,
            matches,
            route: "california_drop_primary_controller_request_fallback",
            raw_contact_addresses_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_catalog_health",
        label: "RightOut catalog health",
        description: "Report fresh, expiring, and stale official-source catalog facts without network access or subject data. Stale entries block live provider I/O until refreshed.",
        parameters: EmptyParameters,
        async execute(_toolCallId, params) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length !== 0) {
            throw new Error("rightout_catalog_health_input_invalid");
          }
          const report = catalogPolicyHealth(await catalogPromise);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_setup",
        label: "RightOut initialize",
        description: "Autonomously detect configured RightOut capabilities, select the most autonomous valid transport/browser combination, initialize encrypted profile state, and report only missing upgrades. Never creates secrets, changes OpenClaw config, or contacts a provider.",
        parameters: EmptyParameters,
        async execute(_toolCallId, params) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length !== 0) throw new Error("rightout_setup_input_invalid");
          const config = api.pluginConfig as RightOutConfig | undefined;
          const profileIds = Object.keys(config?.profiles ?? {}).filter((value) => /^profile_[a-f0-9]{16,32}$/.test(value)).sort();
          const browser = resolveBrowserBackend(toolContext as Record<string, any>, config);
          const browserControlTransport = resolveBrowserControlTransport(toolContext as Record<string, any>, config);
          const emailMode = config?.smtpTransport ? "smtp" : browser.webmail_ready ? "browser_webmail" : "unavailable";
          let requiredBrowserVerificationProfileDigest: string | null = null;
          try {
            requiredBrowserVerificationProfileDigest = browserVerificationProfileDigest({
              browserControlBaseUrl: config?.browserControlBaseUrl,
              browserProfile: config?.browserProfile,
              browserBackendMode: config?.browserBackendMode,
            });
          } catch { /* no exact logged-in browser profile is configured */ }
          const verificationMode = config?.imapTransport ? "imap"
            : browserVerificationTransportReady(config, browser) ? "browser_webmail" : "unavailable";
          const missing = [
            ...(stateEncryptionReady(config) ? [] : ["stateEncryptionKey_secretref"]),
            ...(profileIds.length ? [] : ["profiles_secretref"]),
            ...(typeof config?.braveApiKey === "string" ? [] : ["braveApiKey_secretref"]),
            ...(browser.configured ? [] : ["browser_backend"]),
            ...(emailMode !== "unavailable" ? [] : ["smtp_or_logged_in_webmail"]),
            ...(verificationMode !== "unavailable" ? [] : ["receiver_authenticated_imap_or_bound_browser_webmail_verification"]),
          ];
          let initialized = 0;
          if (stateEncryptionReady(config)) {
            for (const profileId of profileIds) {
              if (typeof config.profiles?.[profileId]?.payload !== "string") continue;
              await ensureImmutableProfileSnapshot(profileId);
              await caseLedger.ensure(profileId);
              initialized += 1;
            }
          }
          const report = {
            report_version: 1, state: missing.length === 0 ? "ready" : "needs_configuration",
            initialized_profiles: initialized, encrypted_state_auto_initialized: initialized > 0,
            durable_campaign_case_resume_ready: initialized > 0,
            active_browser_session_resume_ready: false,
            restart_browser_cleanup: "manual_close_or_discard_required_for_tabs_or_gmail_drafts_left_open_by_an_unclean_gateway_stop",
            capability_detection: {
              discovery: typeof config?.braveApiKey === "string" ? "brave_index" : "unavailable",
              browser: browser.selected,
              email_send: emailMode,
              verification: verificationMode,
              supported_browser_backends: browser.supported,
              remote_cloud_fallback: browser.remote_cloud_fallback_ready ? "configured" : "optional_not_configured",
              browser_control_transport: browserControlTransport,
              browser_verification_binding: {
                configured: verificationMode === "browser_webmail",
                required_profile_digest: requiredBrowserVerificationProfileDigest,
              },
            },
            selected_autonomous_modes: { browser: browser.selected, email_send: emailMode, verification: verificationMode },
            readiness_scope: "configuration_only_run_rightout_doctor_for_live_browser_probe",
            missing, configuration_mutated: false,
            provider_reads: 0, provider_writes: 0, raw_pii_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_setup", optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_doctor",
        label: "RightOut capability doctor",
        description: "Diagnose local autonomous-campaign capabilities, official-source parity health, transports, browser modes, encrypted state, and registry readiness without returning secrets or subject data.",
        parameters: EmptyParameters,
        async execute(_toolCallId, params) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length !== 0) throw new Error("rightout_doctor_input_invalid");
          const config = api.pluginConfig as RightOutConfig | undefined;
          const parity = parityCatalogHealth(await parityCatalogPromise);
          const registry = await registryMeta();
          const paritySource = await paritySourceStore.lookup("latest") as Record<string, any> | undefined;
          const authorization = await providerAuthorizationHealth(config);
          const browser = resolveBrowserBackend(toolContext as Record<string, any>, config);
          const browserControlTransport = resolveBrowserControlTransport(toolContext as Record<string, any>, config);
          const browserProbe = browser.configured
            ? await probeBrowserBackend(browser)
            : { reachable: false, operational: false, deep_snapshot: false };
          const remoteCloudProbe = browser.remote_cloud_fallback_ready
            ? await probeBrowserBackend(resolveBrowserControl(toolContext as Record<string, any>, config, "remote_cloud_cdp"))
            : { reachable: false, operational: false, deep_snapshot: false };
          const emailSend = Boolean(config?.smtpTransport) || browser.webmail_ready;
          const browserWebmailVerification = browserVerificationTransportReady(config, browser);
          const verificationReady = Boolean(config?.imapTransport) || browserWebmailVerification;
          const checks = {
            encrypted_state: stateEncryptionReady(config),
            configured_profiles: Object.values(config?.profiles ?? {}).filter((entry) => typeof entry?.payload === "string").length,
            brave_discovery: typeof config?.braveApiKey === "string",
            brave_configured: typeof config?.braveApiKey === "string",
            brave_live_auth_unverified: true,
            smtp_send: Boolean(config?.smtpTransport),
            imap_verification: Boolean(config?.imapTransport),
            browser_webmail_verification: browserWebmailVerification,
            email_send: emailSend,
            verification: verificationReady,
            browser_backend_configured: browser.configured,
            browser_backend_reachable: browserProbe.reachable,
            browser_backend_operational: browserProbe.operational,
            browser_deep_snapshot: browserProbe.deep_snapshot,
            managed_openclaw_browser: browser.configured && browser.selected === "managed_openclaw",
            remote_cloud_cdp_browser: browser.configured && browser.selected === "remote_cloud_cdp",
            existing_logged_in_cdp_browser: browser.configured && browser.selected === "existing_logged_in_cdp",
            remote_cloud_fallback: browser.remote_cloud_fallback_ready,
            remote_cloud_fallback_operational: remoteCloudProbe.operational,
            browser_control_auth: config?.browserControlToken !== undefined,
            standalone_browser_control_http: browserControlTransport === "standalone_loopback_http_opt_in",
            openclaw_sandbox_browser_bridge: browserControlTransport === "openclaw_sandbox_browser_bridge",
            browser_runtime_prerequisites_verified: browserProbe.operational && browserProbe.deep_snapshot,
            official_registry_snapshot: registry.state === "registry_ready",
            official_parity_source_snapshot: Boolean(paritySource?.generated_at) && Number(paritySource?.probed_routes) > 0,
            parity_source_probed_routes: Number(paritySource?.probed_routes ?? 0),
            lane_authorization_ready: authorization.any_publisher_lane_authorized,
            authorized_submit_form_routes: authorization.authorized_route_counts.submit_form,
            authorized_source_refresh_routes: authorization.authorized_route_counts.source_refresh,
            exact_unbroker_broker_count: parity.broker_count === 22,
            normalized_unbroker_contract_surface: parity.source_blockers.length === 0 && parity.broker_count === 22,
            primary_reference_routes_available: parity.externally_unavailable_routes.length === 0,
            autonomous_external_route_rescue: parity.broker_routes
              .filter((route: any) => route.primary_route_available === false)
              .every((route: any) => route.autonomous_rescue_available === true),
            equivalent_reference_outcomes: parity.equivalent_outcome_gaps.length === 0,
          };
          const critical = Object.entries(checks).filter(([key, value]) => [
            "encrypted_state", "configured_profiles", "brave_discovery", "email_send", "verification", "browser_backend_configured", "browser_backend_operational", "browser_deep_snapshot",
            "exact_unbroker_broker_count", "normalized_unbroker_contract_surface", "autonomous_external_route_rescue",
          ].includes(key) && !value).map(([key]) => key);
          const localRuntimeReady = critical.length === 0;
          const report = {
            report_version: 1,
            state: !localRuntimeReady
              ? "needs_attention"
              : !authorization.any_publisher_lane_authorized
                ? "runtime_ready_policy_gates_closed"
                : "runtime_prerequisites_ready_external_providers_unverified",
            checks, critical, parity_release_blockers: parity.source_blockers,
            external_runtime_degradations: parity.externally_unavailable_routes,
            selected_browser_backend: browser.selected,
            browser_control_transport: browserControlTransport,
            supported_browser_backends: browser.supported,
            browser_probe: { selected: browserProbe, remote_cloud_fallback: remoteCloudProbe },
            provider_authorization: authorization,
            readiness: {
              software_release_ready: parity.release_ready,
              local_runtime_prerequisites_ready: localRuntimeReady,
              publisher_lane_authorization_ready: authorization.any_publisher_lane_authorized,
              external_provider_auth_quota_and_effectiveness_verified: false,
            },
            operator_configuration_optional_by_lane: ["smtp_send", "imap_verification", "browser_webmail_verification", "official_registry_snapshot", "official_parity_source_snapshot"],
            provider_reads: 0, provider_writes: 0, raw_pii_in_report: false, secrets_in_report: false,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_doctor", optional: true },
    );

    api.registerTool(
      {
        name: "rightout_due_rechecks",
        label: "RightOut due rechecks",
        description: "List due verification and reappearance checks for one opaque subject reference. Intended for an official OpenClaw Cron turn; performs no network request or provider write.",
        parameters: CaseParameters,
        async execute(_toolCallId, params) {
          const input = validateCaseInput(params);
          assertConfiguredProfile(input.profileId);
          await ensureImmutableProfileSnapshot(input.profileId);
          const report = await caseLedger.due(input.profileId);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_team_session_binding",
        label: "RightOut team session binding",
        description: "Derive the one-way binding for this exact trusted OpenClaw session and agent. Returns no raw session identifier and performs no network request or write.",
        parameters: EmptyParameters,
        async execute(_toolCallId, params) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length !== 0) {
            throw new Error("rightout_team_session_required");
          }
          const binding = teamSessionBindingDigest(teamContext(toolContext as Record<string, any>));
          const report = {
            report_version: 1,
            session_binding_digest: binding,
            raw_session_identifier_in_report: false,
            network_requests: 0,
            provider_writes: 0,
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_team_session_binding", optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_effectiveness",
        label: "RightOut effectiveness metrics",
        description: "Measure discovery, identity confidence, submission, provider confirmation, reappearance, uncertainty, and human handoff for one subject. Operational effectiveness remains needs_evidence without explicit authorized canaries.",
        parameters: CaseParameters,
        async execute(_toolCallId, params) {
          const input = validateCaseInput(params);
          const config = api.pluginConfig as RightOutConfig | undefined;
          const member = currentTeamMember(config, toolContext as Record<string, any>);
          if (member) assertTeamProfileScope(member, input.profileId);
          const report = await effectivenessForProfile(input.profileId);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_effectiveness", optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_team_overview",
        label: "RightOut scoped team overview",
        description: "Read a PII-safe overview limited to the profiles authorized for this exact bound team session. Campaign and worker authority are intentionally omitted.",
        parameters: EmptyParameters,
        async execute(_toolCallId, params) {
          if (!params || typeof params !== "object" || Array.isArray(params) || Object.keys(params).length !== 0) {
            throw new Error("rightout_team_overview_input_invalid");
          }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const member = currentTeamMember(config, toolContext as Record<string, any>);
          if (!member) throw new Error("rightout_team_access_not_configured");
          const report = await teamDashboardModel(member);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_team_overview", optional: true },
    );

    api.registerTool(
      (toolContext) => ({
        name: "rightout_export_dashboard",
        label: "RightOut export private local dashboard",
        description: "Export a static HTML or JSON dashboard limited to this owner/manager session's authorized profiles. Requires native allow-once approval; starts no server and loads no remote assets.",
        parameters: DashboardExportParameters,
        async execute(toolCallId, params) {
          const input = validateDashboardExportInput(params);
          const config = api.pluginConfig as RightOutConfig | undefined;
          const member = currentTeamMember(config, toolContext as Record<string, any>);
          if (!member || !["owner", "manager"].includes(member.role)) throw new Error("rightout_team_role_unauthorized");
          const binding = dashboardExportScopeBinding(input, member, teamSessionBindingDigest(teamContext(toolContext as Record<string, any>)));
          pruneApprovalState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_export_dashboard" || approval.binding !== binding) {
            throw new Error("rightout_approval_binding_failed");
          }
          const exported = await exportLocalDashboard(await teamDashboardModel(member), stateDir, input.format);
          const report = { report_version: 1, ...exported, native_approval_consumed: true };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      }),
      { name: "rightout_export_dashboard", optional: true },
    );
  },
});
