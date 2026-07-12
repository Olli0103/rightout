import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import {
  buildHostnameAllowlistPolicyFromSuffixAllowlist,
  fetchWithSsrFGuard,
} from "openclaw/plugin-sdk/ssrf-runtime";
import {
  BRAVE_TERMS_VERSION,
  approvalDescription,
  runLiveScan,
  validateOperatorAttestations,
  validatePublicToolInput,
} from "./lib/live-scan.mjs";
import {
  RIGHTOUT_REMOVAL_POLICY_VERSION,
  removalApprovalDescription,
  removalScopeBinding,
  resolveRemovalCatalogEntry,
  runRemovalSubmission,
  validateRemovalOperatorAttestations,
  validateRemovalPreflight,
  validateRemovalPublicToolInput,
} from "./lib/removal.mjs";
import { createSmtpSender } from "./lib/smtp.mjs";
import { createCaseLedger } from "./lib/cases.mjs";
import { createBrowserFormSubmitter } from "./lib/browser-form.mjs";
import { createImapPoller, newVerificationHandle } from "./lib/imap.mjs";
import { createListingTokenVault } from "./lib/listing-tokens.mjs";
import { createEncryptedFileKeyedStore } from "./lib/file-keyed-store.mjs";
import {
  RIGHTOUT_DIRECT_SCAN_POLICY_VERSION,
  directScanApprovalDescription,
  directScanScopeBinding,
  resolveDirectScanCatalogEntry,
  runDirectRescan,
  validateDirectScanAttestations,
  validateDirectScanInput,
} from "./lib/direct-rescan.mjs";
import {
  RIGHTOUT_VERIFICATION_POLICY_VERSION,
  resolveVerificationCatalogEntry,
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

type SmtpTransportConfig = {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  fromAddress: string;
};

type ImapTransportConfig = {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  address: string;
};

type VerificationAttestations = {
  rightoutVerificationPolicyAccepted: boolean;
  rightoutVerificationPolicyVersion: string;
  subjectConsentReviewed: boolean;
  inboxReadAuthorized: boolean;
  verificationLinkOpenAuthorized: boolean;
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

type RightOutConfig = {
  braveApiKey?: string;
  profiles?: Record<string, { payload: string }>;
  operatorAttestations?: ScanAttestations;
  smtpTransport?: SmtpTransportConfig;
  removalAttestations?: RemovalAttestations;
  imapTransport?: ImapTransportConfig;
  verificationAttestations?: VerificationAttestations;
  formAttestations?: FormAttestations;
  stateEncryptionKey?: string;
  directScanAttestations?: DirectScanAttestations;
};

const LiveScanParameters = Type.Object(
  {
    profileId: Type.String({
      pattern: "^profile_[a-f0-9]{16,32}$",
      description: "Opaque operator-configured profile reference. Contains no personal data.",
    }),
    brokerIds: Type.Array(Type.String({ pattern: "^[a-z0-9_]{2,24}$" }), { minItems: 1, maxItems: 2, uniqueItems: true }),
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

const VerificationPollParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$", description: "Opaque private profile reference." }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,24}$", description: "Catalog broker with a verified IMAP lane." }),
  },
  { additionalProperties: false },
);

const VerificationOpenParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$", description: "Opaque private profile reference." }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,24}$", description: "Catalog broker bound to the verification handle." }),
    verificationHandle: Type.String({ pattern: "^verify_[a-f0-9]{24}$", description: "Opaque short-lived handle returned by RightOut inbox polling." }),
  },
  { additionalProperties: false },
);

const DirectScanParameters = Type.Object(
  {
    profileId: Type.String({ pattern: "^profile_[a-f0-9]{16,32}$", description: "Opaque private profile reference." }),
    brokerId: Type.String({ pattern: "^[a-z0-9_]{2,24}$", description: "Catalog broker bound to the encrypted listing handle." }),
    listingHandle: Type.String({ pattern: "^listing_[a-f0-9]{24}$", description: "Opaque encrypted candidate handle returned by a RightOut live scan." }),
  },
  { additionalProperties: false },
);

async function loadCatalog(path: string): Promise<Record<string, unknown>> {
  const text = await readFile(path, { encoding: "utf-8" });
  return JSON.parse(text) as Record<string, unknown>;
}

type PublicScanInput = { profileId: string; brokerIds: string[] };
type PublicRemovalInput = { profileId: string; brokerId: string; requestKind: "delete_and_opt_out" | "gdpr_erasure_objection" };
type PublicCaseInput = { profileId: string };
type PublicVerificationPollInput = { profileId: string; brokerId: string };
type PublicVerificationOpenInput = PublicVerificationPollInput & { verificationHandle: string };
type PublicDirectScanInput = PublicVerificationPollInput & { listingHandle: string };
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

function purgeScopeBinding(input: PublicCaseInput): string {
  return JSON.stringify(["purge_subject_state", validateCaseInput(input).profileId]);
}

function assertSupportedBrokerScope(catalog: Record<string, unknown>, input: PublicScanInput): void {
  const brokers = Array.isArray(catalog.brokers) ? catalog.brokers : [];
  for (const brokerId of input.brokerIds) {
    const broker = brokers.find((value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) return false;
      const entry = value as Record<string, unknown>;
      const scan = entry.scan as Record<string, unknown> | undefined;
      return entry.id === brokerId
        && entry.category === "people_search"
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
  description: "Separately approval-gated live data-broker scans and broker removal requests",
  register(api) {
    const approvalBindings = new Map<string, ApprovalBinding>();
    const submittedScopes = new Map<string, number>();
    const approvalTtlMs = 120_000;
    const duplicateCooldownMs = 24 * 60 * 60_000;
    const catalogPath = api.resolvePath("skills/data-broker-removal/references/brokers/core.json");
    const catalogPromise = loadCatalog(catalogPath);
    const sendSmtpMail = createSmtpSender();
    const pollImapVerification = createImapPoller();
    const submitBrowserForm = createBrowserFormSubmitter();
    const stateDir = api.runtime.state.resolveStateDir(process.env);
    const openRightOutStore = <T>(options: { namespace: string; maxEntries: number; defaultTtlMs?: number }) =>
      createEncryptedFileKeyedStore({
        stateDir,
        ...options,
        getSecret: () => (api.pluginConfig as RightOutConfig | undefined)?.stateEncryptionKey,
      }) as any;
    const caseLedger = createCaseLedger(openRightOutStore({
      namespace: "rightout-cases-v1",
      maxEntries: 100,
    }));
    const verificationTokens = openRightOutStore<VerificationToken>({
      namespace: "rightout-verification-tokens-v1",
      maxEntries: 200,
      defaultTtlMs: 7 * 24 * 60 * 60_000,
    });
    const submissionDedupe = openRightOutStore<{ createdAt: string; channel: string; profileId: string; brokerId: string }>({
      namespace: "rightout-submission-dedupe-v1",
      maxEntries: 500,
      defaultTtlMs: duplicateCooldownMs,
    });
    const listingTokens = openRightOutStore<Record<string, unknown>>({
      namespace: "rightout-listing-tokens-v1",
      maxEntries: 500,
      defaultTtlMs: 180 * 24 * 60 * 60_000,
    });

    async function purgeProfileEntries(store: any, profileId: string): Promise<number> {
      let deleted = 0;
      for (const entry of await store.entries()) {
        if (entry?.value?.profileId === profileId && await store.delete(entry.key)) deleted += 1;
      }
      return deleted;
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

    function verificationAttestationSnapshot(
      config: RightOutConfig | undefined,
      input: PublicVerificationPollInput,
    ): VerificationAttestations {
      return validateVerificationAttestations(input, config?.verificationAttestations) as VerificationAttestations;
    }

    function formAttestationSnapshot(config: RightOutConfig | undefined, input: PublicRemovalInput): FormAttestations {
      return validateFormAttestations(input, config?.formAttestations) as FormAttestations;
    }

    function directScanAttestationSnapshot(config: RightOutConfig | undefined, input: PublicDirectScanInput): DirectScanAttestations {
      return validateDirectScanAttestations(input, config?.directScanAttestations) as DirectScanAttestations;
    }

    function pruneTransientState(now = Date.now()): void {
      for (const [toolCallId, approval] of approvalBindings) {
        if (approval.expiresAt <= now) approvalBindings.delete(toolCallId);
      }
      for (const [scope, expiresAt] of submittedScopes) {
        if (expiresAt <= now) submittedScopes.delete(scope);
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
        secretFinding(rightout, "smtpTransport.fromAddress", "RightOut sender address is stored as plaintext"),
        secretFinding(rightout, "imapTransport.username", "RightOut IMAP username is stored as plaintext"),
        secretFinding(rightout, "imapTransport.password", "RightOut IMAP password is stored as plaintext"),
        secretFinding(rightout, "imapTransport.address", "RightOut IMAP mailbox address is stored as plaintext"),
        secretFinding(rightout, "stateEncryptionKey", "RightOut durable-state encryption key is stored as plaintext"),
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
      if (rightout?.imapTransport !== undefined && (
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
        || typeof verificationAttestations?.imapTransportDigest !== "string"
        || !/^[a-f0-9]{64}$/.test(verificationAttestations.imapTransportDigest)
      )) {
        findings.push({
          checkId: "rightout.verification_operator_attestations",
          severity: "critical" as const,
          title: "RightOut inbox-verification attestations are incomplete",
          detail: `Inbox reads and confirmation-link opens require exact scope and policy ${RIGHTOUT_VERIFICATION_POLICY_VERSION}.`,
          remediation: "Review the verification policy and configure exact revision-bound verificationAttestations out of band.",
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
      const runtime = config as Record<string, any>;
      const httpDeny = runtime.gateway?.tools?.deny;
      const missingDeny = [
        "rightout_live_scan",
        "rightout_submit_removal",
        "rightout_submit_form_removal",
        "rightout_poll_verification",
        "rightout_open_verification",
        "rightout_direct_rescan",
        "rightout_purge_subject_state",
      ].filter((tool) => !Array.isArray(httpDeny) || !httpDeny.includes(tool));
      if (missingDeny.length) {
        findings.push({
          checkId: "rightout.gateway.tools_invoke",
          severity: "warn" as const,
          title: "RightOut tools are reachable through direct Gateway tool invoke",
          detail: `The following tools are not denied on the full-operator /tools/invoke surface: ${missingDeny.join(", ")}.`,
          remediation: "Add all live RightOut tools to gateway.tools.deny unless direct operator invocation is explicitly required.",
        });
      }
      return findings;
    });

    api.on("before_tool_call", async (event) => {
      const approvalTools = new Set([
        "rightout_live_scan",
        "rightout_submit_removal",
        "rightout_submit_form_removal",
        "rightout_poll_verification",
        "rightout_open_verification",
        "rightout_direct_rescan",
        "rightout_purge_subject_state",
      ]);
      if (!approvalTools.has(event.toolName)) return;
      if (!event.toolCallId) return { block: true, blockReason: "RightOut requires a host-authoritative tool call ID" };
      const config = api.pluginConfig as RightOutConfig | undefined;
      const catalog = await catalogPromise;
      pruneTransientState();
      approvalBindings.delete(event.toolCallId);
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
              timeoutBehavior: "deny" as const,
              onResolution(decision: string) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid RightOut subject-state purge scope" };
        }
      }
      if (event.toolName === "rightout_live_scan") {
        try {
          const input = validatePublicToolInput(event.params) as PublicScanInput;
          assertSupportedBrokerScope(catalog, input);
          const attestations = scanAttestationSnapshot(config, input);
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
              timeoutBehavior: "deny" as const,
              onResolution(decision: string) {
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
          const input = validateRemovalPublicToolInput(event.params) as PublicRemovalInput;
          const broker = resolveRemovalCatalogEntry(catalog, input);
          const attestations = removalAttestationSnapshot(config, input);
          const dedupeKey = removalDedupeKey(input);
          if (submittedScopes.has(dedupeKey)) return { block: true, blockReason: "duplicate RightOut removal request is cooling down" };
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
              timeoutBehavior: "deny" as const,
              onResolution(decision: string) {
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
          const input = validateFormRemovalInput(event.params) as PublicRemovalInput;
          const broker = resolveFormCatalogEntry(catalog, input);
          const attestations = formAttestationSnapshot(config, input);
          const dedupeKey = removalDedupeKey(input);
          if (submittedScopes.has(dedupeKey)) return { block: true, blockReason: "duplicate RightOut form removal is cooling down" };
          const binding = formScopeBinding(input, attestations, broker);
          const toolCallId = event.toolCallId;
          return {
            params: input,
            requireApproval: {
              title: "Submit broker suppression form",
              description: formApprovalDescription(input, broker),
              severity: "critical" as const,
              allowedDecisions: ["allow-once", "deny"] as const,
              timeoutMs: approvalTtlMs,
              timeoutBehavior: "deny" as const,
              onResolution(decision: string) {
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
          const input = validateVerificationPollInput(event.params) as PublicVerificationPollInput;
          const broker = resolveVerificationCatalogEntry(catalog, input);
          const attestations = verificationAttestationSnapshot(config, input);
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
              timeoutBehavior: "deny" as const,
              onResolution(decision: string) {
                if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                else approvalBindings.delete(toolCallId);
              },
            },
          };
        } catch {
          return { block: true, blockReason: "invalid, unsupported, or unattested RightOut inbox-verification scope" };
        }
      }

      if (event.toolName === "rightout_direct_rescan") {
        try {
          const input = validateDirectScanInput(event.params) as PublicDirectScanInput;
          const broker = resolveDirectScanCatalogEntry(catalog, input);
          const attestations = directScanAttestationSnapshot(config, input);
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
              timeoutBehavior: "deny" as const,
              onResolution(decision: string) {
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
        const input = validateVerificationOpenInput(event.params) as PublicVerificationOpenInput;
        const broker = resolveVerificationCatalogEntry(catalog, input);
        const attestations = verificationAttestationSnapshot(config, input);
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
            timeoutBehavior: "deny" as const,
            onResolution(decision: string) {
              if (decision === "allow-once") approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
              else approvalBindings.delete(toolCallId);
            },
          },
        };
      } catch {
        return { block: true, blockReason: "invalid, expired, mismatched, or unattested RightOut verification-link scope" };
      }
    });

    api.registerTool(
      {
        name: "rightout_live_scan",
        label: "RightOut live scan",
        description: "Run a read-only live Brave index scan of supported catalog brokers. Requires native OpenClaw allow-once approval. Never authorizes or submits a removal.",
        parameters: LiveScanParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicScanInput;
          try {
            input = validatePublicToolInput(params) as PublicScanInput;
          } catch {
            throw new Error("rightout_approval_binding_failed");
          }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await catalogPromise;
          assertSupportedBrokerScope(catalog, input);
          let attestations: ScanAttestationSnapshot | undefined;
          try {
            attestations = scanAttestationSnapshot(config, input);
          } catch {
            // Missing or changed attestations invalidate the approval binding.
          }
          pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_live_scan" || !attestations || approval.binding !== scanScopeBinding(input, attestations)) {
            throw new Error("rightout_approval_binding_failed");
          }
          if (!stateEncryptionReady(config) || typeof config.braveApiKey !== "string" || typeof config.profiles?.[input.profileId]?.payload !== "string") {
            throw new Error("rightout_not_configured");
          }
          const guardedFetch = async ({ url, allowedHosts, ...options }: {
            url: string;
            allowedHosts: string[];
            timeoutMs?: number;
            maxRedirects?: number;
            signal?: AbortSignal;
            init?: RequestInit;
          }) => fetchWithSsrFGuard({
            url,
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
            ...(typeof config.stateEncryptionKey === "string" ? {
              storeCandidate: createListingTokenVault(listingTokens, config.stateEncryptionKey).storeCandidate,
            } : {}),
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
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_direct_rescan",
        label: "RightOut direct rescan",
        description: "Directly recheck only encrypted, broker-domain listing URLs previously observed through Brave. Requires separate exact-scope attestations and native allow-once approval. Never submits a request.",
        parameters: DirectScanParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicDirectScanInput;
          try { input = validateDirectScanInput(params) as PublicDirectScanInput; }
          catch { throw new Error("rightout_approval_binding_failed"); }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await catalogPromise;
          const broker = resolveDirectScanCatalogEntry(catalog, input);
          let attestations: DirectScanAttestations | undefined;
          try { attestations = directScanAttestationSnapshot(config, input); } catch { /* fail below */ }
          pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !approval || approval.toolName !== "rightout_direct_rescan" || !attestations
            || approval.binding !== directScanScopeBinding(input, attestations, broker)
          ) throw new Error("rightout_approval_binding_failed");
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string") {
            throw new Error("rightout_not_configured");
          }
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
          const trackedReport = { ...report, state, tracking: { durable_case_recorded: durableCaseRecorded } };
          return { content: [{ type: "text", text: JSON.stringify(trackedReport) }], details: trackedReport };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_submit_removal",
        label: "RightOut submit removal",
        description: "Send one catalog-locked US delete/opt-out or EU GDPR erasure/objection email through the operator's approved SMTP account. Requires a separate native OpenClaw allow-once approval. Submission is never reported as confirmed removal.",
        parameters: RemovalParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicRemovalInput;
          try {
            input = validateRemovalPublicToolInput(params) as PublicRemovalInput;
          } catch {
            throw new Error("rightout_approval_binding_failed");
          }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await catalogPromise;
          const broker = resolveRemovalCatalogEntry(catalog, input);
          let attestations: RemovalAttestationSnapshot | undefined;
          try {
            attestations = removalAttestationSnapshot(config, input);
          } catch {
            // Missing or changed attestations invalidate the approval binding.
          }
          pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_submit_removal" || !attestations || approval.binding !== removalScopeBinding(input, attestations, broker)) {
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
          if ((broker as Record<string, any>).discoveryRequirement !== "not_required_for_data_subject_request") {
            await caseLedger.removalContext(input.profileId, input.brokerId);
          }
          const dedupeKey = removalDedupeKey(input);
          if (submittedScopes.has(dedupeKey)) throw new Error("rightout_duplicate_removal_request");
          if (!await submissionDedupe.registerIfAbsent(dedupeKey, {
            createdAt: new Date().toISOString(), channel: "smtp_email", profileId: input.profileId, brokerId: input.brokerId,
          })) {
            throw new Error("rightout_duplicate_removal_request");
          }
          submittedScopes.set(dedupeKey, Number.POSITIVE_INFINITY);
          try {
            const report = await runRemovalSubmission({
              input,
              catalog,
              profilePayload: config.profiles[input.profileId].payload,
              smtpConfig: config.smtpTransport,
              operatorAttestations: attestations,
              signal,
              sendMail: sendSmtpMail,
            });
            submittedScopes.set(dedupeKey, Date.now() + duplicateCooldownMs);
            let durableCaseRecorded = true;
            try {
              const processingDays = Number((broker as Record<string, any>).processingDays ?? 14);
              await caseLedger.recordRemoval(report, processingDays);
            } catch {
              durableCaseRecorded = false;
              api.logger.error("RightOut removal was submitted but its PII-safe case update failed");
            }
            const trackedReport = { ...report, tracking: { durable_case_recorded: durableCaseRecorded } };
            return { content: [{ type: "text", text: JSON.stringify(trackedReport) }], details: trackedReport };
          } catch (error) {
            const code = error instanceof Error ? error.message : "";
            if (code === "rightout_removal_transport_failed" || code === "rightout_removal_not_accepted") {
              submittedScopes.set(dedupeKey, Date.now() + duplicateCooldownMs);
            } else {
              submittedScopes.delete(dedupeKey);
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
        name: "rightout_submit_form_removal",
        label: "RightOut submit form removal",
        description: "Initiate a catalog-locked broker suppression flow in OpenClaw's sandbox browser. PII is resolved inside the plugin, CAPTCHA/ID fails closed, and a separate native allow-once approval is mandatory.",
        parameters: RemovalParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicRemovalInput;
          try { input = validateFormRemovalInput(params) as PublicRemovalInput; }
          catch { throw new Error("rightout_approval_binding_failed"); }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await catalogPromise;
          const broker = resolveFormCatalogEntry(catalog, input);
          let attestations: FormAttestations | undefined;
          try { attestations = formAttestationSnapshot(config, input); } catch { /* fail below */ }
          pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_submit_form_removal" || !attestations || approval.binding !== formScopeBinding(input, attestations, broker)) {
            throw new Error("rightout_approval_binding_failed");
          }
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string") throw new Error("rightout_not_configured");
          validateFormPreflight({ input, catalog, profilePayload: config.profiles[input.profileId].payload, attestations });
          await caseLedger.removalContext(input.profileId, input.brokerId);
          const dedupeKey = removalDedupeKey(input);
          if (submittedScopes.has(dedupeKey)) throw new Error("rightout_duplicate_removal_request");
          if (!await submissionDedupe.registerIfAbsent(dedupeKey, {
            createdAt: new Date().toISOString(), channel: "browser_form", profileId: input.profileId, brokerId: input.brokerId,
          })) {
            throw new Error("rightout_duplicate_removal_request");
          }
          submittedScopes.set(dedupeKey, Number.POSITIVE_INFINITY);
          try {
            const report = await runFormRemoval({
              input,
              catalog,
              profilePayload: config.profiles[input.profileId].payload,
              attestations,
              bridgeUrl: toolContext.browser?.sandboxBridgeUrl,
              submitForm: submitBrowserForm,
              signal,
            });
            submittedScopes.set(dedupeKey, Date.now() + duplicateCooldownMs);
            let durableCaseRecorded = true;
            try { await caseLedger.recordFormSubmission(report); }
            catch {
              durableCaseRecorded = false;
              api.logger.error("RightOut submitted a browser form but its PII-safe case update failed");
            }
            const trackedReport = { ...report, tracking: { durable_case_recorded: durableCaseRecorded } };
            return { content: [{ type: "text", text: JSON.stringify(trackedReport) }], details: trackedReport };
          } catch (error) {
            const code = error instanceof Error ? error.message : "rightout_form_failed";
            const safeCodes = new Set([
              "rightout_browser_bridge_unavailable", "rightout_browser_bridge_failed",
              "rightout_browser_snapshot_invalid", "rightout_form_contract_mismatch",
              "rightout_form_human_gate_required", "rightout_form_profile_field_missing",
              "rightout_form_submission_unconfirmed", "rightout_form_cancelled",
            ]);
            const reason = safeCodes.has(code) ? code : "rightout_form_failed";
            const possibleWrite = ["rightout_browser_bridge_failed", "rightout_form_submission_unconfirmed"].includes(reason);
            if (possibleWrite) submittedScopes.set(dedupeKey, Date.now() + duplicateCooldownMs);
            else {
              submittedScopes.delete(dedupeKey);
              await submissionDedupe.delete(dedupeKey);
            }
            let durableCaseRecorded = true;
            try {
              await caseLedger.recordLifecycle(input.profileId, input.brokerId, "human_task_queued", {
                evidenceKind: "human_task",
                reason,
              });
            } catch { durableCaseRecorded = false; }
            const report = {
              report_version: 1,
              subject_ref: input.profileId,
              broker_id: input.brokerId,
              state: "human_task_queued",
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
        description: "Read recent mail from the subject's approved IMAP account and find a broker-domain confirmation link without returning raw mail or link values. Requires a separate native OpenClaw allow-once approval.",
        parameters: VerificationPollParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicVerificationPollInput;
          try {
            input = validateVerificationPollInput(params) as PublicVerificationPollInput;
          } catch {
            throw new Error("rightout_approval_binding_failed");
          }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await catalogPromise;
          const broker = resolveVerificationCatalogEntry(catalog, input);
          let attestations: VerificationAttestations | undefined;
          try { attestations = verificationAttestationSnapshot(config, input); } catch { /* fail below */ }
          pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_poll_verification" || !attestations || approval.binding !== verificationPollScopeBinding(input, attestations, broker)) {
            throw new Error("rightout_approval_binding_failed");
          }
          if (!stateEncryptionReady(config) || typeof config.profiles?.[input.profileId]?.payload !== "string" || !config.imapTransport) {
            throw new Error("rightout_not_configured");
          }
          const caseContext = await caseLedger.verificationContext(input.profileId, input.brokerId, ["submitted", "verification_pending"]);
          const preflight = validateVerificationPreflight({
            input,
            catalog,
            profilePayload: config.profiles[input.profileId].payload,
            imapTransport: config.imapTransport,
            attestations,
          });
          const result = await pollImapVerification({
            transport: preflight.imap,
            expectedAddress: preflight.profile.contactEmail,
            broker: preflight.broker.raw,
            notBefore: caseContext.submitted_at,
            sinceDays: 14,
            signal,
          });
          if (!result.found) {
            const report = {
              report_version: 1,
              subject_ref: input.profileId,
              broker_id: input.brokerId,
              state: "verification_not_observed",
              generated_at: new Date().toISOString(),
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
            verification_handle: verificationHandle,
            message_reference: result.message_reference,
            generated_at: token.createdAt,
            next_action: "separately_approve_rightout_open_verification",
            tracking: { durable_case_recorded: true, bound_to_submission: true },
            invariants: { raw_mail_in_report: false, raw_link_in_report: false, raw_pii_in_report: false, provider_writes: 0 },
          };
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );

    api.registerTool(
      {
        name: "rightout_open_verification",
        label: "RightOut open verification",
        description: "Consume one short-lived broker-bound handle and open its stored HTTPS confirmation link. This is an external write and requires its own native OpenClaw allow-once approval.",
        parameters: VerificationOpenParameters,
        async execute(toolCallId, params, signal) {
          let input: PublicVerificationOpenInput;
          try { input = validateVerificationOpenInput(params) as PublicVerificationOpenInput; }
          catch { throw new Error("rightout_approval_binding_failed"); }
          const config = api.pluginConfig as RightOutConfig | undefined;
          const catalog = await catalogPromise;
          const broker = resolveVerificationCatalogEntry(catalog, input);
          let attestations: VerificationAttestations | undefined;
          try { attestations = verificationAttestationSnapshot(config, input); } catch { /* fail below */ }
          pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (
            !approval
            || approval.toolName !== "rightout_open_verification"
            || !attestations
            || approval.binding !== verificationOpenScopeBinding(input, attestations, broker)
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
          const consumed = await verificationTokens.consume(input.verificationHandle);
          if (!consumed || consumed.url !== token.url) throw new Error("rightout_verification_handle_expired");
          let request;
          try {
            request = await fetchWithSsrFGuard({
              url: consumed.url,
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
            if (signal?.aborted) throw new Error("rightout_verification_cancelled");
            if (error instanceof Error && error.message === "rightout_verification_open_failed") throw error;
            throw new Error("rightout_verification_open_failed");
          } finally {
            await request?.release?.();
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
              generated_at: new Date().toISOString(),
              verification_handle_consumed: true,
              removal_confirmed: false,
              next_action: "manual_provider_status_check_required",
              tracking: { durable_case_recorded: false },
              invariants: { raw_link_in_report: false, raw_pii_in_report: false, provider_writes: 1 },
            };
            return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
          }
          const report = {
            report_version: 1,
            subject_ref: input.profileId,
            broker_id: input.brokerId,
            state: "awaiting_processing",
            generated_at: new Date().toISOString(),
            verification_handle_consumed: true,
            removal_confirmed: false,
            tracking: { durable_case_recorded: durableCaseRecorded },
            invariants: { raw_link_in_report: false, raw_pii_in_report: false, provider_writes: 1 },
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
          pruneTransientState();
          const approval = approvalBindings.get(toolCallId);
          approvalBindings.delete(toolCallId);
          if (!approval || approval.toolName !== "rightout_purge_subject_state" || approval.binding !== purgeScopeBinding(input)) {
            throw new Error("rightout_approval_binding_failed");
          }
          const config = api.pluginConfig as RightOutConfig | undefined;
          if (!stateEncryptionReady(config)) throw new Error("rightout_not_configured");
          const [caseDeleted, verificationHandles, listingHandles, dedupeRecords] = await Promise.all([
            caseLedger.purge(input.profileId),
            purgeProfileEntries(verificationTokens, input.profileId),
            purgeProfileEntries(listingTokens, input.profileId),
            purgeProfileEntries(submissionDedupe, input.profileId),
          ]);
          submittedScopes.clear();
          const report = {
            report_version: 1,
            subject_ref: input.profileId,
            state: "local_subject_state_purged",
            generated_at: new Date().toISOString(),
            deleted: {
              case_record: caseDeleted ? 1 : 0,
              verification_handles: verificationHandles,
              listing_handles: listingHandles,
              dedupe_records: dedupeRecords,
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
        name: "rightout_next_actions",
        label: "RightOut next actions",
        description: "Plan deterministic next actions for one opaque subject reference from the clean-room catalog and PII-safe durable case ledger. Performs no network request or provider write.",
        parameters: CaseParameters,
        async execute(_toolCallId, params) {
          const input = validateCaseInput(params);
          assertConfiguredProfile(input.profileId);
          const report = await caseLedger.plan(input.profileId, await catalogPromise);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
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
          const report = await caseLedger.status(input.profileId);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
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
          const report = await caseLedger.due(input.profileId);
          return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
        },
      },
      { optional: true },
    );
  },
});
