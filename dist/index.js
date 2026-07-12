import { readFile } from "node:fs/promises";
import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { buildHostnameAllowlistPolicyFromSuffixAllowlist, fetchWithSsrFGuard, } from "openclaw/plugin-sdk/ssrf-runtime";
import { BRAVE_TERMS_VERSION, approvalDescription, runLiveScan, validateOperatorAttestations, validatePublicToolInput, } from "./lib/live-scan.mjs";
import { RIGHTOUT_REMOVAL_POLICY_VERSION, removalApprovalDescription, removalScopeBinding, resolveRemovalCatalogEntry, runRemovalSubmission, validateRemovalOperatorAttestations, validateRemovalPreflight, validateRemovalPublicToolInput, } from "./lib/removal.mjs";
import { createSmtpSender } from "./lib/smtp.mjs";
const LiveScanParameters = Type.Object({
    profileId: Type.String({
        pattern: "^profile_[a-f0-9]{16,32}$",
        description: "Opaque operator-configured profile reference. Contains no personal data.",
    }),
    brokerIds: Type.Array(Type.String({ pattern: "^[a-z0-9_]{2,24}$" }), { minItems: 1, maxItems: 2, uniqueItems: true }),
}, { additionalProperties: false });
const RemovalParameters = Type.Object({
    profileId: Type.String({
        pattern: "^profile_[a-f0-9]{16,32}$",
        description: "Opaque operator-configured profile reference. Contains no personal data.",
    }),
    brokerId: Type.String({
        pattern: "^[a-z0-9_]{2,24}$",
        description: "Catalog broker with a supported, official email-removal lane.",
    }),
    requestKind: Type.Literal("delete_and_opt_out", {
        description: "Catalog-validated deletion and sale/share opt-out request.",
    }),
}, { additionalProperties: false });
async function loadCatalog(path) {
    const text = await readFile(path, { encoding: "utf-8" });
    return JSON.parse(text);
}
function scanScopeBinding(input, attestations) {
    return JSON.stringify(["scan", input.profileId, input.brokerIds, attestations]);
}
function removalDedupeKey(input) {
    return JSON.stringify([input.profileId, input.brokerId, input.requestKind]);
}
function assertSupportedBrokerScope(catalog, input) {
    const brokers = Array.isArray(catalog.brokers) ? catalog.brokers : [];
    for (const brokerId of input.brokerIds) {
        const broker = brokers.find((value) => {
            if (!value || typeof value !== "object" || Array.isArray(value))
                return false;
            const entry = value;
            const scan = entry.scan;
            return entry.id === brokerId
                && entry.category === "people_search"
                && scan?.supported === true
                && scan.automated_access_policy === "search_index_only_no_publisher_access";
        });
        if (!broker)
            throw new Error("unsupported_broker");
    }
}
function scanAttestationSnapshot(config, input) {
    return validateOperatorAttestations(input, config?.operatorAttestations);
}
function removalAttestationSnapshot(config, input) {
    return validateRemovalOperatorAttestations(input, config?.removalAttestations);
}
function isSecretRef(value) {
    if (typeof value === "string")
        return /^\$\{?[A-Z][A-Z0-9_]*\}?$/.test(value);
    if (!value || typeof value !== "object" || Array.isArray(value))
        return false;
    const ref = value;
    return ["env", "file", "exec"].includes(String(ref.source))
        && typeof ref.provider === "string"
        && typeof ref.id === "string";
}
function secretFinding(rightout, path, title) {
    const parts = path.split(".");
    let value = rightout;
    for (const part of parts)
        value = value?.[part];
    if (value === undefined || isSecretRef(value))
        return undefined;
    return {
        checkId: `rightout.secretref.${path.replaceAll(".", "_")}`,
        severity: "critical",
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
        const approvalBindings = new Map();
        const submittedScopes = new Map();
        const approvalTtlMs = 120_000;
        const duplicateCooldownMs = 24 * 60 * 60_000;
        const catalogPath = api.resolvePath("skills/data-broker-removal/references/brokers/core.json");
        const catalogPromise = loadCatalog(catalogPath);
        const sendSmtpMail = createSmtpSender();
        function pruneTransientState(now = Date.now()) {
            for (const [toolCallId, approval] of approvalBindings) {
                if (approval.expiresAt <= now)
                    approvalBindings.delete(toolCallId);
            }
            for (const [scope, expiresAt] of submittedScopes) {
                if (expiresAt <= now)
                    submittedScopes.delete(scope);
            }
        }
        api.registerSecurityAuditCollector(({ config, sourceConfig }) => {
            const findings = [];
            const source = sourceConfig;
            const rightout = source.plugins?.entries?.rightout?.config;
            for (const candidate of [
                secretFinding(rightout, "braveApiKey", "RightOut Brave key is stored as plaintext"),
                secretFinding(rightout, "smtpTransport.username", "RightOut SMTP username is stored as plaintext"),
                secretFinding(rightout, "smtpTransport.password", "RightOut SMTP password is stored as plaintext"),
                secretFinding(rightout, "smtpTransport.fromAddress", "RightOut sender address is stored as plaintext"),
            ]) {
                if (candidate)
                    findings.push(candidate);
            }
            for (const [profileId, profile] of Object.entries(rightout?.profiles ?? {})) {
                if (!isSecretRef(profile?.payload)) {
                    findings.push({
                        checkId: `rightout.secretref.profile.${profileId}`,
                        severity: "critical",
                        title: "RightOut subject profile is stored as plaintext",
                        detail: "A private subject profile is not an OpenClaw SecretRef.",
                        remediation: "Migrate every profiles.*.payload value to a SecretRef, scrub plaintext residue, and run openclaw secrets audit --check.",
                    });
                }
            }
            const scanAttestations = rightout?.operatorAttestations;
            if (rightout?.braveApiKey !== undefined && (scanAttestations?.braveTermsAccepted !== true
                || scanAttestations?.braveTermsVersion !== BRAVE_TERMS_VERSION
                || scanAttestations?.braveCustomerResponsibilitiesAccepted !== true
                || scanAttestations?.subjectConsentReviewed !== true
                || !Array.isArray(scanAttestations?.authorizedProfileIds)
                || scanAttestations.authorizedProfileIds.length < 1
                || !scanAttestations?.authorizedProfileDigests
                || typeof scanAttestations.authorizedProfileDigests !== "object"
                || scanAttestations.authorizedProfileIds.some((profileId) => !/^[a-f0-9]{64}$/.test(scanAttestations.authorizedProfileDigests?.[profileId]))
                || !Array.isArray(scanAttestations?.authorizedBrokerIds)
                || scanAttestations.authorizedBrokerIds.length < 1)) {
                findings.push({
                    checkId: "rightout.scan_operator_attestations",
                    severity: "critical",
                    title: "RightOut scan attestations are incomplete",
                    detail: `Live scans require exact scope plus Brave terms version ${BRAVE_TERMS_VERSION} and customer responsibilities.`,
                    remediation: "Review the cited Brave terms and privacy notice, then set revision-bound operatorAttestations out of band.",
                });
            }
            const removalAttestations = rightout?.removalAttestations;
            if (rightout?.smtpTransport !== undefined && (removalAttestations?.rightoutRemovalPolicyAccepted !== true
                || removalAttestations?.rightoutRemovalPolicyVersion !== RIGHTOUT_REMOVAL_POLICY_VERSION
                || removalAttestations?.subjectConsentReviewed !== true
                || removalAttestations?.smtpAccountAuthorized !== true
                || removalAttestations?.minimumDisclosureAccepted !== true
                || !Array.isArray(removalAttestations?.authorizedProfileIds)
                || removalAttestations.authorizedProfileIds.length < 1
                || !removalAttestations?.authorizedProfileDigests
                || typeof removalAttestations.authorizedProfileDigests !== "object"
                || removalAttestations.authorizedProfileIds.some((profileId) => !/^[a-f0-9]{64}$/.test(removalAttestations.authorizedProfileDigests?.[profileId]))
                || !Array.isArray(removalAttestations?.authorizedBrokerIds)
                || removalAttestations.authorizedBrokerIds.length < 1
                || !Array.isArray(removalAttestations?.authorizedRequestKinds)
                || !removalAttestations.authorizedRequestKinds.includes("delete_and_opt_out")
                || typeof removalAttestations?.smtpTransportDigest !== "string"
                || !/^[a-f0-9]{64}$/.test(removalAttestations.smtpTransportDigest))) {
                findings.push({
                    checkId: "rightout.removal_operator_attestations",
                    severity: "critical",
                    title: "RightOut removal attestations are incomplete",
                    detail: `Removal writes require consent, SMTP authority, minimum-disclosure acceptance, exact scope, and policy ${RIGHTOUT_REMOVAL_POLICY_VERSION}.`,
                    remediation: "Review the removal policy and configure exact revision-bound removalAttestations out of band.",
                });
            }
            const runtime = config;
            const httpDeny = runtime.gateway?.tools?.deny;
            const missingDeny = ["rightout_live_scan", "rightout_submit_removal"].filter((tool) => !Array.isArray(httpDeny) || !httpDeny.includes(tool));
            if (missingDeny.length) {
                findings.push({
                    checkId: "rightout.gateway.tools_invoke",
                    severity: "warn",
                    title: "RightOut tools are reachable through direct Gateway tool invoke",
                    detail: `The following tools are not denied on the full-operator /tools/invoke surface: ${missingDeny.join(", ")}.`,
                    remediation: "Add both RightOut tools to gateway.tools.deny unless direct operator invocation is explicitly required.",
                });
            }
            return findings;
        });
        api.on("before_tool_call", async (event) => {
            if (event.toolName !== "rightout_live_scan" && event.toolName !== "rightout_submit_removal")
                return;
            if (!event.toolCallId)
                return { block: true, blockReason: "RightOut requires a host-authoritative tool call ID" };
            const config = api.pluginConfig;
            const catalog = await catalogPromise;
            pruneTransientState();
            approvalBindings.delete(event.toolCallId);
            if (event.toolName === "rightout_live_scan") {
                try {
                    const input = validatePublicToolInput(event.params);
                    assertSupportedBrokerScope(catalog, input);
                    const attestations = scanAttestationSnapshot(config, input);
                    const binding = scanScopeBinding(input, attestations);
                    const toolCallId = event.toolCallId;
                    return {
                        params: input,
                        requireApproval: {
                            title: "Run live data-broker scan",
                            description: approvalDescription(input),
                            severity: "critical",
                            allowedDecisions: ["allow-once", "deny"],
                            timeoutMs: approvalTtlMs,
                            timeoutBehavior: "deny",
                            onResolution(decision) {
                                if (decision === "allow-once") {
                                    approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                                }
                                else {
                                    approvalBindings.delete(toolCallId);
                                }
                            },
                        },
                    };
                }
                catch {
                    return { block: true, blockReason: "invalid, unsupported, or unattested RightOut scan scope" };
                }
            }
            try {
                const input = validateRemovalPublicToolInput(event.params);
                const broker = resolveRemovalCatalogEntry(catalog, input);
                const attestations = removalAttestationSnapshot(config, input);
                const dedupeKey = removalDedupeKey(input);
                if (submittedScopes.has(dedupeKey))
                    return { block: true, blockReason: "duplicate RightOut removal request is cooling down" };
                const binding = removalScopeBinding(input, attestations, broker);
                const toolCallId = event.toolCallId;
                return {
                    params: input,
                    requireApproval: {
                        title: "Submit broker removal request",
                        description: removalApprovalDescription(input, broker),
                        severity: "critical",
                        allowedDecisions: ["allow-once", "deny"],
                        timeoutMs: approvalTtlMs,
                        timeoutBehavior: "deny",
                        onResolution(decision) {
                            if (decision === "allow-once") {
                                approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs, toolName: event.toolName });
                            }
                            else {
                                approvalBindings.delete(toolCallId);
                            }
                        },
                    },
                };
            }
            catch {
                return { block: true, blockReason: "invalid, unsupported, unconsented, or unattested RightOut removal scope" };
            }
        });
        api.registerTool({
            name: "rightout_live_scan",
            label: "RightOut live scan",
            description: "Run a read-only live Brave index scan of supported catalog brokers. Requires native OpenClaw allow-once approval. Never authorizes or submits a removal.",
            parameters: LiveScanParameters,
            async execute(toolCallId, params, signal) {
                let input;
                try {
                    input = validatePublicToolInput(params);
                }
                catch {
                    throw new Error("rightout_approval_binding_failed");
                }
                const config = api.pluginConfig;
                const catalog = await catalogPromise;
                assertSupportedBrokerScope(catalog, input);
                let attestations;
                try {
                    attestations = scanAttestationSnapshot(config, input);
                }
                catch {
                    // Missing or changed attestations invalidate the approval binding.
                }
                pruneTransientState();
                const approval = approvalBindings.get(toolCallId);
                approvalBindings.delete(toolCallId);
                if (!approval || approval.toolName !== "rightout_live_scan" || !attestations || approval.binding !== scanScopeBinding(input, attestations)) {
                    throw new Error("rightout_approval_binding_failed");
                }
                if (!config || typeof config.braveApiKey !== "string" || typeof config.profiles?.[input.profileId]?.payload !== "string") {
                    throw new Error("rightout_not_configured");
                }
                const guardedFetch = async ({ url, allowedHosts, ...options }) => fetchWithSsrFGuard({
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
                });
                return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
            },
        }, { optional: true });
        api.registerTool({
            name: "rightout_submit_removal",
            label: "RightOut submit removal",
            description: "Send one catalog-locked broker deletion and opt-out email through the operator's approved SMTP account. Requires a separate native OpenClaw allow-once approval. Submission is never reported as confirmed removal.",
            parameters: RemovalParameters,
            async execute(toolCallId, params, signal) {
                let input;
                try {
                    input = validateRemovalPublicToolInput(params);
                }
                catch {
                    throw new Error("rightout_approval_binding_failed");
                }
                const config = api.pluginConfig;
                const catalog = await catalogPromise;
                const broker = resolveRemovalCatalogEntry(catalog, input);
                let attestations;
                try {
                    attestations = removalAttestationSnapshot(config, input);
                }
                catch {
                    // Missing or changed attestations invalidate the approval binding.
                }
                pruneTransientState();
                const approval = approvalBindings.get(toolCallId);
                approvalBindings.delete(toolCallId);
                if (!approval || approval.toolName !== "rightout_submit_removal" || !attestations || approval.binding !== removalScopeBinding(input, attestations, broker)) {
                    throw new Error("rightout_approval_binding_failed");
                }
                if (!config || typeof config.profiles?.[input.profileId]?.payload !== "string" || !config.smtpTransport) {
                    throw new Error("rightout_not_configured");
                }
                validateRemovalPreflight({
                    input,
                    catalog,
                    profilePayload: config.profiles[input.profileId].payload,
                    smtpConfig: config.smtpTransport,
                    operatorAttestations: attestations,
                });
                const dedupeKey = removalDedupeKey(input);
                if (submittedScopes.has(dedupeKey))
                    throw new Error("rightout_duplicate_removal_request");
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
                    return { content: [{ type: "text", text: JSON.stringify(report) }], details: report };
                }
                catch (error) {
                    const code = error instanceof Error ? error.message : "";
                    if (code === "rightout_removal_transport_failed" || code === "rightout_removal_not_accepted") {
                        submittedScopes.set(dedupeKey, Date.now() + duplicateCooldownMs);
                    }
                    else {
                        submittedScopes.delete(dedupeKey);
                    }
                    throw error;
                }
            },
        }, { optional: true });
    },
});
