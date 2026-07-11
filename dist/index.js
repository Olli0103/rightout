import { readFile } from "node:fs/promises";
import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { buildHostnameAllowlistPolicyFromSuffixAllowlist, fetchWithSsrFGuard, } from "openclaw/plugin-sdk/ssrf-runtime";
import { approvalDescription, runLiveScan, validateOperatorAttestations, validatePublicToolInput, } from "./lib/live-scan.mjs";
const LiveScanParameters = Type.Object({
    profileId: Type.String({
        pattern: "^profile_[a-f0-9]{16,32}$",
        description: "Opaque operator-configured profile reference. Contains no personal data.",
    }),
    brokerIds: Type.Array(Type.String({ pattern: "^[a-z0-9_]{2,24}$" }), { minItems: 1, maxItems: 2, uniqueItems: true }),
}, { additionalProperties: false });
async function loadCatalog(path) {
    const text = await readFile(path, { encoding: "utf-8" });
    return JSON.parse(text);
}
function scopeBinding(input, attestations) {
    return JSON.stringify([input.profileId, input.brokerIds, attestations]);
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
                && scan.automated_access_policy === "operator_permission_required";
        });
        if (!broker)
            throw new Error("unsupported_broker");
    }
}
function operatorAttestationSnapshot(config, input) {
    return validateOperatorAttestations(input, config?.operatorAttestations);
}
function isSecretRef(value) {
    if (typeof value === "string") {
        return /^\$\{?[A-Z][A-Z0-9_]*\}?$/.test(value);
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const ref = value;
    return ["env", "file", "exec"].includes(String(ref.source))
        && typeof ref.provider === "string"
        && typeof ref.id === "string";
}
export default definePluginEntry({
    id: "rightout",
    name: "RightOut",
    description: "Approval-gated read-only live data-broker scans with PII-safe reports",
    register(api) {
        const approvalBindings = new Map();
        const approvalTtlMs = 120_000;
        const catalogPath = api.resolvePath("skills/data-broker-removal/references/brokers/core.json");
        const catalogPromise = loadCatalog(catalogPath);
        function pruneApprovalBindings(now = Date.now()) {
            for (const [toolCallId, approval] of approvalBindings) {
                if (approval.expiresAt <= now)
                    approvalBindings.delete(toolCallId);
            }
        }
        api.registerSecurityAuditCollector(({ config, sourceConfig }) => {
            const findings = [];
            const source = sourceConfig;
            const rightout = source.plugins?.entries?.rightout?.config;
            if (rightout && rightout.braveApiKey !== undefined && !isSecretRef(rightout.braveApiKey)) {
                findings.push({
                    checkId: "rightout.secretref.brave_key",
                    severity: "critical",
                    title: "RightOut Brave key is stored as plaintext",
                    detail: "The configured Brave Search key is not an OpenClaw SecretRef.",
                    remediation: "Migrate plugins.entries.rightout.config.braveApiKey to a SecretRef and run openclaw secrets audit --check.",
                });
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
            const attestations = rightout?.operatorAttestations;
            if (rightout && (attestations?.braveTermsAccepted !== true
                || !Array.isArray(attestations?.authorizedProfileIds)
                || attestations.authorizedProfileIds.length < 1
                || !Array.isArray(attestations?.authorizedBrokerIds)
                || attestations.authorizedBrokerIds.length < 1)) {
                findings.push({
                    checkId: "rightout.operator_attestations",
                    severity: "critical",
                    title: "RightOut operator attestations are incomplete",
                    detail: "Live scans require exact authorized profile IDs, Brave terms acceptance, and explicit broker access authorization.",
                    remediation: "Set operatorAttestations only after the operator has verified the applicable authority and provider/broker terms out of band.",
                });
            }
            const runtime = config;
            const httpDeny = runtime.gateway?.tools?.deny;
            if (!Array.isArray(httpDeny) || !httpDeny.includes("rightout_live_scan")) {
                findings.push({
                    checkId: "rightout.gateway.tools_invoke",
                    severity: "warn",
                    title: "RightOut is reachable through direct Gateway tool invoke",
                    detail: "The live scan tool is not denied on the full-operator /tools/invoke surface.",
                    remediation: "Add rightout_live_scan to gateway.tools.deny unless direct operator invocation is explicitly required.",
                });
            }
            return findings;
        });
        api.on("before_tool_call", async (event) => {
            if (event.toolName !== "rightout_live_scan") {
                return;
            }
            if (!event.toolCallId) {
                return { block: true, blockReason: "RightOut requires a host-authoritative tool call ID" };
            }
            let input;
            let attestationSnapshot;
            try {
                input = validatePublicToolInput(event.params);
                assertSupportedBrokerScope(await catalogPromise, input);
                attestationSnapshot = operatorAttestationSnapshot(api.pluginConfig, input);
            }
            catch {
                return { block: true, blockReason: "invalid, unsupported, or unattested RightOut scan scope" };
            }
            const toolCallId = event.toolCallId;
            const binding = scopeBinding(input, attestationSnapshot);
            pruneApprovalBindings();
            approvalBindings.delete(toolCallId);
            return {
                params: input,
                requireApproval: {
                    title: "Run live data-broker scan",
                    description: approvalDescription(input),
                    severity: "critical",
                    allowedDecisions: ["allow-once", "deny"],
                    timeoutMs: 120_000,
                    timeoutBehavior: "deny",
                    onResolution(decision) {
                        if (decision === "allow-once") {
                            approvalBindings.set(toolCallId, { binding, expiresAt: Date.now() + approvalTtlMs });
                        }
                        else {
                            approvalBindings.delete(toolCallId);
                        }
                    },
                },
            };
        });
        api.registerTool({
            name: "rightout_live_scan",
            label: "RightOut live scan",
            description: "Run a read-only live scan of explicitly selected, supported catalog brokers. Requires a native OpenClaw allow-once approval. Never submits removals, sends email, stores PII, or returns raw PII/URLs.",
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
                let attestationSnapshot;
                try {
                    attestationSnapshot = operatorAttestationSnapshot(config, input);
                }
                catch {
                    // Missing or changed attestations invalidate the approval binding.
                }
                pruneApprovalBindings();
                const approval = approvalBindings.get(toolCallId);
                approvalBindings.delete(toolCallId);
                if (!approval || !attestationSnapshot || approval.binding !== scopeBinding(input, attestationSnapshot)) {
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
                    input: {
                        ...input,
                        subject: config.profiles?.[input.profileId]?.payload,
                    },
                    catalog,
                    apiKey: config.braveApiKey,
                    maxCandidatesPerBroker: config.maxCandidatesPerBroker,
                    guardedFetch,
                    signal,
                    operatorAttestations: attestationSnapshot,
                });
                return {
                    content: [{ type: "text", text: JSON.stringify(report) }],
                    details: report,
                };
            },
        }, { optional: true });
    },
});
