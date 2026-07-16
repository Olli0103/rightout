const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_TOKEN = /^[a-z0-9_]{2,80}$/;
function cleanCell(value, max = 160) {
    if (value === null || value === undefined)
        return "";
    const text = String(value).replace(/[\r\n\t]+/g, " ").trim();
    return text.slice(0, max);
}
function assertStatus(value) {
    if (!value || typeof value !== "object" || !SAFE_PROFILE_ID.test(value.subject_ref ?? "")
        || !Array.isArray(value.cases) || !Array.isArray(value.preference_controls)
        || value.preference_controls.length !== 1) {
        throw new Error("rightout_report_state_invalid");
    }
    for (const item of value.cases) {
        if (!item || !SAFE_TOKEN.test(item.broker_id ?? "") || !SAFE_TOKEN.test(item.state ?? ""))
            throw new Error("rightout_report_state_invalid");
    }
    for (const item of value.preference_controls) {
        if (!item || item.control_id !== "global_privacy_control"
            || !["needs_human_verification", "enabled_human_verified"].includes(item.state)
            || item.deletion_request !== false || item.deletion_confirmed !== false
            || item.browser_configuration_performed_by_rightout !== false
            || item.provider_compliance !== "needs_evidence_per_site")
            throw new Error("rightout_report_state_invalid");
    }
}
export function createReportExport(caseStatus, { generatedAt = new Date().toISOString() } = {}) {
    assertStatus(caseStatus);
    const cases = [...caseStatus.cases].sort((a, b) => a.broker_id.localeCompare(b.broker_id));
    const preferenceControls = structuredClone(caseStatus.preference_controls);
    const headers = ["subject_ref", "broker_id", "state", "submission_channel", "next_recheck_at", "confirmation_scope", "coverage_gap"];
    const rows = [headers, ...cases.map((item) => [
            caseStatus.subject_ref,
            cleanCell(item.broker_id),
            cleanCell(item.state),
            cleanCell(item.submission_channel),
            cleanCell(item.next_recheck_at),
            cleanCell(item.removal_confirmation_scope),
            cleanCell(item.coverage_gap),
        ])];
    const markdown = [
        `# RightOut status - ${caseStatus.subject_ref}`,
        "",
        `Generated: ${generatedAt}`,
        "",
        `- Confirmed removed: ${Number(caseStatus.metrics?.confirmed_removed ?? 0)}`,
        `- In flight: ${Number(caseStatus.metrics?.in_flight ?? 0)}`,
        `- Needs reconciliation: ${Number(caseStatus.metrics?.needs_reconciliation ?? 0)}`,
        `- Human tasks: ${Number(caseStatus.metrics?.human_tasks ?? 0)}`,
        "",
        "## Preference controls",
        "",
        ...preferenceControls.flatMap((item) => [
            `- ${cleanCell(item.control_id)}: ${cleanCell(item.state)}`,
            "  - Deletion request: false",
            "  - Deletion confirmed: false",
            "  - Provider compliance: needs_evidence_per_site",
        ]),
        "",
        "Preference signals are not deletion requests or deletion proof.",
        "",
        "## Removal cases",
        "",
        "| Broker | State | Next recheck | Scope | Coverage gap |",
        "| --- | --- | --- | --- | --- |",
        ...cases.map((item) => `| ${cleanCell(item.broker_id)} | ${cleanCell(item.state)} | ${cleanCell(item.next_recheck_at) || "-"} | ${cleanCell(item.removal_confirmation_scope) || "-"} | ${cleanCell(item.coverage_gap) || "-"} |`),
    ].join("\n");
    return {
        report_version: 1,
        subject_ref: caseStatus.subject_ref,
        generated_at: generatedAt,
        structured: {
            counts: { ...caseStatus.counts },
            metrics: { ...caseStatus.metrics },
            cases,
            preference_controls: preferenceControls,
        },
        markdown,
        google_sheets_rows: rows,
        google_sheets_range: `Sheet1!A1:G${rows.length}`,
        provider_reads: 0,
        provider_writes: 0,
        raw_pii_in_report: false,
    };
}
