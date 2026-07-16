import { createHash } from "node:crypto";
const SAFE_ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
function deepFreeze(value) {
    if (value && typeof value === "object" && !Object.isFrozen(value)) {
        for (const nested of Object.values(value))
            deepFreeze(nested);
        Object.freeze(value);
    }
    return value;
}
export const UK_RIGHTS_CONTRACT = deepFreeze({
    contract_id: "uk_controller_erasure_objection_v1",
    reviewed_at: "2026-07-16",
    next_review_at: "2026-09-17",
    request_kind: "uk_erasure_objection",
    process_class: "uk_controller_email_erasure",
    template_id: "uk_erasure_objection_v1",
    eligible_jurisdictions: ["UK"],
    identity_policy: "controller_may_request_proportionate_follow_up_human_review",
    deadline_policy: "one_calendar_month_conservative_recheck_v1",
    legal_sources: [
        "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-erasure/",
        "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-object/",
        "https://ico.org.uk/about-the-ico/what-we-do/legislation-we-cover/data-use-and-access-act-2025/the-data-use-and-access-act-2025-duaa-summary-of-the-changes/",
    ],
});
export function ukRightsContractDigest() {
    return createHash("sha256").update(JSON.stringify(UK_RIGHTS_CONTRACT)).digest("hex");
}
function receivedDate(value) {
    if (typeof value !== "string" || !SAFE_ISO_TIMESTAMP.test(value)) {
        throw new Error("rightout_uk_deadline_invalid");
    }
    const parsed = new Date(value);
    if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== (value.length === 20 ? value.replace("Z", ".000Z") : value)) {
        throw new Error("rightout_uk_deadline_invalid");
    }
    return parsed;
}
/**
 * The ICO expresses the ordinary response period as one calendar month. RightOut
 * schedules its recheck at the start of the corresponding due date, rather than
 * claiming the end-of-day/weekend/public-holiday legal deadline. This is
 * deliberately conservative and leaves any extension or identity-clock change
 * to human-reviewed controller evidence.
 */
export function calculateUkRightsResponseWindow(receivedAt) {
    const received = receivedDate(receivedAt);
    const year = received.getUTCFullYear();
    const month = received.getUTCMonth();
    const day = received.getUTCDate();
    const targetYear = month === 11 ? year + 1 : year;
    const targetMonth = (month + 1) % 12;
    const lastTargetDay = new Date(Date.UTC(targetYear, targetMonth + 1, 0)).getUTCDate();
    const dueDay = Math.min(day, lastTargetDay);
    const dueDate = [
        String(targetYear).padStart(4, "0"),
        String(targetMonth + 1).padStart(2, "0"),
        String(dueDay).padStart(2, "0"),
    ].join("-");
    return {
        policy: UK_RIGHTS_CONTRACT.deadline_policy,
        ordinary_due_date: dueDate,
        conservative_recheck_at: `${dueDate}T00:00:00.000Z`,
        extension_applied: false,
        identity_clock_change_applied: false,
        weekend_or_public_holiday_adjustment: "not_applied_conservative_earlier_recheck",
        extension_or_identity_change_requires: "human_reviewed_controller_evidence",
    };
}
export function assertUkRightsCatalogRoute(broker, removal) {
    if (broker?.process_class !== UK_RIGHTS_CONTRACT.process_class
        || removal?.request_kinds?.length !== 1
        || removal.request_kinds[0] !== UK_RIGHTS_CONTRACT.request_kind
        || removal.template_id !== UK_RIGHTS_CONTRACT.template_id
        || removal.identity_verification !== UK_RIGHTS_CONTRACT.identity_policy
        || removal.deadline_policy !== UK_RIGHTS_CONTRACT.deadline_policy
        || removal.rights_contract_id !== UK_RIGHTS_CONTRACT.contract_id
        || JSON.stringify(removal.eligible_jurisdictions) !== JSON.stringify(UK_RIGHTS_CONTRACT.eligible_jurisdictions)
        || removal.processing_days !== 28) {
        throw new Error("unsupported_removal_lane");
    }
    return {
        rightsContractId: UK_RIGHTS_CONTRACT.contract_id,
        rightsContractDigest: ukRightsContractDigest(),
        deadlinePolicy: UK_RIGHTS_CONTRACT.deadline_policy,
    };
}
