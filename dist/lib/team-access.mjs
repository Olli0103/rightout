import { createHash } from "node:crypto";
const SAFE_MEMBER_ID = /^member_[a-f0-9]{16,32}$/;
const SAFE_PROFILE_ID = /^profile_[a-f0-9]{16,32}$/;
const SAFE_SHA256 = /^[a-f0-9]{64}$/;
const ROLES = new Set(["owner", "manager", "viewer"]);
export function teamSessionBindingDigest({ sessionKey, agentId }) {
    if (typeof sessionKey !== "string" || !/^[A-Za-z0-9._:@/-]{8,240}$/.test(sessionKey)
        || typeof agentId !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(agentId))
        throw new Error("rightout_team_session_required");
    return createHash("sha256").update(JSON.stringify(["rightout-team-session-v1", sessionKey, agentId])).digest("hex");
}
export function validateTeamAccess(value, configuredProfileIds) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        throw new Error("rightout_team_access_invalid");
    const configured = new Set(configuredProfileIds);
    const members = Object.entries(value).map(([memberId, record]) => {
        if (!SAFE_MEMBER_ID.test(memberId) || !record || typeof record !== "object" || Array.isArray(record))
            throw new Error("rightout_team_access_invalid");
        if (Object.keys(record).some((key) => !["role", "sessionBindingDigest", "authorizedProfileIds"].includes(key)))
            throw new Error("rightout_team_access_invalid");
        if (!ROLES.has(record.role) || !SAFE_SHA256.test(record.sessionBindingDigest ?? ""))
            throw new Error("rightout_team_access_invalid");
        if (!Array.isArray(record.authorizedProfileIds) || record.authorizedProfileIds.length < 1 || record.authorizedProfileIds.length > 100
            || record.authorizedProfileIds.some((id) => !SAFE_PROFILE_ID.test(id) || !configured.has(id))
            || new Set(record.authorizedProfileIds).size !== record.authorizedProfileIds.length)
            throw new Error("rightout_team_access_invalid");
        return { member_id: memberId, role: record.role, session_binding_digest: record.sessionBindingDigest, authorized_profile_ids: [...record.authorizedProfileIds].sort() };
    });
    if (members.length < 1 || members.length > 100 || !members.some((member) => member.role === "owner"))
        throw new Error("rightout_team_access_invalid");
    if (new Set(members.map((member) => member.session_binding_digest)).size !== members.length)
        throw new Error("rightout_team_access_invalid");
    return members.sort((a, b) => a.member_id.localeCompare(b.member_id));
}
export function resolveTeamMember(value, configuredProfileIds, context) {
    const members = validateTeamAccess(value, configuredProfileIds);
    const digest = teamSessionBindingDigest(context);
    const member = members.find((candidate) => candidate.session_binding_digest === digest);
    if (!member)
        throw new Error("rightout_team_session_unauthorized");
    return structuredClone(member);
}
