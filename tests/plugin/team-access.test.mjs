import assert from "node:assert/strict";
import test from "node:test";

import { resolveTeamMember, teamSessionBindingDigest, validateTeamAccess } from "../../lib/team-access.mjs";
import { workerSessionBindingDigest } from "../../lib/autonomy-worker.mjs";

const profileA = "profile_0123456789abcdef";
const profileB = "profile_fedcba9876543210";
const ownerContext = { sessionKey: "agent:main:rightout-owner", agentId: "main" };
const viewerContext = { sessionKey: "agent:main:rightout-viewer", agentId: "main" };
const access = {
  member_0123456789abcdef: {
    role: "owner",
    sessionBindingDigest: teamSessionBindingDigest(ownerContext),
    authorizedProfileIds: [profileA, profileB],
  },
  member_fedcba9876543210: {
    role: "viewer",
    sessionBindingDigest: teamSessionBindingDigest(viewerContext),
    authorizedProfileIds: [profileB],
  },
};

test("team session bindings are deterministic, one-way, and protocol-separated", () => {
  const digest = teamSessionBindingDigest(ownerContext);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.equal(digest, teamSessionBindingDigest(ownerContext));
  assert.notEqual(digest, workerSessionBindingDigest(ownerContext));
  assert.doesNotMatch(digest, /agent|owner|main/u);
});

test("team access resolves only the exact bound member and configured profile scopes", () => {
  const members = validateTeamAccess(access, [profileA, profileB]);
  assert.equal(members.length, 2);
  const viewer = resolveTeamMember(access, [profileA, profileB], viewerContext);
  assert.equal(viewer.role, "viewer");
  assert.deepEqual(viewer.authorized_profile_ids, [profileB]);
  assert.throws(() => resolveTeamMember(access, [profileA, profileB], {
    sessionKey: "agent:main:rightout-unbound", agentId: "main",
  }), /session_unauthorized/);
});

test("team access rejects missing owners, duplicate sessions, unknown profiles, and extra authority fields", () => {
  assert.throws(() => validateTeamAccess({
    member_fedcba9876543210: access.member_fedcba9876543210,
  }, [profileA, profileB]), /access_invalid/);
  assert.throws(() => validateTeamAccess({
    ...access,
    member_aaaaaaaaaaaaaaaa: { ...access.member_fedcba9876543210, role: "manager" },
  }, [profileA, profileB]), /access_invalid/);
  assert.throws(() => validateTeamAccess({
    ...access,
    member_fedcba9876543210: { ...access.member_fedcba9876543210, authorizedProfileIds: ["profile_aaaaaaaaaaaaaaaa"] },
  }, [profileA, profileB]), /access_invalid/);
  assert.throws(() => validateTeamAccess({
    ...access,
    member_0123456789abcdef: { ...access.member_0123456789abcdef, canMutate: true },
  }, [profileA, profileB]), /access_invalid/);
});
