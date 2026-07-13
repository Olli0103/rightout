import assert from "node:assert/strict";
import test from "node:test";

import { compareUnbrokerUpstream } from "../../scripts/unbroker-upstream-contract.mjs";

const pinnedCommit = "1".repeat(40);
const evidenceCurrentCommit = "2".repeat(40);
const pinnedSubtreeSha = "3".repeat(40);

test("unrelated upstream head drift is explicit and does not invalidate an unchanged pinned subtree", () => {
  const result = compareUnbrokerUpstream({
    pinnedCommit,
    evidenceCurrentCommit,
    currentCommit: "4".repeat(40),
    pinnedSubtreeSha,
    currentSubtreeSha: pinnedSubtreeSha,
    checkedAt: "2026-07-13T17:36:01Z",
  });
  assert.equal(result.upstream_head_advanced_since_evidence, true);
  assert.equal(result.subtree_sha, pinnedSubtreeSha);
});

test("a changed Unbroker subtree remains a hard manual-review gate", () => {
  assert.throws(() => compareUnbrokerUpstream({
    pinnedCommit,
    evidenceCurrentCommit,
    currentCommit: "4".repeat(40),
    pinnedSubtreeSha,
    currentSubtreeSha: "5".repeat(40),
  }), /rightout_unbroker_subtree_changed_review_required/);
});

test("malformed observations fail closed", () => {
  assert.throws(() => compareUnbrokerUpstream({
    pinnedCommit,
    evidenceCurrentCommit,
    currentCommit: "not-a-commit",
    pinnedSubtreeSha,
    currentSubtreeSha: pinnedSubtreeSha,
  }), /rightout_unbroker_upstream_observation_invalid/);
});
