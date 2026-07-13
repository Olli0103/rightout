const SHA1 = /^[a-f0-9]{40}$/;

function sha(value) {
  if (typeof value !== "string" || !SHA1.test(value)) throw new Error("rightout_unbroker_upstream_observation_invalid");
  return value;
}

export function compareUnbrokerUpstream({
  pinnedCommit,
  evidenceCurrentCommit,
  currentCommit,
  pinnedSubtreeSha,
  currentSubtreeSha,
  checkedAt = new Date(),
}) {
  const pinned = sha(pinnedCommit);
  const evidenceCommit = sha(evidenceCurrentCommit);
  const observedCommit = sha(currentCommit);
  const pinnedTree = sha(pinnedSubtreeSha);
  const observedTree = sha(currentSubtreeSha);
  if (observedTree !== pinnedTree) throw new Error("rightout_unbroker_subtree_changed_review_required");
  const timestamp = checkedAt instanceof Date ? checkedAt : new Date(checkedAt);
  if (!Number.isFinite(timestamp.getTime())) throw new Error("rightout_unbroker_upstream_observation_invalid");
  return {
    state: "current_unbroker_subtree_matches_pinned_baseline",
    pinned_commit: pinned,
    evidence_current_commit: evidenceCommit,
    current_commit: observedCommit,
    upstream_head_advanced_since_evidence: observedCommit !== evidenceCommit,
    subtree_sha: observedTree,
    checked_at: timestamp.toISOString(),
  };
}
