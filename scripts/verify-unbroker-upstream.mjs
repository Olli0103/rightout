#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { compareUnbrokerUpstream } from "./unbroker-upstream-contract.mjs";

const root = new URL("../", import.meta.url);
const evidence = JSON.parse(readFileSync(new URL("docs/unbroker-upstream-refresh.json", root), "utf8"));
const baseline = JSON.parse(readFileSync(new URL("docs/unbroker-parity-baseline.json", root), "utf8"));
const catalog = JSON.parse(readFileSync(new URL("skills/data-broker-removal/references/brokers/unbroker-parity.json", root), "utf8"));
const expectedRepository = "https://github.com/NousResearch/hermes-agent.git";
const subtreePath = "optional-skills/security/unbroker";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

if (
  evidence.schema_version !== 1
  || evidence.source_repository !== expectedRepository
  || evidence.branch !== "main"
  || evidence.subtree_path !== subtreePath
  || evidence.pinned_commit !== baseline.reference?.commit
  || evidence.pinned_commit !== catalog.reference_commit
  || !/^[a-f0-9]{40}$/.test(evidence.pinned_subtree_sha ?? "")
  || !/^[a-f0-9]{40}$/.test(evidence.current_commit ?? "")
  || !/^[a-f0-9]{40}$/.test(evidence.current_subtree_sha ?? "")
  || evidence.unbroker_subtree_unchanged !== true
  || evidence.pinned_subtree_sha !== evidence.current_subtree_sha
  || !Number.isFinite(Date.parse(evidence.checked_at))
  || Date.parse(evidence.checked_at) > Date.now() + 300_000
) fail("rightout_unbroker_upstream_evidence_invalid");

const worktree = mkdtempSync(join(tmpdir(), "rightout-unbroker-upstream-"));
try {
  execFileSync("git", ["init", "--quiet", worktree], { stdio: "ignore" });
  execFileSync("git", ["-C", worktree, "fetch", "--quiet", "--depth=1", "--no-tags", expectedRepository, "refs/heads/main"], {
    stdio: "ignore",
    timeout: 120_000,
  });
  const currentCommit = execFileSync("git", ["-C", worktree, "rev-parse", "FETCH_HEAD"], { encoding: "utf8" }).trim();
  const currentTree = execFileSync("git", ["-C", worktree, "rev-parse", `FETCH_HEAD:${subtreePath}`], { encoding: "utf8" }).trim();
  try {
    process.stdout.write(`${JSON.stringify(compareUnbrokerUpstream({
      pinnedCommit: evidence.pinned_commit,
      evidenceCurrentCommit: evidence.current_commit,
      currentCommit,
      pinnedSubtreeSha: evidence.pinned_subtree_sha,
      currentSubtreeSha: currentTree,
    }))}\n`);
  } catch (error) {
    fail(error instanceof Error ? error.message : "rightout_unbroker_upstream_observation_invalid");
  }
} finally {
  rmSync(worktree, { recursive: true, force: true });
}
