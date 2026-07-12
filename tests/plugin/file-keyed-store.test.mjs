import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, rmdir, symlink, unlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createEncryptedFileKeyedStore } from "../../lib/file-keyed-store.mjs";

const secret = "dummy-state-key-with-more-than-32-characters";

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

test("community-plugin file store is encrypted, durable, atomic, and deduplicating", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "rightout-file-store-"));
  try {
    const options = { stateDir, namespace: "rightout-test-state", maxEntries: 5, getSecret: () => secret };
    const first = createEncryptedFileKeyedStore(options);
    assert.equal(await first.registerIfAbsent("opaque-key", { private: "must-not-appear" }), true);
    assert.equal(await first.registerIfAbsent("opaque-key", { private: "replacement" }), false);
    assert.deepEqual(await first.lookup("opaque-key"), { private: "must-not-appear" });
    const bytes = await readFile(join(stateDir, "rightout-plugin-state-v1", "rightout-test-state.json.enc"));
    assert.equal(bytes.includes(Buffer.from("must-not-appear")), false);
    const restarted = createEncryptedFileKeyedStore(options);
    assert.deepEqual(await restarted.lookup("opaque-key"), { private: "must-not-appear" });
    assert.deepEqual(await restarted.consume("opaque-key"), { private: "must-not-appear" });
    assert.equal(await restarted.lookup("opaque-key"), undefined);
    const contenderA = createEncryptedFileKeyedStore(options);
    const contenderB = createEncryptedFileKeyedStore(options);
    const claims = await Promise.all([
      contenderA.registerIfAbsent("shared-dedupe", { owner: "a" }),
      contenderB.registerIfAbsent("shared-dedupe", { owner: "b" }),
    ]);
    assert.deepEqual(claims.sort(), [false, true]);
  } finally { await rm(stateDir, { recursive: true, force: true }); }
});

test("TTL expiry, unsafe permissions, symlinks, and wrong keys fail closed", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "rightout-file-store-security-"));
  let at = 1_000;
  try {
    const options = { stateDir, namespace: "rightout-test-state", maxEntries: 5, defaultTtlMs: 10, getSecret: () => secret, now: () => at };
    const store = createEncryptedFileKeyedStore(options);
    await store.register("opaque-key", { value: 1 });
    const encryptedFile = join(stateDir, "rightout-plugin-state-v1", "rightout-test-state.json.enc");
    const beforePrune = await readFile(encryptedFile);
    at = 1_011;
    assert.deepEqual(await store.entries(), []);
    const afterPrune = await readFile(encryptedFile);
    assert.notDeepEqual(afterPrune, beforePrune, "entries() must persist TTL pruning");
    assert.equal(await store.lookup("opaque-key"), undefined);
    await store.register("opaque-key", { value: 2 });
    const file = encryptedFile;
    await chmod(file, 0o644);
    await assert.rejects(store.lookup("opaque-key"), /file_unsafe/);
    await chmod(file, 0o600);
    const wrong = createEncryptedFileKeyedStore({ ...options, getSecret: () => "different-state-key-with-more-than-32-characters" });
    await assert.rejects(wrong.lookup("opaque-key"), /decryption_failed/);
  } finally { await rm(stateDir, { recursive: true, force: true }); }

  const root = await mkdtemp(join(tmpdir(), "rightout-file-store-link-"));
  const outside = await mkdtemp(join(tmpdir(), "rightout-file-store-outside-"));
  try {
    await symlink(outside, join(root, "rightout-plugin-state-v1"));
    const linked = createEncryptedFileKeyedStore({ stateDir: root, namespace: "rightout-test-state", maxEntries: 5, getSecret: () => secret });
    await assert.rejects(linked.register("opaque-key", { value: 1 }), /directory_unsafe/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("an untouched legacy entry receives and persists finite retention on first read", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "rightout-file-store-legacy-ttl-"));
  let at = 1_000;
  try {
    const base = { stateDir, namespace: "rightout-test-state", maxEntries: 5, getSecret: () => secret, now: () => at };
    const legacy = createEncryptedFileKeyedStore(base);
    await legacy.register("legacy-key", { value: "retained-until-deadline" });
    const encryptedFile = join(stateDir, "rightout-plugin-state-v1", "rightout-test-state.json.enc");
    const before = await readFile(encryptedFile);

    at = 1_050;
    const upgraded = createEncryptedFileKeyedStore({ ...base, defaultTtlMs: 100 });
    assert.deepEqual(await upgraded.lookup("legacy-key"), { value: "retained-until-deadline" });
    const migrated = await readFile(encryptedFile);
    assert.notDeepEqual(migrated, before, "first read must persist the legacy TTL migration");
    assert.deepEqual(await upgraded.entries(), [{
      key: "legacy-key",
      value: { value: "retained-until-deadline" },
      createdAt: 1_000,
      expiresAt: 1_100,
    }]);

    at = 1_101;
    assert.equal(await upgraded.lookup("legacy-key"), undefined);
    assert.deepEqual(await upgraded.entries(), []);
  } finally { await rm(stateDir, { recursive: true, force: true }); }
});

test("a previous SecretRef key can decrypt once and reencrypt under the active key", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "rightout-file-store-rotation-"));
  const previousSecret = "dummy-previous-state-key-with-more-than-32-characters";
  const activeSecret = "dummy-active-state-key-with-more-than-32-characters";
  try {
    const original = createEncryptedFileKeyedStore({
      stateDir, namespace: "rightout-test-state", maxEntries: 5, getSecret: () => previousSecret,
    });
    await original.register("opaque-key", { value: "retained" });

    const rotating = createEncryptedFileKeyedStore({
      stateDir,
      namespace: "rightout-test-state",
      maxEntries: 5,
      getSecret: () => activeSecret,
      getPreviousSecrets: () => [previousSecret],
    });
    assert.deepEqual(await rotating.lookup("opaque-key"), { value: "retained" });
    assert.equal(await rotating.reencrypt(), 1);

    const activeOnly = createEncryptedFileKeyedStore({
      stateDir, namespace: "rightout-test-state", maxEntries: 5, getSecret: () => activeSecret,
    });
    assert.deepEqual(await activeOnly.lookup("opaque-key"), { value: "retained" });
    const previousOnly = createEncryptedFileKeyedStore({
      stateDir, namespace: "rightout-test-state", maxEntries: 5, getSecret: () => previousSecret,
    });
    await assert.rejects(previousOnly.lookup("opaque-key"), /decryption_failed/);
  } finally { await rm(stateDir, { recursive: true, force: true }); }
});

test("an old live-process lock is never stolen by another store instance", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "rightout-file-store-live-lock-"));
  try {
    const dataDir = join(stateDir, "rightout-plugin-state-v1");
    const lockDir = join(dataDir, "rightout-test-state.lock");
    await mkdir(dataDir, { mode: 0o700 });
    await mkdir(lockDir, { mode: 0o700 });
    const ownerPath = join(lockDir, "owner.json");
    const owner = { pid: process.pid, token: "a".repeat(32), createdAt: 1 };
    await writeFile(ownerPath, JSON.stringify(owner), { mode: 0o600 });
    await utimes(lockDir, new Date(0), new Date(0));
    const store = createEncryptedFileKeyedStore({ stateDir, namespace: "rightout-test-state", maxEntries: 5, getSecret: () => secret });
    const pending = store.register("opaque-key", { value: 1 });
    await new Promise((resolve) => setTimeout(resolve, 75));
    assert.deepEqual(JSON.parse(await readFile(ownerPath, "utf8")), owner);
    await unlink(ownerPath);
    await rmdir(lockDir);
    await pending;
    assert.deepEqual(await store.lookup("opaque-key"), { value: 1 });
  } finally { await rm(stateDir, { recursive: true, force: true }); }
});

test("a delayed stale acquirer cannot delete the replacement owner's lock", async () => {
  const stateDir = await mkdtemp(join(tmpdir(), "rightout-file-store-replaced-lock-"));
  try {
    const aDirectoryCreated = deferred();
    const resumeA = deferred();
    let pauseA = true;
    const storeA = createEncryptedFileKeyedStore({
      stateDir, namespace: "rightout-test-state", maxEntries: 5, getSecret: () => secret,
      _testHooks: {
        async afterDirectoryCreated() {
          if (!pauseA) return;
          pauseA = false;
          aDirectoryCreated.resolve();
          await resumeA.promise;
        },
      },
    });
    const pendingA = storeA.register("owner-a", { value: "a" });
    await aDirectoryCreated.promise;
    const lockDir = join(stateDir, "rightout-plugin-state-v1", "rightout-test-state.lock");
    await utimes(lockDir, new Date(0), new Date(0));

    const bOwnerPublished = deferred();
    const resumeB = deferred();
    let bToken;
    let pauseB = true;
    const storeB = createEncryptedFileKeyedStore({
      stateDir, namespace: "rightout-test-state", maxEntries: 5, getSecret: () => secret,
      _testHooks: {
        async afterOwnerPublished({ token }) {
          if (!pauseB) return;
          pauseB = false;
          bToken = token;
          bOwnerPublished.resolve();
          await resumeB.promise;
        },
      },
    });
    const pendingB = storeB.register("owner-b", { value: "b" });
    await bOwnerPublished.promise;
    resumeA.resolve();
    await new Promise((resolve) => setTimeout(resolve, 75));
    const currentOwner = JSON.parse(await readFile(join(lockDir, "owner.json"), "utf8"));
    assert.equal(currentOwner.token, bToken, "delayed A must not unlink B's canonical owner");
    resumeB.resolve();
    await Promise.all([pendingA, pendingB]);
    assert.deepEqual(await storeA.lookup("owner-a"), { value: "a" });
    assert.deepEqual(await storeA.lookup("owner-b"), { value: "b" });
  } finally { await rm(stateDir, { recursive: true, force: true }); }
});
