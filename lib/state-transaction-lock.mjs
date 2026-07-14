import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, realpath, rename, rmdir, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { randomBytes } from "node:crypto";

const SAFE_NAMESPACE = /^[a-z][a-z0-9-]{2,63}$/;

function safePath(root, child) {
  const base = resolve(root);
  const target = resolve(base, child);
  const rel = relative(base, target);
  if (!rel || rel.startsWith("..") || isAbsolute(rel)) throw new Error("rightout_transaction_lock_path_invalid");
  return target;
}

async function privateStateDirectory(stateDir) {
  const trustedRoot = await realpath(stateDir).catch(() => { throw new Error("rightout_transaction_lock_root_unavailable"); });
  const directory = safePath(trustedRoot, "rightout-plugin-state-v1");
  try { await mkdir(directory, { mode: 0o700 }); }
  catch (error) { if (error?.code !== "EEXIST") throw new Error("rightout_transaction_lock_directory_unsafe"); }
  const metadata = await lstat(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("rightout_transaction_lock_directory_unsafe");
  await chmod(directory, 0o700);
  const canonical = await realpath(directory);
  if (canonical !== directory || dirname(canonical) !== trustedRoot) throw new Error("rightout_transaction_lock_directory_unsafe");
  return directory;
}

function processIsAlive(pid) {
  if (!Number.isInteger(pid) || pid < 1) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error?.code === "EPERM"; }
}

async function readOwner(lockDir) {
  let handle;
  try { handle = await open(join(lockDir, "owner.json"), constants.O_RDONLY | constants.O_NOFOLLOW); }
  catch { return undefined; }
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > 1_024 || (metadata.mode & 0o077) !== 0) return undefined;
    const value = JSON.parse(await handle.readFile({ encoding: "utf8" }));
    if (!Number.isInteger(value?.pid) || typeof value?.token !== "string" || !/^[a-f0-9]{32}$/.test(value.token)) return undefined;
    return value;
  } catch { return undefined; }
  finally { await handle.close().catch(() => undefined); }
}

function sameIdentity(first, second) {
  return Boolean(first && second && first.dev === second.dev && first.ino === second.ino);
}

/**
 * Cross-process transaction coordinator for operations spanning multiple
 * encrypted store namespaces and managed filesystem artifacts.
 *
 * @param {{ stateDir: string, namespace: string }} options
 */
export function createStateTransactionLock({ stateDir, namespace }) {
  if (typeof stateDir !== "string" || !stateDir || !SAFE_NAMESPACE.test(namespace ?? "")) {
    throw new Error("rightout_transaction_lock_options_invalid");
  }
  let tail = Promise.resolve();

  async function removeDeadLock(directory, lockDir) {
    const staleDir = safePath(directory, `.${namespace}.stale.${randomBytes(12).toString("hex")}`);
    try { await rename(lockDir, staleDir); }
    catch { return false; }
    await unlink(join(staleDir, "owner.json")).catch(() => undefined);
    await rmdir(staleDir).catch(() => undefined);
    return true;
  }

  async function cleanupCreatedLock(lockDir, identity, token) {
    const current = await lstat(lockDir).catch(() => undefined);
    if (!sameIdentity(identity, current)) return "replaced";
    const owner = await readOwner(lockDir);
    if (owner && (owner.pid !== process.pid || owner.token !== token)) return "contended";
    if (owner) await unlink(join(lockDir, "owner.json")).catch(() => undefined);
    await rmdir(lockDir).catch(() => undefined);
    return "cleaned";
  }

  async function acquire() {
    const directory = await privateStateDirectory(stateDir);
    const lockDir = safePath(directory, `${namespace}.lock`);
    const token = randomBytes(16).toString("hex");
    for (let attempt = 0; attempt < 400; attempt += 1) {
      let createdIdentity;
      try {
        await mkdir(lockDir, { mode: 0o700 });
        createdIdentity = await lstat(lockDir);
        const ownerPath = join(lockDir, "owner.json");
        const handle = await open(ownerPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        try {
          await handle.writeFile(JSON.stringify({ pid: process.pid, token, createdAt: Date.now() }));
          await handle.sync();
        } finally { await handle.close(); }
        const currentIdentity = await lstat(lockDir).catch(() => undefined);
        const owner = await readOwner(lockDir);
        if (!sameIdentity(createdIdentity, currentIdentity) || owner?.pid !== process.pid || owner?.token !== token) {
          throw new Error("rightout_transaction_lock_lost");
        }
        return async () => {
          const currentOwner = await readOwner(lockDir);
          if (currentOwner?.pid !== process.pid || currentOwner?.token !== token) return;
          await unlink(ownerPath).catch(() => undefined);
          await rmdir(lockDir).catch(() => undefined);
        };
      } catch (error) {
        if (createdIdentity) {
          const cleanup = await cleanupCreatedLock(lockDir, createdIdentity, token);
          if (cleanup === "cleaned" && error?.message !== "rightout_transaction_lock_lost") {
            throw new Error("rightout_transaction_lock_failed");
          }
          if (cleanup !== "cleaned" || error?.message === "rightout_transaction_lock_lost") {
            await new Promise((resolveWait) => setTimeout(resolveWait, 25));
            continue;
          }
        }
        if (error?.code !== "EEXIST") throw new Error("rightout_transaction_lock_failed");
        let metadata;
        try { metadata = await lstat(lockDir); }
        catch (metadataError) {
          if (metadataError?.code !== "ENOENT") throw new Error("rightout_transaction_lock_unsafe");
          await new Promise((resolveWait) => setTimeout(resolveWait, 25));
          continue;
        }
        if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("rightout_transaction_lock_unsafe");
        const owner = await readOwner(lockDir);
        if (owner && !processIsAlive(owner.pid)) {
          if (await removeDeadLock(directory, lockDir)) continue;
        } else if (!owner && Date.now() - metadata.mtimeMs > 30_000) {
          if (await removeDeadLock(directory, lockDir)) continue;
        }
        await new Promise((resolveWait) => setTimeout(resolveWait, 25));
      }
    }
    throw new Error("rightout_transaction_lock_timeout");
  }

  /** @template T @param {() => Promise<T> | T} operation @returns {Promise<T>} */
  function run(operation) {
    const guarded = async () => {
      const release = await acquire();
      try { return await operation(); } finally { await release(); }
    };
    const result = tail.then(guarded, guarded);
    tail = result.then(() => undefined, () => undefined);
    return result;
  }

  return { run };
}

export const __test = { safePath, privateStateDirectory };
