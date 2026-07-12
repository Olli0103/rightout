import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, realpath, rename, rmdir, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
const SAFE_NAMESPACE = /^[a-z][a-z0-9-]{2,63}$/;
const SAFE_KEY = /^[A-Za-z0-9._:-]{1,160}$/;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_VALUE_BYTES = 64 * 1024;
function encryptionKey(secret) {
    if (typeof secret !== "string" || secret.length < 32 || secret.length > 4_096) {
        throw new Error("rightout_state_encryption_key_required");
    }
    return createHash("sha256").update(secret, "utf8").digest();
}
function safePath(root, child) {
    const base = resolve(root);
    const target = resolve(base, child);
    const rel = relative(base, target);
    if (!rel || rel.startsWith("..") || isAbsolute(rel))
        throw new Error("rightout_state_path_invalid");
    return target;
}
async function ensurePrivateDirectory(stateDir) {
    const trustedRoot = await realpath(stateDir).catch(() => { throw new Error("rightout_state_root_unavailable"); });
    const dataDir = safePath(trustedRoot, "rightout-plugin-state-v1");
    try {
        await mkdir(dataDir, { mode: 0o700 });
    }
    catch (error) {
        if (error?.code !== "EEXIST")
            throw new Error("rightout_state_directory_unsafe");
    }
    const metadata = await lstat(dataDir);
    if (!metadata.isDirectory() || metadata.isSymbolicLink())
        throw new Error("rightout_state_directory_unsafe");
    await chmod(dataDir, 0o700);
    const canonical = await realpath(dataDir);
    if (canonical !== dataDir || dirname(canonical) !== trustedRoot)
        throw new Error("rightout_state_directory_unsafe");
    return dataDir;
}
function emptyState() {
    return { schemaVersion: 1, entries: {} };
}
function cleanKey(value) {
    if (typeof value !== "string" || !SAFE_KEY.test(value))
        throw new Error("rightout_state_key_invalid");
    return value;
}
function cloneValue(value) {
    let text;
    try {
        text = JSON.stringify(value);
    }
    catch {
        throw new Error("rightout_state_value_invalid");
    }
    if (text === undefined || Buffer.byteLength(text) > MAX_VALUE_BYTES)
        throw new Error("rightout_state_value_invalid");
    return JSON.parse(text);
}
function encryptState(state, secret, namespace) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", encryptionKey(secret), iv);
    cipher.setAAD(Buffer.from(`rightout-file-state-v1:${namespace}`, "utf8"));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(state), "utf8"), cipher.final()]);
    return Buffer.from(JSON.stringify({
        schemaVersion: 1,
        iv: iv.toString("base64url"),
        tag: cipher.getAuthTag().toString("base64url"),
        ciphertext: ciphertext.toString("base64url"),
    }), "utf8");
}
function decryptState(bytes, secret, namespace) {
    let envelope;
    try {
        envelope = JSON.parse(bytes.toString("utf8"));
    }
    catch {
        throw new Error("rightout_state_corrupt");
    }
    if (envelope?.schemaVersion !== 1)
        throw new Error("rightout_state_corrupt");
    try {
        const decipher = createDecipheriv("aes-256-gcm", encryptionKey(secret), Buffer.from(envelope.iv, "base64url"));
        decipher.setAAD(Buffer.from(`rightout-file-state-v1:${namespace}`, "utf8"));
        decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
        const state = JSON.parse(Buffer.concat([
            decipher.update(Buffer.from(envelope.ciphertext, "base64url")), decipher.final(),
        ]).toString("utf8"));
        if (state?.schemaVersion !== 1 || !state.entries || typeof state.entries !== "object" || Array.isArray(state.entries)) {
            throw new Error("rightout_state_corrupt");
        }
        return state;
    }
    catch (error) {
        if (error instanceof Error && error.message === "rightout_state_corrupt")
            throw error;
        throw new Error("rightout_state_decryption_failed");
    }
}
function secretRing(getSecret, getPreviousSecrets) {
    const active = getSecret();
    encryptionKey(active);
    const previous = getPreviousSecrets();
    if (!Array.isArray(previous) || previous.some((value) => typeof value !== "string")) {
        throw new Error("rightout_state_previous_keys_invalid");
    }
    const unique = [];
    for (const value of [active, ...previous]) {
        encryptionKey(value);
        if (!unique.includes(value))
            unique.push(value);
    }
    return { active, all: unique };
}
function decryptStateFromRing(bytes, secrets, namespace) {
    let lastError;
    for (const secret of secrets) {
        try {
            return decryptState(bytes, secret, namespace);
        }
        catch (error) {
            if (error?.message === "rightout_state_corrupt")
                throw error;
            lastError = error;
        }
    }
    if (lastError)
        throw new Error("rightout_state_decryption_failed");
    throw new Error("rightout_state_encryption_key_required");
}
export function createEncryptedFileKeyedStore({ stateDir, namespace, maxEntries, defaultTtlMs = /** @type {number | undefined} */ (undefined), getSecret, getPreviousSecrets = /** @type {() => string[]} */ (() => []), now = () => Date.now(), _testHooks = undefined, }) {
    if (typeof stateDir !== "string" || !stateDir || !SAFE_NAMESPACE.test(namespace))
        throw new Error("rightout_state_options_invalid");
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 2_000)
        throw new Error("rightout_state_options_invalid");
    if (defaultTtlMs !== undefined && (!Number.isInteger(defaultTtlMs) || defaultTtlMs < 1))
        throw new Error("rightout_state_options_invalid");
    if (typeof getSecret !== "function")
        throw new Error("rightout_state_options_invalid");
    if (typeof getPreviousSecrets !== "function")
        throw new Error("rightout_state_options_invalid");
    let lock = Promise.resolve();
    function processIsAlive(pid) {
        if (!Number.isInteger(pid) || pid < 1)
            return false;
        try {
            process.kill(pid, 0);
            return true;
        }
        catch (error) {
            return error?.code === "EPERM";
        }
    }
    async function readLockOwner(lockDir) {
        let handle;
        try {
            handle = await open(join(lockDir, "owner.json"), constants.O_RDONLY | constants.O_NOFOLLOW);
        }
        catch {
            return undefined;
        }
        try {
            const metadata = await handle.stat();
            if (!metadata.isFile() || metadata.size > 1_024 || (metadata.mode & 0o077) !== 0)
                return undefined;
            const value = JSON.parse(await handle.readFile({ encoding: "utf8" }));
            if (!Number.isInteger(value?.pid) || typeof value?.token !== "string" || !/^[a-f0-9]{32}$/.test(value.token))
                return undefined;
            return value;
        }
        catch {
            return undefined;
        }
        finally {
            await handle.close().catch(() => undefined);
        }
    }
    async function removeDeadLock(directory, lockDir) {
        const staleDir = safePath(directory, `.${namespace}.stale.${randomBytes(12).toString("hex")}`);
        try {
            await rename(lockDir, staleDir);
        }
        catch {
            return false;
        }
        await unlink(join(staleDir, "owner.json")).catch(() => undefined);
        await rmdir(staleDir).catch(() => undefined);
        return true;
    }
    function sameIdentity(first, second) {
        return Boolean(first && second && first.dev === second.dev && first.ino === second.ino);
    }
    async function cleanupCreatedLock(lockDir, identity, token) {
        const current = await lstat(lockDir).catch(() => undefined);
        if (!sameIdentity(identity, current))
            return "replaced";
        const owner = await readLockOwner(lockDir);
        if (owner && (owner.pid !== process.pid || owner.token !== token))
            return "contended";
        if (owner)
            await unlink(join(lockDir, "owner.json")).catch(() => undefined);
        await rmdir(lockDir).catch(() => undefined);
        return "cleaned";
    }
    async function acquireFileLock() {
        const directory = await ensurePrivateDirectory(stateDir);
        const lockDir = safePath(directory, `${namespace}.lock`);
        const token = randomBytes(16).toString("hex");
        for (let attempt = 0; attempt < 400; attempt += 1) {
            let createdIdentity;
            try {
                await mkdir(lockDir, { mode: 0o700 });
                createdIdentity = await lstat(lockDir);
                await _testHooks?.afterDirectoryCreated?.({ lockDir, token });
                const ownerPath = join(lockDir, "owner.json");
                const ownerHandle = await open(ownerPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
                try {
                    await ownerHandle.writeFile(JSON.stringify({ pid: process.pid, token, createdAt: Date.now() }));
                    await ownerHandle.sync();
                }
                finally {
                    await ownerHandle.close();
                }
                await _testHooks?.afterOwnerPublished?.({ lockDir, token });
                const currentIdentity = await lstat(lockDir).catch(() => undefined);
                const publishedOwner = await readLockOwner(lockDir);
                if (!sameIdentity(createdIdentity, currentIdentity)
                    || !publishedOwner
                    || publishedOwner.pid !== process.pid
                    || publishedOwner.token !== token)
                    throw new Error("rightout_state_lock_lost");
                return async () => {
                    const owner = await readLockOwner(lockDir);
                    if (!owner || owner.token !== token || owner.pid !== process.pid)
                        return;
                    await unlink(ownerPath).catch(() => undefined);
                    await rmdir(lockDir).catch(() => undefined);
                };
            }
            catch (error) {
                if (createdIdentity) {
                    const cleanup = await cleanupCreatedLock(lockDir, createdIdentity, token);
                    if (cleanup === "cleaned" && error?.message !== "rightout_state_lock_lost") {
                        throw new Error("rightout_state_lock_failed");
                    }
                    if (cleanup !== "cleaned" || error?.message === "rightout_state_lock_lost") {
                        await new Promise((resolveWait) => setTimeout(resolveWait, 25));
                        continue;
                    }
                }
                if (error?.code !== "EEXIST")
                    throw new Error("rightout_state_lock_failed");
                const metadata = await lstat(lockDir).catch(() => undefined);
                if (!metadata || !metadata.isDirectory() || metadata.isSymbolicLink())
                    throw new Error("rightout_state_lock_unsafe");
                const owner = await readLockOwner(lockDir);
                if (owner && !processIsAlive(owner.pid)) {
                    if (await removeDeadLock(directory, lockDir))
                        continue;
                }
                else if (!owner && Date.now() - metadata.mtimeMs > 30_000) {
                    if (await removeDeadLock(directory, lockDir))
                        continue;
                }
                await new Promise((resolveWait) => setTimeout(resolveWait, 25));
            }
        }
        throw new Error("rightout_state_lock_timeout");
    }
    /** @template R @param {() => R | Promise<R>} operation @returns {Promise<R>} */
    function serialized(operation) {
        const guarded = async () => {
            const release = await acquireFileLock();
            try {
                return await operation();
            }
            finally {
                await release();
            }
        };
        const result = lock.then(guarded, guarded);
        lock = result.then(() => undefined, () => undefined);
        return result;
    }
    async function locations() {
        const directory = await ensurePrivateDirectory(stateDir);
        return { directory, file: safePath(directory, `${namespace}.json.enc`) };
    }
    async function readState(file, secrets) {
        let handle;
        try {
            handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
        }
        catch (error) {
            if (error?.code === "ENOENT")
                return emptyState();
            throw new Error("rightout_state_read_failed");
        }
        try {
            const metadata = await handle.stat();
            if (!metadata.isFile() || metadata.size > MAX_FILE_BYTES || (metadata.mode & 0o077) !== 0)
                throw new Error("rightout_state_file_unsafe");
            return decryptStateFromRing(await handle.readFile(), secrets, namespace);
        }
        finally {
            await handle.close().catch(() => undefined);
        }
    }
    function prune(state, at) {
        let changed = false;
        for (const [key, entry] of Object.entries(state.entries)) {
            if (!entry || typeof entry !== "object" || !Number.isFinite(entry.createdAt)) {
                delete state.entries[key];
                changed = true;
                continue;
            }
            if (entry.expiresAt === undefined && defaultTtlMs !== undefined) {
                entry.expiresAt = entry.createdAt + defaultTtlMs;
                changed = true;
            }
            if (entry.expiresAt !== undefined
                && (!Number.isFinite(entry.expiresAt) || entry.expiresAt <= entry.createdAt || entry.expiresAt <= at)) {
                delete state.entries[key];
                changed = true;
            }
        }
        return changed;
    }
    async function writeState(directory, file, state, secret) {
        const bytes = encryptState(state, secret, namespace);
        if (bytes.length > MAX_FILE_BYTES)
            throw new Error("rightout_state_too_large");
        const temp = join(directory, `.${namespace}.${randomBytes(12).toString("hex")}.tmp`);
        let handle;
        try {
            handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
            await handle.writeFile(bytes);
            await handle.sync();
            await handle.close();
            handle = undefined;
            await rename(temp, file);
            await chmod(file, 0o600);
            const dirHandle = await open(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
            try {
                await dirHandle.sync();
            }
            finally {
                await dirHandle.close();
            }
        }
        catch {
            throw new Error("rightout_state_write_failed");
        }
        finally {
            await handle?.close().catch(() => undefined);
            await unlink(temp).catch(() => undefined);
        }
    }
    function ttl(opts) {
        const value = opts?.ttlMs ?? defaultTtlMs;
        if (value !== undefined && (!Number.isInteger(value) || value < 1))
            throw new Error("rightout_state_ttl_invalid");
        return value;
    }
    /** @template R @param {(state: any) => R | Promise<R>} callback @returns {Promise<R>} */
    async function mutate(callback) {
        return serialized(async () => {
            const keys = secretRing(getSecret, getPreviousSecrets);
            const { directory, file } = await locations();
            const state = await readState(file, keys.all);
            prune(state, now());
            const outcome = await callback(state);
            await writeState(directory, file, state, keys.active);
            return outcome;
        });
    }
    async function register(key, value, opts) {
        const clean = cleanKey(key);
        const copy = cloneValue(value);
        const ttlMs = ttl(opts);
        return mutate((state) => {
            const at = now();
            state.entries[clean] = { value: copy, createdAt: at, ...(ttlMs ? { expiresAt: at + ttlMs } : {}) };
            const ordered = Object.entries(state.entries).sort((a, b) => a[1].createdAt - b[1].createdAt);
            while (ordered.length > maxEntries)
                delete state.entries[ordered.shift()[0]];
        });
    }
    async function registerIfAbsent(key, value, opts) {
        const clean = cleanKey(key);
        const copy = cloneValue(value);
        const ttlMs = ttl(opts);
        return mutate((state) => {
            if (state.entries[clean])
                return false;
            const at = now();
            state.entries[clean] = { value: copy, createdAt: at, ...(ttlMs ? { expiresAt: at + ttlMs } : {}) };
            const ordered = Object.entries(state.entries).sort((a, b) => a[1].createdAt - b[1].createdAt);
            while (ordered.length > maxEntries)
                delete state.entries[ordered.shift()[0]];
            return true;
        });
    }
    async function lookup(key) {
        const clean = cleanKey(key);
        return serialized(async () => {
            const keys = secretRing(getSecret, getPreviousSecrets);
            const { file } = await locations();
            const state = await readState(file, keys.all);
            const changed = prune(state, now());
            const entry = state.entries[clean];
            if (changed) {
                const { directory } = await locations();
                await writeState(directory, file, state, keys.active);
            }
            return entry ? cloneValue(entry.value) : undefined;
        });
    }
    async function consume(key) {
        const clean = cleanKey(key);
        return mutate((state) => {
            const entry = state.entries[clean];
            delete state.entries[clean];
            return entry ? cloneValue(entry.value) : undefined;
        });
    }
    async function deleteKey(key) {
        const clean = cleanKey(key);
        return mutate((state) => {
            const existed = Boolean(state.entries[clean]);
            delete state.entries[clean];
            return existed;
        });
    }
    async function entries() {
        return serialized(async () => {
            const keys = secretRing(getSecret, getPreviousSecrets);
            const { directory, file } = await locations();
            const state = await readState(file, keys.all);
            const changed = prune(state, now());
            if (changed)
                await writeState(directory, file, state, keys.active);
            return Object.entries(state.entries).map(([key, entry]) => ({
                key, value: cloneValue(entry.value), createdAt: entry.createdAt, ...(entry.expiresAt ? { expiresAt: entry.expiresAt } : {}),
            }));
        });
    }
    async function clear() { return mutate((state) => { state.entries = {}; }); }
    async function reencrypt() { return mutate((state) => Object.keys(state.entries).length); }
    async function update(key, updateValue, opts) {
        const clean = cleanKey(key);
        const ttlMs = ttl(opts);
        if (typeof updateValue !== "function")
            throw new Error("rightout_state_update_invalid");
        return mutate((state) => {
            const next = updateValue(state.entries[clean] ? cloneValue(state.entries[clean].value) : undefined);
            if (next === undefined) {
                const existed = Boolean(state.entries[clean]);
                delete state.entries[clean];
                return existed;
            }
            const at = now();
            state.entries[clean] = { value: cloneValue(next), createdAt: at, ...(ttlMs ? { expiresAt: at + ttlMs } : {}) };
            return true;
        });
    }
    return { register, registerIfAbsent, update, lookup, consume, delete: deleteKey, entries, clear, reencrypt };
}
export const __test = { safePath, encryptionKey, encryptState, decryptState, decryptStateFromRing };
