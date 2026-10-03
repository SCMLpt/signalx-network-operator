import { constants } from 'node:fs';
import { mkdir, open, lstat, realpath, rename, unlink } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { hostname } from 'node:os';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';

const queues = new Map();
const LOCK_WAIT_MS = 5_000;
const LOCK_BYTES = 4_096;
const emptyState = () => ({ version: 1, revision: 0, publications: {}, runs: [] });
const failure = (message, code, cause) => Object.assign(new Error(message, { cause }), { code });

function validateState(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state) || state.version !== 1 ||
      !Number.isSafeInteger(state.revision) || state.revision < 0 ||
      !state.publications || typeof state.publications !== 'object' || Array.isArray(state.publications) ||
      !Array.isArray(state.runs) || state.runs.length > 100) {
    throw failure('Journal state has an invalid schema or more than 100 runs', 'JOURNAL_CORRUPT');
  }
  const ancestors = new Set();
  let nodes = 0;
  function visit(value, depth, arrayEntry = false) {
    if (++nodes > 100_000 || depth > 64) throw failure('Journal structure exceeds its limits', 'JOURNAL_OVERSIZE');
    if (value === undefined && !arrayEntry) return; // JSON omits optional object fields.
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
    if (typeof value === 'number' && Number.isFinite(value) &&
        (!Number.isInteger(value) || Number.isSafeInteger(value))) return;
    if (!value || typeof value !== 'object' || ancestors.has(value)) {
      throw failure('Journal contains a non-JSON value or a cycle', 'JOURNAL_CORRUPT');
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null && !(Array.isArray(value) && proto === Array.prototype)) {
      throw failure('Journal values must be plain JSON objects', 'JOURNAL_CORRUPT');
    }
    ancestors.add(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.getOwnPropertySymbols(value).length) throw failure('Journal contains symbol keys', 'JOURNAL_CORRUPT');
    if (Array.isArray(value)) {
      if (Object.keys(value).length !== value.length) throw failure('Journal arrays must be dense', 'JOURNAL_CORRUPT');
      for (let i = 0; i < value.length; i++) {
        const descriptor = descriptors[i];
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw failure('Journal contains an accessor', 'JOURNAL_CORRUPT');
        visit(descriptor.value, depth + 1, true);
      }
    } else {
      for (const [key, descriptor] of Object.entries(descriptors)) {
        if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
          throw failure('Journal contains hidden fields or accessors', 'JOURNAL_CORRUPT');
        }
        if (key === '__proto__') throw failure('Journal contains an unsafe object key', 'JOURNAL_CORRUPT');
        visit(descriptor.value, depth + 1);
      }
    }
    ancestors.delete(value);
  }
  visit(state, 0);
}

function sameFile(a, b) { return a.dev === b.dev && a.ino === b.ino; }

async function regularStat(path, { missing = false } = {}) {
  let stat;
  try { stat = await lstat(path); }
  catch (error) { if (missing && error.code === 'ENOENT') return null; throw error; }
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) {
    throw failure(`Journal path is not a private regular file: ${path}`, 'JOURNAL_UNSAFE_PATH');
  }
  return stat;
}

async function readProtected(path, maximum, { missing = false } = {}) {
  const before = await regularStat(path, { missing });
  if (!before) return null;
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW); }
  catch (error) { if (missing && error.code === 'ENOENT') return null; throw error; }
  try {
    const stat = await handle.stat();
    // An atomic rename can replace the path after lstat, or unlink the opened
    // old snapshot. The fd still provides a complete old or new regular file.
    if (!stat.isFile() || stat.nlink > 1) {
      throw failure('Journal file is unsafe while opening it', 'JOURNAL_UNSAFE_PATH');
    }
    if (stat.size > maximum) throw failure('Journal file exceeds its byte limit', 'JOURNAL_OVERSIZE');
    // Do not use readFile: the file can grow after fstat.
    const bytes = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < bytes.length) {
      const result = await handle.read(bytes, length, bytes.length - length, length);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length > maximum) throw failure('Journal file exceeds its byte limit', 'JOURNAL_OVERSIZE');
    let value;
    try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length))); }
    catch (error) { throw failure('Journal file is corrupt JSON or UTF-8', 'JOURNAL_CORRUPT', error); }
    return { value, stat };
  } finally { await handle.close(); }
}

function validLock(value) {
  return value?.version === 1 && Number.isSafeInteger(value.pid) && value.pid > 0 &&
    value.host === hostname() && typeof value.token === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.token) && Number.isSafeInteger(value.createdAtMs) &&
    value.createdAtMs > 0 && value.createdAtMs <= Date.now();
}

function requireDeadPid(pid) {
  try { process.kill(pid, 0); }
  catch (error) {
    if (error.code === 'ESRCH') return;
    throw failure('Cannot verify lock owner is dead; recovery refused', 'JOURNAL_LOCK_UNVERIFIED', error);
  }
  // A reused PID also fails here. Start-time guesses must never authorize deletion.
  throw failure('Lock PID is still alive or has been reused; recovery refused', 'JOURNAL_LOCK_LIVE');
}

/** Local POSIX journal. The directory must be exclusively administered by its operator.
 * Cross-host/NFS storage is not supported. No lock is automatically reaped.
 */
export class FileJournal {
  constructor(directory, { maxBytes = 1_048_576 } = {}) {
    if (typeof directory !== 'string' || !directory || directory.includes('\0')) throw new TypeError('Journal directory is required');
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 64 * 1_048_576) {
      throw new RangeError('Journal maxBytes must be 1–67108864');
    }
    this.directory = resolve(directory);
    this.file = join(this.directory, 'journal.json');
    this.lock = join(this.directory, 'journal.lock');
    this.recoveryFence = join(this.directory, 'journal.recovery.lock');
    this.maxBytes = maxBytes;
    this._directoryIdentity = null;
    this._ancestryDurable = false;
  }

  async _directory({ create = false } = {}) {
    if (create) {
      let path = this.directory;
      while (true) {
        try {
          const ancestor = await lstat(path);
          if (ancestor.isSymbolicLink() || !ancestor.isDirectory()) {
            throw failure('Journal directory ancestry is unsafe', 'JOURNAL_UNSAFE_PATH');
          }
          break;
        } catch (error) {
          if (error.code !== 'ENOENT') throw error;
          path = dirname(path);
        }
      }
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
    }
    let stat;
    try { stat = await lstat(this.directory); }
    catch (error) { if (!create && error.code === 'ENOENT') return false; throw error; }
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw failure('Journal directory is unsafe', 'JOURNAL_UNSAFE_PATH');
    const handle = await open(this.directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      if (!sameFile(stat, await handle.stat())) throw failure('Journal directory changed', 'JOURNAL_UNSAFE_PATH');
      if (this._directoryIdentity && !sameFile(this._directoryIdentity, stat)) {
        throw failure('Journal directory was replaced', 'JOURNAL_UNSAFE_PATH');
      }
      this._directoryIdentity = stat;
      if (create && !this._ancestryDurable) {
        // Sync every physical ancestor on first use, also covering a failed
        // earlier mkdir/fsync attempt or directories just created by a peer.
        // realpath handles OS-managed aliases such as macOS /var -> /private/var.
        let path = await realpath(this.directory);
        while (true) {
          const parentPath = dirname(path);
          const parent = await open(parentPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
          try { await parent.sync(); } finally { await parent.close(); }
          if (parentPath === path) break;
          path = parentPath;
        }
        this._ancestryDurable = true;
      }
    } finally { await handle.close(); }
    return true;
  }

  async _syncDirectory() {
    const handle = await open(this.directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await handle.sync(); } finally { await handle.close(); }
  }

  async _serial(operation) {
    const previous = queues.get(this.directory) ?? Promise.resolve();
    let release;
    const current = new Promise(resolveQueue => { release = resolveQueue; });
    queues.set(this.directory, current);
    let timer, entered = false;
    const releaseQueue = () => {
      release();
      if (queues.get(this.directory) === current) queues.delete(this.directory);
    };
    try {
      const ready = await Promise.race([
        previous.then(() => true),
        new Promise(resolveWait => { timer = setTimeout(() => resolveWait(false), LOCK_WAIT_MS); }),
      ]);
      if (!ready) {
        // Preserve FIFO ordering even after this waiting caller times out.
        previous.then(releaseQueue);
        throw failure('Journal process semaphore timed out; inspect the running mutator', 'JOURNAL_LOCK_TIMEOUT');
      }
      entered = true;
      return await operation();
    }
    finally {
      clearTimeout(timer);
      if (entered) releaseQueue();
    }
  }

  async read() {
    if (!(await this._directory())) return emptyState();
    const result = await readProtected(this.file, this.maxBytes, { missing: true });
    if (!result) return emptyState();
    validateState(result.value);
    return structuredClone(result.value);
  }

  async _createLock(path) {
    const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    const stat = await handle.stat();
    const value = { version: 1, pid: process.pid, host: hostname(), token: randomUUID(), createdAtMs: Date.now() };
    try {
      await handle.writeFile(JSON.stringify(value) + '\n');
      await handle.sync();
      await this._syncDirectory();
      return { path, handle, stat, value };
    } catch (error) {
      try { await this._releaseLock({ path, handle, stat }); }
      catch (cleanup) { throw new AggregateError([error, cleanup], 'Lock creation and cleanup failed', { cause: error }); }
      throw error;
    }
  }

  async _releaseLock(lock) {
    let error;
    try {
      const current = await regularStat(lock.path);
      if (!sameFile(current, lock.stat)) throw failure('Journal lock was replaced; refusing to remove it', 'JOURNAL_LOCK_UNVERIFIED');
      await unlink(lock.path);
      await this._syncDirectory();
    } catch (caught) { error = caught; }
    try { await lock.handle.close(); }
    catch (caught) { error = error ? new AggregateError([error, caught], 'Lock cleanup failed', { cause: error }) : caught; }
    if (error) throw error;
  }

  async _acquireLock() {
    const deadline = performance.now() + LOCK_WAIT_MS;
    while (true) {
      if (await regularStat(this.recoveryFence, { missing: true })) {
        throw failure('A recovery fence exists; inspect recovery before writing', 'JOURNAL_RECOVERY_LOCKED');
      }
      let lock;
      try { lock = await this._createLock(this.lock); }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        // Validate the path immediately rather than retrying a symlink or corrupt owner.
        let existing;
        try { existing = await readProtected(this.lock, LOCK_BYTES, { missing: true }); }
        catch (readError) {
          if (!['JOURNAL_CORRUPT', 'JOURNAL_OVERSIZE'].includes(readError.code)) throw readError;
          if (performance.now() >= deadline) {
            throw failure('Journal lock owner is corrupt or incomplete; inspect it', 'JOURNAL_LOCK_UNVERIFIED', readError);
          }
          await delay(20);
          continue;
        }
        if (existing && !validLock(existing.value)) {
          throw failure('Journal lock owner is unverified; inspect it', 'JOURNAL_LOCK_UNVERIFIED');
        }
        if (existing) {
          try { process.kill(existing.value.pid, 0); }
          catch (probe) {
            if (probe.code === 'ESRCH') throw failure('Journal lock owner is dead; call recoverLock explicitly', 'JOURNAL_LOCK_STUCK');
            if (probe.code !== 'EPERM') throw probe;
          }
        }
        if (performance.now() >= deadline) throw failure('Journal write lock timed out; inspect the owner', 'JOURNAL_LOCK_TIMEOUT');
        await delay(20);
        continue;
      }
      if (await regularStat(this.recoveryFence, { missing: true })) {
        await this._releaseLock(lock);
        throw failure('Recovery started during lock acquisition', 'JOURNAL_RECOVERY_LOCKED');
      }
      return lock;
    }
  }

  /** Mutate a draft, or return a replacement. Return value is the committed JSON snapshot. */
  async transact(mutator) {
    if (typeof mutator !== 'function') throw new TypeError('Journal mutator must be a function');
    return this._serial(async () => {
      await this._directory({ create: true });
      const lock = await this._acquireLock();
      let temporary, error, result, retainLock = false;
      try {
        const previous = await this.read();
        if (previous.revision === Number.MAX_SAFE_INTEGER) throw failure('Journal revision is exhausted', 'JOURNAL_CORRUPT');
        const draft = structuredClone(previous);
        const replacement = await mutator(draft);
        const next = replacement === undefined ? draft : replacement;
        validateState(next);
        if (next.revision !== previous.revision) throw failure('Mutators must not change the journal revision', 'JOURNAL_CORRUPT');
        next.revision = previous.revision + 1;
        const bytes = Buffer.from(JSON.stringify(next) + '\n');
        if (bytes.length > this.maxBytes) throw failure('Journal commit exceeds its byte limit', 'JOURNAL_OVERSIZE');
        result = JSON.parse(bytes.toString('utf8'));
        const target = await regularStat(this.file, { missing: true });
        // The verified lock identity identifies exactly one abandoned temporary
        // file during explicit dead-owner recovery; no directory-wide reaping.
        const temporaryPath = join(this.directory, `.journal-${lock.value.token}.tmp`);
        const handle = await open(temporaryPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        // A failed exclusive create does not confer ownership of this path.
        // In particular, preserve any existing file when open rejects EEXIST.
        temporary = temporaryPath;
        try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
        const current = await regularStat(this.file, { missing: true });
        if ((target === null) !== (current === null) || (target && !sameFile(target, current))) {
          throw failure('Journal target changed during transaction', 'JOURNAL_UNSAFE_PATH');
        }
        await rename(temporary, this.file);
        temporary = null;
        try { await this._syncDirectory(); }
        catch (cause) {
          retainLock = true;
          throw failure('Journal rename succeeded but durability is unknown; reconcile before recovery', 'JOURNAL_COMMIT_UNKNOWN', cause);
        }
      } catch (caught) { error = caught; }
      if (temporary) {
        try { await unlink(temporary); }
        catch (cleanup) { error = error ? new AggregateError([error, cleanup], 'Journal update and temporary cleanup failed', { cause: error }) : cleanup; }
      }
      try {
        if (retainLock) await lock.handle.close();
        else await this._releaseLock(lock);
      } catch (cleanup) { error = error ? new AggregateError([error, cleanup], 'Journal update and lock cleanup failed', { cause: error }) : cleanup; }
      if (error) throw error;
      return structuredClone(result);
    });
  }

  /** Explicit recovery only. A live/reused PID, foreign host or malformed lock is never deleted.
   * A crashed recovery leaves a separate fence: inspect it while all writers are stopped.
   * This method deliberately does not guess that such a fence is safe to remove.
   */
  async recoverLock() {
    return this._serial(async () => {
      await this._directory({ create: true });
      let fence;
      try { fence = await this._createLock(this.recoveryFence); }
      catch (error) {
        if (error.code === 'EEXIST') throw failure('Another recovery fence exists; manual inspection is required', 'JOURNAL_RECOVERY_LOCKED', error);
        throw error;
      }
      let result, error;
      try {
        const existing = await readProtected(this.lock, LOCK_BYTES, { missing: true });
        if (!existing) result = { recovered: false };
        else {
          if (!validLock(existing.value)) throw failure('Lock identity is malformed or belongs to another host', 'JOURNAL_LOCK_UNVERIFIED');
          requireDeadPid(existing.value.pid);
          const confirmed = await readProtected(this.lock, LOCK_BYTES);
          if (!sameFile(existing.stat, confirmed.stat) || JSON.stringify(existing.value) !== JSON.stringify(confirmed.value)) {
            throw failure('Lock identity changed during recovery', 'JOURNAL_LOCK_UNVERIFIED');
          }
          requireDeadPid(confirmed.value.pid);
          const abandoned = join(this.directory, `.journal-${confirmed.value.token}.tmp`);
          if (await regularStat(abandoned, { missing: true })) await unlink(abandoned);
          await unlink(this.lock);
          await this._syncDirectory();
          result = { recovered: true, pid: confirmed.value.pid, token: confirmed.value.token };
        }
      } catch (caught) { error = caught; }
      try { await this._releaseLock(fence); }
      catch (cleanup) { error = error ? new AggregateError([error, cleanup], 'Lock recovery and cleanup failed', { cause: error }) : cleanup; }
      if (error) throw error;
      return result;
    });
  }
}
