import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, readdir, rm, symlink, link, open, unlink } from 'node:fs/promises';
import { tmpdir, hostname } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { FileJournal } from './journal.mjs';

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'signalx-journal-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, journal: new FileJournal(directory) };
}

function launch(t, directory, body) {
  const script = `import { FileJournal } from ${JSON.stringify(new URL('./journal.mjs', import.meta.url).href)};
const journal = new FileJournal(${JSON.stringify(directory)});
${body}`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stderr }));
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await done;
  });
  return { child, done };
}

function waitForLock(child) {
  return new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => finish(new Error('Child never entered its locked transaction')), 10_000);
    const data = chunk => {
      output += chunk;
      if (output.includes('LOCKED\n')) finish();
    };
    const closed = () => finish(new Error('Child exited before acquiring journal lock'));
    const finish = error => {
      clearTimeout(timer);
      child.stdout.off('data', data);
      child.off('close', closed);
      error ? reject(error) : resolve();
    };
    child.stdout.on('data', data);
    child.once('close', closed);
  });
}

test('default state, detached snapshots and durable restart preserve IPNS high-water', async t => {
  const { directory, journal } = await fixture(t);
  const fresh = await journal.read();
  assert.deepEqual(fresh, { version: 1, revision: 0, publications: {}, runs: [] });
  fresh.publications.accidental = {};
  let draft;
  const committed = await journal.transact(state => {
    draft = state;
    state.publications.release = {
      highestRecord: { sequence: '18446744073709551615', recordSha256: 'a'.repeat(64) },
      lastCheck: { checkedAtMs: 1_000, optional: undefined },
    };
  });
  assert.equal(committed.revision, 1);
  assert.equal(Object.hasOwn(committed.publications.release.lastCheck, 'optional'), false);
  draft.publications.release.highestRecord.sequence = '0';
  committed.publications.release.highestRecord.recordSha256 = 'changed';
  const restored = await new FileJournal(directory).read();
  assert.equal(restored.publications.release.highestRecord.sequence, '18446744073709551615');
  assert.equal(restored.publications.release.highestRecord.recordSha256, 'a'.repeat(64));
  assert.equal(restored.revision, 1);
  assert.deepEqual(JSON.parse(await readFile(journal.file, 'utf8')), restored);
});

test('async transactions serialize across instances and an exception rolls back without poisoning queue', async t => {
  const { directory, journal } = await fixture(t);
  const other = new FileJournal(directory);
  await Promise.all(Array.from({ length: 25 }, (_, index) => (index % 2 ? other : journal).transact(async state => {
    const previous = state.publications.counter?.count ?? 0;
    await new Promise(resolve => setTimeout(resolve, 2));
    state.publications.counter = { count: previous + 1 };
  })));
  const before = await journal.read();
  assert.equal(before.publications.counter.count, 25);
  const expected = new Error('Mutator failed before commit');
  await assert.rejects(journal.transact(state => {
    state.publications.counter.count = 9_999;
    throw expected;
  }), error => error === expected);
  assert.deepEqual(await other.read(), before);
  const next = await other.transact(state => { state.publications.counter.count++; return state; });
  assert.equal(next.publications.counter.count, 26);
  assert.equal(next.revision, 26);
});

test('a timed-out process semaphore waiter never runs and preserves the queue for subsequent commits', { timeout: 15_000 }, async t => {
  const { directory, journal } = await fixture(t);
  let release, entered;
  const blocked = new Promise(resolve => { release = resolve; });
  const locked = new Promise(resolve => { entered = resolve; });
  t.after(() => release());
  const first = journal.transact(async state => {
    entered();
    await blocked;
    state.publications.counter = { count: 1 };
  });
  await locked;
  let timedOutCalled = false;
  await assert.rejects(new FileJournal(directory).transact(() => { timedOutCalled = true; }),
    { code: 'JOURNAL_LOCK_TIMEOUT' });
  assert.equal(timedOutCalled, false);
  const next = new FileJournal(directory).transact(state => { state.publications.counter.count++; });
  release();
  await Promise.all([first, next]);
  const state = await journal.read();
  assert.equal(state.publications.counter.count, 2);
  assert.equal(state.revision, 2);
  assert.deepEqual(await readdir(directory), ['journal.json']);
});

test('real separate processes serialize commits without lost updates', async t => {
  const { directory, journal } = await fixture(t);
  const workers = Array.from({ length: 4 }, () => launch(t, directory, `
for (let i = 0; i < 8; i++) {
  await journal.transact(async state => {
    const count = state.publications.counter?.count ?? 0;
    await new Promise(resolve => setTimeout(resolve, 3));
    state.publications.counter = { count: count + 1 };
  });
}`));
  for (const result of await Promise.all(workers.map(worker => worker.done))) {
    assert.equal(result.code, 0, result.stderr);
  }
  assert.equal((await journal.read()).publications.counter.count, 32);
  assert.equal((await journal.read()).revision, 32);
  assert.deepEqual(await readdir(directory), ['journal.json']);
});

test('a live separate-process lock times out without deleting its owner evidence', { timeout: 15_000 }, async t => {
  const { directory, journal } = await fixture(t);
  await journal.transact(state => { state.publications.release = { sequence: '8' }; });
  const worker = launch(t, directory, `await journal.transact(async state => {
  state.publications.release.sequence = '9';
  process.stdout.write('LOCKED\\n');
  await new Promise(resolve => setTimeout(resolve, 60_000));
});`);
  await waitForLock(worker.child);
  const owner = await readFile(journal.lock, 'utf8');
  let called = false;
  await assert.rejects(journal.transact(() => { called = true; }), { code: 'JOURNAL_LOCK_TIMEOUT' });
  assert.equal(called, false);
  assert.equal(await readFile(journal.lock, 'utf8'), owner);
  assert.equal((await journal.read()).publications.release.sequence, '8');
  await assert.rejects(journal.recoverLock(), { code: 'JOURNAL_LOCK_LIVE' });
  assert.equal(await readFile(journal.lock, 'utf8'), owner);
  worker.child.kill('SIGKILL');
  assert.equal((await worker.done).signal, 'SIGKILL');
  assert.equal((await journal.recoverLock()).recovered, true);
  assert.equal((await journal.transact(state => { state.publications.release.sequence = '10'; })).revision, 2);
});

test('killed transaction fails closed, explicit verified-dead recovery preserves old commit', async t => {
  const { directory, journal } = await fixture(t);
  await journal.transact(state => { state.publications.release = { sequence: '8' }; });
  const worker = launch(t, directory, `await journal.transact(async state => {
  state.publications.release.sequence = '9';
  process.stdout.write('LOCKED\\n');
  await new Promise(resolve => setTimeout(resolve, 60_000));
});`);
  await waitForLock(worker.child);
  worker.child.kill('SIGKILL');
  assert.equal((await worker.done).signal, 'SIGKILL');
  const restarted = new FileJournal(directory);
  await assert.rejects(restarted.transact(state => { state.publications.release.sequence = '10'; }),
    { code: 'JOURNAL_LOCK_STUCK' });
  assert.equal((await restarted.read()).publications.release.sequence, '8');
  const lock = JSON.parse(await readFile(restarted.lock, 'utf8'));
  const recovered = await restarted.recoverLock();
  assert.deepEqual(recovered, { recovered: true, pid: worker.child.pid, token: lock.token });
  const committed = await restarted.transact(state => { state.publications.release.sequence = '10'; });
  assert.equal(committed.revision, 2);
  assert.equal(committed.publications.release.sequence, '10');
  assert.deepEqual(await restarted.recoverLock(), { recovered: false });
});

test('SIGKILL during temporary file write leaves old snapshot and recovery removes only the verified orphan', async t => {
  const { directory, journal } = await fixture(t);
  await journal.transact(state => { state.publications.release = { sequence: '8' }; });
  const unrelated = `.journal-${randomUUID()}.tmp`;
  const unrelatedBytes = 'unrelated orphan requires separate inspection';
  await writeFile(join(directory, unrelated), unrelatedBytes);
  const worker = launch(t, directory, `
const { open, unlink } = await import('node:fs/promises');
const { join } = await import('node:path');
const probePath = join(journal.directory, 'probe');
const probe = await open(probePath, 'wx');
const proto = Object.getPrototypeOf(probe);
const original = proto.writeFile;
await probe.close(); await unlink(probePath);
proto.writeFile = async function(data, ...options) {
  if (Buffer.isBuffer(data)) {
    await original.call(this, data.subarray(0, Math.max(1, Math.floor(data.length / 2))), ...options);
    process.stdout.write('LOCKED\\n');
    await new Promise(resolve => setTimeout(resolve, 60_000));
  }
  return original.call(this, data, ...options);
};
await journal.transact(state => { state.publications.release.sequence = '9'; });`);
  await waitForLock(worker.child);
  worker.child.kill('SIGKILL');
  assert.equal((await worker.done).signal, 'SIGKILL');
  const lock = JSON.parse(await readFile(journal.lock, 'utf8'));
  const orphan = `.journal-${lock.token}.tmp`;
  assert.ok((await readdir(directory)).includes(orphan));
  const partial = await readFile(join(directory, orphan), 'utf8');
  assert.ok(partial.length > 0);
  assert.throws(() => JSON.parse(partial), SyntaxError);
  await assert.rejects(new FileJournal(directory).transact(() => {}), { code: 'JOURNAL_LOCK_STUCK' });
  assert.equal((await journal.read()).publications.release.sequence, '8');
  await journal.recoverLock();
  assert.deepEqual((await readdir(directory)).sort(), [unrelated, 'journal.json'].sort());
  assert.equal(await readFile(join(directory, unrelated), 'utf8'), unrelatedBytes);
  const restarted = new FileJournal(directory);
  assert.equal((await restarted.read()).revision, 1);
  const committed = await restarted.transact(state => { state.publications.release.sequence = '10'; });
  assert.equal(committed.revision, 2);
  assert.equal(committed.publications.release.sequence, '10');
});

test('exclusive temporary-file create failure preserves the unowned path and original error', async t => {
  const { directory, journal } = await fixture(t);
  await journal.transact(state => { state.publications.release = { sequence: '3' }; });
  const before = await readFile(journal.file, 'utf8');
  let collision;
  const collisionBytes = 'existing file must remain available for inspection';
  await assert.rejects(journal.transact(async state => {
    state.publications.release.sequence = '4';
    const lock = JSON.parse(await readFile(journal.lock, 'utf8'));
    collision = join(directory, `.journal-${lock.token}.tmp`);
    await writeFile(collision, collisionBytes, { flag: 'wx' });
  }), error => error.code === 'EEXIST' && !(error instanceof AggregateError));
  assert.equal(await readFile(collision, 'utf8'), collisionBytes);
  assert.equal(await readFile(journal.file, 'utf8'), before);
  assert.equal((await journal.transact(state => { state.publications.release.sequence = '5'; })).revision, 2);
});

test('live or reused PID, foreign owner and corrupt recovery evidence cannot authorize lock removal', async t => {
  const { directory, journal } = await fixture(t);
  const lock = { version: 1, pid: process.pid, host: hostname(), token: randomUUID(), createdAtMs: 1 };
  await writeFile(journal.lock, JSON.stringify(lock));
  await assert.rejects(journal.recoverLock(), { code: 'JOURNAL_LOCK_LIVE' });
  assert.deepEqual(JSON.parse(await readFile(journal.lock, 'utf8')), lock);
  await writeFile(journal.lock, JSON.stringify({ ...lock, host: 'a-different-operator-host' }));
  await assert.rejects(journal.recoverLock(), { code: 'JOURNAL_LOCK_UNVERIFIED' });
  await writeFile(journal.lock, '{broken');
  await assert.rejects(journal.recoverLock(), { code: 'JOURNAL_CORRUPT' });
  assert.equal(await readFile(journal.lock, 'utf8'), '{broken');
  assert.deepEqual(await readdir(directory), ['journal.lock']);
});

test('corrupt, unsupported and oversized state is never replaced by a new default', async t => {
  const { journal } = await fixture(t);
  for (const content of ['{broken', JSON.stringify({ version: 2, revision: 1, publications: {}, runs: [] }),
    JSON.stringify({ version: 1, revision: -1, publications: {}, runs: [] })]) {
    await writeFile(journal.file, content);
    await assert.rejects(journal.read(), { code: 'JOURNAL_CORRUPT' });
    let called = false;
    await assert.rejects(journal.transact(() => { called = true; }), { code: 'JOURNAL_CORRUPT' });
    assert.equal(called, false);
    assert.equal(await readFile(journal.file, 'utf8'), content);
  }
  await writeFile(journal.file, 'x'.repeat(257));
  const small = new FileJournal(journal.directory, { maxBytes: 256 });
  await assert.rejects(small.read(), { code: 'JOURNAL_OVERSIZE' });
  await assert.rejects(small.transact(() => {}), { code: 'JOURNAL_OVERSIZE' });
  assert.equal((await readFile(journal.file)).length, 257);
});

test('oversized commits, overlong history and non-JSON values roll back exactly', async t => {
  const { directory } = await fixture(t);
  const journal = new FileJournal(directory, { maxBytes: 512 });
  await journal.transact(state => { state.publications.release = { sequence: '1' }; });
  const previous = await journal.read();
  await assert.rejects(journal.transact(state => { state.publications.huge = { data: 'x'.repeat(513) }; }),
    { code: 'JOURNAL_OVERSIZE' });
  await assert.rejects(journal.transact(state => { state.runs = Array.from({ length: 101 }, () => ({})); }),
    { code: 'JOURNAL_CORRUPT' });
  for (const value of [1n, NaN, Number.MAX_SAFE_INTEGER + 1, new Date(), () => {}, Symbol('hidden')]) {
    await assert.rejects(journal.transact(state => { state.publications.invalid = { value }; }), { code: 'JOURNAL_CORRUPT' });
  }
  await assert.rejects(journal.transact(state => { state.publications.circular = state; }), { code: 'JOURNAL_CORRUPT' });
  await assert.rejects(journal.transact(state => { state.revision++; }), { code: 'JOURNAL_CORRUPT' });
  assert.deepEqual(await journal.read(), previous);
  assert.deepEqual(await readdir(directory), ['journal.json']);
});

test('journal, lock and directory symlinks plus hardlinked state are refused', async t => {
  const { directory, journal } = await fixture(t);
  const external = join(directory, 'external.json');
  const content = JSON.stringify({ version: 1, revision: 7, publications: {}, runs: [] });
  await writeFile(external, content);
  await symlink(external, journal.file);
  await assert.rejects(journal.read(), { code: 'JOURNAL_UNSAFE_PATH' });
  await assert.rejects(journal.transact(() => {}), { code: 'JOURNAL_UNSAFE_PATH' });
  assert.equal(await readFile(external, 'utf8'), content);
  await unlink(journal.file);
  await link(external, journal.file);
  await assert.rejects(journal.read(), { code: 'JOURNAL_UNSAFE_PATH' });
  await unlink(journal.file);
  await symlink(external, journal.lock);
  await assert.rejects(journal.transact(() => {}), { code: 'JOURNAL_UNSAFE_PATH' });
  await assert.rejects(journal.recoverLock(), { code: 'JOURNAL_UNSAFE_PATH' });
  await unlink(journal.lock);
  const alias = join(directory, 'alias');
  await symlink(directory, alias);
  await assert.rejects(new FileJournal(alias).read(), { code: 'JOURNAL_UNSAFE_PATH' });
  await assert.rejects(new FileJournal(alias).transact(() => {}), { code: 'JOURNAL_UNSAFE_PATH' });
});

test('actual file write failure preserves original error and previously committed bytes', async t => {
  const { directory, journal } = await fixture(t);
  await journal.transact(state => { state.publications.release = { sequence: '3' }; });
  const before = await readFile(journal.file, 'utf8');
  const probe = await open(join(directory, 'probe'), 'wx');
  const proto = Object.getPrototypeOf(probe);
  const original = proto.writeFile;
  await probe.close();
  await unlink(join(directory, 'probe'));
  const expected = Object.assign(new Error('Injected storage exhaustion'), { code: 'ENOSPC' });
  const mocked = t.mock.method(proto, 'writeFile', async function (data, ...options) {
    if (Buffer.isBuffer(data)) throw expected;
    return original.call(this, data, ...options);
  });
  await assert.rejects(journal.transact(state => { state.publications.release.sequence = '4'; }), error => error === expected);
  mocked.mock.restore();
  assert.equal(await readFile(journal.file, 'utf8'), before);
  assert.deepEqual(await readdir(directory), ['journal.json']);
  assert.equal((await journal.transact(state => { state.publications.release.sequence = '5'; })).revision, 2);
});

test('post-rename fsync failure is commit-unknown, never success or claimed rollback', async t => {
  const { directory, journal } = await fixture(t);
  await journal.transact(state => { state.publications.release = { sequence: '3' }; });
  const original = journal._syncDirectory.bind(journal);
  const expected = Object.assign(new Error('Injected directory fsync failure'), { code: 'EIO' });
  let calls = 0;
  const mocked = t.mock.method(journal, '_syncDirectory', async () => {
    if (++calls === 2) throw expected; // Lock is durable; commit rename has happened.
    return original();
  });
  await assert.rejects(journal.transact(state => { state.publications.release.sequence = '4'; }),
    error => error.code === 'JOURNAL_COMMIT_UNKNOWN' && error.cause === expected);
  mocked.mock.restore();
  assert.equal((await journal.read()).publications.release.sequence, '4');
  assert.ok((await readdir(directory)).includes('journal.lock'));
  await assert.rejects(journal.recoverLock(), { code: 'JOURNAL_LOCK_LIVE' });
});

test('nested new directories survive reopen and the retained run bound is exactly 100', async t => {
  const { directory } = await fixture(t);
  const nested = join(directory, 'new-a', 'new-b', 'state');
  const journal = new FileJournal(nested);
  await journal.transact(state => { state.runs = Array.from({ length: 100 }, (_, id) => ({ id })); });
  assert.equal((await new FileJournal(nested).read()).runs.length, 100);
  assert.deepEqual(await readdir(nested), ['journal.json']);
});

test('an abandoned recovery fence is fail-closed and never silently deleted', async t => {
  const { directory, journal } = await fixture(t);
  const marker = JSON.stringify({ version: 1, pid: process.pid, host: hostname(), token: randomUUID(), createdAtMs: Date.now() });
  await writeFile(journal.recoveryFence, marker);
  await assert.rejects(journal.transact(() => {}), { code: 'JOURNAL_RECOVERY_LOCKED' });
  await assert.rejects(journal.recoverLock(), { code: 'JOURNAL_RECOVERY_LOCKED' });
  assert.equal(await readFile(journal.recoveryFence, 'utf8'), marker);
  assert.deepEqual(await readdir(directory), ['journal.recovery.lock']);
});
