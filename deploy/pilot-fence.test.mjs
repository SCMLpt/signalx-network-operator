import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ROOT, PATHS, sha256, validateManifest, render, admit, expire } from './pilot-fence.mjs';

// All admission/systemd/storage checks use this finite filesystem model. No
// daemon, RPC, network, systemctl, privileged path or infrastructure is touched.
function fixture() {
  const dirs = new Map(), files = new Map(), descriptors = new Map();
  let nextFd = 10;
  const rootDir = { uid: 0, mode: 0o755, directory: true };
  function addFile(p, content, opts = {}) {
    for (let d = path.posix.dirname(p); d !== '/'; d = path.posix.dirname(d)) if (!dirs.has(d)) dirs.set(d, { ...rootDir });
    files.set(p, { bytes: Buffer.from(content), uid: 0, mode: 0o644, nlink: 1, ...opts });
  }
  const c = { version: 1, operatorId: 'orcestra-bowtie-pilot', stateDirectory: PATHS.state, pin: true,
    kuboUrl: 'http://127.0.0.1:5001', gateways: ['https://ipfs.orcestra-campaign.org/'], ipnsRouters: ['https://delegated-ipfs.dev/'],
    publications: [{ id: 'orcestra-bowtie', root: ROOT }], limits: { maxCarBytes: 1048576, maxRunBytes: 4194304,
      maxBlocks: 64, maxLinks: 256, timeoutMs: 15000, runTimeoutMs: 60000, maxRepoBytes: 268435456 }, intervalSeconds: 300 };
  const k = { Identity: { PeerID: '12D3KooWExampleReviewedPeerIdentity' }, Addresses: { API: '/ip4/127.0.0.1/tcp/5001', Gateway: '/ip4/127.0.0.1/tcp/8080',
    Swarm: ['/ip4/0.0.0.0/tcp/4001', '/ip4/0.0.0.0/udp/4001/quic-v1'] }, Provide: { Enabled: true, Strategy: 'pinned' }, Routing: { Type: 'autoclient' } };
  const cb = JSON.stringify(c), kb = JSON.stringify(k);
  const m = { schemaVersion: 1, approved: true, termId: 'bounded-test', startUtc: '2026-10-03T00:00:00Z', endUtc: '2026-10-10T00:00:00Z',
    operatorOwner: 'Test owner', stopOwner: 'Test stop owner', hostIdentity: 'Test model, no host', root: ROOT, dedicatedRepoConfirmed: true,
    operatorConfigSha256: sha256(cb), kuboConfigSha256: sha256(kb), kuboRepoVersion: '17', peerId: k.Identity.PeerID, nodeVersion: '22.23.3' };
  addFile(PATHS.config, cb);
  addFile(`${PATHS.repo}/config`, kb, { uid: 1000, mode: 0o600 });
  addFile(`${PATHS.repo}/version`, '17\n', { uid: 1000, mode: 0o600 });
  dirs.set(PATHS.repo, { uid: 1000, mode: 0o700, directory: true });
  dirs.set(PATHS.state, { uid: 1000, mode: 0o700, directory: true });
  dirs.set(PATHS.control, { ...rootDir });
  for (const p of [PATHS.node, PATHS.kubo, PATHS.fence, PATHS.cli]) addFile(p, 'root-reviewed code');
  for (const item of render(m).files) addFile(item.path, item.content);
  function missing() { const e = new Error('Missing model path'); e.code = 'ENOENT'; throw e; }
  function stat(entry) {
    if (!entry) missing();
    return { uid: entry.uid, mode: entry.mode, nlink: entry.nlink ?? 1, size: entry.bytes?.length ?? 0,
      isFile: () => !entry.directory && !entry.symlink, isDirectory: () => !!entry.directory, isSymbolicLink: () => !!entry.symlink };
  }
  const io = {
    lstatSync: p => stat(files.get(p) ?? dirs.get(p)),
    openSync(p, flags, mode) {
      let e = files.get(p) ?? dirs.get(p);
      if (flags & fs.constants.O_CREAT) {
        if (e && flags & fs.constants.O_EXCL) { const error = new Error('exists'); error.code = 'EEXIST'; throw error; }
        if (!e) { e = { bytes: Buffer.alloc(0), uid: 0, mode, nlink: 1 }; files.set(p, e); }
      }
      if (!e) missing();
      const fd = nextFd++; descriptors.set(fd, { entry: e, offset: 0 }); return fd;
    },
    fstatSync: fd => stat(descriptors.get(fd).entry),
    readSync(fd, target, offset, length) {
      const d = descriptors.get(fd), n = Math.min(length, d.entry.bytes.length - d.offset);
      d.entry.bytes.copy(target, offset, d.offset, d.offset + n); d.offset += n; return n;
    },
    writeFileSync(fd, bytes) { descriptors.get(fd).entry.bytes = Buffer.from(bytes); },
    fsyncSync() {}, closeSync(fd) { descriptors.delete(fd); },
  };
  const timer = { ActiveState: 'active', FragmentPath: PATHS.timer, DropInPaths: '', NeedDaemonReload: 'no', NextElapseUSecRealtime: m.endUtc };
  return { m, c, k, dirs, files, addFile, io, timer, now: () => Date.parse('2026-10-04T00:00:00Z') };
}
function enter(f, unit = 'kubo.service', extras = {}) {
  return admit(f.m, unit, { io: f.io, now: f.now, timerState: () => f.timer, runtimeVersions: () => ({ kubo: '0.43.1', node: '22.23.3' }), ...extras });
}

test('approved active term admits both entries with dedicated service-owned repo', () => {
  const f = fixture();
  for (const u of ['kubo.service', 'operator.service']) assert.equal(enter(f, u).admitted, true);
  assert.equal(enter(f).hardTrafficCapVerified, false);
});
test('before start, exact expiry and reboot after expiry refuse both entries', () => {
  for (const timestamp of ['2026-10-02T23:59:59Z', '2026-10-10T00:00:00Z', '2026-10-11T00:00:00Z']) {
    const f = fixture();
    for (const u of ['kubo.service', 'operator.service']) assert.throws(() => enter(f, u, { now: () => Date.parse(timestamp) }));
  }
});
test('late timer inspection crossing expiry cannot admit an already expired start', () => {
  const f = fixture(); let count = 0;
  assert.throws(() => enter(f, 'operator.service', { now: () => count++ ? Date.parse(f.m.endUtc) : Date.parse(f.m.endUtc) - 1 }), /expired/);
});
test('unapproved template, extra fields, wrong root, malformed UTC and extended term refuse', () => {
  const f = fixture();
  for (const edits of [{ approved: false }, { root: 'bafywrong' }, { extra: true }, { startUtc: '2026-02-30T00:00:00Z' },
    { startUtc: '2026-10-03T00:00:00+00:00' }, { endUtc: '2026-10-10T00:00:01Z' }, { stopOwner: null }, { dedicatedRepoConfirmed: false }]) {
    assert.throws(() => validateManifest({ ...f.m, ...edits }));
  }
  const example = JSON.parse(fs.readFileSync(new URL('./pilot-manifest.example.json', import.meta.url)));
  assert.throws(() => render(example), /not approved/);
});
test('config digest/root/budgets/private API tampering refuses', () => {
  const f = fixture(); f.files.get(PATHS.config).bytes = Buffer.from('{}');
  assert.throws(() => enter(f), /digest/);
  for (const change of [c => { c.publications[0].root = 'bafywrong'; }, c => { c.limits.maxCarBytes++; }, c => { c.kuboUrl = 'http://0.0.0.0:5001'; }]) {
    const g = fixture(); change(g.c); const bytes = Buffer.from(JSON.stringify(g.c)); g.files.get(PATHS.config).bytes = bytes; g.m.operatorConfigSha256 = sha256(bytes);
    assert.throws(() => enter(g));
  }
  const g = fixture(); g.k.Addresses.API = '/ip4/0.0.0.0/tcp/5001'; const bytes = Buffer.from(JSON.stringify(g.k));
  g.files.get(`${PATHS.repo}/config`).bytes = bytes; g.m.kuboConfigSha256 = sha256(bytes); assert.throws(() => enter(g), /boundary/);
});
test('unsafe ancestor/leaf ownership, symlink, oversized and changed file refuse', () => {
  for (const change of [f => { f.dirs.get('/var/lib').uid = 1000; }, f => { f.dirs.get(PATHS.repo).mode = 0o777; },
    f => { f.files.get(PATHS.config).uid = 1000; }, f => { f.files.get(PATHS.config).symlink = true; },
    f => { f.files.get(PATHS.config).bytes = Buffer.alloc(16385); }, f => { f.files.get(PATHS.config).nlink = 2; }]) {
    const f = fixture(); change(f); assert.throws(() => enter(f));
  }
});
test('timer inactive, wrong/stale deadline, reload need and override refuse', () => {
  for (const edit of [{ ActiveState: 'inactive' }, { NextElapseUSecRealtime: '2026-10-17T00:00:00Z' }, { NeedDaemonReload: 'yes' },
    { DropInPaths: '/etc/systemd/system/signalx-pilot-stop.timer.d/late.conf' }, { FragmentPath: '/run/unrelated.timer' }]) {
    const f = fixture(); Object.assign(f.timer, edit); assert.throws(() => enter(f), /Timer/);
  }
  const f = fixture(); f.files.get(PATHS.timer).bytes = Buffer.from('old term'); assert.throws(() => enter(f), /Installed fence/);
});
test('current Node patch and actual Kubo executable version are required', () => {
  const f = fixture();
  assert.throws(() => enter(f, 'kubo.service', { runtimeVersions: () => ({ kubo: '0.42.0', node: '22.23.3' }) }), /runtime versions/);
  assert.throws(() => enter(f, 'operator.service', { runtimeVersions: () => ({ kubo: '0.43.1', node: '22.23.1' }) }), /runtime versions/);
  assert.throws(() => validateManifest({ ...f.m, nodeVersion: '22.23.1' }), /current Node patch/);
});
test('root-only stop marker is durable, idempotent and blocks a rolled-back clock restart', () => {
  const f = fixture(), atEnd = () => Date.parse(f.m.endUtc);
  assert.throws(() => expire(f.m, { io: f.io, now: atEnd, uid: 1000 }), /root/);
  assert.throws(() => expire(f.m, { io: f.io, now: f.now, uid: 0 }), /not elapsed/);
  assert.equal(expire(f.m, { io: f.io, now: atEnd, uid: 0 }).markerAlreadyPresent, false);
  assert.equal(expire(f.m, { io: f.io, now: atEnd, uid: 0 }).markerAlreadyPresent, true);
  assert.throws(() => enter(f), /stop marker/);
});
test('render binds both entries/deadline/resources; stops both before marker IO', () => {
  const f = fixture(), output = render(f.m);
  assert.deepEqual(output, render(f.m));
  const byPath = Object.fromEntries(output.files.map(x => [x.path, x.content]));
  for (const [p, u] of [[PATHS.kuboDropIn, 'kubo.service'], [PATHS.operatorDropIn, 'operator.service']]) {
    assert.match(byPath[p], new RegExp(`admit ${PATHS.manifest} ${u}`));
    assert.match(byPath[p], /Requires=signalx-pilot-stop.timer/); assert.match(byPath[p], /After=signalx-pilot-stop.timer time-sync.target/);
    assert.match(byPath[p], /TimeoutStopSec=5s/);
  }
  assert.match(byPath[PATHS.kuboDropIn], /MemoryMax=2G/); assert.match(byPath[PATHS.kuboDropIn], /GOMEMLIMIT=1GiB/);
  assert.match(byPath[PATHS.operatorDropIn], /MemoryMax=512M/);
  assert.match(byPath[PATHS.timer], /OnCalendar=2026-10-10 00:00:00 UTC/); assert.match(byPath[PATHS.timer], /Persistent=true/);
  assert.ok(byPath[PATHS.stop].indexOf('systemctl --no-block stop kubo.service operator.service') < byPath[PATHS.stop].indexOf(' expire '));
  assert.match(byPath[PATHS.stop], /ExecStart=-/); assert.doesNotMatch(byPath[PATHS.stop], /unpin|destroy|rm /);
});
test('actual CLI invocation through preserved leaf and ancestor symlinks still refuses', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'pilot-fence-cli-'));
  try {
    const link = path.join(directory, 'fence.mjs'); fs.symlinkSync(fileURLToPath(new URL('./pilot-fence.mjs', import.meta.url)), link);
    const ancestor = path.join(directory, 'deploy'); fs.symlinkSync(fileURLToPath(new URL('./', import.meta.url)), ancestor, 'dir');
    for (const args of [[link], ['--preserve-symlinks-main', link],
      ['--preserve-symlinks-main', path.join(ancestor, 'pilot-fence.mjs')]]) {
      const r = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 3000, maxBuffer: 4096 });
      assert.equal(r.status, 1); assert.match(r.stderr, /Pilot fence refused: Usage/);
    }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
