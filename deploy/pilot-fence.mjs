#!/usr/bin/env node
// This helper renders and checks a systemd admission fence. It never starts a
// daemon, installs units, unpins content, or changes provider infrastructure.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const ROOT = 'bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle';
export const PATHS = Object.freeze({
  manifest: '/etc/signalx-network/pilot-manifest.json',
  config: '/etc/signalx-network/operator-pilot.json',
  repo: '/var/lib/signalx-kubo-pilot',
  state: '/var/lib/signalx-operator-pilot',
  control: '/var/lib/signalx-pilot-control',
  node: '/opt/node-v22/bin/node',
  kubo: '/opt/kubo-v0.43.1/ipfs',
  fence: '/opt/signalx/network-operator/deploy/pilot-fence.mjs',
  cli: '/opt/signalx/network-operator/cli.mjs',
  timer: '/etc/systemd/system/signalx-pilot-stop.timer',
  stop: '/etc/systemd/system/signalx-pilot-stop.service',
  kuboDropIn: '/etc/systemd/system/kubo.service.d/90-pilot.conf',
  operatorDropIn: '/etc/systemd/system/operator.service.d/90-pilot.conf',
});
const UNITS = new Set(['kubo.service', 'operator.service']);
const MAX_TERM_MS = 7 * 24 * 60 * 60 * 1000;
const HASH = /^[a-f0-9]{64}$/;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const fail = reason => { throw new Error(reason); };
export const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function instant(value) {
  if (typeof value !== 'string' || !UTC.test(value)) fail('UTC time must use YYYY-MM-DDTHH:mm:ssZ');
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString().replace('.000Z', 'Z') !== value) fail('Invalid UTC date');
  return milliseconds;
}
export function validateManifest(m) {
  const keys = ['schemaVersion', 'approved', 'termId', 'startUtc', 'endUtc', 'operatorOwner', 'stopOwner',
    'hostIdentity', 'root', 'dedicatedRepoConfirmed', 'operatorConfigSha256', 'kuboConfigSha256', 'kuboRepoVersion', 'peerId', 'nodeVersion'];
  if (!m || typeof m !== 'object' || Array.isArray(m) || Object.keys(m).length !== keys.length || Object.keys(m).some(k => !keys.includes(k))) fail('Invalid manifest fields');
  if (m.schemaVersion !== 1 || m.approved !== true) fail('Pilot manifest is not approved');
  if (!/^[a-z0-9][a-z0-9-]{0,47}$/.test(m.termId ?? '')) fail('Invalid term ID');
  for (const key of ['operatorOwner', 'stopOwner', 'hostIdentity']) {
    if (typeof m[key] !== 'string' || m[key].trim() !== m[key] || m[key].length < 1 || m[key].length > 160 || /[\x00-\x1f\x7f]/.test(m[key])) fail(`Missing or invalid ${key}`);
  }
  if (m.root !== ROOT || m.dedicatedRepoConfirmed !== true) fail('Require the exact root and approved dedicated repository');
  if (!HASH.test(m.operatorConfigSha256 ?? '') || !HASH.test(m.kuboConfigSha256 ?? '')) fail('Require reviewed configuration digests');
  if (!/^[0-9]{1,3}$/.test(m.kuboRepoVersion ?? '') || !/^[a-zA-Z0-9]{20,128}$/.test(m.peerId ?? '')) fail('Require reviewed repository version and peer identity');
  if (m.nodeVersion !== '22.23.3') fail('Require the reviewed current Node patch 22.23.3');
  const start = instant(m.startUtc), end = instant(m.endUtc);
  if (end <= start || end - start > MAX_TERM_MS) fail('Pilot term must be positive and at most seven days');
  return { ...m, startMs: start, endMs: end };
}

function checkTerm(m, now) {
  if (!Number.isSafeInteger(now)) fail('Invalid clock');
  if (now < m.startMs) fail('Pilot has not started');
  if (now >= m.endMs) fail('Pilot term expired');
}
function canonical(p) {
  if (typeof p !== 'string' || !/^\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/.test(p) || path.posix.normalize(p) !== p || p.split('/').some(x => x === '.' || x === '..')) fail('Unsafe absolute path');
}
function statWalk(p, io, { rootLeaf = true, directory = false } = {}) {
  canonical(p);
  const segments = p.split('/').filter(Boolean);
  let current = '';
  for (let i = 0; i < segments.length; i++) {
    current += `/${segments[i]}`;
    const s = io.lstatSync(current);
    if (s.isSymbolicLink()) fail('Symlink path refused');
    const last = i === segments.length - 1;
    if ((!last || directory) && !s.isDirectory()) fail('Expected directory');
    const serviceRepoAncestor = !last && current === PATHS.repo && (p === `${PATHS.repo}/config` || p === `${PATHS.repo}/version`);
    if (s.mode & 0o022) fail('Group/world writable path refused');
    if ((!last || rootLeaf) && !serviceRepoAncestor) {
      if (s.uid !== 0 || (s.mode & 0o022)) fail('Require root ownership and no group/world write');
    }
    if (last && !directory && (!s.isFile() || s.nlink !== 1)) fail('Require regular single-link file');
  }
}
function boundedFile(p, max, io, options) {
  statWalk(p, io, options);
  // Opening with O_NOFOLLOW and checking the descriptor closes the final-leaf
  // swap race. Root-owned ancestors are the administrative trust boundary.
  const fd = io.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const s = io.fstatSync(fd);
    if (!s.isFile() || s.nlink !== 1 || s.size > max || s.size < 1) fail('File type or byte bound refused');
    if (options?.rootLeaf !== false && (s.uid !== 0 || (s.mode & 0o022))) fail('Unsafe opened file permissions');
    const bytes = Buffer.alloc(s.size + 1);
    let n = 0;
    while (n < bytes.length) {
      const read = io.readSync(fd, bytes, n, bytes.length - n, null);
      if (!read) break;
      n += read;
    }
    if (n > max || n !== s.size) fail('File changed or exceeded byte bound');
    return bytes.subarray(0, n);
  } finally { io.closeSync(fd); }
}
function parse(bytes) { try { return JSON.parse(bytes.toString('utf8')); } catch { fail('Invalid JSON'); } }
function markerPath(m) { return `${PATHS.control}/${m.termId}.expired`; }

export function render(raw) {
  const m = validateManifest(raw);
  const command = `${PATHS.node} ${PATHS.fence}`;
  const calendar = m.endUtc.replace('T', ' ').replace('Z', ' UTC');
  const common = `[Unit]\nRequires=signalx-pilot-stop.timer\nAfter=signalx-pilot-stop.timer time-sync.target\n\n[Service]\nExecStartPre=\n`;
  const kubo = `${common}ExecStartPre=${command} admit ${PATHS.manifest} kubo.service\nEnvironment=IPFS_PATH=${PATHS.repo}\nEnvironment=GOMEMLIMIT=1GiB\nWorkingDirectory=${PATHS.repo}\nStateDirectory=\nStateDirectory=signalx-kubo-pilot\nMemoryHigh=1536M\nMemoryMax=2G\nMemorySwapMax=0\nCPUQuota=150%\nTasksMax=512\nLimitNOFILE=4096\nTimeoutStopSec=5s\nKillMode=control-group\nSendSIGKILL=yes\n`;
  const operator = `${common}ExecStartPre=${command} admit ${PATHS.manifest} operator.service\nStateDirectory=\nStateDirectory=signalx-operator-pilot\nExecStart=\nExecStart=${PATHS.node} --max-old-space-size=256 ${PATHS.cli} run ${PATHS.config}\nMemoryHigh=256M\nMemoryMax=512M\nMemorySwapMax=0\nCPUQuota=50%\nTasksMax=64\nLimitNOFILE=1024\nTimeoutStopSec=5s\nKillMode=control-group\nSendSIGKILL=yes\n`;
  const timer = `[Unit]\nDescription=Absolute stop for reviewed SignalX finite pilot\nAfter=time-sync.target\n\n[Timer]\nOnCalendar=${calendar}\nAccuracySec=1s\nRandomizedDelaySec=0\nPersistent=true\nUnit=signalx-pilot-stop.service\n\n[Install]\nWantedBy=timers.target\n`;
  // Submit both stop jobs before any manifest/marker IO. A marker error or
  // filesystem stall cannot prevent this earlier shutdown request.
  const stop = `[Unit]\nDescription=Stop both SignalX pilot services and preserve repository\n\n[Service]\nType=oneshot\nUser=root\nStateDirectory=signalx-pilot-control\nStateDirectoryMode=0755\nUMask=0022\nExecStart=/usr/bin/systemctl --no-block stop kubo.service operator.service\nExecStart=-${command} expire ${PATHS.manifest}\nTimeoutStartSec=10s\n`;
  return { manifestSha256: sha256(Buffer.from(JSON.stringify(raw))), stopGraceSeconds: 5,
    files: [{ path: PATHS.timer, content: timer }, { path: PATHS.stop, content: stop },
      { path: PATHS.kuboDropIn, content: kubo }, { path: PATHS.operatorDropIn, content: operator }] };
}

function checkOperator(c, m) {
  const keys = ['version', 'operatorId', 'stateDirectory', 'pin', 'kuboUrl', 'gateways', 'ipnsRouters', 'publications', 'limits', 'intervalSeconds'];
  if (!c || Object.keys(c).length !== keys.length || Object.keys(c).some(k => !keys.includes(k)) || c.version !== 1 || c.pin !== true || c.stateDirectory !== PATHS.state || c.kuboUrl !== 'http://127.0.0.1:5001' || c.publications?.length !== 1 || c.publications[0].root !== m.root || Object.keys(c.publications[0]).sort().join(',') !== 'id,root') fail('Operator configuration does not match the fixed pilot');
  const ceilings = { maxCarBytes: 1048576, maxRunBytes: 4194304, maxBlocks: 64, maxLinks: 256, timeoutMs: 15000, runTimeoutMs: 60000, maxRepoBytes: 268435456 };
  if (!c.limits || Object.keys(c.limits).length !== Object.keys(ceilings).length || Object.keys(c.limits).some(k => !Object.hasOwn(ceilings, k))) fail('Require explicit bounded limits');
  for (const [key, ceiling] of Object.entries(ceilings)) if (!Number.isSafeInteger(c.limits[key]) || c.limits[key] < 1 || c.limits[key] > ceiling) fail('Operator limit exceeds pilot envelope');
  if (c.limits.maxRunBytes < c.limits.maxCarBytes || c.limits.runTimeoutMs < c.limits.timeoutMs || !Number.isSafeInteger(c.intervalSeconds) || c.intervalSeconds < 300 || c.intervalSeconds > 86400) fail('Invalid pilot run budget');
  if (c.gateways?.length !== 1 || c.gateways[0] !== 'https://ipfs.orcestra-campaign.org/' || !Array.isArray(c.ipnsRouters) || c.ipnsRouters.length !== 1 || c.ipnsRouters[0] !== 'https://delegated-ipfs.dev/') fail('Unexpected publication sources');
}
function checkKubo(c, m) {
  if (c.Identity?.PeerID !== m.peerId || c.Addresses?.API !== '/ip4/127.0.0.1/tcp/5001' || c.Addresses?.Gateway !== '/ip4/127.0.0.1/tcp/8080') fail('Kubo identity or private administration boundary changed');
  const expected = ['/ip4/0.0.0.0/tcp/4001', '/ip4/0.0.0.0/udp/4001/quic-v1', '/ip6/::/tcp/4001', '/ip6/::/udp/4001/quic-v1'];
  if (!Array.isArray(c.Addresses.Swarm) || c.Addresses.Swarm.length < 2 || c.Addresses.Swarm.some(x => !expected.includes(x)) || !expected.slice(0, 2).every(x => c.Addresses.Swarm.includes(x))) fail('Unexpected public swarm listeners');
  if (c.Provide?.Enabled !== true || c.Provide?.Strategy !== 'pinned' || !['auto', 'autoclient'].includes(c.Routing?.Type)) fail('Unexpected native providing policy');
}

export function readManifest(filename, io = fs) {
  if (filename !== PATHS.manifest) fail('Use the reviewed manifest path');
  return parse(boundedFile(filename, 16384, io));
}
export function readTimerState() {
  const r = spawnSync('/usr/bin/systemctl', ['show', 'signalx-pilot-stop.timer', '--property=ActiveState', '--property=FragmentPath', '--property=DropInPaths', '--property=NeedDaemonReload', '--property=NextElapseUSecRealtime'],
    { encoding: 'utf8', timeout: 2000, maxBuffer: 4096, env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', TZ: 'UTC' } });
  if (r.error || r.status !== 0) fail('Cannot inspect the installed timer');
  const values = {};
  for (const line of r.stdout.trim().split('\n')) {
    const at = line.indexOf('=');
    if (at < 1 || Object.hasOwn(values, line.slice(0, at))) fail('Invalid timer state');
    values[line.slice(0, at)] = line.slice(at + 1);
  }
  return values;
}
export function readRuntimeVersions() {
  const r = spawnSync(PATHS.kubo, ['version', '--number'], { encoding: 'utf8', timeout: 2000, maxBuffer: 512,
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', IPFS_PATH: PATHS.repo } });
  if (r.error || r.status !== 0) fail('Cannot inspect reviewed Kubo executable');
  return { kubo: r.stdout.trim(), node: process.versions.node };
}
export function admit(raw, unit, { io = fs, now = Date.now, timerState = readTimerState, runtimeVersions = readRuntimeVersions } = {}) {
  if (!UNITS.has(unit)) fail('Unsupported service entry');
  const m = validateManifest(raw);
  checkTerm(m, now());
  statWalk(PATHS.repo, io, { rootLeaf: false, directory: true });
  statWalk(PATHS.state, io, { rootLeaf: false, directory: true });
  statWalk(PATHS.control, io, { directory: true });
  try { io.lstatSync(markerPath(m)); fail('Pilot has an irreversible stop marker'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  for (const p of [PATHS.node, PATHS.kubo, PATHS.fence, PATHS.cli]) statWalk(p, io);
  const versions = runtimeVersions();
  if (versions.kubo !== '0.43.1' || versions.node !== m.nodeVersion) fail('Installed runtime versions differ from reviewed patches');
  const config = boundedFile(PATHS.config, 16384, io);
  if (sha256(config) !== m.operatorConfigSha256) fail('Operator configuration digest changed');
  checkOperator(parse(config), m);
  // The service account owns its dedicated Kubo repository. A config digest
  // detects edits; this is not a cryptographic inventory of stored pins/blocks.
  const kubo = boundedFile(`${PATHS.repo}/config`, 262144, io, { rootLeaf: false });
  if (sha256(kubo) !== m.kuboConfigSha256) fail('Kubo configuration digest changed');
  checkKubo(parse(kubo), m);
  if (boundedFile(`${PATHS.repo}/version`, 128, io, { rootLeaf: false }).toString('utf8').trim() !== m.kuboRepoVersion) fail('Repository version changed');
  for (const item of render(raw).files) if (!boundedFile(item.path, 16384, io).equals(Buffer.from(item.content))) fail('Installed fence differs from approved term');
  const t = timerState();
  if (t.ActiveState !== 'active' || t.FragmentPath !== PATHS.timer || t.DropInPaths !== '' || t.NeedDaemonReload !== 'no' || Date.parse(t.NextElapseUSecRealtime) !== m.endMs) fail('Timer is not active with the reviewed loaded deadline');
  // Slow filesystem/system-manager checks may cross the deadline.
  checkTerm(m, now());
  return { admitted: true, unit, termId: m.termId, root: m.root, endUtc: m.endUtc, hardTrafficCapVerified: false };
}

export function expire(raw, { io = fs, now = Date.now, uid = process.getuid?.() } = {}) {
  const m = validateManifest(raw);
  if (uid !== 0) fail('Only the root stop supervisor may write the stop marker');
  if (now() < m.endMs) fail('Deadline has not elapsed');
  statWalk(PATHS.control, io, { directory: true });
  const p = markerPath(m);
  const bytes = Buffer.from(JSON.stringify({ schemaVersion: 1, termId: m.termId, root: m.root, endUtc: m.endUtc, expired: true }) + '\n');
  let fd;
  try { fd = io.openSync(p, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o644); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    if (!boundedFile(p, 4096, io).equals(bytes)) fail('Unexpected stop marker');
    return { expired: true, termId: m.termId, markerAlreadyPresent: true };
  }
  try { io.writeFileSync(fd, bytes); io.fsyncSync(fd); } finally { io.closeSync(fd); }
  const dir = io.openSync(PATHS.control, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try { io.fsyncSync(dir); } finally { io.closeSync(dir); }
  return { expired: true, termId: m.termId, markerAlreadyPresent: false };
}

export function main(args) {
  if (!['render', 'admit', 'expire'].includes(args[0]) || (args[0] === 'admit' ? args.length !== 3 : args.length !== 2)) fail('Usage: pilot-fence.mjs render|expire MANIFEST; pilot-fence.mjs admit MANIFEST kubo.service|operator.service');
  const raw = readManifest(args[1]);
  const result = args[0] === 'render' ? render(raw) : args[0] === 'admit' ? admit(raw, args[2]) : expire(raw);
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}
if (process.argv[1] && fs.realpathSync(fileURLToPath(import.meta.url)) === fs.realpathSync(process.argv[1])) {
  try { main(process.argv.slice(2)); } catch (error) { process.stderr.write(`Pilot fence refused: ${error.message}\n`); process.exitCode = 1; }
}
