import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CarWriter } from '@ipld/car';
import * as dagPB from '@ipld/dag-pb';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { identity } from 'multiformats/hashes/identity';
import * as digest from 'multiformats/hashes/digest';
import { peerIdFromMultihash } from '@libp2p/peer-id';
import { validateConfig } from './operator.mjs';
import { DEFAULT_ROOT, acquisitionPlan, graphManifest, verifyEvidence } from './live-evidence.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value));
// Fixed public identity fixtures: no private keys, daemon or network service.
const ids = [1, 2, 3].map(value => peerIdFromMultihash(digest.create(0,
  Uint8Array.of(8, 1, 18, 32, ...Array(32).fill(value)))).toString());
const start = 1801540800000, end = start + 1000, now = end + 1000;
async function block(code, bytes, hasher = sha256) {
  return { cid: CID.createV1(code, await hasher.digest(bytes)), bytes };
}
async function car(root, blocks) {
  const { writer, out } = CarWriter.create([root]);
  const output = (async () => { const chunks = []; for await (const chunk of out) chunks.push(chunk); return Buffer.concat(chunks); })();
  for (const item of blocks) await writer.put(item);
  await writer.close(); return output;
}
async function publication() {
  const leaves = await Promise.all(['csv A', 'csv B', 'xlsx contents', 'license metadata'].map(value =>
    block(0x55, Buffer.from(value))));
  const root = await block(dagPB.code, dagPB.encode(dagPB.prepare({
    Data: Uint8Array.of(8, 1), Links: leaves.map((leaf, index) => ({ Name: String(index), Hash: leaf.cid, Tsize: leaf.bytes.length })),
  })));
  return { root, leaves, source: await car(root.cid, [root, ...leaves]),
    received: await car(root.cid, [...leaves].reverse().concat(root, leaves[0])) };
}

async function fixture(t, { inline = false } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'signalx-evidence-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let graph = await publication();
  if (inline) {
    const root = await block(0x55, Buffer.from('inline'), identity);
    graph = { root, source: await car(root.cid, [root]), received: await car(root.cid, [root]) };
  }
  const root = graph.root.cid.toString();
  const config = { version: 1, operatorId: 'parser-fixture', stateDirectory: './state', pin: true,
    gateways: ['https://ipfs.orcestra-campaign.org/'], ipnsRouters: ['https://delegated-ipfs.dev/'],
    publications: [{ id: 'meteor-logs', root }],
    limits: { maxCarBytes: 1048576, maxRunBytes: 4194304, timeoutMs: 30000, runTimeoutMs: 30000 } };
  const normalized = validateConfig({ ...config, stateDirectory: '/approved/state' });
  const policyDigest = hash(JSON.stringify(normalized));
  const epoch = Buffer.from('MainPID=42\nInvocationID=0123456789abcdef0123456789abcdef\n');
  const payloadBytes = (await graphManifest(graph.received, root)).nonInlinePayloadBytes;
  const workerPackage = encode({ name: 'synthetic-parser-worker', version: '0.1.0' });
  const fileNames = ['cli.mjs', 'operator.mjs', 'car.mjs', 'kubo.mjs', 'ipns.mjs', 'io.mjs',
    'journal.mjs', 'state.mjs', 'package.json', 'package-lock.json'];
  const sourceHashes = Object.fromEntries(fileNames.map(name => [name, name === 'package.json' ? hash(workerPackage) : hash(name)]));
  const data = {
    workerPackage, workerSourceHashes: Buffer.from(fileNames.map(name => `${sourceHashes[name]}  /opt/fixture/${name}\n`).join('')),
    operatorBinaryHash: Buffer.from('a'.repeat(64) + '  /usr/local/bin/ipfs\n'),
    probeBinaryHash: Buffer.from('b'.repeat(64) + '  /usr/local/bin/ipfs\n'),
    config: encode(config), workerReport: encode({ status: 'verified', policyDigest, pinRequested: true,
      completedAtMs: start - 100, results: [{ root, status: 'locally_pinned' }] }),
    operatorVersion: encode({ Version: '0.43.1' }), probeVersion: encode({ Version: '0.43.1' }),
    operatorId: encode({ ID: ids[0] }), probeId: encode({ ID: ids[1] }), discoveryId: encode({ ID: ids[2] }),
    operatorEpochBefore: epoch, operatorEpochAfter: epoch, probeEpochBefore: epoch, probeEpochAfter: epoch,
    pinLs: encode({ Keys: { [root]: { Type: 'recursive' } } }), pinVerify: encode({ Cid: root, Ok: true }),
    ledgerBefore: encode({ Peer: ids[1], Sent: 0 }), ledgerAfter: encode({ Peer: ids[1], Sent: payloadBytes }),
    coldRefs: Buffer.alloc(0), routingConfig: encode({ Key: 'Routing.Type', Value: 'none' }), bootstrapList: Buffer.alloc(0),
    peersBefore: encode({ Peers: [{ Peer: ids[0], Addr: '/ip4/192.0.2.1/tcp/4001' }] }),
    peersAfter: encode({ Peers: [{ Peer: ids[0], Addr: '/ip4/192.0.2.1/tcp/4001' }] }),
    providerDiscovery: Buffer.from(ids[0] + '\n'), sourceCar: graph.source, retrievedCar: graph.received,
    isolationRules: Buffer.from('SYNTHETIC PARSER TEST ONLY; no actual firewall\n'),
    isolationTrace: Buffer.from('SYNTHETIC PARSER TEST ONLY; no actual traffic\n'),
    provideStat: encode({ Sweep: { Schedule: {} } }), dhtStat: encode({ Name: 'wanserver', Buckets: [] }),
    bandwidthBefore: encode({ TotalIn: 0, TotalOut: 0 }), bandwidthAfter: encode({ TotalIn: 100, TotalOut: 1000 }),
  };
  const after = new Set(['operatorEpochAfter', 'ledgerAfter', 'bandwidthAfter', 'probeEpochAfter', 'peersAfter', 'retrievedCar', 'isolationTrace']);
  const manifest = { schemaVersion: 1, root, triggerOrigin: 'controlled_probe',
    operator: { peerId: ids[0], site: 'synthetic-operator' }, probe: { peerId: ids[1], site: 'synthetic-probe' },
    discoveryObserver: { peerId: ids[2], site: 'synthetic-discovery' }, window: { startAtMs: start, endAtMs: end },
    implementation: { workerVersion: '0.1.0', workerFileHashes: sourceHashes,
      operatorKuboSha256: 'a'.repeat(64), probeKuboSha256: 'b'.repeat(64) },
    approval: { reference: 'synthetic parser fixture, not real approval', configPath: '/approved/config.json', policyDigest,
      retentionUntilMs: end + 60000 },
    isolation: { allowedPeerId: ids[0], targetOnly: true, gatewayEgressDenied: true, thirdPartyPeerEgressDenied: true,
      startAtMs: start, endAtMs: end, reviewReference: 'synthetic parser fixture, not a real review' },
    artifacts: Object.fromEntries(Object.keys(data).map(key => [key, { file: key + (key.endsWith('Car') ? '.car' : '.txt'),
      sha256: hash(data[key]), capturedAtMs: after.has(key) ? end : start,
      command: 'Synthetic parser fixture; command was not executed', exitCode: 0 }])),
  };
  const path = join(directory, 'manifest.json');
  async function save() {
    for (const [key, bytes] of Object.entries(data)) {
      const name = manifest.artifacts[key].file;
      if (/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)) await writeFile(join(directory, name), bytes);
    }
    await writeFile(path, encode(manifest));
  }
  async function change(key, bytes) {
    data[key] = bytes; manifest.artifacts[key].sha256 = hash(bytes); await save();
  }
  await save();
  return { directory, path, graph, data, manifest, save, change, verify: () => verifyEvidence(path, { now }) };
}

test('real five-block CAR fixture accepts reordering/duplicates without promoting provenance, DHT or adoption', async t => {
  const f = await fixture(t); const report = await f.verify();
  assert.equal(report.controlledRetrievalArtifactsConsistent, true, JSON.stringify(report.issues));
  assert.equal(report.graph.reachableBlockCount, 5);
  assert.notEqual(hash(f.data.sourceCar), hash(f.data.retrievedCar));
  assert.equal(report.controlledDirectDeliveryVerified, false);
  assert.equal(report.continuousIsolation, 'requires_review_of_raw_rules_and_trace');
  for (const key of ['publicDhtServerServing', 'providerRefreshOverNativeInterval', 'retainedWithoutOrigin',
    'organicExternalRequests', 'independentOperators', 'serviceRevenue']) assert.equal(report[key], null);
  assert.equal(report.externalUseVerified, false);
});

test('incomplete native export, hash tampering and inline-only graph fail transfer acceptance', async t => {
  const f = await fixture(t);
  await f.change('retrievedCar', await car(f.graph.root.cid, [f.graph.root]));
  assert.match((await f.verify()).issues[0], /missing/i);
  const corrupted = Buffer.from(f.graph.received); corrupted[corrupted.length - 1] ^= 1;
  await f.change('retrievedCar', corrupted); assert.match((await f.verify()).issues[0], /CID/i);
  const inline = await fixture(t, { inline: true }); assert.match((await inline.verify()).issues[0], /Inline-only/);
});

test('cold cache, alternate peer, missing isolation trace and wrong native config key fail', async t => {
  for (const [key, bytes, pattern] of [
    ['coldRefs', encode({ Ref: 'preexisting-block', Err: '' }), /empty/],
    ['peersAfter', encode({ Peers: [{ Peer: ids[2] }] }), /alternate peer/],
    ['isolationTrace', Buffer.alloc(0), /restriction/],
    ['routingConfig', encode({ Key: 'Other.Config', Value: 'none' }), /Routing.Type/],
  ]) { const f = await fixture(t); await f.change(key, bytes); assert.match((await f.verify()).issues[0], pattern); }
});

test('counter reset, insufficient payload, wrong ledger peer and daemon restart fail', async t => {
  for (const [key, value, pattern] of [
    ['ledgerBefore', { Peer: ids[1], Sent: 100000 }, /reset/],
    ['ledgerAfter', { Peer: ids[1], Sent: 1 }, /cover/],
    ['ledgerAfter', { Peer: ids[2], Sent: 100000 }, /wrong receiver/],
  ]) { const f = await fixture(t); await f.change(key, encode(value)); assert.match((await f.verify()).issues[0], pattern); }
  const f = await fixture(t); await f.change('operatorEpochAfter', Buffer.from('MainPID=43\nInvocationID=abcdef0123456789abcdef0123456789ab\n'));
  assert.match((await f.verify()).issues[0], /epoch/);
});

test('reversed capture order, expired retention, old snapshot and oversized window fail', async t => {
  const changes = [
    [m => { m.artifacts.coldRefs.capturedAtMs = end; }, /before/],
    [m => { m.artifacts.ledgerAfter.capturedAtMs = start; }, /after/],
    [m => { m.approval.retentionUntilMs = end; }, /retention/],
    [m => { m.artifacts.pinVerify.capturedAtMs = start - 600001; }, /interval/],
    [m => { m.window.startAtMs = end - 30001; }, /30-second/],
  ];
  for (const [change, pattern] of changes) { const f = await fixture(t); change(f.manifest); await f.save(); assert.match((await f.verify()).issues[0], pattern); }
});

test('wrong policy, same operator/receiver identity and noncontrolled trigger cannot pass', async t => {
  for (const [change, pattern] of [
    [m => { m.approval.policyDigest = '0'.repeat(64); }, /digest/],
    [m => { m.probe.peerId = m.operator.peerId; }, /distinct/],
    [m => { m.triggerOrigin = 'unprompted_native'; }, /controlled/],
  ]) { const f = await fixture(t); change(f.manifest); await f.save(); assert.match((await f.verify()).issues[0], pattern); }
});

test('exact deployed source/binary provenance is required; direct scope can omit routing diagnostics and discovery', async t => {
  const wrongSource = await fixture(t); wrongSource.manifest.implementation.workerFileHashes['car.mjs'] = '0'.repeat(64);
  await wrongSource.save(); assert.match((await wrongSource.verify()).issues[0], /source hashes/);
  const wrongBinary = await fixture(t); wrongBinary.manifest.implementation.probeKuboSha256 = '0'.repeat(64);
  await wrongBinary.save(); assert.match((await wrongBinary.verify()).issues[0], /binary digest/);
  const direct = await fixture(t);
  for (const key of ['provideStat', 'dhtStat', 'discoveryId', 'providerDiscovery']) {
    delete direct.manifest.artifacts[key]; delete direct.data[key];
  }
  delete direct.manifest.discoveryObserver; await direct.save();
  const result = await direct.verify();
  assert.equal(result.controlledRetrievalArtifactsConsistent, true, JSON.stringify(result.issues));
  assert.equal(result.providerDiscoveryArtifactsConsistent, false);
  assert.equal(result.publicDhtServerServing, null);
});

test('path escape, hash mismatch, oversized raw output and final symlink fail bounded reads', async t => {
  const pathEscape = await fixture(t); pathEscape.manifest.artifacts.pinLs.file = '../pin.txt'; await pathEscape.save();
  assert.match((await pathEscape.verify()).issues[0], /filename/);
  const wrongHash = await fixture(t); wrongHash.manifest.artifacts.pinLs.sha256 = '0'.repeat(64); await wrongHash.save();
  assert.match((await wrongHash.verify()).issues[0], /digest/);
  const large = await fixture(t); await large.change('isolationTrace', Buffer.alloc(128 * 1024 + 1));
  assert.match((await large.verify()).issues[0], /bounded/);
  const link = await fixture(t); const path = join(link.directory, link.manifest.artifacts.pinLs.file);
  await rm(path); await symlink(join(link.directory, link.manifest.artifacts.operatorId.file), path);
  assert.equal((await link.verify()).status, 'rejected');
});

test('plan defaults to exact qualified root and CLI works through a symlink without network execution', async t => {
  const plan = acquisitionPlan(); assert.equal(plan.root, DEFAULT_ROOT); assert.equal(plan.executesNetworkActions, false);
  assert.equal(plan.budgets.retrievedCarBytes, 1048576);
  assert.match(plan.commands.approvedWorkerPreflight, /verification-only-config/);
  assert.equal(Object.hasOwn(plan.commands, 'approvedFinitePin'), false);
  assert.match(plan.commands.admittedWorkerReportCapture.sourceCommand, /operator.service/);
  assert.doesNotMatch(plan.commands.operator.find(command => command.includes('pin verify')), new RegExp(DEFAULT_ROOT));
  const directory = await mkdtemp(join(tmpdir(), 'signalx-evidence-cli-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const link = join(directory, 'evidence.mjs'); await symlink(fileURLToPath(new URL('./live-evidence.mjs', import.meta.url)), link);
  const output = execFileSync(process.execPath, [link, 'plan'], { timeout: 5000, maxBuffer: 128 * 1024 });
  assert.equal(JSON.parse(output).root, DEFAULT_ROOT);
  await assert.rejects(() => graphManifest(Buffer.from('not a CAR'), DEFAULT_ROOT));
});

test('preserved main and dependency symlink modes execute through an ancestor directory symlink', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'signalx-evidence-ancestor-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sourceAlias = join(directory, 'operator-source');
  // A symlink to the directory preserves sibling imports and node_modules.
  // A tool-only symlink cannot establish this mode: its relative imports fail
  // before execution reaches the entry guard.
  await symlink(fileURLToPath(new URL('.', import.meta.url)), sourceAlias, 'dir');
  const entry = join(sourceAlias, 'live-evidence.mjs');
  for (const flags of [
    ['--preserve-symlinks-main'],
    ['--preserve-symlinks', '--preserve-symlinks-main'],
  ]) {
    const output = execFileSync(process.execPath, [...flags, entry, 'plan'], {
      timeout: 5000, maxBuffer: 128 * 1024,
    });
    const plan = JSON.parse(output);
    assert.equal(plan.root, DEFAULT_ROOT);
    assert.equal(plan.executesNetworkActions, false);
  }
});
