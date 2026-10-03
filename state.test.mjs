import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CarWriter } from '@ipld/car';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { generateKeyPair } from '@libp2p/crypto/keys';
import { peerIdFromPublicKey } from '@libp2p/peer-id';
import { base36 } from 'multiformats/bases/base36';
import { createIPNSRecordWithExpiration, marshalIPNSRecord } from 'ipns';
import { FileJournal } from './journal.mjs';
import { runOnce, validateConfig } from './operator.mjs';
import { validateOperatorState } from './state.mjs';

async function content(text) {
  const block = new TextEncoder().encode(text);
  const cid = CID.createV1(0x55, await sha256.digest(block));
  const { writer, out } = CarWriter.create([cid]);
  const chunks = [];
  const collect = (async () => { for await (const chunk of out) chunks.push(chunk); })();
  await writer.put({ cid, bytes: block });
  await writer.close();
  await collect;
  return { root: cid.toString(), bytes: Buffer.concat(chunks) };
}

const first = await content('Actual verified CAR evidence for persisted-state validation.');
const second = await content('A newer IPNS root can remain unavailable without discarding old verification.');
const key = await generateKeyPair('Ed25519');
const name = peerIdFromPublicKey(key.publicKey).toCID().toString(base36.encoder);
const otherKey = await generateKeyPair('Ed25519');
const otherName = peerIdFromPublicKey(otherKey.publicKey).toCID().toString(base36.encoder);

async function directory(t) {
  const path = await mkdtemp(join(tmpdir(), 'signalx-operator-state-'));
  t.after(() => rm(path, { recursive: true, force: true }));
  return path;
}

function config(path, overrides = {}) {
  return validateConfig({ version: 1, operatorId: 'state-regression', stateDirectory: path,
    pin: true, kuboUrl: 'http://127.0.0.1:5001', gateways: ['https://gateway.example/'],
    ipnsRouters: ['https://a.example/', 'https://b.example/'],
    publications: [{ id: 'approved', root: first.root }], ...overrides });
}

const carResponse = bytes => new Response(bytes, { headers: { 'content-type': 'application/vnd.ipld.car;version=1' } });
const recordResponse = bytes => new Response(bytes, { headers: { 'content-type': 'application/vnd.ipfs.ipns-record' } });

async function fixedSnapshots(t) {
  const path = await directory(t);
  const policy = config(path);
  const journal = new FileJournal(path);
  const fresh = await journal.read();
  let leaseOnly, pending, pinned = false;
  const kubo = {
    isPinned: async () => pinned,
    inspect: async () => { pending = await journal.read(); return { repoBytes: 0 }; },
    importVerifiedCar: async () => { pinned = true; throw new Error('Reply lost after recursive pin'); },
  };
  const fetchFn = async () => { leaseOnly = await journal.read(); return carResponse(first.bytes); };
  assert.equal((await runOnce(policy, { journal, kubo, fetchFn })).status, 'degraded');
  const unknown = await journal.read();
  assert.equal((await runOnce(policy, { journal, kubo,
    fetchFn: async () => assert.fail('Confirmed readback reuses verified bytes') })).status, 'verified');
  return { path, policy, journal, fresh, leaseOnly, pending, unknown, confirmed: await journal.read() };
}

async function namedSnapshots(t) {
  const path = await directory(t);
  const policy = config(path, { pin: false, publications: [{ id: 'approved', ipnsName: name }] });
  const journal = new FileJournal(path);
  const record = async (sequence, rootPath) => marshalIPNSRecord(await createIPNSRecordWithExpiration(key,
    rootPath, BigInt(sequence), '2099-01-01T00:00:00.000000000Z'));
  const old = await record(1, `/ipfs/${first.root}`);
  const newer = await record(2, `/ipfs/${second.root}`);
  const subpath = await record(3, `/ipfs/${second.root}/file`);
  const conflictA = await record(4, `/ipfs/${first.root}`);
  const conflictB = await record(4, `/ipfs/${second.root}`);
  let mode = 'old';
  const fetchFn = async url => {
    if (String(url).includes('/routing/')) return recordResponse(mode === 'old' ? old : mode === 'newer' ? newer
      : mode === 'subpath' ? subpath : String(url).includes('b.example') ? conflictB : conflictA);
    return mode === 'old' ? carResponse(first.bytes) : new Response(null, { status: 503 });
  };
  assert.equal((await runOnce(policy, { journal, fetchFn })).status, 'verified');
  const verified = await journal.read();
  mode = 'newer';
  assert.equal((await runOnce(policy, { journal, fetchFn })).status, 'degraded');
  const unavailable = await journal.read();
  mode = 'subpath';
  assert.equal((await runOnce(policy, { journal, fetchFn })).status, 'degraded');
  const unsupported = await journal.read();
  mode = 'conflict';
  assert.equal((await runOnce(policy, { journal, fetchFn })).status, 'degraded');
  return { path, policy, journal, verified, unavailable, unsupported, quarantined: await journal.read() };
}

function accepted(state, policy) {
  const before = structuredClone(state);
  assert.equal(validateOperatorState(state, policy), state);
  assert.deepEqual(state, before, 'validation must not repair or normalize stored evidence');
}

async function rejectsPersisted(journal, policy, original, changes) {
  for (const [label, mutate] of changes) {
    const candidate = structuredClone(original);
    mutate(candidate);
    const bytes = JSON.stringify(candidate) + '\n';
    await writeFile(journal.file, bytes);
    const restarted = new FileJournal(journal.directory);
    const observed = await restarted.read();
    assert.throws(() => validateOperatorState(observed, policy), { code: 'OPERATOR_STATE_CORRUPT' }, label);
    let called = false;
    await assert.rejects(restarted.transact(state => {
      validateOperatorState(state, policy);
      called = true;
    }), { code: 'OPERATOR_STATE_CORRUPT' }, label);
    assert.equal(called, false, `${label}: corrupt evidence must fence the callback`);
    assert.equal(await readFile(journal.file, 'utf8'), bytes, `${label}: corrupt bytes must be preserved`);
  }
}

test('real fresh, leased, pending, unknown-pin and reconciled snapshots validate without changes', async t => {
  const snapshots = await fixedSnapshots(t);
  for (const key of ['fresh', 'leaseOnly', 'pending', 'unknown', 'confirmed']) accepted(snapshots[key], snapshots.policy);
  assert.equal(snapshots.pending.publications.approved.pinIntent.status, 'pending');
  assert.equal(snapshots.unknown.publications.approved.pinIntent.status, 'outcome_unknown');
  assert.equal(snapshots.confirmed.publications.approved.pinIntent.status, 'confirmed');
});

test('malformed persisted lease evidence cannot be overwritten as an expired lease', async t => {
  const { journal, policy, leaseOnly } = await fixedSnapshots(t);
  await rejectsPersisted(journal, policy, leaseOnly, [
    ['string deadline', state => { state.activeRun.expiresAtMs = 'garbage'; }],
    ['missing deadline', state => { delete state.activeRun.expiresAtMs; }],
    ['NaN persisted as null', state => { state.activeRun.expiresAtMs = NaN; }],
    ['zero deadline', state => { state.activeRun.expiresAtMs = 0; }],
    ['non-increasing deadline', state => { state.activeRun.expiresAtMs = state.activeRun.startedAtMs; }],
    ['missing start', state => { delete state.activeRun.startedAtMs; }],
    ['non-UUID owner', state => { state.activeRun.id = 'alien'; }],
    ['non-object lease', state => { state.activeRun = 'not-a-lease'; }],
  ]);
});

test('incomplete or malformed persisted CAR evidence and pin intents fail closed before callbacks', async t => {
  const { journal, policy, unknown } = await fixedSnapshots(t);
  await rejectsPersisted(journal, policy, unknown, [
    ['incomplete content', state => { state.publications.approved.lastVerified.complete = false; }],
    ['missing completeness', state => { delete state.publications.approved.lastVerified.complete; }],
    ['malformed root', state => { state.publications.approved.lastVerified.root = 'not-a-CID'; }],
    ['different fixed root', state => { state.publications.approved.lastVerified.root = second.root; }],
    ['string block count', state => { state.publications.approved.lastVerified.blockCount = '1'; }],
    ['impossible reachable count', state => { state.publications.approved.lastVerified.reachableBlockCount = 2; }],
    ['exceeded archive bound', state => { state.publications.approved.lastVerified.byteLength = policy.limits.maxCarBytes + 1; }],
    ['unsupported codec claim', state => { state.publications.approved.lastVerified.codecs = ['unverified-codec']; }],
    ['missing digest', state => { delete state.publications.approved.lastVerified.sha256; }],
    ['missing verification time', state => { delete state.publications.approved.lastVerified.verifiedAtMs; }],
    ['invalid source', state => { state.publications.approved.lastVerified.source = 'http://gateway.example/'; }],
    ['pin without verified evidence', state => { delete state.publications.approved.lastVerified; }],
    ['pin for a different root', state => { state.publications.approved.pinIntent.root = second.root; }],
    ['unknown pin intent status', state => { state.publications.approved.pinIntent.status = 'success'; }],
    ['invalid pin owner', state => { state.publications.approved.pinIntent.runId = 'alien'; }],
    ['invalid pin timestamp', state => { state.publications.approved.pinIntent.atMs = -1; }],
  ]);
});

test('publication identity, policy binding and retained result claims reject corrupt JSON state', async t => {
  const { journal, policy, confirmed } = await fixedSnapshots(t);
  await rejectsPersisted(journal, policy, confirmed, [
    ['unknown publication ID', state => { state.publications.alien = state.publications.approved; }],
    ['inherited publication key', state => { state.publications.constructor = state.publications.approved; }],
    ['missing policy digest', state => { delete state.policyDigest; }],
    ['invalid policy digest', state => { state.policyDigest = 'garbage'; }],
    ['result ID differs', state => { state.publications.approved.lastResult.id = 'alien'; }],
    ['result verification incomplete', state => { state.publications.approved.lastResult.verification.complete = false; }],
    ['verified result without verification', state => { delete state.publications.approved.lastResult.verification; }],
    ['external use falsely asserted', state => { state.publications.approved.lastResult.externalUseVerified = true; }],
    ['pin success without confirmation', state => { state.publications.approved.lastResult.reconciled = false; }],
    ['unknown history publication', state => { state.runs[0].results[0].id = 'alien'; }],
    ['history status promoted', state => { state.runs[0].status = 'verified'; }],
  ]);
});

test('real IPNS advancement, unavailable roots, unsupported subpaths and quarantine preserve valid history', async t => {
  const snapshots = await namedSnapshots(t);
  for (const key of ['verified', 'unavailable', 'unsupported', 'quarantined']) accepted(snapshots[key], snapshots.policy);
  assert.equal(snapshots.unavailable.publications.approved.highestRecord.sequence, '2');
  assert.equal(snapshots.unavailable.publications.approved.lastVerified.root, first.root);
  assert.equal(snapshots.unsupported.publications.approved.highestRecord.sequence, '3');
  const expired = structuredClone(snapshots.verified);
  expired.publications.approved.highestRecord.validUntil = '2000-01-01T00:00:00.000000000Z';
  expired.publications.approved.lastResult.ipns.validUntil = expired.publications.approved.highestRecord.validUntil;
  accepted(expired, snapshots.policy); // History is not subjected to a fresh-record expiry check.
});

test('malformed high-water and quarantine evidence is never discarded as a degraded source result', async t => {
  const { journal, policy, quarantined } = await namedSnapshots(t);
  await rejectsPersisted(journal, policy, quarantined, [
    ['unverified high-water', state => { state.publications.approved.highestRecord.verified = false; }],
    ['invalid sequence', state => { state.publications.approved.highestRecord.sequence = '-1'; }],
    ['sequence overflow', state => { state.publications.approved.highestRecord.sequence = '18446744073709551616'; }],
    ['invalid calendar', state => { state.publications.approved.highestRecord.validUntil = '2099-02-30T00:00:00Z'; }],
    ['different valid naming owner', state => { state.publications.approved.highestRecord.name = otherName; }],
    ['invalid record hash', state => { state.publications.approved.highestRecord.recordSha256 = 'bad'; }],
    ['invalid TTL', state => { state.publications.approved.highestRecord.ttlNanoseconds = '18446744073709551616'; }],
    ['global freshness falsely asserted', state => { state.publications.approved.highestRecord.latestGloballyKnown = true; }],
    ['missing high-water', state => { delete state.publications.approved.highestRecord; }],
    ['quarantine sequence above high-water', state => { state.publications.approved.equivocation.sequence = '5'; }],
    ['duplicate conflict paths', state => { state.publications.approved.equivocation.paths[1] = state.publications.approved.equivocation.paths[0]; }],
    ['invalid conflict path', state => { state.publications.approved.equivocation.paths[1] = '/ipfs/not-a-CID'; }],
    ['invalid quarantine timestamp', state => { state.publications.approved.equivocation.observedAtMs = null; }],
  ]);
});
