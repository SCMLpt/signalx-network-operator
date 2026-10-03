import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
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
import { readBounded, publicBase } from './io.mjs';

const key = await generateKeyPair('Ed25519');
const name = peerIdFromPublicKey(key.publicKey).toCID().toString(base36.encoder);
async function fixture(text) {
  const block = new TextEncoder().encode(text);
  const root = CID.createV1(0x55, await sha256.digest(block));
  const { writer, out } = CarWriter.create([root]);
  const chunks = [];
  const collect = (async () => { for await (const chunk of out) chunks.push(chunk); })();
  await writer.put({ cid: root, bytes: block });
  await writer.close();
  await collect;
  return { root: root.toString(), bytes: Buffer.concat(chunks) };
}
const content = await fixture('Independent content integrity is checked by CID, not gateway headers.');
const other = await fixture('A second root for signed publisher-equivocation tests.');
async function record(sequence, path = `/ipfs/${content.root}`, expiry = '2099-01-01T00:00:00.000000000Z') {
  return marshalIPNSRecord(await createIPNSRecordWithExpiration(key, path, BigInt(sequence), expiry));
}
const carResponse = bytes => new Response(bytes, { headers: { 'content-type': 'application/vnd.ipld.car;version=1' } });
const recordResponse = bytes => new Response(bytes, { headers: { 'content-type': 'application/vnd.ipfs.ipns-record' } });
function config(directory, overrides = {}) {
  return { version: 1, operatorId: 'operator-tests', stateDirectory: directory,
    pin: false, kuboUrl: 'http://127.0.0.1:5001', gateways: ['https://gateway.example/'],
    ipnsRouters: ['https://router.example/'], publications: [{ id: 'approved', root: content.root }],
    ...overrides };
}
async function directory(t) {
  const path = await mkdtemp(join(tmpdir(), 'signalx-operator-test-'));
  t.after(() => rm(path, { recursive: true, force: true }));
  return path;
}

test('real complete CAR verification is persisted and leaves independent use unknown', async t => {
  const dir = await directory(t);
  const report = await runOnce(config(dir), { fetchFn: async () => carResponse(content.bytes) });
  assert.equal(report.status, 'verified');
  assert.equal(report.results[0].status, 'content_verified');
  assert.equal(report.results[0].verification.complete, true);
  assert.equal(report.networkContribution.externalRequests, null);
  assert.equal(report.networkContribution.externalUseVerified, false);
  const restarted = new FileJournal(dir);
  const stored = await restarted.read();
  assert.equal(stored.publications.approved.lastVerified.root, content.root);
  assert.equal(stored.activeRun, null);
  assert.equal(stored.runs[0].status, 'verified');
  assert.match(stored.runs[0].reportSha256, /^[0-9a-f]{64}$/);
});

test('tampered complete CAR never reaches a pin effect', async t => {
  const dir = await directory(t);
  const broken = Uint8Array.from(content.bytes);
  broken[broken.length - 1] ^= 1;
  let effects = 0;
  const report = await runOnce(config(dir, { pin: true }), {
    fetchFn: async () => carResponse(broken),
    kubo: { isPinned: async () => false, inspect: async () => ({ repoBytes: 0 }),
      importVerifiedCar: async () => { effects++; return { pinned: true }; } },
  });
  assert.equal(report.status, 'degraded');
  assert.equal(effects, 0);
  assert.match(report.results[0].error, /does not match|hash/i);
});

test('unknown pin outcome reconciles after restart without reimport or redownload', async t => {
  const dir = await directory(t);
  const policy = config(dir, { pin: true });
  let pinned = false;
  let effects = 0;
  let downloads = 0;
  const kubo = { isPinned: async () => pinned, inspect: async () => ({ repoBytes: 0 }),
    importVerifiedCar: async () => { effects++; pinned = true; throw new Error('Response lost after pin'); } };
  const fetchFn = async () => { downloads++; return carResponse(content.bytes); };
  const first = await runOnce(policy, { kubo, fetchFn });
  assert.equal(first.status, 'degraded');
  assert.equal((await new FileJournal(dir).read()).publications.approved.pinIntent.status, 'outcome_unknown');
  const second = await runOnce(policy, { kubo, fetchFn });
  assert.equal(second.results[0].status, 'locally_pinned');
  assert.equal(second.results[0].reconciled, true);
  assert.equal(effects, 1);
  assert.equal(downloads, 1);
  assert.equal((await new FileJournal(dir).read()).publications.approved.pinIntent.status, 'confirmed');
});

test('unknown repository size prevents an otherwise verified pin', async t => {
  const dir = await directory(t);
  let effects = 0;
  const report = await runOnce(config(dir, { pin: true }), {
    fetchFn: async () => carResponse(content.bytes),
    kubo: { isPinned: async () => false, inspect: async () => ({ repoBytes: null }),
      importVerifiedCar: async () => { effects++; return { pinned: true }; } },
  });
  assert.equal(report.status, 'degraded');
  assert.equal(effects, 0);
  assert.match(report.results[0].error, /repository size/i);
});

test('higher signed sequence persists even if its target is outside supported scope', async t => {
  const dir = await directory(t);
  const policy = config(dir, { publications: [{ id: 'approved', ipnsName: name }] });
  let bytes = await record(2, `/ipfs/${content.root}/file`);
  const fetchFn = async url => String(url).includes('/routing/') ? recordResponse(bytes) : carResponse(content.bytes);
  const first = await runOnce(policy, { fetchFn });
  assert.equal(first.status, 'degraded');
  assert.equal((await new FileJournal(dir).read()).publications.approved.highestRecord.sequence, '2');
  bytes = await record(1);
  const second = await runOnce(policy, { fetchFn });
  assert.equal(second.status, 'degraded');
  assert.match(second.results[0].error, /rollback/i);
});

test('router selection chooses higher sequence and later nanosecond expiry', async t => {
  const dir = await directory(t);
  const early = await record(5, `/ipfs/${content.root}`, '2099-01-01T00:00:00.000000001Z');
  const late = await record(5, `/ipfs/${content.root}`, '2099-01-01T00:00:00.000000002Z');
  const policy = config(dir, { publications: [{ id: 'approved', ipnsName: name }],
    ipnsRouters: ['https://older.example/', 'https://newer.example/'] });
  const report = await runOnce(policy, { fetchFn: async url => {
    if (String(url).includes('older.example')) return recordResponse(early);
    if (String(url).includes('newer.example')) return recordResponse(late);
    return carResponse(content.bytes);
  } });
  assert.equal(report.status, 'verified');
  assert.equal(report.results[0].ipns.validUntil, '2099-01-01T00:00:00.000000002Z');
});

test('signed equivocation quarantines sequence, survives restart, and requires higher sequence', async t => {
  const dir = await directory(t);
  const original = await record(7);
  const conflicting = await record(7, `/ipfs/${other.root}`);
  const newer = await record(8);
  const policy = config(dir, { publications: [{ id: 'approved', ipnsName: name }],
    ipnsRouters: ['https://a.example/', 'https://b.example/'] });
  let mode = 'conflict';
  const fetchFn = async url => {
    if (String(url).includes('/routing/')) return recordResponse(mode === 'newer' ? newer
      : mode === 'conflict' && String(url).includes('b.example') ? conflicting : original);
    return carResponse(content.bytes);
  };
  assert.equal((await runOnce(policy, { fetchFn })).status, 'degraded');
  assert.equal((await new FileJournal(dir).read()).publications.approved.equivocation.sequence, '7');
  mode = 'single';
  const second = await runOnce(policy, { fetchFn });
  assert.equal(second.status, 'degraded');
  assert.match(second.results[0].error, /quarantined/i);
  mode = 'newer';
  assert.equal((await runOnce(policy, { fetchFn })).status, 'verified');
  assert.equal((await new FileJournal(dir).read()).publications.approved.equivocation, null);
});

test('conflicting signed value is detected even after one value was persisted', async t => {
  const dir = await directory(t);
  const original = await record(3);
  const conflicting = await record(3, `/ipfs/${other.root}`);
  const policy = config(dir, { publications: [{ id: 'approved', ipnsName: name }],
    ipnsRouters: ['https://a.example/', 'https://b.example/'] });
  let conflict = false;
  const fetchFn = async url => String(url).includes('/routing/')
    ? recordResponse(conflict && String(url).includes('b.example') ? conflicting : original)
    : carResponse(content.bytes);
  assert.equal((await runOnce(policy, { fetchFn })).status, 'verified');
  conflict = true;
  assert.equal((await runOnce(policy, { fetchFn })).status, 'degraded');
  assert.equal((await new FileJournal(dir).read()).publications.approved.equivocation.sequence, '3');
});

test('expiry crossing during content retrieval cannot produce a verified publication', async t => {
  const dir = await directory(t);
  let clock = Date.now();
  const expires = new Date(clock + 1000).toISOString();
  const bytes = await record(1, `/ipfs/${content.root}`, expires);
  const policy = config(dir, { publications: [{ id: 'approved', ipnsName: name }] });
  const report = await runOnce(policy, { now: () => clock, fetchFn: async url => {
    if (String(url).includes('/routing/')) return recordResponse(bytes);
    clock += 2000;
    return carResponse(content.bytes);
  } });
  assert.equal(report.status, 'degraded');
  assert.equal(report.results[0].verification.complete, true);
  assert.match(report.results[0].error, /expired/i);
});

test('concurrent runs are fenced before any second external read', async t => {
  const dir = await directory(t);
  let entered;
  let release;
  const ready = new Promise(resolve => { entered = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  const first = runOnce(config(dir), { fetchFn: async () => { entered(); await gate; return carResponse(content.bytes); } });
  await ready;
  await assert.rejects(runOnce(config(dir), { fetchFn: async () => assert.fail('Second run must not read') }), /lease/i);
  release();
  assert.equal((await first).status, 'verified');
});

test('policy edits cannot discard persisted naming history silently', async t => {
  const dir = await directory(t);
  await runOnce(config(dir), { fetchFn: async () => carResponse(content.bytes) });
  await assert.rejects(runOnce(config(dir, { intervalSeconds: 600 }),
    { fetchFn: async () => assert.fail('Changed policy must not read') }), /Configuration changed/i);
});

test('failed source fallback shares the aggregate streamed download budget', async t => {
  const dir = await directory(t);
  const broken = Uint8Array.from(content.bytes);
  broken[broken.length - 1] ^= 1;
  const policy = config(dir, { gateways: ['https://bad.example/', 'https://good.example/'],
    limits: { maxCarBytes: content.bytes.length, maxRunBytes: content.bytes.length } });
  const report = await runOnce(policy, { fetchFn: async url =>
    carResponse(String(url).includes('bad.example') ? broken : content.bytes) });
  assert.equal(report.status, 'degraded');
  assert.match(report.results[0].error, /budget/i);
});

test('redirects and private or credentialed source origins are rejected', async () => {
  for (const base of ['http://example.com/', 'https://localhost/', 'https://127.0.0.1/',
    'https://user:secret@example.com/', 'https://example.com/path']) assert.throws(() => publicBase(base));
  let request;
  await assert.rejects(readBounded('https://example.com/', { maxBytes: 2, timeoutMs: 100,
    accept: 'application/octet-stream', fetchFn: async (_url, options) => {
      request = options;
      return new Response(null, { status: 302, headers: { location: 'https://localhost/' } });
    } }), /HTTP 302/);
  assert.equal(request.redirect, 'manual');
});

test('a stuck cancellation callback cannot defeat the streaming size limit', async () => {
  const body = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(2)); },
    cancel() { return new Promise(() => {}); } });
  await assert.rejects(readBounded('https://example.com/', { maxBytes: 1, timeoutMs: 50,
    fetchFn: async () => new Response(body) }), /exceeds limit/);
});

test('a fetch implementation ignoring AbortSignal still respects the deadline', async () => {
  const keepAlive = setTimeout(() => {}, 100);
  try {
    await assert.rejects(readBounded('https://example.com/', { maxBytes: 1, timeoutMs: 20,
      fetchFn: () => new Promise(() => {}) }), /timeout/i);
  } finally { clearTimeout(keepAlive); }
});

test('configuration rejects oversized queues, ambiguous publications and zero budgets', async () => {
  assert.throws(() => validateConfig(config('/tmp/x', { limits: { timeoutMs: 0 } })), /timeoutMs/);
  assert.throws(() => validateConfig(config('/tmp/x', { publications: [{ id: 'x', root: content.root, ipnsName: name }] })), /exactly one/);
  assert.throws(() => validateConfig(config('/tmp/x', { publications: Array.from({ length: 9 }, (_, id) => ({ id: `p${id}`, root: content.root })) })), /eight/);
});

test('configuration rejects coerced or reserved IDs and ambiguous present selectors before journal access', () => {
  for (const id of [1, null, {}, '__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty']) {
    assert.throws(() => validateConfig(config('/tmp/x', { operatorId: id })), /configuration/);
    assert.throws(() => validateConfig(config('/tmp/x', { publications: [{ id, root: content.root }] })), /unique ID/);
  }
  assert.throws(() => validateConfig(config('/tmp/x', { publications: [
    { id: 1, root: content.root }, { id: '1', root: other.root },
  ] })), /unique ID/);
  for (const publication of [
    { id: 'x', root: content.root, ipnsName: null },
    { id: 'x', ipnsName: name, root: '' },
    { id: 'x', root: null },
    { id: 'x' },
  ]) assert.throws(() => validateConfig(config('/tmp/x', { publications: [publication] })), /exactly one/);
  assert.equal(validateConfig(config('/tmp/x', { operatorId: '1', publications: [{ id: '1', root: content.root }] })).publications[0].id, '1');
});

test('runOnce refuses malformed persisted leases or incomplete cached evidence before any provider or pin read', async t => {
  for (const mutation of [
    state => { state.activeRun = { id: 'malformed-owner', expiresAtMs: 'garbage' }; },
    state => { state.publications.approved.lastVerified.complete = false; },
  ]) {
    const dir = await directory(t);
    const policy = config(dir, { pin: true });
    let providerReads = 0;
    let pinReads = 0;
    const fetchFn = async () => { providerReads++; return carResponse(content.bytes); };
    const kubo = { isPinned: async () => { pinReads++; return true; },
      inspect: async () => ({ repoBytes: 0 }), importVerifiedCar: async () => ({ pinned: true }) };
    assert.equal((await runOnce(policy, { fetchFn, kubo })).status, 'verified');
    const journal = new FileJournal(dir);
    await journal.transact(mutation);
    const corrupted = await journal.read();
    providerReads = 0;
    pinReads = 0;
    await assert.rejects(runOnce(policy, { fetchFn, kubo }), { code: 'OPERATOR_STATE_CORRUPT' });
    assert.equal(providerReads, 0);
    assert.equal(pinReads, 0);
    assert.deepEqual(await journal.read(), corrupted);
  }
});
