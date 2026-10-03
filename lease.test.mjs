import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
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
import { runOnce } from './operator.mjs';

const block = new TextEncoder().encode('A real CAR must be verified before the operator can import it.');
const cid = CID.createV1(0x55, await sha256.digest(block));
const root = cid.toString();
const { writer, out } = CarWriter.create([cid]);
const chunks = [];
const collect = (async () => { for await (const chunk of out) chunks.push(chunk); })();
await writer.put({ cid, bytes: block });
await writer.close();
await collect;
const car = Buffer.concat(chunks);
const peerId = CID.createV0(await sha256.digest(new TextEncoder().encode('lease regression peer'))).toString();

async function directory(t) {
  const path = await mkdtemp(join(tmpdir(), 'signalx-operator-lease-'));
  t.after(() => rm(path, { recursive: true, force: true }));
  return path;
}

function policy(directory) {
  return { version: 1, operatorId: 'lease-regression', stateDirectory: directory,
    pin: true, kuboUrl: 'http://127.0.0.1:5001', gateways: ['https://gateway.example/'],
    ipnsRouters: ['https://router.example/'], publications: [{ id: 'approved', root }],
    limits: { runTimeoutMs: 30_000 } };
}

function json(value, status = 200) {
  const body = JSON.stringify(value);
  return new Response(body, { status, headers: {
    'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)),
  } });
}

// Only transport responses are injected. runOnce constructs its normal KuboClient,
// validates the real CAR, and commits through a real FileJournal on disk.
function transport({ afterImport = async () => {}, afterPin = async () => {}, ipnsRecord } = {}) {
  const counts = { downloads: 0, imports: 0, pins: 0, pinReads: 0 };
  const signals = [];
  let pinned = false;
  const fetchFn = async (input, init) => {
    const url = new URL(input);
    if (url.origin === 'https://router.example') {
      assert.ok(ipnsRecord, 'an IPNS response must be explicitly configured');
      return new Response(ipnsRecord, { headers: {
        'content-type': 'application/vnd.ipfs.ipns-record',
        'content-length': String(ipnsRecord.byteLength),
      } });
    }
    if (url.origin === 'https://gateway.example') {
      counts.downloads++;
      assert.equal(url.pathname, `/ipfs/${root}`);
      return new Response(car, { headers: { 'content-type': 'application/vnd.ipld.car;version=1',
        'content-length': String(car.byteLength) } });
    }
    assert.equal(url.origin, 'http://127.0.0.1:5001');
    assert.equal(init.method, 'POST');
    assert.ok(init.signal instanceof AbortSignal);
    const command = url.pathname.slice('/api/v0/'.length);
    const observations = {
      id: { ID: peerId }, version: { Version: '0.43.1' },
      'swarm/peers': { Peers: null }, 'stats/repo': { RepoSize: 0 },
      'stats/bitswap': { DataSent: 0, BlocksSent: 0 },
      config: { Key: 'Routing.Type', Value: 'dhtserver' },
    };
    if (Object.hasOwn(observations, command)) return json(observations[command]);
    if (command === 'pin/ls') {
      counts.pinReads++;
      assert.equal(url.searchParams.get('arg'), root);
      return pinned ? json({ Keys: { [root]: { Type: 'recursive' } } })
        : json({ Message: `path '${root}' is not pinned`, Code: 0, Type: 'error' }, 500);
    }
    if (command === 'dag/import') {
      counts.imports++;
      signals.push(init.signal);
      assert.equal(url.searchParams.get('pin-roots'), 'false');
      assert.equal(url.searchParams.get('offline'), 'true');
      await afterImport({ signal: init.signal });
      return json({ Stats: { BlockCount: 1, BlockBytesCount: block.byteLength } });
    }
    if (command === 'pin/add') {
      counts.pins++;
      pinned = true;
      await afterPin();
      return json({ Pins: [root] });
    }
    assert.fail(`Unexpected RPC command ${command}`);
  };
  return { fetchFn, counts, signals };
}

test('default Kubo client fences pin/add after an absolute clock jump following dag/import', async t => {
  const dir = await directory(t);
  const config = policy(dir);
  const startedAtMs = Date.now();
  let clock = startedAtMs;
  let beforeClockJump;
  const rpc = transport({ afterImport: async ({ signal }) => {
    beforeClockJump = await new FileJournal(dir).read();
    assert.equal(beforeClockJump.publications.approved.lastVerified.complete, true);
    assert.equal(beforeClockJump.publications.approved.pinIntent.status, 'pending');
    assert.equal(signal.aborted, false);
    clock = startedAtMs + config.limits.runTimeoutMs;
  } });

  await assert.rejects(runOnce(config, { now: () => clock, fetchFn: rpc.fetchFn }), /lease.*expired/i);
  assert.equal(rpc.counts.imports, 1);
  assert.equal(rpc.counts.pins, 0, 'absolute lease expiry must prevent the next Kubo write');
  assert.equal(rpc.signals[0].aborted, false, 'the wall timer cannot explain the rejected write');
  const persisted = await new FileJournal(dir).read();
  assert.deepEqual(persisted, beforeClockJump, 'expired owner cannot promote unresolved intent or write a result');
  assert.equal(persisted.publications.approved.lastResult, undefined);
  assert.deepEqual(persisted.runs, []);
});

test('default Kubo client fences pin/add when another journal owner supersedes the import lease', async t => {
  const dir = await directory(t);
  const config = policy(dir);
  const clock = Date.now();
  const successorRunId = randomUUID();
  let successorState;
  let originalRunId;
  const successor = new FileJournal(dir);
  const rpc = transport({ afterImport: async ({ signal }) => {
    successorState = await successor.transact(state => {
      originalRunId = state.activeRun.id;
      state.activeRun = { id: successorRunId, startedAtMs: clock,
        expiresAtMs: clock + config.limits.runTimeoutMs };
    });
    assert.equal(signal.aborted, false);
  } });

  await assert.rejects(runOnce(config, { now: () => clock, fetchFn: rpc.fetchFn }), /lease.*superseded/i);
  assert.equal(rpc.counts.imports, 1);
  assert.equal(rpc.counts.pins, 0, 'lost journal ownership must prevent the next Kubo write');
  assert.equal(rpc.signals[0].aborted, false);
  const persisted = await new FileJournal(dir).read();
  assert.deepEqual(persisted, successorState, 'the previous owner cannot overwrite its successor or claim success');
  assert.equal(persisted.activeRun.id, successorRunId);
  assert.equal(persisted.publications.approved.pinIntent.runId, originalRunId);
  assert.equal(persisted.publications.approved.pinIntent.status, 'pending');
  assert.equal(persisted.publications.approved.lastResult, undefined);
  assert.deepEqual(persisted.runs, []);
});

test('default Kubo client preserves an unknown pin reply and reconciles it through restart readback', async t => {
  const dir = await directory(t);
  const config = policy(dir);
  const rpc = transport({ afterPin: async () => { throw new Error('Connection lost after Kubo applied pin/add'); } });

  const first = await runOnce(config, { fetchFn: rpc.fetchFn });
  assert.equal(first.status, 'degraded');
  assert.equal(first.results[0].status, 'unverified');
  assert.match(first.results[0].error, /TRANSPORT_ERROR/);
  const unknown = await new FileJournal(dir).read();
  assert.equal(unknown.publications.approved.pinIntent.status, 'outcome_unknown');
  assert.equal(unknown.publications.approved.lastVerified.complete, true);
  assert.equal(unknown.publications.approved.lastResult.status, 'unverified');
  assert.equal(unknown.publications.approved.lastResult.pin, undefined);
  assert.equal(unknown.runs[0].status, 'degraded');

  const restarted = await runOnce(config, { fetchFn: rpc.fetchFn });
  assert.equal(restarted.results[0].status, 'locally_pinned');
  assert.equal(restarted.results[0].reconciled, true);
  assert.equal(restarted.results[0].externalUseVerified, false);
  assert.equal(rpc.counts.downloads, 1, 'readback reconciliation reuses verified content');
  assert.equal(rpc.counts.imports, 1, 'readback reconciliation must not repeat import');
  assert.equal(rpc.counts.pins, 1, 'readback reconciliation must not repeat pin/add');
  const confirmed = await new FileJournal(dir).read();
  assert.equal(confirmed.publications.approved.pinIntent.status, 'confirmed');
  assert.equal(confirmed.publications.approved.lastResult.reconciled, true);
  assert.deepEqual(confirmed.runs.map(run => run.status), ['degraded', 'verified']);
});

test('default Kubo client fences pin/add when accepted signed IPNS expires during dag/import', async t => {
  const dir = await directory(t);
  const config = policy(dir);
  const startedAtMs = Date.now();
  let clock = startedAtMs;
  const key = await generateKeyPair('Ed25519');
  const name = peerIdFromPublicKey(key.publicKey).toCID().toString(base36.encoder);
  const expiration = new Date(startedAtMs + 10_000).toISOString();
  const ipnsRecord = marshalIPNSRecord(await createIPNSRecordWithExpiration(
    key, `/ipfs/${root}`, 1n, expiration));
  config.publications = [{ id: 'approved', ipnsName: name }];
  let beforeNamingExpiry;
  const rpc = transport({ ipnsRecord, afterImport: async ({ signal }) => {
    beforeNamingExpiry = await new FileJournal(dir).read();
    assert.equal(beforeNamingExpiry.publications.approved.highestRecord.sequence, '1');
    assert.equal(beforeNamingExpiry.publications.approved.lastVerified.complete, true);
    assert.equal(beforeNamingExpiry.publications.approved.pinIntent.status, 'pending');
    assert.equal(signal.aborted, false);
    clock = startedAtMs + 11_000;
  } });

  const report = await runOnce(config, { now: () => clock, fetchFn: rpc.fetchFn });
  assert.equal(report.status, 'degraded');
  assert.equal(report.results[0].status, 'unverified');
  assert.match(report.results[0].error, /expired/i);
  assert.equal(rpc.counts.imports, 1);
  assert.equal(rpc.counts.pins, 0, 'expiry of the accepted naming record must stop the next Kubo write');
  assert.equal(rpc.signals[0].aborted, false);
  assert.ok(clock < beforeNamingExpiry.activeRun.expiresAtMs,
    'the execution lease remains valid when naming authority expires');
  const persisted = await new FileJournal(dir).read();
  assert.equal(persisted.publications.approved.pinIntent.status, 'outcome_unknown');
  assert.equal(persisted.publications.approved.lastResult.status, 'unverified');
  assert.equal(persisted.publications.approved.lastResult.pin, undefined);
  assert.deepEqual(persisted.publications.approved.highestRecord,
    beforeNamingExpiry.publications.approved.highestRecord,
    'expiry cannot discard the highest observed sequence and authorize rollback');
  assert.equal(persisted.publications.approved.lastVerified.complete, true);
  assert.equal(persisted.runs[0].status, 'degraded');
  assert.equal(persisted.activeRun, null);
});
