import test from 'node:test';
import assert from 'node:assert/strict';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { KuboClient, KuboApiError } from './kubo.mjs';

const root = CID.createV1(0x55, await sha256.digest(new TextEncoder().encode('verified test block'))).toString();
const peerId = CID.createV0(await sha256.digest(new TextEncoder().encode('test peer public key'))).toString();
const bytes = new Uint8Array([1, 2, 3, 4]); // The client boundary takes already-verified CAR bytes.
const json = (value, status = 200, headers) => new Response(JSON.stringify(value), { status, headers });
const missing = () => json({ Message: `path '${root}' is not pinned`, Code: 0, Type: 'error' }, 500);
const pin = () => json({ Keys: { [root]: { Type: 'recursive' } } });
const command = url => new URL(url).pathname.slice('/api/v0/'.length);
const healthy = {
  id: { ID: peerId }, version: { Version: '0.43.1' },
  'swarm/peers': { Peers: [{ Peer: peerId, Addr: '/ip4/192.0.2.1/tcp/4001' }] },
  'stats/repo': { RepoSize: 1000 }, 'stats/bitswap': { DataSent: 1024, BlocksSent: 2 },
  config: { Key: 'Routing.Type', Value: 'dhtserver' },
};

test('admin URL and authentication remain operator-configured and private', () => {
  for (const url of ['http://127.0.0.1:5001', 'http://localhost:5001/api/v0/', 'http://[::1]:5001']) {
    assert.doesNotThrow(() => new KuboClient({ url }));
  }
  for (const url of ['http://192.0.2.1:5001', 'https://admin.example', 'http://user:secret@localhost:5001',
    'http://localhost:5001?token=secret', 'http://localhost:5001#secret', 'http://localhost:5001/api/v0/shutdown']) {
    assert.throws(() => new KuboClient({ url }), TypeError);
  }
  assert.throws(() => new KuboClient({ url: 'http://admin.example', allowRemoteHttps: true }), TypeError);
  assert.doesNotThrow(() => new KuboClient({ url: 'https://admin.example', allowRemoteHttps: true }));
  assert.throws(() => new KuboClient({ token: 'secret\r\nInjected: header' }), TypeError);
  assert.throws(() => new KuboClient({ timeoutMs: 0 }), TypeError);
  assert.equal(JSON.stringify(new KuboClient({ token: 'private-test-token' })), '{}');
});

test('inspect records actual reported fields and never infers external use or DHT server activity', async () => {
  const calls = [];
  const client = new KuboClient({ token: 'private-test-token', fetchFn: async (url, init) => {
    calls.push({ url, init });
    return json(healthy[command(url)]);
  } });
  const report = await client.inspect();
  assert.equal(report.peerId, peerId);
  assert.equal(report.version, '0.43.1');
  assert.equal(report.peers, 1);
  assert.equal(report.repoBytes, 1000);
  assert.equal(report.bitswapSentBytes, 1024);
  assert.equal(report.bitswapSentBlocks, 2);
  assert.equal(report.dhtModeReported, 'dhtserver');
  assert.equal(report.externalUseVerified, false);
  assert.deepEqual(report.errors, {});
  assert.equal(report.provenance.dhtModeReported.field, 'Value (Routing.Type configuration only)');
  assert.equal(report.provenance.repoBytes.status, 'reported');
  assert.equal(calls.length, 6);
  for (const { url, init } of calls) {
    assert.equal(new URL(url).origin, 'http://127.0.0.1:5001');
    assert.equal(new URL(url).searchParams.has('token'), false);
    assert.equal(init.method, 'POST');
    assert.equal(init.redirect, 'manual');
    assert.equal(init.headers.authorization, 'Bearer private-test-token');
    assert.ok(init.signal instanceof AbortSignal);
  }
  const configCall = calls.find(call => command(call.url) === 'config');
  assert.deepEqual(new URL(configCall.url).searchParams.getAll('arg'), ['Routing.Type']);
});

test('inspect preserves independent failures and rejects missing or unsafe counters', async () => {
  const client = new KuboClient({ token: 'private-test-token', fetchFn: async url => {
    const name = command(url);
    if (name === 'config') return json({ Message: 'reflected private-test-token', Code: 0, Type: 'error' }, 403);
    if (name === 'stats/repo') return json({ SizeStat: { RepoSize: '9007199254740993' } });
    if (name === 'stats/bitswap') return json({ DataSent: -1, BlocksSent: 3 });
    if (name === 'swarm/peers') return json({ Peers: null });
    return json(healthy[name]);
  } });
  const report = await client.inspect();
  assert.equal(report.peerId, peerId);
  assert.equal(report.peers, 0);
  assert.equal(report.repoBytes, null);
  assert.equal(report.bitswapSentBytes, null);
  assert.equal(report.bitswapSentBlocks, 3);
  assert.equal(report.dhtModeReported, null);
  assert.equal(report.errors.config.code, 'API_ERROR');
  assert.equal(report.provenance.repoBytes.status, 'unknown');
  assert.equal(JSON.stringify(report).includes('private-test-token'), false);
  const nested = await new KuboClient({ fetchFn: async url => json(command(url) === 'stats/repo'
    ? { SizeStat: { RepoSize: '1200' } } : healthy[command(url)]) }).inspect();
  assert.equal(nested.repoBytes, 1200);
});

test('only the exact Kubo missing-pin error produces false; unknown failures halt reconciliation', async () => {
  assert.equal(await new KuboClient({ fetchFn: async () => missing() }).isPinned(root), false);
  const cases = [
    json({ Message: 'permission denied', Code: 0, Type: 'error' }, 500),
    json({ Message: `path '${root}' is not pinned`, Code: 1, Type: 'error' }, 500),
    json({ Message: `path '${root}' is not pinned`, Code: 0, Type: 'error' }, 403),
    json({ Keys: {} }),
    json({ Keys: { [root]: { Type: 'direct' } } }),
  ];
  for (const response of cases) {
    await assert.rejects(new KuboClient({ fetchFn: async () => response }).isPinned(root), KuboApiError);
  }
  assert.equal(await new KuboClient({ fetchFn: async () => pin() }).isPinned(root), true);
});

test('bounded offline import requires a positive stats response, a matching pin, and pin readback', async () => {
  const calls = [];
  const client = new KuboClient({ fetchFn: async (url, init) => {
    const name = command(url);
    calls.push(name);
    assert.equal(new URL(url).searchParams.get('offline'), 'true');
    if (name === 'pin/ls') return calls.length === 1 ? missing() : pin();
    for (const flag of ['fast-provide-root', 'fast-provide-dag', 'fast-provide-wait']) {
      assert.equal(new URL(url).searchParams.get(flag), 'false');
    }
    if (name === 'dag/import') {
      assert.equal(new URL(url).searchParams.get('pin-roots'), 'false');
      assert.equal(new URL(url).searchParams.get('stats'), 'true');
      assert.equal(new URL(url).searchParams.get('allow-big-block'), 'false');
      assert.ok(init.body.byteLength <= bytes.byteLength + 512);
      const data = await new Response(init.body, { headers: { 'content-type': init.headers['content-type'] } }).formData();
      assert.equal(data.get('file').name, 'verified.car');
      assert.deepEqual(new Uint8Array(await data.get('file').arrayBuffer()), bytes);
      return json({ Stats: { BlockCount: 1, BlockBytesCount: bytes.length } });
    }
    if (name === 'pin/add') {
      assert.equal(new URL(url).searchParams.get('recursive'), 'true');
      assert.equal(new URL(url).searchParams.get('arg'), root);
      return json({ Pins: [root] });
    }
    throw new Error('unexpected command');
  } });
  const report = await client.importVerifiedCar(bytes, root);
  assert.deepEqual(calls, ['pin/ls', 'dag/import', 'pin/add', 'pin/ls']);
  assert.equal(report.imported, true);
  assert.equal(report.reconciled, false);
  assert.equal(report.pinned, true);
  assert.equal(report.externalUseVerified, false);
  assert.equal(report.provenance.pin.command, '/api/v0/pin/ls');
});

test('restart reconciliation skips a second import after an uncertain pin response committed', async () => {
  let pinned = false;
  let imports = 0;
  let additions = 0;
  const client = new KuboClient({ fetchFn: async url => {
    if (command(url) === 'pin/ls') return pinned ? pin() : missing();
    if (command(url) === 'dag/import') { imports++; return json({ Stats: { BlockCount: 1, BlockBytesCount: 4 } }); }
    if (command(url) === 'pin/add') { additions++; pinned = true; throw new Error('response lost after server commit'); }
    throw new Error('unexpected command');
  } });
  await assert.rejects(client.importVerifiedCar(bytes, root), { code: 'TRANSPORT_ERROR' });
  const reconciled = await client.importVerifiedCar(bytes, root);
  assert.equal(reconciled.imported, false);
  assert.equal(reconciled.reconciled, true);
  assert.equal(imports, 1);
  assert.equal(additions, 1);
});

test('absolute lease fencing before every mutation prevents pin/add after the clock expires', async () => {
  let fakeNow = 1000;
  const expiresAt = 1100;
  const guards = [];
  const calls = [];
  const client = new KuboClient({ beforeMutation: async ({ command: name }) => {
    guards.push(name);
    if (fakeNow >= expiresAt) throw new Error('operator lease expired');
  }, fetchFn: async url => {
    const name = command(url);
    calls.push(name);
    if (name === 'pin/ls') return missing();
    if (name === 'dag/import') {
      fakeNow = 1101;
      return json({ Stats: { BlockCount: 1, BlockBytesCount: 4 } });
    }
    throw new Error('pin/add must not run');
  } });
  await assert.rejects(client.importVerifiedCar(bytes, root), /operator lease expired/);
  assert.deepEqual(guards, ['dag/import', 'pin/add']);
  assert.deepEqual(calls, ['pin/ls', 'dag/import']);
});

test('overall abort interrupts mutation guards and prevents the following mutation', async () => {
  const controller = new AbortController();
  const calls = [];
  const client = new KuboClient({ signal: controller.signal, beforeMutation: async () => {
    controller.abort();
    return new Promise(() => {});
  }, fetchFn: async url => { calls.push(command(url)); return missing(); } });
  await assert.rejects(client.importVerifiedCar(bytes, root), { code: 'ABORTED' });
  assert.deepEqual(calls, ['pin/ls']);
});

test('verified bytes are snapshotted before awaiting pin reconciliation', async () => {
  const input = new Uint8Array([1, 2, 3, 4]);
  let initialPinResponse;
  let reads = 0;
  const client = new KuboClient({ fetchFn: async (url, init) => {
    if (command(url) === 'pin/ls') {
      if (++reads === 1) return new Promise(resolve => { initialPinResponse = resolve; });
      return pin();
    }
    if (command(url) === 'dag/import') {
      const data = await new Response(init.body, { headers: { 'content-type': init.headers['content-type'] } }).formData();
      assert.deepEqual(new Uint8Array(await data.get('file').arrayBuffer()), bytes);
      return json({ Stats: { BlockCount: 1, BlockBytesCount: 4 } });
    }
    return json({ Pins: [root] });
  } });
  const pending = client.importVerifiedCar(input, root);
  input.fill(9);
  initialPinResponse(missing());
  assert.equal((await pending).pinned, true);
  await assert.rejects(client.importVerifiedCar(new Uint8Array(new SharedArrayBuffer(4)), root), TypeError);
});

test('invalid import, pin, or final readback never becomes confirmed success', async () => {
  for (const badPhase of ['dag/import', 'pin/add', 'final pin/ls']) {
    let reads = 0;
    const client = new KuboClient({ fetchFn: async url => {
      const name = command(url);
      if (name === 'pin/ls') { reads++; return reads === 1 || badPhase === 'final pin/ls' ? missing() : pin(); }
      if (name === 'dag/import') return json(badPhase === name ? {} : { Stats: { BlockCount: 1, BlockBytesCount: 4 } });
      if (name === 'pin/add') return json({ Pins: badPhase === name ? [] : [root] });
      throw new Error('unexpected command');
    } });
    await assert.rejects(client.importVerifiedCar(bytes, root), KuboApiError);
  }
});

test('response cap covers actual streaming bytes and rejects redirects before sending another RPC', async () => {
  const oversized = new KuboClient({ maxResponseBytes: 32, fetchFn: async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(20)); controller.enqueue(new Uint8Array(20)); controller.close(); },
  })) });
  await assert.rejects(oversized.isPinned(root), { code: 'RESPONSE_TOO_LARGE' });
  const declared = new KuboClient({ maxResponseBytes: 32, fetchFn: async () => json({}, 200, { 'content-length': '1000' }) });
  await assert.rejects(declared.isPinned(root), { code: 'RESPONSE_TOO_LARGE' });
  let calls = 0;
  const redirected = new KuboClient({ fetchFn: async (_url, init) => {
    calls++; assert.equal(init.redirect, 'manual');
    return new Response('', { status: 307, headers: { location: 'https://untrusted.example' } });
  } });
  await assert.rejects(redirected.isPinned(root), { code: 'REDIRECT_REJECTED' });
  assert.equal(calls, 1);
});

test('200 NDJSON API errors do not become successful imports', async () => {
  const calls = [];
  const client = new KuboClient({ fetchFn: async url => {
    calls.push(command(url));
    if (command(url) === 'pin/ls') return missing();
    return new Response(JSON.stringify({ Stats: { BlockCount: 1, BlockBytesCount: 4 } }) + '\n' +
      JSON.stringify({ Message: 'import failed after partial write', Code: 0, Type: 'error' }) + '\n');
  } });
  await assert.rejects(client.importVerifiedCar(bytes, root), { code: 'API_ERROR' });
  assert.deepEqual(calls, ['pin/ls', 'dag/import']);
});

test('timeout bounds noncooperating fetch and body streams, without automatic mutation retry', async () => {
  for (const fetchFn of [async () => new Promise(() => {}), async () => new Response(new ReadableStream({ start() {} }))]) {
    const client = new KuboClient({ timeoutMs: 20, fetchFn });
    const started = Date.now();
    await assert.rejects(client.isPinned(root), { code: 'TIMEOUT' });
    assert.ok(Date.now() - started < 500);
  }
});

test('overall abort stops in-flight work and prevents every subsequent RPC', async () => {
  const controller = new AbortController();
  let calls = 0;
  const client = new KuboClient({ signal: controller.signal, fetchFn: async (_url, init) => {
    calls++;
    assert.equal(init.signal.aborted, false);
    return new Promise(() => {});
  } });
  const pending = client.isPinned(root);
  controller.abort(new Error('operator deadline with private details'));
  await assert.rejects(pending, { code: 'ABORTED' });
  await assert.rejects(client.isPinned(root), { code: 'ABORTED' });
  await assert.rejects(client.inspect(), { code: 'ABORTED' });
  await assert.rejects(client.importVerifiedCar(bytes, root), { code: 'ABORTED' });
  assert.equal(calls, 1);
});

test('CAR admission rejects invalid roots, oversized bytes, and concurrent unrelated imports before mutation', async () => {
  let calls = 0;
  const client = new KuboClient({ maxImportBytes: 4, fetchFn: async () => { calls++; return pin(); } });
  await assert.rejects(client.importVerifiedCar(bytes, '/ipns/untrusted'), TypeError);
  await assert.rejects(client.importVerifiedCar(new Uint8Array(5), root), TypeError);
  await assert.rejects(client.importVerifiedCar(new Uint8Array(), root), TypeError);
  assert.equal(calls, 0);
  let finish;
  const active = new KuboClient({ fetchFn: async () => new Promise(resolve => { finish = resolve; }) });
  const first = active.importVerifiedCar(bytes, root);
  const same = active.importVerifiedCar(bytes, root);
  const otherRoot = CID.createV1(0x55, await sha256.digest(new Uint8Array([9]))).toString();
  await assert.rejects(active.importVerifiedCar(bytes, otherRoot), { code: 'IMPORT_BUSY' });
  finish(pin());
  assert.deepEqual(await first, await same);
});
