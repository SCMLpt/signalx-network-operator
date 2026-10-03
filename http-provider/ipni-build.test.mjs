import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { CarWriter } from '@ipld/car';
import * as dagCBOR from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { identity } from 'multiformats/hashes/identity';
import { generateKeyPair } from '@libp2p/crypto/keys';
import { peerIdFromPrivateKey } from '@libp2p/peer-id';
import { prepareRequest, handlerIPNI, HISTORICAL_PROVIDER_HOST, validateProviderHost, referenceRun } from './ipni-build.mjs';

const fixture = async () => JSON.parse(await readFile(new URL('./deployment-data.json', import.meta.url)));

async function archive(root, blocks) {
  const { writer, out } = CarWriter.create([root]);
  const result = (async () => {
    const chunks = [];
    for await (const chunk of out) chunks.push(chunk);
    return Buffer.concat(chunks);
  })();
  for (const block of blocks) await writer.put(block);
  await writer.close();
  return result;
}

async function graphFixture(count, payloadBytes = 0) {
  const key = await generateKeyPair('Ed25519');
  const blocks = [];
  for (let i = 1; i < count; i++) {
    const bytes = Buffer.from(`graph leaf ${i}`);
    blocks.push({ cid: CID.createV1(0x55, await sha256.digest(bytes)), bytes });
  }
  const bytes = payloadBytes ? Buffer.alloc(payloadBytes) : dagCBOR.encode({ links: blocks.map(block => block.cid) });
  const root = CID.createV1(payloadBytes ? 0x55 : dagCBOR.code, await sha256.digest(bytes));
  blocks.unshift({ cid: root, bytes });
  return {
    root: root.toString(), blocks: Object.fromEntries(blocks.map(block => [block.cid.toString(), Buffer.from(block.bytes).toString('base64')])),
    carBase64: (await archive(root, blocks)).toString('base64'),
    providerHost: 'another-ipfs-provider.kamuitranslator.workers.dev', providerId: peerIdFromPrivateKey(key).toString(),
    startedAtUtc: '2026-10-03T09:50:00.370Z', termEndUtc: '2026-10-10T09:50:00.370Z',
  };
}

test('public signing request comes from the exact verified CAR and original block map', async () => {
  const data = await fixture();
  const prepared = await prepareRequest(data);
  assert.equal(prepared.request.blockCids.length, 5);
  assert.equal(prepared.request.providerId, data.providerId);
  assert.equal(prepared.request.providerHost, data.providerHost ?? HISTORICAL_PROVIDER_HOST);
  assert.equal(prepared.integrity.carBytes, 166374);
  assert.equal(prepared.integrity.carSha256, 'd79dd33f1717beed7d7152f61170c06f318529edf193277c997a576663007078');
  assert.equal(JSON.stringify(prepared).includes('private'), false);
});

test('other complete graphs use the supplied root, hostname and bounded block count', async () => {
  for (const count of [1, 25, 64]) {
    const data = await graphFixture(count);
    const prepared = await prepareRequest(data);
    assert.equal(prepared.request.rootCid, data.root);
    assert.equal(prepared.request.providerHost, data.providerHost);
    assert.deepEqual(prepared.request.blockCids, Object.keys(data.blocks).sort());
    assert.equal(prepared.integrity.reachableBlocks, count);
  }
  const empty = await graphFixture(1);
  const emptyBytes = Buffer.alloc(0);
  const emptyCid = CID.createV1(0x55, await sha256.digest(emptyBytes));
  const emptyPrepared = await prepareRequest({ ...empty, root: emptyCid.toString(), blocks: { [emptyCid.toString()]: '' }, carBase64: (await archive(emptyCid, [{ cid: emptyCid, bytes: emptyBytes }])).toString('base64') });
  assert.equal(emptyPrepared.integrity.reachableBlocks, 1);
  await assert.rejects(prepareRequest(await graphFixture(65)), /maxBlocks/);
  await assert.rejects(prepareRequest(await graphFixture(1, 1048576)), /maxBytes/);
});

test('missing, extra, duplicated, corrupted and inline blocks cannot reach the signer', async () => {
  const data = await graphFixture(3);
  const cids = Object.keys(data.blocks);
  const blocks = cids.map(cid => ({ cid: CID.parse(cid), bytes: Buffer.from(data.blocks[cid], 'base64') }));
  const missingMap = structuredClone(data);
  delete missingMap.blocks[cids[1]];
  await assert.rejects(prepareRequest(missingMap), /reachable blocks/);
  const extraMap = structuredClone(data);
  extraMap.blocks[Object.keys((await graphFixture(1)).blocks)[0]] = 'eA==';
  await assert.rejects(prepareRequest(extraMap), /reachable blocks/);
  const missingCar = { ...data, carBase64: (await archive(CID.parse(data.root), blocks.slice(0, -1))).toString('base64') };
  await assert.rejects(prepareRequest(missingCar), /missing/);
  const duplicate = { ...data, carBase64: (await archive(CID.parse(data.root), [...blocks, blocks[0]])).toString('base64') };
  await assert.rejects(prepareRequest(duplicate), /duplicate CAR sections/);
  const extra = await graphFixture(1);
  const extraBlock = { cid: CID.parse(extra.root), bytes: Buffer.from(extra.blocks[extra.root], 'base64') };
  await assert.rejects(prepareRequest({ ...data, carBase64: (await archive(CID.parse(data.root), [...blocks, extraBlock])).toString('base64') }), /unreachable/);
  const corrupted = blocks.map(block => ({ ...block, bytes: Buffer.from(block.bytes) }));
  corrupted[1].bytes[0] ^= 1;
  await assert.rejects(prepareRequest({ ...data, carBase64: (await archive(CID.parse(data.root), corrupted)).toString('base64') }), /does not match its CID/);
  const inlineBytes = Buffer.from('inline');
  const inlineCid = CID.createV1(0x55, await identity.digest(inlineBytes));
  await assert.rejects(prepareRequest({ ...extra, root: inlineCid.toString(), blocks: { [inlineCid.toString()]: inlineBytes.toString('base64') }, carBase64: (await archive(inlineCid, [{ cid: inlineCid, bytes: inlineBytes }])).toString('base64') }), /SHA-256/);
});

test('hostnames bind to a public DNS name with fixed HTTPS transport', async () => {
  assert.equal(validateProviderHost(HISTORICAL_PROVIDER_HOST), HISTORICAL_PROVIDER_HOST);
  for (const host of [null, '', 'https://provider.org', 'provider.org:443', 'provider.org/path', '127.0.0.1', '[::1]', 'Provider.org', 'provider.org.', 'provider.local', 'provider.test', 'provider.example', 'provider.example.org', '-provider.org', 'provider..org', `${'a'.repeat(64)}.org`]) {
    assert.throws(() => validateProviderHost(host), /public DNS/);
  }
  const data = await graphFixture(1);
  for (const host of [null, '', 'provider.local']) await assert.rejects(prepareRequest({ ...data, providerHost: host }), /public DNS/);
  const absent = { ...data };
  delete absent.providerHost;
  await assert.rejects(prepareRequest(absent), /explicit providerHost/);
});

test('public verification refuses a private key before starting Go', () => {
  assert.throws(() => referenceRun({}, { verify: true, keyPath: '/unused-private-key.pb' }), /must not receive/);
  assert.throws(() => referenceRun({}, {}), /key path/);
  assert.throws(() => referenceRun('x'.repeat(131073), { verify: true }), /input exceeds/);
});

test('changed block bytes and an extended serving term cannot reach the signer', async () => {
  const changed = await fixture();
  changed.blocks[Object.keys(changed.blocks)[0]] = Buffer.from('bad').toString('base64');
  await assert.rejects(prepareRequest(changed), /differs/);
  const extended = await fixture();
  extended.termEndUtc = '2026-10-11T09:50:00.370Z';
  await assert.rejects(prepareRequest(extended), /seven days/);
});

test('continuous serving requires explicit mode, null expiry and the verified unchanged publication', async () => {
  const data = await graphFixture(25);
  const finite = await prepareRequest(data);
  assert.equal(Object.hasOwn(finite.request, 'servingMode'), false);
  const explicitFinite = await prepareRequest({ ...data, servingMode: 'finite' });
  assert.equal(explicitFinite.request.servingMode, 'finite');
  const continuous = await prepareRequest({ ...data, servingMode: 'continuous', termEndUtc: null });
  assert.equal(continuous.request.servingMode, 'continuous');
  assert.equal(continuous.request.expiresAt, null);
  assert.deepEqual(continuous.request.blockCids, finite.request.blockCids);
  assert.deepEqual(continuous.integrity, finite.integrity);
  for (const changed of [{ termEndUtc: null }, { servingMode: 'continuous' }, { servingMode: 'continuous', termEndUtc: undefined }, { servingMode: 'unknown', termEndUtc: null }]) {
    await assert.rejects(prepareRequest({ ...data, ...changed }), /policy|servingMode/);
  }
});

test('continuous mapping serves old bridge history and has no expiry removal slots', () => {
  const bundle = { activeHead: { cid: 'new-add', bodyBase64: 'current' }, removalHead: null,
    objects: ['old-entry', 'old-add', 'old-remove', 'new-add'].map(cid => ({ cid, bodyBase64: cid, contentType: 'application/vnd.ipld.dag-cbor' })) };
  const mapped = handlerIPNI(bundle);
  assert.deepEqual(Object.keys(mapped.objects), ['old-entry', 'old-add', 'old-remove', 'new-add']);
  assert.deepEqual(mapped.removalObjects, {});
  assert.equal(mapped.removalHeadBase64, null);
  assert.equal(mapped.headBase64, 'current');
});

test('handler mapping withholds the removal object until the end phase', () => {
  const bundle = {
    activeHead: { cid: 'add', bodyBase64: 'active' },
    removalHead: { cid: 'remove', bodyBase64: 'end' },
    objects: ['entry', 'add', 'remove'].map(cid => ({ cid, bodyBase64: cid, contentType: 'application/vnd.ipld.dag-cbor' })),
  };
  const mapped = handlerIPNI(bundle);
  assert.deepEqual(Object.keys(mapped.objects), ['entry', 'add']);
  assert.deepEqual(Object.keys(mapped.removalObjects), ['remove']);
  assert.equal(mapped.headBase64, 'active');
  assert.equal(mapped.removalHeadBase64, 'end');
});
