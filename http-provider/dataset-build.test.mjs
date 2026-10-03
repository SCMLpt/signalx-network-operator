import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { CarWriter } from '@ipld/car';
import * as dagPB from '@ipld/dag-pb';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { buildDataset, ROOT, CAR_SHA256 } from './dataset-build.mjs';

const term = { startedAtUtc: '2030-01-01T00:00:00.000Z', termEndUtc: '2030-01-08T00:00:00.000Z' };
const attribution = { title: 'Explicit test fixture', creators: ['Test author'], source: 'https://example.org/publication/', license: 'CC0-1.0', changes: 'Unmodified fixture bytes' };
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

async function archive(root, blocks) {
  const { writer, out } = CarWriter.create([root]);
  const collecting = (async () => { const chunks = []; for await (const chunk of out) chunks.push(chunk); return Buffer.concat(chunks); })();
  for (const block of blocks) await writer.put(block);
  await writer.close();
  return collecting;
}
async function fixture({ empty = false, extra = false, duplicate = false } = {}) {
  const leafBytes = new TextEncoder().encode(empty ? '' : 'Original public fixture bytes\n');
  const leaf = { cid: CID.createV1(0x55, await sha256.digest(leafBytes)), bytes: leafBytes };
  const directoryBytes = dagPB.encode(dagPB.prepare({ Data: new Uint8Array([8, 1]), Links: [{ Name: 'original.txt', Hash: leaf.cid, Tsize: leaf.bytes.length }] }));
  const root = { cid: CID.createV1(dagPB.code, await sha256.digest(directoryBytes)), bytes: directoryBytes };
  const blocks = [root, leaf];
  if (extra) { const bytes = new TextEncoder().encode('unreachable payload'); blocks.push({ cid: CID.createV1(0x55, await sha256.digest(bytes)), bytes }); }
  if (duplicate) blocks.push(leaf);
  const car = await archive(root.cid, blocks);
  return { root: root.cid.toString(), car, leaf, options: { ...term, root: root.cid.toString(), carSha256: digest(car), attribution, providerHost: 'replica.example.org' } };
}
async function withFile(bytes, fn) {
  const directory = await mkdtemp(join(tmpdir(), 'signalx-dataset-'));
  const path = join(directory, 'original.car');
  try { await writeFile(path, bytes); return await fn(path, directory); }
  finally { await rm(directory, { recursive: true, force: true }); }
}

test('historical publication builds exact original bytes and attribution', async () => {
  const deployed = JSON.parse(await readFile(new URL('./deployment-data.json', import.meta.url), 'utf8'));
  await withFile(Buffer.from(deployed.carBase64, 'base64'), async path => {
    const built = await buildDataset(path, term);
    assert.equal(built.root, ROOT);
    assert.equal(built.verification.carSha256, CAR_SHA256);
    assert.deepEqual(built.blocks, deployed.blocks);
    assert.equal(built.verification.blocks, 5);
    assert.equal(built.providerId, null);
    assert.equal(built.ipni, null);
  });
});

test('a distinct complete publication and provider host preserve every original block', async () => {
  const f = await fixture();
  await withFile(f.car, async path => {
    const built = await buildDataset(path, { ...f.options, expectedBlocks: 2, carBytes: f.car.length });
    assert.equal(built.root, f.root);
    assert.equal(built.providerHost, 'replica.example.org');
    assert.equal(built.verification.blocks, 2);
    assert.equal(built.blocks[f.leaf.cid.toString()], Buffer.from(f.leaf.bytes).toString('base64'));
    assert.deepEqual(built.attribution, attribution);
    assert.equal(built.verification.upstreamFetchOnRead, false);
  });
});

test('legitimate empty original raw files remain represented', async () => {
  const f = await fixture({ empty: true });
  await withFile(f.car, async path => {
    const built = await buildDataset(path, f.options);
    assert.equal(built.blocks[f.leaf.cid.toString()], '');
    assert.equal(built.verification.blocks, 2);
  });
});

test('continuous publication has explicit null expiry and unchanged bounded original content', async () => {
  const f = await fixture();
  await withFile(f.car, async path => {
    const built = await buildDataset(path, { ...f.options, servingMode: 'continuous', termEndUtc: null });
    assert.equal(built.servingMode, 'continuous');
    assert.equal(built.termEndUtc, null);
    assert.equal(built.startedAtUtc, term.startedAtUtc);
    assert.equal(built.carBase64, f.car.toString('base64'));
    assert.equal(built.blocks[f.leaf.cid.toString()], Buffer.from(f.leaf.bytes).toString('base64'));
    assert.equal(built.verification.upstreamFetchOnRead, false);
    for (const change of [
      { servingMode: 'continuous' }, { servingMode: 'continuous', termEndUtc: undefined },
      { servingMode: 'continuous', termEndUtc: null, startedAtUtc: '2030-01-01' },
      { servingMode: 'continuous', termEndUtc: null, carSha256: '0'.repeat(64) },
      { servingMode: 'finite', termEndUtc: null }, { servingMode: 'forever' },
      { termEndUtc: null },
    ]) await assert.rejects(buildDataset(path, { ...f.options, ...change }));
  });
});

test('duplicate and unreachable sections cannot enter a public deployment', async () => {
  for (const mode of [{ duplicate: true }, { extra: true }]) {
    const f = await fixture(mode);
    await withFile(f.car, async path => { await assert.rejects(buildDataset(path, f.options)); });
  }
});

test('qualification hashes, term, attribution, hostname and graph bounds are enforced', async () => {
  const f = await fixture();
  await withFile(f.car, async path => {
    for (const change of [
      { carSha256: '0'.repeat(64) }, { expectedBlocks: 3 }, { carBytes: f.car.length + 1 },
      { payloadBytes: 0 }, { graphDigest: '1'.repeat(64) }, { expectedBlocks: 65 },
      { termEndUtc: '2030-01-08T00:00:00.001Z' }, { startedAtUtc: '2030-01-01' },
      { attribution: { ...attribution, creators: [] } }, { providerHost: 'https://replica.example.org' },
      { attribution: { ...attribution, source: 'https://user:secret@example.org/' } },
    ]) await assert.rejects(buildDataset(path, { ...f.options, ...change }));
  });
});

test('symlinks, oversized files and trailing CAR bytes are rejected', async () => {
  const f = await fixture();
  await withFile(f.car, async (path, directory) => {
    const link = join(directory, 'linked.car');
    await symlink(path, link);
    await assert.rejects(buildDataset(link, f.options));
    const trailing = Buffer.concat([f.car, Buffer.from([0])]);
    await writeFile(path, trailing);
    await assert.rejects(buildDataset(path, { ...f.options, carSha256: digest(trailing) }));
    await writeFile(path, Buffer.alloc(1048577));
    await assert.rejects(buildDataset(path, f.options));
  });
});
