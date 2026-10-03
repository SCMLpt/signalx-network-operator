import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as dagPb from '@ipld/dag-pb';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { CarReader } from '@ipld/car';
import data from './deployment-data.json' with { type: 'json' };
import { createUnixfs, UnixfsError } from './unixfs.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const sourceMap = () => new Map(Object.entries(data.blocks).map(([cid, value]) => [cid, Buffer.from(value, 'base64')]));
const originalFiles = [
  ['M203-StationList_md_new.csv', 45611, '14428a2465939de6b7b7d8015960c9ab1d7cd689a3ffbc1aade5048fd9436494'],
  ['coordination_log.xlsx', 11685, '59a0bb6d95fd55cab97389bc5f695fc9ce61131c1b7ac696e4bdb3f174863fc2'],
  ['dataset_meta.yaml', 797, '5ab5e593aa21613548d5eb333b89eb3844c8aeb36d62183276a7cbdc683000c3'],
  ['met_203_1_station_book.csv', 107753, '085429ca31eeb908e599c9be4e8aa7a2c462c45aa01a636c4270659c37549228'],
];
function vi(value) { const out = []; do { const n = value % 128; value = Math.floor(value / 128); out.push(n | (value ? 128 : 0)); } while (value); return Buffer.from(out); }
function unixData(type, { bytes = Buffer.alloc(0), filesize, sizes = [], packed = false } = {}) {
  const parts = [Buffer.from([8]), vi(type)];
  if (bytes.length) parts.push(Buffer.from([18]), vi(bytes.length), bytes);
  if (filesize !== undefined) parts.push(Buffer.from([24]), vi(filesize));
  if (packed && sizes.length) {
    const values = Buffer.concat(sizes.map(vi)); parts.push(Buffer.from([34]), vi(values.length), values);
  } else for (const size of sizes) parts.push(Buffer.from([32]), vi(size));
  return Buffer.concat(parts);
}
async function put(map, bytes, codec = dagPb.code) {
  const cid = CID.createV1(codec, await sha256.digest(bytes)); map.set(cid.toString(), bytes); return cid;
}
async function directory(map, links) {
  return put(map, dagPb.encode(dagPb.prepare({ Data: unixData(1), Links: links })));
}
async function proofBlocks(proof) {
  const reader = await CarReader.fromBytes(proof.bytes);
  const blocks = [];
  for await (const block of reader.blocks()) {
    assert.equal(hash(block.bytes), Buffer.from(block.cid.multihash.digest).toString('hex'));
    blocks.push(block);
  }
  return blocks;
}

test('real original directory names, CSV/XLSX/YAML bytes and published hashes resolve unchanged', () => {
  const unixfs = createUnixfs(data.root, sourceMap());
  const listing = unixfs.resolve([]);
  assert.equal(listing.type, 'directory');
  assert.deepEqual(listing.entries.map(entry => entry.name), originalFiles.map(entry => entry[0]));
  for (const [name, size, expected] of originalFiles) {
    const file = unixfs.resolve([name]);
    assert.equal(file.type, 'file'); assert.equal(file.size, size); assert.equal(hash(file.bytes), expected);
    assert.equal(hash(file.bytes), Buffer.from(CID.parse(file.cid).multihash.digest).toString('hex'));
  }
  assert.match(new TextDecoder().decode(unixfs.resolve(['dataset_meta.yaml']).bytes), /license: CC-BY-4\.0/);
  assert.deepEqual([...unixfs.resolve(['coordination_log.xlsx']).bytes.subarray(0, 4)], [80, 75, 3, 4]);
});

test('root and filename proof CARs contain only the original path blocks, in traversal order', async () => {
  const map = sourceMap(); const unixfs = createUnixfs(data.root, map);
  for (const scope of ['block', 'entity']) {
    const rootProof = await proofBlocks(unixfs.proof([], scope));
    assert.deepEqual(unixfs.proof([], scope).pathRoots, [data.root]);
    assert.deepEqual(rootProof.map(block => block.cid.toString()), [data.root]);
    assert.deepEqual(Buffer.from(rootProof[0].bytes), map.get(data.root));
    for (const [name] of originalFiles) {
      const target = unixfs.resolve([name]);
      const proof = unixfs.proof([name], scope);
      assert.deepEqual(proof.pathRoots, [data.root, target.cid]);
      const blocks = await proofBlocks(proof);
      assert.deepEqual(blocks.map(block => block.cid.toString()), [data.root, target.cid]);
      const parent = dagPb.decode(blocks[0].bytes);
      assert.equal(parent.Links.find(link => link.Name === name).Hash.toString(), blocks[1].cid.toString());
      assert.deepEqual(Buffer.from(blocks[1].bytes), map.get(target.cid));
      assert.ok(proof.etag.includes(`car.${scope}`));
    }
  }
  assert.notEqual(unixfs.proof([], 'block').etag, unixfs.proof([], 'entity').etag);
  assert.notEqual(unixfs.proof([originalFiles[0][0]], 'block').etag, unixfs.proof([originalFiles[1][0]], 'block').etag);
});

test('valid nested directories, raw leaves and UnixFS file chunks are reconstructed and scoped correctly', async () => {
  const map = new Map();
  const leaf = await put(map, Buffer.from('world'), 0x55);
  const file = await put(map, dagPb.encode({ Data: unixData(2, { bytes: Buffer.from('hello '), filesize: 11, sizes: [5], packed: true }),
    Links: [{ Hash: leaf, Name: '' }] }));
  const sub = await directory(map, [{ Hash: file, Name: 'readme.csv' }]);
  const root = await directory(map, [{ Hash: sub, Name: 'data' }]);
  const unixfs = createUnixfs(root.toString(), map);
  const resolved = unixfs.resolve(['data', 'readme.csv']);
  assert.equal(new TextDecoder().decode(resolved.bytes), 'hello world');
  assert.equal(resolved.mediaType, 'text/csv; charset=utf-8');
  for (const scope of ['block', 'entity']) {
    assert.deepEqual(unixfs.proof(['data', 'readme.csv'], scope).pathRoots,
      [root, sub, file].map(cid => cid.toString()));
  }
  assert.deepEqual((await proofBlocks(unixfs.proof(['data', 'readme.csv'], 'block'))).map(block => block.cid.toString()),
    [root, sub, file].map(cid => cid.toString()));
  assert.deepEqual((await proofBlocks(unixfs.proof(['data', 'readme.csv'], 'entity'))).map(block => block.cid.toString()),
    [root, sub, file, leaf].map(cid => cid.toString()));
  assert.deepEqual((await proofBlocks(unixfs.proof(['data'], 'entity'))).map(block => block.cid.toString()),
    [root, sub].map(cid => cid.toString()));
});

test('legacy protobuf Raw and inline File nodes preserve data, including empty files', async () => {
  for (const type of [0, 2]) {
    const map = new Map(); const bytes = type === 0 ? Buffer.from('raw legacy') : Buffer.alloc(0);
    const cid = await put(map, dagPb.encode({ Data: unixData(type, { bytes, filesize: bytes.length }), Links: [] }));
    const unixfs = createUnixfs(cid.toString(), map);
    assert.deepEqual(Buffer.from(unixfs.resolve([]).bytes), bytes);
  }
});

test('traversal, ambiguous names, duplicate links and unavailable blocks are refused', async () => {
  const base = createUnixfs(data.root, sourceMap());
  for (const path of [['..'], ['.'], [''], ['a/b'], ['a\\b'], ['a%2fb'], ['a?b']]) {
    assert.throws(() => base.resolve(path), error => error instanceof UnixfsError && error.status === 400);
  }
  assert.throws(() => base.resolve(['absent']), error => error.status === 404);
  for (const names of [['same', 'same'], ['..'], ['a/b'], ['a%2fb']]) {
    const map = new Map(); const raw = await put(map, Buffer.from('leaf'), 0x55);
    const root = await directory(map, names.map(Name => ({ Name, Hash: raw })));
    assert.throws(() => createUnixfs(root.toString(), map).resolve([]), error => error.status === 503);
  }
  const missing = sourceMap(); missing.delete(base.resolve(['dataset_meta.yaml']).cid);
  assert.throws(() => createUnixfs(data.root, missing).resolve(['dataset_meta.yaml']), error => error.status === 503);
});

test('symlinks, HAMT and malformed protobuf or file-size declarations do not produce file bytes', async () => {
  for (const type of [3, 4, 5, 99]) {
    const map = new Map(); const cid = await put(map, dagPb.encode({ Data: unixData(type), Links: [] }));
    assert.throws(() => createUnixfs(cid.toString(), map).resolve([]), error => error.status === 501);
  }
  const malformed = [Buffer.from([8]), Buffer.from([8, 1, 8, 1]), Buffer.from([10, 1, 1]), Buffer.from([8, 1, 72, 0]),
    unixData(2, { bytes: Buffer.from('payload'), filesize: 1 }), unixData(2, { bytes: Buffer.from('payload') }),
    Buffer.from([8, ...Array(10).fill(255)])];
  for (const Data of malformed) {
    const map = new Map(); const cid = await put(map, dagPb.encode({ Data, Links: [] }));
    assert.throws(() => createUnixfs(cid.toString(), map).resolve([]), error => error.status === 503);
  }
  const map = new Map(); const child = await put(map, Buffer.from('abc'), 0x55);
  const wrong = await put(map, dagPb.encode({ Data: unixData(2, { filesize: 2, sizes: [2] }), Links: [{ Hash: child, Name: '' }] }));
  assert.throws(() => createUnixfs(wrong.toString(), map).resolve([]), error => error.status === 503);
});
