import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { CarWriter } from '@ipld/car';
import * as dagPB from '@ipld/dag-pb';
import * as dagCBOR from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { sha256, sha512 } from 'multiformats/hashes/sha2';
import { identity } from 'multiformats/hashes/identity';
import * as digest from 'multiformats/hashes/digest';
import { verifyCar } from './car.mjs';

const text = value => new TextEncoder().encode(value);
function concat(...parts) {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.byteLength; }
  return output;
}
async function block(code, bytes, hasher = sha256) {
  return { cid: CID.createV1(code, await hasher.digest(bytes)), bytes };
}
async function raw(value) { return block(0x55, text(value)); }
async function cbor(value) { return block(dagCBOR.code, dagCBOR.encode(value)); }
async function pb(links) {
  return block(dagPB.code, dagPB.encode(dagPB.prepare({
    Data: text('graph fixture'),
    Links: links.map((link, index) => ({ Hash: link.cid, Name: String(index), Tsize: link.bytes.byteLength })),
  })));
}
async function car(roots, blocks) {
  const { writer, out } = CarWriter.create(roots);
  const bytesPromise = (async () => {
    const chunks = [];
    for await (const chunk of out) chunks.push(chunk);
    return concat(...chunks);
  })();
  for (const entry of blocks) await writer.put(entry);
  await writer.close();
  return bytesPromise;
}
async function graph() {
  const a = await raw('first payload');
  const b = await raw('second payload');
  const branch = await pb([a]);
  const root = await cbor({ branch: branch.cid, shared: [a.cid, { leaf: b.cid }] });
  return { a, b, branch, root, blocks: [b, branch, root, a] };
}
function rejectsCode(promise, code) { return assert.rejects(promise, error => error.code === code); }

test('official-writer mixed graph proves every reachable raw, DAG-PB and nested DAG-CBOR block', async () => {
  const fixture = await graph();
  const bytes = await car([fixture.root.cid], fixture.blocks);
  const verified = await verifyCar(bytes, fixture.root.cid.toString());
  assert.deepEqual(verified, {
    root: fixture.root.cid.toString(), blockCount: 4, byteLength: bytes.byteLength,
    reachableBlockCount: 4, complete: true, codecs: ['dag-cbor', 'dag-pb', 'raw'],
    sha256: createHash('sha256').update(bytes).digest('hex'),
  });
  assert.deepEqual(JSON.parse(JSON.stringify(verified)), verified);
});

test('raw leaf, empty raw leaf, and CIDv0 DAG-PB roots are supported', async () => {
  for (const value of ['leaf', '']) {
    const root = await raw(value);
    const verified = await verifyCar(await car([root.cid], [root]), root.cid);
    assert.equal(verified.reachableBlockCount, 1);
    assert.deepEqual(verified.codecs, ['raw']);
  }
  const branch = await pb([]);
  const v0 = { ...branch, cid: branch.cid.toV0() };
  assert.equal((await verifyCar(await car([v0.cid], [v0]), v0.cid.toString())).root, v0.cid.toString());
});

test('bounded identity CID validates exact inline contents', async () => {
  const root = await block(0x55, text('inline'), identity);
  assert.equal((await verifyCar(await car([root.cid], [root]), root.cid)).complete, true);
  const wrong = { cid: root.cid, bytes: text('changed') };
  await rejectsCode(verifyCar(await car([root.cid], [wrong]), root.cid), 'CAR_HASH_MISMATCH');
  const tooLarge = await block(0x55, new Uint8Array(513), identity);
  await rejectsCode(verifyCar(await car([tooLarge.cid], [tooLarge]), tooLarge.cid), 'CAR_HASH');
});

test('tampered block bytes are rejected even when the official writer accepts the claimed CID', async () => {
  const root = await raw('authentic');
  const forged = { cid: root.cid, bytes: text('tampered') };
  await rejectsCode(verifyCar(await car([root.cid], [forged]), root.cid), 'CAR_HASH_MISMATCH');
});

test('requested root must match the only CAR header root exactly', async () => {
  const root = await raw('root');
  const other = await raw('other');
  await rejectsCode(verifyCar(await car([root.cid], [root]), other.cid), 'CAR_ROOT');
  await rejectsCode(verifyCar(await car([root.cid, other.cid], [root, other]), root.cid), 'CAR_HEADER');
  await rejectsCode(verifyCar(await car([], [root]), root.cid), 'CAR_HEADER');
});

test('matching header without its root block is rejected', async () => {
  const root = await raw('missing root');
  await rejectsCode(verifyCar(await car([root.cid], []), root.cid), 'CAR_MISSING_ROOT');
});

test('both DAG-PB and nested DAG-CBOR missing children prevent complete graph claims', async () => {
  const child = await raw('required child');
  const branch = await pb([child]);
  await rejectsCode(verifyCar(await car([branch.cid], [branch]), branch.cid), 'CAR_MISSING_LINK');
  const root = await cbor({ deeply: [{ child: child.cid }] });
  await rejectsCode(verifyCar(await car([root.cid], [root]), root.cid), 'CAR_MISSING_LINK');
});

test('an inline identity-linked child is still required as an explicit CAR block', async () => {
  const child = await block(0x55, text('inline child'), identity);
  const root = await cbor({ child: child.cid });
  await rejectsCode(verifyCar(await car([root.cid], [root]), root.cid), 'CAR_MISSING_LINK');
});

test('extra unreachable blocks are rejected after their content is verified', async () => {
  const root = await raw('root');
  const extra = await raw('unreachable');
  await rejectsCode(verifyCar(await car([root.cid], [root, extra]), root.cid), 'CAR_UNREACHABLE');
});

test('identical duplicate sections are bounded and counted; conflicting duplicates are rejected', async () => {
  const root = await raw('duplicate');
  const bytes = await car([root.cid], [root, root]);
  const verified = await verifyCar(bytes, root.cid);
  assert.equal(verified.blockCount, 2);
  assert.equal(verified.reachableBlockCount, 1);
  await rejectsCode(verifyCar(bytes, root.cid, { maxBlocks: 1 }), 'CAR_LIMIT');
  const conflict = { cid: root.cid, bytes: text('different') };
  await rejectsCode(verifyCar(await car([root.cid], [root, conflict]), root.cid), 'CAR_DUPLICATE');
});

test('padding, trailing garbage, truncation and noncanonical framing are rejected', async () => {
  const root = await raw('payload');
  const bytes = await car([root.cid], [root]);
  for (const invalid of [concat(bytes, new Uint8Array([0])), concat(bytes, new Uint8Array([255])), bytes.subarray(0, -1)]) {
    await rejectsCode(verifyCar(invalid, root.cid), 'CAR_FRAMING');
  }
  assert.ok(bytes[0] < 128, 'fixture header length uses one byte');
  const overlong = concat(new Uint8Array([bytes[0] | 128, 0]), bytes.subarray(1));
  await rejectsCode(verifyCar(overlong, root.cid), 'CAR_FRAMING');
});

test('CARv2 pragma and malformed CARv1 headers are rejected', async () => {
  const root = await raw('header');
  const v2Pragma = dagCBOR.encode({ version: 2 });
  await rejectsCode(verifyCar(concat(new Uint8Array([v2Pragma.byteLength]), v2Pragma), root.cid), 'CAR_HEADER');
  const wrongRoot = dagCBOR.encode({ version: 1, roots: ['not a CID'] });
  await rejectsCode(verifyCar(concat(new Uint8Array([wrongRoot.byteLength]), wrongRoot), root.cid), 'CAR_HEADER');
  await rejectsCode(verifyCar(new Uint8Array([0]), root.cid), 'CAR_HEADER');
});

test('unsupported block codecs and hashes, including reachable child links, fail closed', async () => {
  const unsupported = await block(0x129, text('unsupported codec'));
  await rejectsCode(verifyCar(await car([unsupported.cid], [unsupported]), unsupported.cid), 'CAR_CODEC');
  const hash = await block(0x55, text('unsupported hash'), sha512);
  await rejectsCode(verifyCar(await car([hash.cid], [hash]), hash.cid), 'CAR_HASH');
  const root = await cbor({ child: unsupported.cid });
  await rejectsCode(verifyCar(await car([root.cid], [root]), root.cid), 'CAR_CODEC');
  const malformedHash = CID.createV1(0x55, digest.create(sha256.code, new Uint8Array(31)));
  await rejectsCode(verifyCar(await car([malformedHash], [{ cid: malformedHash, bytes: text('bad') }]), malformedHash), 'CAR_HASH');
});

test('invalid codec contents with an authentic hash are rejected', async () => {
  const malformedPB = await block(dagPB.code, new Uint8Array([255]));
  await rejectsCode(verifyCar(await car([malformedPB.cid], [malformedPB]), malformedPB.cid), 'CAR_BLOCK');
  const malformedCBOR = await block(dagCBOR.code, new Uint8Array([255]));
  await rejectsCode(verifyCar(await car([malformedCBOR.cid], [malformedCBOR]), malformedCBOR.cid), 'CAR_BLOCK');
});

test('byte, block and link limits apply to real writer-generated graphs', async () => {
  const fixture = await graph();
  const bytes = await car([fixture.root.cid], fixture.blocks);
  await rejectsCode(verifyCar(bytes, fixture.root.cid, { maxBytes: bytes.byteLength - 1 }), 'CAR_LIMIT');
  await rejectsCode(verifyCar(bytes, fixture.root.cid, { maxBlocks: 3 }), 'CAR_LIMIT');
  await rejectsCode(verifyCar(bytes, fixture.root.cid, { maxLinks: 3 }), 'CAR_LIMIT');
  const leaf = await raw('no links');
  assert.equal((await verifyCar(await car([leaf.cid], [leaf]), leaf.cid, { maxLinks: 0 })).complete, true);
  const repeated = await cbor({ links: Array(10).fill(leaf.cid) });
  await rejectsCode(verifyCar(await car([repeated.cid], [repeated, leaf]), repeated.cid, { maxLinks: 9 }), 'CAR_LIMIT');
});

test('shared children are a DAG; a forged self-link cannot bypass content-address validation', async () => {
  const leaf = await raw('shared');
  const branch = await cbor({ a: leaf.cid, b: leaf.cid });
  const root = await cbor({ branches: [branch.cid, branch.cid], leaf: leaf.cid });
  assert.equal((await verifyCar(await car([root.cid], [root, branch, leaf]), root.cid)).reachableBlockCount, 3);
  // Constructing a genuine sha256 self-cycle would require a hash fixed point.
  // This adversarial CAR claims one; CID authentication rejects it first.
  const falseSelf = { cid: root.cid, bytes: dagCBOR.encode({ self: root.cid }) };
  await rejectsCode(verifyCar(await car([root.cid], [falseSelf]), root.cid), 'CAR_HASH_MISMATCH');
});

test('deep nesting and invalid limit/input types are bounded', async () => {
  let nested = 1;
  for (let index = 0; index < 130; index++) nested = [nested];
  const root = await cbor(nested);
  await rejectsCode(verifyCar(await car([root.cid], [root]), root.cid), 'CAR_LIMIT');
  const leaf = await raw('leaf');
  const bytes = await car([leaf.cid], [leaf]);
  for (const options of [{ maxBlocks: 0 }, { maxBytes: Infinity }, { maxLinks: -1 }, { maxLinks: 1.5 }]) {
    await rejectsCode(verifyCar(bytes, leaf.cid, options), 'CAR_LIMIT');
  }
  await rejectsCode(verifyCar('bytes', leaf.cid), 'CAR_BYTES');
  await rejectsCode(verifyCar(new Uint8Array(), leaf.cid), 'CAR_LIMIT');
  await rejectsCode(verifyCar(bytes, 'not a CID'), 'CAR_ROOT');
});
