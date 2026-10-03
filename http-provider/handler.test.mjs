import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import { CarReader } from '@ipld/car';
import * as dagPb from '@ipld/dag-pb';
import deploymentData from './deployment-data.json' with { type: 'json' };
import { createProvider } from './handler.mjs';
import { createUnixfs } from './unixfs.mjs';

const root = deploymentData.root;
const deadline = Date.parse(deploymentData.termEndUtc);
const base = 'https://provider.example';
const blockCids = Object.keys(deploymentData.blocks);
const raw = cid => `/ipfs/${cid}?format=raw`;
const carPath = `/ipfs/${root}?format=car&dag-scope=all`;
const b64 = value => Buffer.from(value).toString('base64');
const request = (path, options) => new Request(base + path, options);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function base32Decode(text) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0; let acc = 0; const output = [];
  for (const char of text) {
    const n = alphabet.indexOf(char);
    assert.ok(n >= 0);
    acc = (acc << 5) | n; bits += 5;
    if (bits >= 8) { bits -= 8; output.push((acc >>> bits) & 255); }
  }
  return Buffer.from(output);
}
function readVarint(bytes, at) {
  let value = 0; let shift = 0;
  for (let i = at; i < bytes.length; i++) {
    value += (bytes[i] & 127) * 2 ** shift;
    if (!(bytes[i] & 128)) return { value, next: i + 1 };
    shift += 7; assert.ok(shift <= 49);
  }
  assert.fail('Truncated fixture varint');
}
function fixtureCarBlocks(bytes) {
  const header = readVarint(bytes, 0);
  let at = header.next + header.value;
  const result = new Map();
  while (at < bytes.length) {
    const section = readVarint(bytes, at);
    const end = section.next + section.value;
    assert.ok(end <= bytes.length);
    let cursor = section.next;
    const version = readVarint(bytes, cursor); assert.equal(version.value, 1); cursor = version.next;
    const codec = readVarint(bytes, cursor); assert.ok([0x55, 0x70].includes(codec.value)); cursor = codec.next;
    const hashCode = readVarint(bytes, cursor); assert.equal(hashCode.value, 0x12); cursor = hashCode.next;
    const hashSize = readVarint(bytes, cursor); assert.equal(hashSize.value, 32); cursor = hashSize.next;
    const hash = bytes.subarray(cursor, cursor + 32); cursor += 32;
    const body = bytes.subarray(cursor, end);
    assert.equal(digest(body), hash.toString('hex'));
    assert.ok(!result.has(hash.toString('hex')));
    result.set(hash.toString('hex'), body);
    at = end;
  }
  assert.equal(at, bytes.length);
  return result;
}
function clock(t, now = deadline - 60_000) {
  return t.mock.method(Date, 'now', () => now);
}

test('real five-block fixture: raw responses and complete CAR preserve each original SHA-256 payload', async t => {
  clock(t);
  const provider = createProvider(deploymentData);
  const sourceCar = Buffer.from(deploymentData.carBase64, 'base64');
  assert.equal(sourceCar.length, 166_374);
  const parts = fixtureCarBlocks(sourceCar);
  assert.equal(parts.size, 5);
  assert.equal(blockCids.length, 5);
  for (const cid of blockCids) {
    const cidBytes = base32Decode(cid.slice(1));
    const expectedHash = cidBytes.subarray(-32).toString('hex');
    const result = provider.fetch(request(raw(cid), { headers: { accept: 'application/vnd.ipld.raw' } }));
    assert.equal(result.status, 200);
    assert.equal(result.headers.get('content-type'), 'application/vnd.ipld.raw');
    assert.equal(result.headers.get('x-ipfs-roots'), cid);
    const received = Buffer.from(await result.arrayBuffer());
    assert.deepEqual(received, Buffer.from(deploymentData.blocks[cid], 'base64'));
    assert.equal(digest(received), expectedHash);
    assert.deepEqual(received, parts.get(expectedHash));
    assert.equal(Number(result.headers.get('content-length')), received.length);
  }
  const response = provider.fetch(request(carPath));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'application/vnd.ipld.car; version=1; order=dfs; dups=n');
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), sourceCar);
});

test('HEAD, identity probe and conditional requests have accurate lengths without bodies', async t => {
  clock(t);
  const provider = createProvider(deploymentData);
  for (const path of [raw(root), carPath]) {
    const get = provider.fetch(request(path));
    const head = provider.fetch(request(path, { method: 'HEAD' }));
    assert.equal(head.status, 200);
    assert.equal(head.headers.get('content-length'), get.headers.get('content-length'));
    assert.equal((await head.arrayBuffer()).byteLength, 0);
    assert.equal(head.headers.get('etag'), `"${root}"`);
    const conditional = provider.fetch(request(path, { headers: { 'if-none-match': `"unrelated", W/"${root}"` } }));
    assert.equal(conditional.status, 304);
    assert.equal((await conditional.arrayBuffer()).byteLength, 0);
    assert.equal(conditional.headers.get('content-length'), null);
  }
  for (const method of ['GET', 'HEAD']) {
    const response = provider.fetch(request('/ipfs/bafkqaaa', { method }));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-length'), '0');
    assert.equal((await response.arrayBuffer()).byteLength, 0);
  }
});

test('malformed, unknown, duplicate and unsupported representation requests fail honestly', async t => {
  clock(t);
  const provider = createProvider(deploymentData);
  const cases = [
    ['/ipfs/unknown?format=raw', 404], ['/ipfs/', 404], [raw(root) + '&format=raw', 400],
    [`/ipfs/${root}/child`, 404], [`/ipfs/${root}/`, 404], [`/ipfs/%${root.charCodeAt(0).toString(16)}${root.slice(1)}`, 400],
    [`/ipfs//${root}`, 400], [raw(root) + '&dag-scope=all', 400],
    [`/ipfs/${root}?format=car`, 400], [carPath.replace('all', 'unsupported'), 400],
    [carPath + '&car-version=2', 400], [carPath + '&car-dups=y', 400],
    [carPath + '&car-order=unk', 400], [carPath + '&entity-bytes=0:1', 400],
    [`/ipfs/${blockCids.find(cid => cid !== root)}?format=car&dag-scope=all`, 404],
    [`/ipfs/${root}?format=dag-json`, 400], ['/health?debug=1', 400],
  ];
  for (const [path, status] of cases) assert.equal(provider.fetch(request(path)).status, status, path);
  const post = provider.fetch(request(raw(root), { method: 'POST' }));
  assert.equal(post.status, 405); assert.equal(post.headers.get('allow'), 'GET, HEAD, OPTIONS');
  for (const accept of ['text/html', 'application/vnd.ipld.raw;q=0, */*;q=1', 'application/vnd.ipld.raw;q=bogus']) {
    assert.equal(provider.fetch(request(raw(root), { headers: { accept } })).status, 406);
  }
  assert.equal(provider.fetch(request(carPath, { headers: { accept: 'application/vnd.ipld.car;version=2' } })).status, 406);
});

test('public read CORS and bounded preflights do not open mutation or credential headers', t => {
  clock(t);
  const provider = createProvider(deploymentData);
  const result = provider.fetch(request(raw(root), { headers: { origin: 'https://external-reader.example' } }));
  assert.equal(result.headers.get('access-control-allow-origin'), '*');
  assert.equal(result.headers.get('access-control-allow-credentials'), null);
  const options = provider.fetch(request(raw(root), { method: 'OPTIONS', headers: {
    origin: 'https://external-reader.example', 'access-control-request-method': 'GET',
    'access-control-request-headers': 'Accept, If-None-Match',
  } }));
  assert.equal(options.status, 204);
  assert.equal(options.headers.get('cache-control'), 'no-store');
  assert.equal(provider.fetch(request(raw(root), { method: 'OPTIONS', headers: { 'access-control-request-method': 'POST' } })).status, 403);
  assert.equal(provider.fetch(request(raw(root), { method: 'OPTIONS', headers: { 'access-control-request-headers': 'Authorization' } })).status, 403);
});

test('no endpoint performs upstream fetch and construction copies held bytes', async t => {
  clock(t);
  t.mock.method(globalThis, 'fetch', () => { assert.fail('Unexpected upstream network call'); });
  const supplied = structuredClone({ ...deploymentData, ipni: null });
  const provider = createProvider(supplied);
  supplied.blocks[root] = b64('changed'); supplied.root = 'changed'; supplied.carBase64 = b64('changed');
  assert.deepEqual(Buffer.from(await provider.fetch(request(raw(root))).arrayBuffer()), Buffer.from(deploymentData.blocks[root], 'base64'));
  assert.equal(provider.fetch(request('/health')).status, 200);
  assert.equal(provider.fetch(request('/ipni/v1/ad/head')).status, 404);
});

test('content deadline precedes conditionals and cache freshness never exceeds remaining term', async t => {
  const mocked = clock(t, deadline - 1_999);
  const provider = createProvider(deploymentData);
  const response = provider.fetch(request(raw(root)));
  assert.match(response.headers.get('cache-control'), /max-age=1, s-maxage=1/);
  assert.ok(!response.headers.get('cache-control').includes('stale-'));
  mocked.mock.mockImplementation(() => deadline - 1);
  assert.match(provider.fetch(request(raw(root))).headers.get('cache-control'), /max-age=0, s-maxage=0/);
  mocked.mock.mockImplementation(() => deadline);
  for (const path of [raw(root), carPath, '/ipfs/bafkqaaa']) {
    const expired = provider.fetch(request(path, { headers: { 'if-none-match': '*' } }));
    assert.equal(expired.status, 410);
    assert.equal(expired.headers.get('cache-control'), 'no-store');
  }
  const health = await provider.fetch(request('/health')).json();
  assert.equal(health.contentAvailable, false); assert.equal(health.nativeBitswap, false);
});

test('IPNI absent is 404; supplied active/removal wire bytes switch at deadline and history remains', async t => {
  const mocked = clock(t);
  const absent = createProvider({ ...deploymentData, providerId: null, ipni: null });
  assert.equal(absent.fetch(request('/ipni/v1/ad/head')).status, 404);
  assert.equal((await absent.fetch(request('/health')).json()).providerId, null);
  const addCid = blockCids[0]; const removalCid = blockCids[1];
  const ipni = { headBase64: b64('{"active":"signed exact fixture"}'),
    objects: { [addCid]: { bodyBase64: b64('signed add wire bytes'), contentType: 'application/vnd.ipld.dag-cbor' } },
    removalHeadBase64: b64('{"removal":"signed exact fixture"}'),
    removalObjects: { [removalCid]: { bodyBase64: b64('signed removal wire bytes'), contentType: 'application/vnd.ipld.dag-cbor' } } };
  const provider = createProvider({ ...deploymentData, ipni });
  const head = provider.fetch(request('/ipni/v1/ad/head'));
  assert.equal(head.headers.get('content-type'), 'application/vnd.ipld.dag-json');
  assert.equal(head.headers.get('cache-control'), 'no-store');
  assert.equal(await head.text(), '{"active":"signed exact fixture"}');
  assert.equal(await provider.fetch(request(`/ipni/v1/ad/${addCid}`)).text(), 'signed add wire bytes');
  assert.equal(provider.fetch(request(`/ipni/v1/ad/${removalCid}`)).status, 404);
  assert.equal(provider.fetch(request('/ipni/v1/ad/head?format=raw')).status, 400);
  mocked.mock.mockImplementation(() => deadline);
  assert.equal(await provider.fetch(request('/ipni/v1/ad/head')).text(), '{"removal":"signed exact fixture"}');
  assert.equal(await provider.fetch(request(`/ipni/v1/ad/${addCid}`)).text(), 'signed add wire bytes');
  assert.equal(await provider.fetch(request(`/ipni/v1/ad/${removalCid}`)).text(), 'signed removal wire bytes');
  const withoutRemoval = createProvider({ ...deploymentData, ipni: { ...ipni, removalHeadBase64: null, removalObjects: {} } });
  assert.equal(withoutRemoval.fetch(request('/ipni/v1/ad/head')).status, 404);
});

test('invalid deployment inputs fail construction rather than expose invented bytes or identity', () => {
  for (const patch of [
    { termEndUtc: '2026-02-30T00:00:00Z' }, { carBase64: 'Zh==' }, { blocks: {} },
    { providerId: 'invented identity' }, { carBase64: '' },
    { ipni: { headBase64: b64('head'), objects: { [root]: { bodyBase64: b64('ad'), contentType: 'text/plain\r\nsecret: x' } } } },
    { providerId: null, ipni: { headBase64: b64('head'), objects: {} } },
  ]) assert.throws(() => createProvider({ ...deploymentData, ...patch }));
});

test('original publisher filenames and directory JSON supply useful MIME, exact bytes, HEAD and CORS', async t => {
  clock(t);
  const provider = createProvider(deploymentData);
  const directory = dagPb.decode(Buffer.from(deploymentData.blocks[root], 'base64'));
  const response = provider.fetch(request(`/ipfs/${root}?format=json`));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('etag'), `"${root}.unixfs-directory-json"`);
  const listing = await response.json();
  assert.equal(listing.root, root); assert.equal(listing.cid, root); assert.equal(listing.type, 'directory');
  assert.deepEqual(listing.entries.map(entry => [entry.name, entry.cid, entry.size]),
    directory.Links.map(link => [link.Name, link.Hash.toString(), link.Tsize]));
  const expectedTypes = { csv: 'text/csv; charset=utf-8', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', yaml: 'application/yaml' };
  for (const link of directory.Links) {
    const path = `/ipfs/${root}/${link.Name}`;
    const get = provider.fetch(request(path, { headers: { accept: link.Name.endsWith('.csv') ? 'text/*' : '*/*' } }));
    const head = provider.fetch(request(path, { method: 'HEAD' }));
    assert.equal(get.status, 200); assert.equal(head.status, 200);
    const original = Buffer.from(deploymentData.blocks[link.Hash.toString()], 'base64');
    assert.deepEqual(Buffer.from(await get.arrayBuffer()), original);
    assert.equal(digest(original), Buffer.from(link.Hash.multihash.digest).toString('hex'));
    assert.equal(head.headers.get('content-length'), String(original.length));
    assert.equal(head.headers.get('content-type'), expectedTypes[link.Name.split('.').at(-1)]);
    assert.equal(head.headers.get('etag'), `"${link.Hash.toString()}"`);
    assert.equal(head.headers.get('access-control-allow-origin'), '*');
    assert.equal((await head.arrayBuffer()).byteLength, 0);
    assert.equal(provider.fetch(request(path, { headers: { 'if-none-match': head.headers.get('etag') } })).status, 304);
    assert.equal(provider.fetch(request(path + '?format=raw')).status, 400);
    assert.equal(provider.fetch(request(path + '?format=json')).status, 400);
  }
});

test('path-proof CAR queries expose only linked original blocks and scope-specific ETags', async t => {
  clock(t);
  const provider = createProvider(deploymentData);
  const link = dagPb.decode(Buffer.from(deploymentData.blocks[root], 'base64')).Links[0];
  const etags = [];
  for (const scope of ['block', 'entity']) {
    for (const filename of ['', '/' + link.Name]) {
      const path = `/ipfs/${root}${filename}?format=car&dag-scope=${scope}`;
      const response = provider.fetch(request(path, { headers: { accept: 'application/vnd.ipld.car' } }));
      assert.equal(response.status, 200);
      const expectedRoots = filename ? `${root},${link.Hash.toString()}` : root;
      assert.equal(response.headers.get('x-ipfs-roots'), expectedRoots);
      assert.match(response.headers.get('access-control-expose-headers'), /X-Ipfs-Roots/);
      etags.push(response.headers.get('etag'));
      const bytes = new Uint8Array(await response.arrayBuffer());
      assert.equal(response.headers.get('content-length'), String(bytes.length));
      const reader = await CarReader.fromBytes(bytes);
      const blocks = [];
      for await (const block of reader.blocks()) {
        assert.equal(digest(block.bytes), Buffer.from(block.cid.multihash.digest).toString('hex'));
        blocks.push(block);
      }
      assert.deepEqual(blocks.map(block => block.cid.toString()), filename ? [root, link.Hash.toString()] : [root]);
      if (filename) assert.equal(dagPb.decode(blocks[0].bytes).Links.find(item => item.Name === link.Name).Hash.toString(), blocks[1].cid.toString());
      const head = provider.fetch(request(path, { method: 'HEAD' }));
      assert.equal(head.headers.get('content-length'), String(bytes.length));
      assert.equal(head.headers.get('x-ipfs-roots'), expectedRoots);
      assert.equal((await head.arrayBuffer()).byteLength, 0);
      const conditional = provider.fetch(request(path, { headers: { 'if-none-match': response.headers.get('etag') } }));
      assert.equal(conditional.status, 304);
      assert.equal(conditional.headers.get('x-ipfs-roots'), expectedRoots);
    }
  }
  assert.equal(new Set(etags).size, 4);
  assert.ok(!etags.includes(provider.fetch(request(carPath)).headers.get('etag')));
});

test('expanded content routes preserve expiry and refuse ambiguous encoded paths and query overrides', t => {
  const mocked = clock(t);
  const provider = createProvider(deploymentData);
  const name = dagPb.decode(Buffer.from(deploymentData.blocks[root], 'base64')).Links[0].Name;
  for (const suffix of [`/%2e%2e/${name}`, `/${name}%2fchild`, `/${name}%252fchild`, `/${name}/`, `//${name}`]) {
    assert.ok([400, 404].includes(provider.fetch(request(`/ipfs/${root}${suffix}`)).status));
  }
  assert.equal(provider.fetch(request(`/ipfs/${root}/${name}?format=car&dag-scope=all`)).status, 400);
  assert.equal(provider.fetch(request(`/ipfs/${root}/${name}?format=car&dag-scope=block&entity-bytes=0:1`)).status, 400);
  mocked.mock.mockImplementation(() => deadline);
  for (const suffix of [`/${name}`, '?format=json', `/${name}?format=car&dag-scope=block`, '?format=car&dag-scope=entity']) {
    const response = provider.fetch(request(`/ipfs/${root}${suffix}`, { headers: { 'if-none-match': '*' } }));
    assert.equal(response.status, 410); assert.equal(response.headers.get('cache-control'), 'no-store');
  }
});

test('bounded graph counts permit another valid root and reject empty, absent-root, oversized and inconsistent maps', async t => {
  clock(t);
  const leafBytes = Buffer.from('a complete standalone raw publication');
  const leafCid = CID.createV1(0x55, await sha256.digest(leafBytes)).toString();
  const blocks = { [leafCid]: leafBytes.toString('base64') };
  const provider = createProvider({ ...deploymentData, root: leafCid, blocks, verification: { blocks: 1, reachableBlockCount: 1 } });
  assert.deepEqual(Buffer.from(await provider.fetch(request(raw(leafCid))).arrayBuffer()), leafBytes);
  const tooMany = {};
  for (let i = 0; i < 65; i++) {
    const bytes = Buffer.from(`block ${i}`); const cid = CID.createV1(0x55, await sha256.digest(bytes)).toString();
    tooMany[cid] = bytes.toString('base64');
  }
  for (const patch of [{ blocks: {} }, { blocks: tooMany, root: Object.keys(tooMany)[0], verification: undefined },
    { blocks, verification: undefined }, { blocks: deploymentData.blocks, verification: { blocks: 6 } },
    { blocks: deploymentData.blocks, verification: { reachableBlockCount: 0 } }]) {
    assert.throws(() => createProvider({ ...deploymentData, ...patch }));
  }
});

test('a valid SHA-256 zero-byte raw publication supports GET, HEAD and complete CAR', async t => {
  clock(t);
  const empty = new Uint8Array();
  const cid = CID.createV1(0x55, await sha256.digest(empty)).toString();
  const proof = createUnixfs(cid, new Map([[cid, empty]])).proof([], 'entity');
  const provider = createProvider({ ...deploymentData, root: cid, blocks: { [cid]: '' }, ipni: null,
    carBase64: Buffer.from(proof.bytes).toString('base64'), verification: { blocks: 1, reachableBlockCount: 1 } });
  for (const method of ['GET', 'HEAD']) {
    const response = provider.fetch(request(raw(cid), { method }));
    assert.equal(response.status, 200); assert.equal(response.headers.get('content-length'), '0');
    assert.equal(response.headers.get('etag'), `"${cid}"`);
    assert.equal((await response.arrayBuffer()).byteLength, 0);
  }
  const car = await CarReader.fromBytes(new Uint8Array(await provider.fetch(request(`/ipfs/${cid}?format=car&dag-scope=all`)).arrayBuffer()));
  const entries = [];
  for await (const block of car.blocks()) entries.push(block);
  assert.equal(entries.length, 1); assert.equal(entries[0].cid.toString(), cid); assert.equal(entries[0].bytes.length, 0);
  assert.equal(digest(entries[0].bytes), Buffer.from(CID.parse(cid).multihash.digest).toString('hex'));
});
