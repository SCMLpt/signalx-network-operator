import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { decode as decodeDagCbor, encode as encodeDagCbor } from '@ipld/dag-cbor';
import { generateKeyPair, publicKeyToProtobuf } from '@libp2p/crypto/keys';
import { peerIdFromPublicKey } from '@libp2p/peer-id';
import { createIPNSRecordWithExpiration, marshalIPNSRecord, multihashToIPNSRoutingKey } from 'ipns';
import { ipnsValidator } from 'ipns/validator';
import { base32 } from 'multiformats/bases/base32';
import { base36, base36upper } from 'multiformats/bases/base36';
import { base58btc } from 'multiformats/bases/base58';
import { CID } from 'multiformats/cid';
import { compareIpnsRecords, verifyIpnsRecord } from './ipns.mjs';

const { IpnsEntry } = await import(new URL('./pb/ipns.js', import.meta.resolve('ipns')));
const key = await generateKeyPair('Ed25519');
const wrongKey = await generateKeyPair('Ed25519');
const peer = peerIdFromPublicKey(key.publicKey);
const name = peer.toCID().toString(base36.encoder);
const PATH = '/ipfs/bafkqaddwgevxmmraojswg33smq';
const OTHER_PATH = '/ipfs/bafkqahtwgevxmmrao5uxi2bamjzg623fnyqhg2lhnzqxi5lsmuqhmmi';
const EXPIRY = '2099-01-01T00:00:00.000000000Z';
const UINT64_MAX = (1n << 64n) - 1n;
const utf8 = new TextEncoder();

async function fixture({ signingKey = key, path = PATH, sequence = 7n, expiry = EXPIRY,
  ttl = 300_000_000_000n, v1Compatible = true } = {}) {
  const record = await createIPNSRecordWithExpiration(signingKey, path, sequence, expiry, {
    v1Compatible, ttlNs: ttl
  });
  return marshalIPNSRecord(record);
}

// Adversarial data is still signed using the official key API. This separates
// semantic validation failures from the much easier invalid-signature case.
async function signedFixture(changes, { extra = {}, rawData } = {}) {
  const original = IpnsEntry.decode(await fixture({ v1Compatible: false }));
  const data = rawData ?? encodeDagCbor({ ...decodeDagCbor(original.data), ...changes });
  const signatureV2 = await key.sign(Buffer.concat([Buffer.from('ipns-signature:'), Buffer.from(data)]));
  return IpnsEntry.encode({ ...original, ...extra, data, signatureV2 });
}

function verify(bytes, options = {}) {
  return verifyIpnsRecord({ name, bytes, ...options });
}

test('valid generated V1+V2 record yields plain JSON with a digest and exact decimal values', async () => {
  const bytes = await fixture();
  const result = await verify(bytes);
  assert.deepEqual(result, {
    name, path: PATH, sequence: '7', validUntil: EXPIRY,
    ttlNanoseconds: '300000000000', recordSha256: createHash('sha256').update(bytes).digest('hex'),
    verified: true, latestGloballyKnown: false
  });
  assert.deepEqual(JSON.parse(JSON.stringify(result)), result);
});

test('official Peer ID, base32/base36/base58 CID and /ipns/ forms identify the same key', async () => {
  const bytes = await fixture();
  for (const form of [peer.toString(), peer.toCID().toString(base32.encoder), name,
    peer.toCID().toString(base36upper.encoder), peer.toCID().toString(base58btc.encoder), `/ipns/${name}`]) {
    assert.equal((await verify(bytes, { name: form })).name, name, form);
  }
});

test('V2-only records are accepted, and unsigned V1 signature contents are not used for verification', async () => {
  assert.equal((await verify(await fixture({ v1Compatible: false }))).verified, true);
  const entry = IpnsEntry.decode(await fixture());
  entry.signatureV1 = new Uint8Array([1, 2, 3]);
  assert.equal((await verify(IpnsEntry.encode(entry))).verified, true);
});

test('legacy RSA names bind the required embedded public key', async () => {
  const rsaKey = await generateKeyPair('RSA', 2048);
  const rsaPeer = peerIdFromPublicKey(rsaKey.publicKey);
  const bytes = await fixture({ signingKey: rsaKey });
  assert.equal((await verify(bytes, { name: rsaPeer.toString() })).verified, true);
  const entry = IpnsEntry.decode(bytes);
  delete entry.pubKey;
  await assert.rejects(verify(IpnsEntry.encode(entry), { name: rsaPeer.toString() }), /public key/i);
});

test('forged V2 signatures and records under a different name are rejected', async () => {
  const entry = IpnsEntry.decode(await fixture());
  entry.signatureV2[0] ^= 1;
  await assert.rejects(verify(IpnsEntry.encode(entry)), /signature/i);
  await assert.rejects(verify(await fixture({ signingKey: wrongKey })), /signature|public key/i);
  const wrongEmbedded = IpnsEntry.decode(await fixture());
  wrongEmbedded.pubKey = publicKeyToProtobuf(wrongKey.publicKey);
  await assert.rejects(verify(IpnsEntry.encode(wrongEmbedded)), /public key.*routing key/i);
});

test('expired records cannot be authorized using a historical nowMs', async () => {
  const expired = await fixture({ expiry: '2001-01-01T00:00:00.000000000Z' });
  await assert.rejects(verify(expired), /expired/i);
  await assert.rejects(verify(expired, { nowMs: 0 }), /expired/i);
});

test('expiry uses exact nanoseconds and rejects equality at the policy clock', async () => {
  const boundaryMs = Date.parse('2099-01-01T00:00:00.000Z');
  const equal = await fixture();
  await assert.rejects(verify(equal, { nowMs: boundaryMs }), /expired/i);
  assert.equal((await verify(await fixture({ expiry: '2099-01-01T00:00:00.000000001Z' }),
    { nowMs: boundaryMs })).verified, true);
  await assert.rejects(verify(await fixture({ expiry: '2098-12-31T23:59:59.999999999Z' }),
    { nowMs: boundaryMs }), /expired/i);
});

test('timezone offsets and fractional precision preserve the exact signed Validity', async () => {
  const expiry = '2099-01-01T09:00:00.000000001+09:00';
  const bytes = await signedFixture({ Validity: utf8.encode(expiry) });
  const result = await verify(bytes, { nowMs: Date.parse('2099-01-01T00:00:00Z') });
  assert.equal(result.validUntil, expiry);
});

test('malformed calendar, timezone and non-RFC3339 timestamps cannot normalize into valid dates', async () => {
  for (const expiry of ['2099-02-30T00:00:00Z', '2099-13-01T00:00:00Z',
    '2099-01-01T24:00:00Z', '2099-01-01T00:00:00+24:00', '2099-01-01',
    '2099-01-01T00:00:00.0000000001Z', '2099-01-01T00:00:00Z junk']) {
    await assert.rejects(verify(await signedFixture({ Validity: utf8.encode(expiry) })), /Validity/i, expiry);
  }
});

test('sequence and TTL accept uint64 maxima without floating point loss', async () => {
  const result = await verify(await fixture({ sequence: UINT64_MAX, ttl: UINT64_MAX }));
  assert.equal(result.sequence, '18446744073709551615');
  assert.equal(result.ttlNanoseconds, '18446744073709551615');
});

test('negative, fractional, mistyped and overflowing integer fields are rejected', async () => {
  for (const value of [-1n, 1.5, Number.MAX_SAFE_INTEGER + 1, 18_446_744_073_709_551_616, '7', null, true]) {
    await assert.rejects(verify(await signedFixture({ Sequence: value })), /Sequence/i);
    await assert.rejects(verify(await signedFixture({ TTL: value })), /TTL/i);
  }
  // The official record encoder cannot represent values beyond uint64.
  await assert.rejects(fixture({ sequence: UINT64_MAX + 1n }), /64|range|BigInt|encode/i);
  await assert.rejects(fixture({ ttl: UINT64_MAX + 1n }), /64|range|BigInt|encode/i);
});

test('rollback and same-sequence changed Value are rejected; same Value can renew', async () => {
  const prior = await verify(await fixture({ sequence: 9n }));
  await assert.rejects(verify(await fixture({ sequence: 8n }), { prior }), /rollback/i);
  await assert.rejects(verify(await fixture({ sequence: 9n, path: OTHER_PATH }), { prior }), /conflicting Value/i);
  const renewal = await verify(await fixture({ sequence: 9n, expiry: '2099-01-02T00:00:00Z', ttl: 42n }), { prior });
  assert.equal(renewal.sequence, '9');
  assert.equal(renewal.ttlNanoseconds, '42');
  assert.notEqual(renewal.recordSha256, prior.recordSha256);
  assert.equal((await verify(await fixture({ sequence: 10n, path: OTHER_PATH }), { prior })).path, OTHER_PATH);
});

test('same-sequence same-Value EOL cannot roll back, including submillisecond differences', async () => {
  const prior = await verify(await fixture({ expiry: '2099-01-02T00:00:00.000000002Z' }));
  for (const expiry of ['2099-01-01T00:00:00.000000002Z', '2099-01-02T00:00:00.000000001Z']) {
    await assert.rejects(verify(await fixture({ expiry }), { prior }), /EOL rollback/i);
  }
  assert.equal((await verify(await fixture({ expiry: prior.validUntil, ttl: 1n }), { prior })).verified, true);
  assert.equal((await verify(await fixture({ expiry: '2099-01-02T00:00:00.000000003Z' }), { prior })).verified, true);
  // Selection gives sequence priority; a higher sequence may shorten EOL.
  assert.equal((await verify(await fixture({ sequence: 8n, expiry: '2099-01-01T00:00:00Z' }), { prior })).verified, true);
});

test('comparison orders sequence then exact nanosecond EOL, returning only -1/0/1', async () => {
  const early = await verify(await fixture({ sequence: 7n, expiry: '2099-01-01T00:00:00.000000001Z' }));
  const late = await verify(await fixture({ sequence: 7n, expiry: '2099-01-01T00:00:00.000000002Z' }));
  const nextSequence = await verify(await fixture({ sequence: 8n, expiry: '2098-01-01T00:00:00Z' }));
  assert.equal(compareIpnsRecords(early, late), -1);
  assert.equal(compareIpnsRecords(late, early), 1);
  assert.equal(compareIpnsRecords(early, early), 0);
  assert.equal(compareIpnsRecords(late, nextSequence), -1);
  assert.equal(compareIpnsRecords(nextSequence, late), 1);
  const sameInstantWithOffset = await verify(await signedFixture({
    Validity: utf8.encode('2099-01-01T09:00:00.000000001+09:00')
  }));
  assert.equal(compareIpnsRecords(early, sameInstantWithOffset), 0);
  assert.equal(compareIpnsRecords(early, { ...early, name: peer.toString() }), 0);
  const maximum = await verify(await fixture({ sequence: UINT64_MAX }));
  assert.equal(compareIpnsRecords(maximum, nextSequence), 1);
});

test('comparison rejects unverified, malformed or cross-name history', async () => {
  const result = await verify(await fixture());
  for (const invalid of [null, {}, { ...result, verified: false }, { ...result, sequence: '07' },
    { ...result, sequence: '18446744073709551616' }, { ...result, validUntil: undefined },
    { ...result, validUntil: '2099-02-30T00:00:00Z' },
    { ...result, name: peerIdFromPublicKey(wrongKey.publicKey).toString() }]) {
    assert.throws(() => compareIpnsRecords(result, invalid));
    assert.throws(() => compareIpnsRecords(invalid, result));
  }
});

test('prior must refer to the same name and carry a verified decimal uint64 sequence and content path', async () => {
  const bytes = await fixture();
  const prior = await verify(bytes);
  for (const invalid of [[], {}, { ...prior, verified: false },
    { ...prior, name: peerIdFromPublicKey(wrongKey.publicKey).toString() },
    { ...prior, sequence: '07' }, { ...prior, sequence: '18446744073709551616' },
    { ...prior, sequence: 7 }, { ...prior, path: '/untrusted' },
    { ...prior, validUntil: undefined }, { ...prior, validUntil: '2099-02-30T00:00:00Z' }]) {
    await assert.rejects(verify(bytes, { prior: invalid }));
  }
  assert.equal((await verify(bytes, { prior: { ...prior, name: peer.toString() } })).verified, true);
});

test('all legacy copies must agree with V2, including partial V1 fields without signatureV1', async () => {
  const valid = IpnsEntry.decode(await fixture());
  for (const changes of [{ value: utf8.encode(OTHER_PATH) }, { validity: utf8.encode('2099-01-02T00:00:00Z') },
    { sequence: 99n }, { ttl: 0n }]) {
    await assert.rejects(verify(IpnsEntry.encode({ ...valid, ...changes })), /legacy fields/i);
  }
  const v2only = IpnsEntry.decode(await fixture({ v1Compatible: false }));
  const incomplete = IpnsEntry.encode({ ...v2only, value: utf8.encode(OTHER_PATH) });
  // Explicitly capture the upstream AND-condition gap; our wrapper closes it.
  await ipnsValidator(multihashToIPNSRoutingKey(peer.toMultihash()), incomplete);
  await assert.rejects(verify(incomplete), /legacy fields/i);
  await assert.rejects(verify(IpnsEntry.encode({ ...v2only, signatureV1: new Uint8Array([1]) })), /legacy fields/i);
});

test('V1-only, missing/empty V2 fields, malformed protobuf and malformed DAG-CBOR are rejected', async () => {
  const valid = IpnsEntry.decode(await fixture());
  for (const field of ['data', 'signatureV2']) {
    const missing = { ...valid };
    delete missing[field];
    await assert.rejects(verify(IpnsEntry.encode(missing)), /Data|SignatureV2/i);
    await assert.rejects(verify(IpnsEntry.encode({ ...valid, [field]: new Uint8Array() })), /Data|SignatureV2/i);
  }
  for (const bytes of [new Uint8Array([0xff]), new Uint8Array([0x4a, 0x80]),
    IpnsEntry.encode({ ...valid, data: new Uint8Array([0xff]) })]) {
    await assert.rejects(verify(bytes));
  }
});

test('required signed fields have strict types and invalid UTF-8 is rejected', async () => {
  for (const changes of [{ Value: 'not bytes' }, { Validity: 'not bytes' },
    { ValidityType: 1 }, { Value: new Uint8Array([0xff]) }, { Value: utf8.encode(` ${PATH} `) }]) {
    await assert.rejects(verify(await signedFixture(changes)));
  }
  const entry = IpnsEntry.decode(await fixture({ v1Compatible: false }));
  const missing = decodeDagCbor(entry.data);
  delete missing.Sequence;
  await assert.rejects(verify(await signedFixture({}, { rawData: encodeDagCbor(missing) })), /Sequence/i);
});

test('generic content paths permit nested IPFS, peer IPNS and DNSLink targets without resolving them', async () => {
  for (const path of [`${PATH}/directory/file.txt`, `/ipns/${name}/file`, '/ipns/docs.ipfs.tech/index.html']) {
    assert.equal((await verify(await fixture({ path }))).path, path);
  }
  for (const path of ['/ipfs/not-a-cid', '/ipfs/', '/ipns/bad-name', '/ipns/-bad.example',
    '/https/example.org', `${PATH}/../other`, `${PATH}\u0000suffix`, `${PATH}/white space`]) {
    await assert.rejects(verify(await fixture({ path })), undefined, path);
  }
});

test('wrong CID codecs, URLs, DNS names and name subpaths cannot masquerade as self-certifying names', async () => {
  const bytes = await fixture();
  for (const invalid of [CID.parse(PATH.slice(6)).toString(), '', ` ${name}`, `${name}/file`,
    `/ipns/${name}/file`, 'https://example.org', 'example.org', 'k'.repeat(513)]) {
    await assert.rejects(verify(bytes, { name: invalid }));
  }
});

test('caller byte mutations during verification cannot change the record being verified and hashed', async () => {
  const bytes = await fixture();
  const expectedDigest = createHash('sha256').update(bytes).digest('hex');
  const pending = verify(bytes);
  bytes.fill(0);
  assert.equal((await pending).recordSha256, expectedDigest);
});

test('unknown well-formed protobuf/CBOR extensions are allowed; malformed trailing binary is rejected', async () => {
  const bytes = await fixture();
  // Protobuf field 15, length-delimited: future readers must ignore unknown fields.
  const extended = Buffer.concat([bytes, new Uint8Array([0x7a, 0x03, 0x61, 0x62, 0x63])]);
  assert.equal((await verify(extended)).verified, true);
  assert.notEqual((await verify(extended)).recordSha256, (await verify(bytes)).recordSha256);
  for (const trailing of [new Uint8Array([0xff]), new Uint8Array([0x7a, 0x05, 0x01])]) {
    await assert.rejects(verify(Buffer.concat([bytes, trailing])));
  }
  assert.equal((await verify(await signedFixture({ _test: { meaning: 'extension' } }))).verified, true);
  const data = IpnsEntry.decode(await fixture({ v1Compatible: false })).data;
  await assert.rejects(verify(await signedFixture({}, { rawData: Buffer.concat([data, new Uint8Array([0])]) })));
});

test('record bounds and policy-clock types are enforced before parsing', async () => {
  for (const bytes of [null, [], new Uint8Array(), new Uint8Array(10 * 1024 + 1)]) {
    await assert.rejects(verify(bytes), /1 to 10240 bytes/i);
  }
  const bytes = await fixture();
  const payloadLength = 10 * 1024 - bytes.byteLength - 3;
  assert.ok(payloadLength > 127 && payloadLength < 16384);
  const exactlyAtLimit = Buffer.concat([bytes,
    new Uint8Array([0x7a, (payloadLength & 0x7f) | 0x80, payloadLength >>> 7]),
    new Uint8Array(payloadLength)]);
  assert.equal(exactlyAtLimit.byteLength, 10240);
  assert.equal((await verify(exactlyAtLimit)).verified, true);
  for (const nowMs of [NaN, Infinity, -1, 1.5, '42', Number.MAX_SAFE_INTEGER]) {
    await assert.rejects(verify(bytes, { nowMs }), /nowMs/i);
  }
});
