import { createHash } from 'node:crypto';
import { decode as decodeDagCbor } from '@ipld/dag-cbor';
import { peerIdFromCID, peerIdFromString } from '@libp2p/peer-id';
import { multihashToIPNSRoutingKey, unmarshalIPNSRecord } from 'ipns';
import { ipnsValidator } from 'ipns/validator';
import { base32, base32upper } from 'multiformats/bases/base32';
import { base36, base36upper } from 'multiformats/bases/base36';
import { base58btc } from 'multiformats/bases/base58';
import { CID } from 'multiformats/cid';
import NanoDate from 'timestamp-nano';

// ipns@11.0.1's public unmarshal checks legacy consistency only when BOTH
// value and signatureV1 exist. The specification requires EITHER. Use that
// pinned dependency's generated protobuf codec to inspect presence, without
// introducing a second protobuf implementation.
const { IpnsEntry } = await import(new URL('./pb/ipns.js', import.meta.resolve('ipns')));
const CID_DECODER = base32.decoder.or(base32upper.decoder)
  .or(base36.decoder).or(base36upper.decoder).or(base58btc.decoder);
const UINT64_MAX = (1n << 64n) - 1n;
const MAX_RECORD_BYTES = 10 * 1024;
const utf8 = new TextDecoder('utf-8', { fatal: true });

function parseName(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 512 || input.trim() !== input) {
    throw new TypeError('IPNS name must be a Peer ID or libp2p-key CID');
  }
  const bare = input.startsWith('/ipns/') ? input.slice(6) : input;
  if (bare.length === 0 || bare.includes('/')) throw new TypeError('IPNS name must not contain a subpath');
  const peer = /^[1Q]/.test(bare)
    ? peerIdFromString(bare)
    : peerIdFromCID(CID.parse(bare, CID_DECODER));
  if (peer.type === 'url' || peer.toCID().code !== 0x72) {
    throw new TypeError('IPNS name must use the libp2p-key codec');
  }
  return { peer, canonical: peer.toCID().toString(base36.encoder) };
}

function uint64(value, field) {
  if (typeof value === 'number' && Number.isSafeInteger(value)) value = BigInt(value);
  if (typeof value !== 'bigint' || value < 0n || value > UINT64_MAX) {
    throw new TypeError(`${field} must be an unsigned 64-bit integer`);
  }
  return value;
}

function contentPath(value) {
  if (typeof value !== 'string' || value.trim() !== value || /[\u0000-\u0020\u007f]/u.test(value)) {
    throw new TypeError('IPNS Value must be an unambiguous content path');
  }
  const match = /^\/(ipfs|ipns)\/([^/]+)(\/.*)?$/u.exec(value);
  if (match == null) throw new TypeError('IPNS Value must use an /ipfs/ or /ipns/ content path');
  if (match[1] === 'ipfs') {
    const cid = CID.parse(match[2], CID_DECODER);
    if (cid.code === 0x72) throw new TypeError('IPFS Value cannot use a libp2p-key CID');
  } else {
    try {
      parseName(match[2]);
    } catch {
      // DNSLink names are valid IPNS targets; this function does not resolve them.
      const labels = match[2].split('.');
      if (match[2].length > 253 || labels.length < 2 || labels.some(label =>
        !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu.test(label))) {
        throw new TypeError('IPNS Value has an invalid peer name or DNSLink name');
      }
    }
  }
  if (match[3]?.split('/').some(segment => segment === '.' || segment === '..')) {
    throw new TypeError('IPNS Value must not contain dot path segments');
  }
  return value;
}

function expiryNanoseconds(value) {
  // timestamp-nano normalizes impossible calendar dates and loose syntax.
  // Check the RFC3339 calendar first, then use its nanosecond time conversion.
  const match = typeof value === 'string' && /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?([Zz]|[+-]\d{2}:\d{2})$/u.exec(value);
  if (!match) throw new TypeError('IPNS Validity must be an RFC3339 timestamp with at most nine fractional digits');
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
    throw new TypeError('IPNS Validity has an invalid calendar date');
  }
  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  calendar.setUTCHours(hour, minute, second, 0);
  if (calendar.getUTCFullYear() !== year || calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day) {
    throw new TypeError('IPNS Validity has an invalid calendar date');
  }
  const zone = match[8];
  if (zone.length > 1 && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4, 6)) > 59)) {
    throw new TypeError('IPNS Validity has an invalid timezone');
  }
  const timestamp = NanoDate.fromString(value.replace('t', 'T').replace(/z$/u, 'Z'));
  const seconds = timestamp.getTimeT();
  const nanos = timestamp.getNano();
  if (!Number.isSafeInteger(seconds) || !Number.isInteger(nanos) || nanos < 0 || nanos >= 1e9) {
    throw new TypeError('IPNS Validity cannot be represented precisely');
  }
  return BigInt(seconds) * 1_000_000_000n + BigInt(nanos);
}

function equalBytes(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && Buffer.from(a).equals(Buffer.from(b));
}

function verifiedResultFields(result) {
  if (result == null || typeof result !== 'object' || Array.isArray(result) || result.verified !== true ||
      typeof result.sequence !== 'string' || !/^(0|[1-9]\d{0,19})$/u.test(result.sequence)) {
    throw new TypeError('IPNS history must be a verified result with a decimal uint64 sequence');
  }
  return {
    canonical: parseName(result.name).canonical,
    sequence: uint64(BigInt(result.sequence), 'history sequence'),
    path: contentPath(result.path),
    expiry: expiryNanoseconds(result.validUntil)
  };
}

/** Compare verified results for the same name, by sequence then exact EOL. */
export function compareIpnsRecords(left, right) {
  const a = verifiedResultFields(left);
  const b = verifiedResultFields(right);
  if (a.canonical !== b.canonical) throw new TypeError('Cannot compare different IPNS names');
  if (a.sequence !== b.sequence) return a.sequence < b.sequence ? -1 : 1;
  return a.expiry === b.expiry ? 0 : a.expiry < b.expiry ? -1 : 1;
}

function validatePrior(prior, canonical, sequence, path, expiry) {
  if (prior == null) return;
  const history = verifiedResultFields(prior);
  if (history.canonical !== canonical) throw new TypeError('prior must be a verified result for the same IPNS name');
  if (sequence < history.sequence) throw new Error('IPNS sequence rollback detected');
  if (sequence === history.sequence && path !== history.path) {
    throw new Error('IPNS conflicting Value at the same sequence');
  }
  if (sequence === history.sequence && expiry < history.expiry) {
    throw new Error('IPNS EOL rollback detected at the same sequence');
  }
}

/**
 * Verify one received IPNS record. No network, key generation, or publication.
 * `prior` is a trusted, persisted result previously returned for this name.
 * The official validator also checks the real system clock. `nowMs` is an
 * additional policy clock, not permission to accept historically expired data.
 * A local high-water sequence cannot prove that unseen newer records do not exist.
 */
export async function verifyIpnsRecord({ name, bytes, nowMs = Date.now(), prior = null }) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > MAX_RECORD_BYTES) {
    throw new TypeError('IPNS record must contain 1 to 10240 bytes');
  }
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > 8_640_000_000_000_000) {
    throw new TypeError('nowMs must be a nonnegative safe integer timestamp');
  }
  // Copy before awaiting cryptography so caller mutations cannot change the
  // object subsequently parsed, hashed, or returned as verified.
  const received = Uint8Array.from(bytes);
  const { peer, canonical } = parseName(name);
  const entry = IpnsEntry.decode(received);
  if (!(entry.data instanceof Uint8Array) || entry.data.byteLength === 0 ||
      !(entry.signatureV2 instanceof Uint8Array) || entry.signatureV2.byteLength === 0) {
    throw new TypeError('IPNS record requires nonempty Data and SignatureV2');
  }
  const signed = decodeDagCbor(entry.data);
  if (signed == null || typeof signed !== 'object' || Array.isArray(signed) ||
      !(signed.Value instanceof Uint8Array) || !(signed.Validity instanceof Uint8Array) || signed.ValidityType !== 0) {
    throw new TypeError('IPNS signed data requires Value, Validity and EOL ValidityType');
  }
  const sequence = uint64(signed.Sequence, 'IPNS Sequence');
  const ttl = uint64(signed.TTL, 'IPNS TTL');
  const path = contentPath(utf8.decode(signed.Value));
  const validUntil = utf8.decode(signed.Validity);
  const expiry = expiryNanoseconds(validUntil);
  if (entry.value != null || entry.signatureV1 != null) {
    if (!equalBytes(entry.value, signed.Value) || !equalBytes(entry.validity, signed.Validity) ||
        entry.validityType !== 'EOL' || entry.sequence !== sequence || entry.ttl !== ttl) {
      throw new Error('IPNS legacy fields did not match signed V2 data');
    }
  }
  await ipnsValidator(multihashToIPNSRoutingKey(peer.toMultihash()), received);
  const record = unmarshalIPNSRecord(received);
  if (record.value !== path || record.sequence !== sequence || record.ttl !== ttl || record.validity !== validUntil) {
    throw new Error('IPNS normalized fields did not match signed data');
  }
  if (expiry <= BigInt(nowMs) * 1_000_000n) throw new Error('IPNS record has expired at nowMs');
  validatePrior(prior, canonical, sequence, path, expiry);
  return {
    name: canonical,
    path,
    sequence: sequence.toString(),
    validUntil,
    ttlNanoseconds: ttl.toString(),
    recordSha256: createHash('sha256').update(received).digest('hex'),
    verified: true,
    latestGloballyKnown: false
  };
}
