import { createHash } from 'node:crypto';
import { CarReader } from '@ipld/car';
import * as dagPB from '@ipld/dag-pb';
import * as dagCBOR from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';

const CODECS = new Map([[0x55, 'raw'], [dagPB.code, 'dag-pb'], [dagCBOR.code, 'dag-cbor']]);
const IDENTITY_CODE = 0x00;
// Identity CIDs carry their contents inline; keep this support explicitly small.
const MAX_IDENTITY_BYTES = 512;
const MAX_HEADER_BYTES = 4096;
const MAX_CBOR_DEPTH = 128;

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function sameBytes(left, right) {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

function limit(value, name, minimum = 1) {
  if (!Number.isSafeInteger(value) || value < minimum) fail('CAR_LIMIT', `${name} must be a safe integer >= ${minimum}`);
}

function supportedCid(cid) {
  if (!CODECS.has(cid.code)) fail('CAR_CODEC', `Unsupported CAR codec: ${cid.code}`);
  const hash = cid.multihash;
  if (hash.code === sha256.code) {
    if (hash.digest.byteLength !== 32) fail('CAR_HASH', 'SHA-256 CID digest must be 32 bytes');
  } else if (hash.code === IDENTITY_CODE) {
    if (hash.digest.byteLength > MAX_IDENTITY_BYTES) fail('CAR_HASH', `Identity CID exceeds ${MAX_IDENTITY_BYTES} bytes`);
  } else {
    fail('CAR_HASH', `Unsupported CAR multihash: ${hash.code}`);
  }
  return cid;
}

function parseRoot(value) {
  try {
    const cid = CID.asCID(value) ?? (typeof value === 'string' ? CID.parse(value) : null);
    if (!cid) fail('CAR_ROOT', 'Expected root must be a CID');
    return supportedCid(cid);
  } catch (error) {
    if (error.code) throw error;
    fail('CAR_ROOT', `Invalid expected root CID: ${error.message}`);
  }
}

function unsignedVarint(bytes, start, label) {
  let value = 0n;
  for (let index = 0; index < 8; index++) {
    const at = start + index;
    if (at >= bytes.byteLength) fail('CAR_FRAMING', `Truncated ${label} varint`);
    const byte = bytes[at];
    value |= BigInt(byte & 0x7f) << BigInt(index * 7);
    if (!(byte & 0x80)) {
      if ((index > 0 && byte === 0) || value > BigInt(Number.MAX_SAFE_INTEGER)) {
        fail('CAR_FRAMING', `Noncanonical or oversized ${label} varint`);
      }
      return { value: Number(value), next: at + 1 };
    }
  }
  fail('CAR_FRAMING', `Oversized ${label} varint`);
}

// Bound the work before the official reader collects blocks into memory. Each
// section must end inside this exact archive; padding is not silently ignored.
function inspectFraming(bytes, expectedRoot, maxBlocks) {
  const headerLength = unsignedVarint(bytes, 0, 'header');
  if (headerLength.value < 1 || headerLength.value > MAX_HEADER_BYTES ||
      headerLength.value > bytes.byteLength - headerLength.next) {
    fail('CAR_HEADER', 'Invalid or oversized CAR header length');
  }
  const headerEnd = headerLength.next + headerLength.value;
  let header;
  try { header = dagCBOR.decode(bytes.subarray(headerLength.next, headerEnd)); }
  catch (error) { fail('CAR_HEADER', `Invalid CAR header: ${error.message}`); }
  if (!header || typeof header !== 'object' || Array.isArray(header) ||
      header.version !== 1 || Object.keys(header).length !== 2 ||
      !Object.hasOwn(header, 'roots') || !Object.hasOwn(header, 'version') ||
      !Array.isArray(header.roots) || header.roots.length !== 1) {
    fail('CAR_HEADER', 'CARv1 must have exactly one root and a valid roots/version header');
  }
  const root = CID.asCID(header.roots[0]);
  if (!root) fail('CAR_HEADER', 'CAR root must be a CID');
  supportedCid(root);
  if (!sameBytes(root.bytes, expectedRoot.bytes)) fail('CAR_ROOT', 'CAR header root differs from expected root');

  let position = headerEnd;
  let blockCount = 0;
  while (position < bytes.byteLength) {
    if (++blockCount > maxBlocks) fail('CAR_LIMIT', 'CAR block count exceeds maxBlocks');
    const section = unsignedVarint(bytes, position, 'section');
    if (section.value < 1 || section.value > bytes.byteLength - section.next) {
      fail('CAR_FRAMING', 'Invalid CAR section length or trailing bytes');
    }
    const sectionEnd = section.next + section.value;
    try {
      const [cid] = CID.decodeFirst(bytes.subarray(section.next, sectionEnd));
      supportedCid(cid);
    } catch (error) {
      if (error.code) throw error;
      fail('CAR_FRAMING', `Invalid block CID or trailing bytes: ${error.message}`);
    }
    position = sectionEnd;
  }
  return { root, blockCount };
}

function blockKey(cid) { return cid.toV1().toString(); }

function blockLinks(cid, bytes) {
  if (cid.code === 0x55) return [];
  try {
    if (cid.code === dagPB.code) return dagPB.decode(bytes).Links.map(link => supportedCid(link.Hash));
    const links = [];
    const pending = [{ value: dagCBOR.decode(bytes), depth: 0 }];
    while (pending.length) {
      const { value, depth } = pending.pop();
      if (depth > MAX_CBOR_DEPTH) fail('CAR_LIMIT', `DAG-CBOR nesting exceeds ${MAX_CBOR_DEPTH}`);
      if (value === null || typeof value !== 'object' || value instanceof Uint8Array) continue;
      const link = CID.asCID(value);
      if (link) { links.push(supportedCid(link)); continue; }
      const children = Array.isArray(value) ? value : Object.values(value);
      for (const child of children) pending.push({ value: child, depth: depth + 1 });
    }
    return links;
  } catch (error) {
    if (error.code) throw error;
    fail('CAR_BLOCK', `Invalid ${CODECS.get(cid.code)} block: ${error.message}`);
  }
}

function reachableGraph(blocks, root) {
  const rootKey = blockKey(root);
  if (!blocks.has(rootKey)) fail('CAR_MISSING_ROOT', 'Expected root block is missing');
  const colors = new Map([[rootKey, 1]]);
  const stack = [{ key: rootKey, next: 0 }];
  let reachableBlockCount = 0;
  while (stack.length) {
    const frame = stack.at(-1);
    const links = blocks.get(frame.key).links;
    if (frame.next === links.length) {
      colors.set(frame.key, 2);
      reachableBlockCount++;
      stack.pop();
      continue;
    }
    const child = blockKey(links[frame.next++]);
    if (!blocks.has(child)) fail('CAR_MISSING_LINK', `Reachable child block is missing: ${child}`);
    if (colors.get(child) === 1) fail('CAR_CYCLE', 'CAR reachable graph contains a cycle');
    if (colors.get(child) === 2) continue;
    colors.set(child, 1);
    stack.push({ key: child, next: 0 });
  }
  if (reachableBlockCount !== blocks.size) fail('CAR_UNREACHABLE', 'CAR contains an unreachable block');
  return reachableBlockCount;
}

/**
 * Verify an exact CARv1 and its complete raw/DAG-PB/DAG-CBOR reachable graph.
 * This establishes content integrity, not UnixFS paths or assembled file bytes.
 * Identical duplicate sections are accepted and counted in blockCount; distinct
 * reachable CIDs are counted in reachableBlockCount. Conflicting duplicates fail.
 */
export async function verifyCar(bytes, expectedRoot, {
  maxBlocks = 4096, maxBytes = 8388608, maxLinks = 16384,
} = {}) {
  limit(maxBlocks, 'maxBlocks');
  limit(maxBytes, 'maxBytes');
  limit(maxLinks, 'maxLinks', 0);
  if (!(bytes instanceof Uint8Array)) fail('CAR_BYTES', 'CAR bytes must be a Uint8Array');
  if (!bytes.byteLength || bytes.byteLength > maxBytes) fail('CAR_LIMIT', 'CAR byte length exceeds maxBytes or is empty');
  // A caller cannot mutate the buffer during asynchronous digest checks.
  const archive = Uint8Array.from(bytes);
  const expected = parseRoot(expectedRoot);
  const framing = inspectFraming(archive, expected, maxBlocks);
  let reader;
  try { reader = await CarReader.fromBytes(archive); }
  catch (error) { fail('CAR_FRAMING', `Invalid CAR: ${error.message}`); }
  if (reader.version !== 1) fail('CAR_HEADER', 'Only CARv1 is supported');
  const roots = await reader.getRoots();
  if (roots.length !== 1 || !sameBytes(roots[0].bytes, expected.bytes)) fail('CAR_ROOT', 'CAR reader root differs from expected root');

  const blocks = new Map();
  const codecs = new Set();
  let blockCount = 0;
  let linkCount = 0;
  for await (const block of reader.blocks()) {
    if (++blockCount > maxBlocks) fail('CAR_LIMIT', 'CAR block count exceeds maxBlocks');
    const cid = supportedCid(block.cid);
    const key = blockKey(cid);
    const previous = blocks.get(key);
    if (previous && !sameBytes(previous.bytes, block.bytes)) fail('CAR_DUPLICATE', 'Duplicate CID has conflicting block bytes');
    const digest = cid.multihash.code === IDENTITY_CODE ? block.bytes : (await sha256.digest(block.bytes)).digest;
    if (!sameBytes(digest, cid.multihash.digest)) fail('CAR_HASH_MISMATCH', `CAR block does not match its CID: ${cid}`);
    codecs.add(CODECS.get(cid.code));
    if (previous) continue;
    const links = blockLinks(cid, block.bytes);
    linkCount += links.length;
    if (linkCount > maxLinks) fail('CAR_LIMIT', 'CAR link count exceeds maxLinks');
    blocks.set(key, { bytes: block.bytes, links });
  }
  if (blockCount !== framing.blockCount) fail('CAR_FRAMING', 'CAR block framing count differs from decoded count');
  const reachableBlockCount = reachableGraph(blocks, framing.root);
  return {
    root: framing.root.toString(), blockCount, byteLength: archive.byteLength,
    reachableBlockCount, complete: true, codecs: [...codecs].sort(),
    sha256: createHash('sha256').update(archive).digest('hex'),
  };
}
