import * as dagPb from '@ipld/dag-pb';
import { CID } from 'multiformats/cid';
import * as dagCbor from '@ipld/dag-cbor';

const MAX_BYTES = 1_048_576;
const MAX_NODES = 128;
const MAX_DEPTH = 16;

export class UnixfsError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
function fail(message, status = 503) { throw new UnixfsError(status, message); }

export function validPathName(name) {
  return typeof name === 'string' && name.length > 0 && name !== '.' && name !== '..' &&
    new TextEncoder().encode(name).byteLength <= 255 && !/[\x00-\x1f\x7f/\\%?#\uFFFD]/.test(name);
}

export function fileMediaType(name = '') {
  const suffix = name.toLowerCase().split('.').at(-1);
  if (suffix === 'csv') return 'text/csv; charset=utf-8';
  if (suffix === 'xlsx') return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  if (suffix === 'yaml' || suffix === 'yml') return 'application/yaml';
  return 'application/octet-stream';
}

// UnixFS Data schema: Type=1, Data=2, filesize=3, blocksizes=4,
// hashType=5, fanout=6, mode=7, mtime=8. Decode bounded uint64 varints,
// packed/unpacked block sizes and optional metadata; reject unknown fields.
function unixfsData(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_BYTES) fail('Invalid UnixFS data');
  let at = 0; let fields = 0;
  function uint() {
    let value = 0n;
    for (let i = 0; i < 10; i++) {
      if (at >= bytes.length) fail('Truncated UnixFS protobuf');
      const byte = bytes[at++];
      if (i === 9 && byte > 1) fail('UnixFS varint overflow');
      value |= BigInt(byte & 127) << BigInt(i * 7);
      if (!(byte & 128)) return value;
    }
    fail('Invalid UnixFS varint');
  }
  function number(max = MAX_BYTES) {
    const value = uint();
    if (value > BigInt(max)) fail('UnixFS value exceeds limit');
    return Number(value);
  }
  function chunk() {
    const size = number(); const end = at + size;
    if (end > bytes.length) fail('Truncated UnixFS bytes');
    const value = bytes.subarray(at, end); at = end; return value;
  }
  const singletons = new Set();
  const output = { type: null, data: new Uint8Array(), filesize: null, blocksizes: [], hashType: null, fanout: null };
  while (at < bytes.length) {
    if (++fields > 512) fail('Too many UnixFS fields');
    const tag = number(0xffffffff); const field = Math.floor(tag / 8); const wire = tag & 7;
    if (field < 1 || field > 8) fail('Unknown UnixFS field');
    if (field !== 4 && singletons.has(field)) fail('Duplicate UnixFS field');
    singletons.add(field);
    if (field === 2 || field === 8) {
      if (wire !== 2) fail('Invalid UnixFS field wire type');
      const value = chunk();
      if (field === 2) output.data = value;
      else validateTimestamp(value);
    } else if (field === 4) {
      if (wire === 0) output.blocksizes.push(number());
      else if (wire === 2) {
        const size = number(); const end = at + size;
        if (end > bytes.length) fail('Truncated packed block sizes');
        while (at < end) { output.blocksizes.push(number()); if (at > end) fail('Invalid packed block size'); }
      } else fail('Invalid block sizes wire type');
      if (output.blocksizes.length > MAX_NODES) fail('Too many UnixFS block sizes');
    } else {
      if (wire !== 0) fail('Invalid UnixFS scalar wire type');
      const value = number(field === 3 || field === 4 ? MAX_BYTES : 0xffffffff);
      if (field === 1) output.type = value;
      if (field === 3) output.filesize = value;
      if (field === 5) output.hashType = value;
      if (field === 6) output.fanout = value;
    }
  }
  if (output.type === null) fail('UnixFS Type is missing');
  return output;
}

function validateTimestamp(bytes) {
  if (bytes.length > 32) fail('UnixFS timestamp exceeds limit');
  let at = 0; let seconds = false; let nanos = false;
  while (at < bytes.length) {
    const tag = bytes[at++];
    if (tag === 8 && !seconds) {
      seconds = true; let ended = false;
      for (let i = 0; i < 10 && at < bytes.length; i++) {
        const byte = bytes[at++];
        if (i === 9 && byte > 1) fail('UnixFS timestamp varint overflow');
        if (!(byte & 128)) { ended = true; break; }
      }
      if (!ended) fail('Invalid UnixFS timestamp');
    } else if (tag === 21 && !nanos && at + 4 <= bytes.length) {
      nanos = true;
      const value = new DataView(bytes.buffer, bytes.byteOffset + at, 4).getUint32(0, true);
      if (value > 999_999_999) fail('Invalid UnixFS timestamp nanos');
      at += 4;
    } else fail('Invalid UnixFS timestamp field');
  }
  if (!seconds) fail('UnixFS timestamp seconds are missing');
}

/** Resolve preverified held blocks. CID integrity is established by the dataset builder. */
export function createUnixfs(root, blockMap) {
  if (!(blockMap instanceof Map) || blockMap.size < 1 || blockMap.size > MAX_NODES) fail('Invalid UnixFS block map');
  const blocks = new Map();
  let total = 0;
  for (const [key, bytes] of blockMap) {
    const cid = CID.parse(key).toV1();
    if (!(bytes instanceof Uint8Array) || bytes.length > MAX_BYTES) fail('Invalid held block');
    total += bytes.length;
    if (total > 2 * MAX_BYTES) fail('UnixFS block map exceeds limit');
    const canonical = cid.toString();
    if (blocks.has(canonical)) fail('Duplicate canonical block CID');
    blocks.set(canonical, { cid, bytes });
  }
  const rootCid = CID.parse(root).toV1().toString();
  const cache = new Map();
  function node(key, ancestors = new Set()) {
    if (ancestors.has(key) || ancestors.size >= MAX_DEPTH) fail('UnixFS cycle or depth limit');
    if (cache.has(key)) return cache.get(key);
    const block = blocks.get(key);
    if (!block) fail('Required UnixFS block is unavailable');
    if (block.cid.code === 0x55) {
      const file = { cid: key, type: 'file', bytes: block.bytes, size: block.bytes.length, children: [] };
      cache.set(key, file); return file;
    }
    if (block.cid.code !== dagPb.code) fail('Unsupported UnixFS block codec', 501);
    let decoded;
    try { decoded = dagPb.decode(block.bytes); }
    catch { fail('Malformed DAG-PB block'); }
    const info = unixfsData(decoded.Data ?? new Uint8Array());
    const links = decoded.Links ?? [];
    if (links.length > MAX_NODES) fail('Too many UnixFS links');
    if (info.type === 4) fail('UnixFS symlinks are unsupported', 501);
    if (![0, 1, 2].includes(info.type)) fail('Unsupported UnixFS node type', 501);
    if (info.hashType !== null || info.fanout !== null) fail('Unsupported UnixFS sharding metadata', 501);
    if (info.type === 1) {
      if (info.data.length || info.blocksizes.length || info.filesize !== null && info.filesize !== 0) fail('Invalid UnixFS directory data');
      const named = new Map();
      for (const link of links) {
        if (!validPathName(link.Name)) fail('Ambiguous UnixFS directory name');
        if (named.has(link.Name)) fail('Duplicate UnixFS directory name');
        named.set(link.Name, link.Hash.toV1().toString());
      }
      const directory = { cid: key, type: 'directory', links: named };
      cache.set(key, directory); return directory;
    }
    if (info.type === 0 && links.length) fail('UnixFS Raw node has child links');
    if (info.blocksizes.length !== links.length) fail('UnixFS block sizes do not match links');
    if (info.type === 2 && info.filesize === null) fail('UnixFS file size is missing');
    const next = new Set(ancestors); next.add(key);
    const pieces = [info.data];
    let size = info.data.length;
    for (let i = 0; i < links.length; i++) {
      if (links[i].Name !== undefined && links[i].Name !== '') fail('Named UnixFS file chunk is unsupported', 501);
      const child = node(links[i].Hash.toV1().toString(), next);
      if (child.type !== 'file') fail('UnixFS file links to a directory');
      if (child.size !== info.blocksizes[i]) fail('UnixFS child size mismatch');
      size += child.size;
      if (size > MAX_BYTES) fail('Reconstructed UnixFS file exceeds limit');
      pieces.push(child.bytes);
    }
    if (info.filesize !== null && size !== info.filesize) fail('UnixFS file size mismatch');
    const bytes = new Uint8Array(size);
    let at = 0; for (const piece of pieces) { bytes.set(piece, at); at += piece.length; }
    const file = { cid: key, type: 'file', bytes, size, children: links.map(link => link.Hash.toV1().toString()) };
    cache.set(key, file); return file;
  }
  function traverse(segments) {
      if (!Array.isArray(segments) || segments.length > MAX_DEPTH || segments.some(name => !validPathName(name))) {
        fail('Invalid UnixFS path', 400);
      }
      let current = node(rootCid);
      const trace = [rootCid];
      for (const name of segments) {
        if (current.type !== 'directory') fail('UnixFS path crosses a file', 404);
        const child = current.links.get(name);
        if (!child) fail('UnixFS path is not present', 404);
        current = node(child);
        trace.push(child);
      }
      return { current, trace };
  }
  return {
    resolve(segments = []) {
      const { current } = traverse(segments);
      if (current.type === 'file') return { cid: current.cid, type: 'file', bytes: current.bytes,
        size: current.size, mediaType: fileMediaType(segments.at(-1)) };
      const entries = [...current.links].map(([name, cid]) => {
        const child = node(cid);
        return { name, cid, type: child.type, size: child.type === 'file' ? child.size : null,
          mediaType: child.type === 'file' ? fileMediaType(name) : null };
      });
      return { cid: current.cid, type: 'directory', entries };
    },
    proof(segments = [], scope = 'block') {
      if (!['block', 'entity'].includes(scope)) fail('Unsupported proof scope', 400);
      const { current, trace } = traverse(segments);
      const ordered = []; const seen = new Set();
      function include(key, depth = 0, recurse = false) {
        if (depth >= MAX_DEPTH) fail('Proof depth limit');
        if (seen.has(key)) return;
        if (!blocks.has(key)) fail('Required proof block is unavailable');
        seen.add(key); ordered.push(key);
        if (recurse) {
          const child = node(key);
          if (child.type !== 'file') fail('File entity contains a directory');
          for (const cid of child.children) include(cid, depth + 1, true);
        }
      }
      for (const key of trace.slice(0, -1)) include(key);
      include(current.cid, 0, scope === 'entity' && current.type === 'file');
      const header = dagCbor.encode({ version: 1, roots: [CID.parse(rootCid)] });
      const pieces = [varint(header.length), header];
      let size = pieces.reduce((sum, part) => sum + part.length, 0);
      for (const key of ordered) {
        const block = blocks.get(key);
        const prefix = varint(block.cid.bytes.length + block.bytes.length);
        pieces.push(prefix, block.cid.bytes, block.bytes);
        size += prefix.length + block.cid.bytes.length + block.bytes.length;
      }
      if (size > 2 * MAX_BYTES + 8_192) fail('Proof CAR exceeds limit');
      const bytes = new Uint8Array(size);
      let at = 0; for (const piece of pieces) { bytes.set(piece, at); at += piece.length; }
      return { bytes, terminalCid: current.cid, pathRoots: trace, scope,
        etag: `"${rootCid}/${segments.map(name => encodeURIComponent(name)).join('/')}.car.${scope}"` };
    },
  };
}

function varint(value) {
  const bytes = [];
  do { const byte = value % 128; value = Math.floor(value / 128); bytes.push(byte | (value ? 128 : 0)); } while (value);
  return Uint8Array.from(bytes);
}
