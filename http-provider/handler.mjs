import { createUnixfs, UnixfsError, validPathName } from './unixfs.mjs';

const IDENTITY_CID = 'bafkqaaa';
const MAX_BYTES = 1_048_576;
const MAX_TOTAL_BYTES = 4 * MAX_BYTES;
const CID = /^(?:b[a-z2-7]{8,120}|Qm[1-9A-HJ-NP-Za-km-z]{44})$/;
const encoder = new TextEncoder();
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function record(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new TypeError(`${name} must be an object`);
  }
  return value;
}

function decode(value, name, { empty = false } = {}) {
  if (typeof value !== 'string' || value.length > Math.ceil(MAX_BYTES / 3) * 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new TypeError(`${name} must contain bounded canonical base64`);
  }
  if (value.endsWith('==') && (BASE64_ALPHABET.indexOf(value.at(-3)) & 15) !== 0 ||
      value.endsWith('=') && !value.endsWith('==') && (BASE64_ALPHABET.indexOf(value.at(-2)) & 3) !== 0) {
    throw new TypeError(`${name} has noncanonical base64`);
  }
  let bytes;
  try {
    if (typeof Uint8Array.fromBase64 === 'function') bytes = Uint8Array.fromBase64(value, { lastChunkHandling: 'strict' });
    else {
      const binary = atob(value);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    }
  }
  catch { throw new TypeError(`${name} has invalid base64`); }
  if ((!empty && bytes.length === 0) || bytes.length > MAX_BYTES) {
    throw new TypeError(`${name} has invalid size or noncanonical base64`);
  }
  return bytes;
}

function mediaType(value) {
  if (typeof value !== 'string' || value.length > 160 ||
      !/^application\/[a-z0-9.+-]+(?:;[ a-zA-Z0-9=._-]+)*$/.test(value)) {
    throw new TypeError('IPNI contentType must be an application media type');
  }
  return value;
}

function accepts(request, type) {
  const accept = request.headers.get('accept');
  if (!accept) return true;
  const matches = [];
  for (const item of accept.split(',')) {
    const [range, ...params] = item.trim().toLowerCase().split(';').map(x => x.trim());
    const specificity = range === type ? 2 : range === `${type.split('/')[0]}/*` ? 1 : range === '*/*' ? 0 : -1;
    if (specificity < 0) continue;
    let quality = 1;
    for (const param of params) {
      if (param.startsWith('q=')) quality = /^(?:0(?:\.\d{0,3})?|1(?:\.0{0,3})?)$/.test(param.slice(2)) ? Number(param.slice(2)) : 0;
      else if (type === 'application/vnd.ipld.car' &&
          !['version=1', 'order=dfs', 'dups=n', 'dups=y'].includes(param)) quality = 0;
      else if (type === 'application/vnd.ipld.raw' && param) quality = 0;
    }
    matches.push({ specificity, quality });
  }
  if (!matches.length) return false;
  const best = Math.max(...matches.map(x => x.specificity));
  return matches.some(x => x.specificity === best && x.quality > 0);
}

function notModified(value, etag) {
  return value?.split(',').some(token => {
    const trimmed = token.trim();
    return trimmed === '*' || trimmed.replace(/^W\//, '') === etag;
  }) ?? false;
}

function baseHeaders() {
  return new Headers({
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, HEAD, OPTIONS',
    'access-control-allow-headers': 'Accept, If-None-Match',
    'access-control-expose-headers': 'Content-Length, Content-Type, ETag, X-Ipfs-Path, X-Ipfs-Roots',
    'x-content-type-options': 'nosniff',
    vary: 'Accept',
  });
}

/** Serve trusted, preverified deployment bytes; this module performs no network or filesystem I/O. */
export function createProvider(data) {
  record(data, 'data');
  if (typeof data.root !== 'string' || !CID.test(data.root)) throw new TypeError('Invalid root');
  if (typeof data.termEndUtc !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(data.termEndUtc)) {
    throw new TypeError('termEndUtc must be a UTC timestamp');
  }
  const deadline = Date.parse(data.termEndUtc);
  if (!Number.isFinite(deadline) || new Date(deadline).toISOString().slice(0, 19) !== data.termEndUtc.slice(0, 19)) {
    throw new TypeError('Invalid termEndUtc');
  }
  if (data.providerId !== null && data.providerId !== undefined &&
      (typeof data.providerId !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,120}$/.test(data.providerId))) {
    throw new TypeError('Invalid providerId');
  }
  const root = data.root;
  const providerId = data.providerId ?? null;
  const termEndUtc = new Date(deadline).toISOString();
  const attributionText = JSON.stringify(data.attribution ?? null);
  if (attributionText.length > 8_192) throw new TypeError('Attribution exceeds metadata limit');
  const attribution = JSON.parse(attributionText);
  let totalBytes = 0;
  function boundedDecode(value, name, options) {
    const bytes = decode(value, name, options);
    totalBytes += bytes.byteLength;
    if (totalBytes > MAX_TOTAL_BYTES) throw new TypeError('Deployment bytes exceed total limit');
    return bytes;
  }
  const car = boundedDecode(data.carBase64, 'carBase64');
  const blocks = new Map();
  const entries = Object.entries(record(data.blocks, 'blocks'));
  if (entries.length < 1 || entries.length > 64 || !Object.hasOwn(data.blocks, root)) throw new TypeError('Expected 1..64 blocks including root');
  if (data.verification !== null && data.verification !== undefined) {
    record(data.verification, 'verification');
    for (const field of ['blocks', 'reachableBlockCount']) {
      if (Object.hasOwn(data.verification, field) && data.verification[field] !== entries.length) {
        throw new TypeError(`Verification ${field} does not match held block count`);
      }
    }
  }
  for (const [cid, value] of entries) {
    if (!CID.test(cid) || cid === IDENTITY_CID) throw new TypeError('Invalid block CID');
    blocks.set(cid, boundedDecode(value, `blocks.${cid}`, { empty: true }));
  }
  blocks.set(IDENTITY_CID, new Uint8Array());
  const unixfs = createUnixfs(root, blocks);
  const objects = new Map();
  const removalObjects = new Map();
  let activeHead = null;
  let removalHead = null;
  if (data.ipni !== null && data.ipni !== undefined) {
    const ipni = record(data.ipni, 'ipni');
    if (!providerId) throw new TypeError('IPNI requires a supplied providerId');
    activeHead = boundedDecode(ipni.headBase64, 'ipni.headBase64');
    if (ipni.removalHeadBase64 !== null && ipni.removalHeadBase64 !== undefined) {
      removalHead = boundedDecode(ipni.removalHeadBase64, 'ipni.removalHeadBase64');
    }
    for (const [name, values] of [['objects', ipni.objects], ['removalObjects', ipni.removalObjects ?? {}]]) {
      const objectEntries = Object.entries(record(values, `ipni.${name}`));
      if (objectEntries.length > 64) throw new TypeError('Too many IPNI objects');
      for (const [cid, value] of objectEntries) {
        if (!CID.test(cid)) throw new TypeError('Invalid IPNI object CID');
        record(value, `ipni.${name}.${cid}`);
        const bytes = boundedDecode(value.bodyBase64, `ipni.${name}.${cid}.bodyBase64`);
        const contentType = mediaType(value.contentType);
        const previous = objects.get(cid);
        if (previous && (previous.contentType !== contentType || previous.bytes.length !== bytes.length ||
            previous.bytes.some((byte, i) => byte !== bytes[i]))) throw new TypeError('Conflicting IPNI object');
        (name === 'objects' ? objects : removalObjects).set(cid, { bytes, contentType });
      }
    }
  }

  return {
    fetch(request) {
      const now = Date.now();
      const active = Number.isFinite(now) && now < deadline;
      const method = request.method;
      function response(bytes, status, contentType, { etag = null, cache = 'no-store', ipfsPath = null, ipfsRoots = null } = {}) {
        const headers = baseHeaders();
        headers.set('cache-control', cache);
        headers.set('content-type', contentType);
        if (etag) headers.set('etag', etag);
        if (ipfsPath) headers.set('x-ipfs-path', ipfsPath);
        if (ipfsRoots) headers.set('x-ipfs-roots', ipfsRoots);
        if (status !== 204 && status !== 304) headers.set('content-length', String(bytes.byteLength));
        if (status === 405) headers.set('allow', 'GET, HEAD, OPTIONS');
        return new Response(method === 'HEAD' || status === 204 || status === 304 ? null : bytes, { status, headers });
      }
      function error(status, message) { return response(encoder.encode(`${message}\n`), status, 'text/plain; charset=utf-8'); }
      if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) return error(405, 'Method not allowed');
      if (/\/(?:\.|%2e){1,2}(?:\/|[?#]|$)/i.test(request.url)) return error(400, 'Path traversal is unsupported');
      let url;
      try { url = new URL(request.url); }
      catch { return error(400, 'Invalid URL'); }
      if (url.hash || /%|\\|\/\//.test(url.pathname)) return error(400, 'Noncanonical path');
      const query = url.searchParams;
      if ([...query.keys()].some(key => query.getAll(key).length !== 1)) return error(400, 'Duplicate query parameter');

      let bytes;
      let type;
      let etag = null;
      let cache = 'no-store';
      let ipfsPath = null;
      let ipfsRoots = null;
      const content = /^\/ipfs\/([^/]+)(?:\/(.+))?$/.exec(url.pathname);
      const ad = /^\/ipni\/v1\/ad\/([^/]+)$/.exec(url.pathname);
      if (content) {
        const cid = content[1];
        if (!blocks.has(cid)) return error(404, 'CID is outside this provider allowlist');
        const segments = content[2]?.split('/') ?? [];
        const format = query.get('format') ?? (segments.length ? 'file' : 'raw');
        if (segments.some(name => !validPathName(name))) return error(400, 'Invalid UnixFS path');
        const scope = query.get('dag-scope');
        const proofRequest = format === 'car' && ['block', 'entity'].includes(scope);
        if (proofRequest) {
          if (cid !== root) return error(404, 'Path proofs are available only below the approved root');
          const allowed = new Map([['format', 'car'], ['dag-scope', scope], ['car-version', '1'], ['car-order', 'dfs'], ['car-dups', 'n']]);
          if ([...query].some(([key, value]) => !allowed.has(key) || allowed.get(key) !== value)) return error(400, 'Unsupported proof CAR query');
          if (!active) return error(410, 'Content serving term has ended');
          let proof;
          try { proof = unixfs.proof(segments, scope); }
          catch (failure) { return error(failure instanceof UnixfsError ? failure.status : 503, failure.message); }
          bytes = proof.bytes; type = 'application/vnd.ipld.car; version=1; order=dfs; dups=n'; etag = proof.etag;
          ipfsRoots = proof.pathRoots.join(',');
        } else if (segments.length || format === 'json') {
          if (cid !== root) return error(404, 'Named paths are available only below the approved root');
          if (format === 'file' && [...query].length || format === 'json' && [...query.keys()].some(key => key !== 'format') ||
              !['file', 'json'].includes(format)) return error(400, 'Unsupported UnixFS query');
          if (!active) return error(410, 'Content serving term has ended');
          let entry;
          try { entry = unixfs.resolve(segments); }
          catch (failure) { return error(failure instanceof UnixfsError ? failure.status : 503, failure.message); }
          if (entry.type === 'file') {
            if (format !== 'file') return error(400, 'JSON listing is available only for directories');
            bytes = entry.bytes; type = entry.mediaType; etag = `"${entry.cid}"`;
          } else {
            if (format !== 'json') return error(400, 'Directory listing requires format=json');
            bytes = encoder.encode(JSON.stringify({ root, ...entry }));
            type = 'application/json; charset=utf-8'; etag = `"${entry.cid}.unixfs-directory-json"`;
          }
        } else if (format === 'raw') {
          if ([...query.keys()].some(key => key !== 'format')) return error(400, 'Unsupported raw query');
          bytes = blocks.get(cid);
          type = 'application/vnd.ipld.raw';
          ipfsRoots = cid;
        } else if (format === 'car') {
          if (cid !== root) return error(404, 'CAR is available only for the approved root');
          const allowed = new Map([['format', 'car'], ['dag-scope', 'all'], ['car-version', '1'], ['car-order', 'dfs'], ['car-dups', 'n']]);
          if (query.get('dag-scope') !== 'all' || [...query].some(([key, value]) => !allowed.has(key) || allowed.get(key) !== value)) {
            return error(400, 'Only the complete CARv1 graph is available');
          }
          bytes = car;
          type = 'application/vnd.ipld.car; version=1; order=dfs; dups=n';
          ipfsRoots = cid;
        } else return error(400, 'Unsupported format');
        if (!active) return error(410, 'Content serving term has ended');
        etag ??= `"${cid}"`;
        const ttl = Math.max(0, Math.min(3_600, Math.floor((deadline - now) / 1_000)));
        cache = `public, max-age=${ttl}, s-maxage=${ttl}, immutable, must-revalidate`;
        ipfsPath = `/ipfs/${cid}${segments.length ? '/' + segments.join('/') : ''}`;
      } else if (ad) {
        if ([...query].length) return error(400, 'IPNI queries are unsupported');
        if (ad[1] === 'head') {
          bytes = active ? activeHead : removalHead;
          if (!bytes) return error(404, active ? 'No IPNI head is configured' : 'No removal head is configured');
          type = 'application/vnd.ipld.dag-json';
        } else {
          const object = objects.get(ad[1]) ?? (!active ? removalObjects.get(ad[1]) : null);
          if (!object) return error(404, 'IPNI object is not available');
          ({ bytes, contentType: type } = object);
          etag = `"${ad[1]}"`;
        }
      } else if (url.pathname === '/health') {
        if ([...query].length) return error(400, 'Health queries are unsupported');
        bytes = encoder.encode(JSON.stringify({ service: 'immutable-http-content-provider', transport: 'https',
          nativeBitswap: false, root, providerId, termEndUtc, contentAvailable: active, attribution,
          ipni: { configured: activeHead !== null, head: active ? activeHead ? 'active' : 'absent' : removalHead ? 'removal' : 'absent' } }));
        type = 'application/json; charset=utf-8';
      } else return error(404, 'Not found');

      if (method === 'OPTIONS') {
        const requestedMethod = request.headers.get('access-control-request-method');
        const requestedHeaders = request.headers.get('access-control-request-headers')?.split(',').map(x => x.trim().toLowerCase()) ?? [];
        if (requestedMethod && !['GET', 'HEAD'].includes(requestedMethod) ||
            requestedHeaders.some(x => !['accept', 'if-none-match'].includes(x))) return error(403, 'Preflight denied');
        return response(new Uint8Array(), 204, type, { cache: 'no-store' });
      }
      if (!accepts(request, type.split(';')[0])) return error(406, 'Requested representation is unavailable');
      if (etag && notModified(request.headers.get('if-none-match'), etag)) {
        return response(new Uint8Array(), 304, type, { etag, cache, ipfsPath, ipfsRoots });
      }
      return response(bytes, 200, type, { etag, cache, ipfsPath, ipfsRoots });
    },
  };
}
