import { constants } from 'node:fs';
import { open, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CarReader } from '@ipld/car';
import * as dagPb from '@ipld/dag-pb';

export const ROOT = 'bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle';
export const ORIGIN = 'https://signalx-ipfs-provider.kamuitranslator.workers.dev';
export const CAR_SHA256 = 'd79dd33f1717beed7d7152f61170c06f318529edf193277c997a576663007078';
export const MAX_BYTES = 1_048_576;
export const MAX_DURATION_MS = 15_000;

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function failure(code, message) { return Object.assign(new Error(message), { code }); }
function typeFor(name) {
  if (name.endsWith('.csv')) return 'text/csv; charset=utf-8';
  if (name.endsWith('.xlsx')) return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  if (name.endsWith('.yaml')) return 'application/yaml';
  throw new Error('Unexpected original file extension');
}

/** Independently inspect the publisher CAR using official CAR/DAG-PB codecs. */
export async function inspectOriginal(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 166374 || sha256(bytes) !== CAR_SHA256) {
    throw new Error('Expected the qualified original 166374-byte publisher CAR');
  }
  const car = await CarReader.fromBytes(bytes);
  const roots = await car.getRoots();
  if (roots.length !== 1 || roots[0].toString() !== ROOT) throw new Error('Original CAR root differs');
  const blocks = new Map();
  for await (const block of car.blocks()) {
    const cid = block.cid.toString();
    if (blocks.has(cid) || block.cid.multihash.code !== 0x12 || block.cid.multihash.digest.length !== 32 ||
        sha256(block.bytes) !== Buffer.from(block.cid.multihash.digest).toString('hex')) {
      throw new Error('Original CAR has a duplicate or invalid block');
    }
    blocks.set(cid, block.bytes);
  }
  if (blocks.size !== 5 || roots[0].code !== dagPb.code || !blocks.has(ROOT)) throw new Error('Expected original five-block DAG');
  const rootBytes = blocks.get(ROOT);
  const directory = dagPb.decode(rootBytes);
  if (Buffer.from(directory.Data ?? []).toString('hex') !== '0801' || directory.Links.length !== 4) {
    throw new Error('Expected the original UnixFS directory with four direct files');
  }
  const names = new Set();
  const files = directory.Links.map(link => {
    const cid = link.Hash.toString();
    const name = link.Name;
    const body = blocks.get(cid);
    if (typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(name) || names.has(name) ||
        link.Hash.code !== 0x55 || !body || link.Tsize !== body.length) {
      throw new Error('Original directory link does not identify a complete direct raw file');
    }
    names.add(name);
    return { name, cid, type: 'file', size: body.length, mediaType: typeFor(name), sha256: sha256(body), body };
  });
  if (files.reduce((sum, file) => sum + file.size, rootBytes.length) !== 166123) throw new Error('Original DAG payload differs');
  return { root: ROOT, carBytes: bytes.length, carSha256: sha256(bytes), rootBytes, rootSha256: sha256(rootBytes), files };
}

async function readOriginal(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size !== 166374) throw new Error('Expected the original bounded regular CAR file');
    const bytes = Buffer.alloc(before.size);
    let position = 0;
    while (position < bytes.length) {
      const { bytesRead } = await handle.read(bytes, position, bytes.length - position, position);
      if (!bytesRead) throw new Error('Original publisher CAR was truncated during read');
      position += bytesRead;
    }
    const after = await handle.stat();
    if (bytes.length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
      throw new Error('Original publisher CAR changed during read');
    }
    return bytes;
  } finally { await handle.close(); }
}

/** One bounded HTTP request; injectable fetch is used only for synthetic validation. */
export async function boundedRequest(url, { method = 'GET', accept = '*/*', maxBytes = MAX_BYTES, fetchImpl = globalThis.fetch } = {}) {
  if (!['GET', 'HEAD'].includes(method) || !Number.isInteger(maxBytes) || maxBytes < 0 || maxBytes > MAX_BYTES) throw new Error('Invalid request bound');
  const started = Date.now();
  const controller = new AbortController();
  let reader;
  let timedOut = false;
  let rejectDeadline;
  const deadline = new Promise((_, reject) => { rejectDeadline = reject; });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
    rejectDeadline(failure('TIMEOUT', 'File request exceeded 15 seconds'));
  }, MAX_DURATION_MS);
  const receipt = {
    url, method, accept, acceptEncoding: 'identity', maximumBodyBytes: maxBytes,
    maximumDurationMs: MAX_DURATION_MS, requestAttempts: 1,
    startedAtUtc: new Date(started).toISOString(), status: null, headers: {},
    responseBytes: 0, observedBytes: 0, bodyComplete: false, byteCapExceeded: false,
    responseSha256: null, error: null,
  };
  let bytes = null;
  try {
    await Promise.race([deadline, (async () => {
      const response = await fetchImpl(url, { method, headers: { Accept: accept, 'Accept-Encoding': 'identity' }, redirect: 'error', signal: controller.signal });
      if (timedOut) {
        response.body?.cancel().catch(() => {});
        throw failure('TIMEOUT', 'File request exceeded 15 seconds');
      }
      receipt.status = response.status;
      for (const name of ['content-type', 'content-length', 'content-encoding', 'content-disposition', 'etag',
        'cache-control', 'access-control-allow-origin', 'access-control-expose-headers', 'x-ipfs-path', 'ipfs-uri']) {
        receipt.headers[name] = response.headers.get(name);
      }
      const length = receipt.headers['content-length'];
      if (method !== 'HEAD' && length !== null && /^\d+$/.test(length) && Number(length) > maxBytes) {
        receipt.byteCapExceeded = true;
        response.body?.cancel().catch(() => {});
        throw failure('BYTE_CAP', 'Response declares more than the file read bound');
      }
      reader = response.body?.getReader();
      const chunks = [];
      if (reader) while (true) {
        const next = await reader.read();
        if (timedOut) throw failure('TIMEOUT', 'File request exceeded 15 seconds');
        if (next.done) break;
        receipt.observedBytes += next.value.byteLength;
        if (next.value.byteLength > maxBytes - receipt.responseBytes) {
          receipt.byteCapExceeded = true;
          throw failure('BYTE_CAP', 'Response exceeds the file read bound');
        }
        chunks.push(Buffer.from(next.value));
        receipt.responseBytes += next.value.byteLength;
      }
      bytes = Buffer.concat(chunks, receipt.responseBytes);
      receipt.bodyComplete = true;
      receipt.responseSha256 = sha256(bytes);
      if (receipt.status !== 200) {
        receipt.errorBodyPreview = bytes.toString('utf8').slice(0, 512);
        throw failure('HTTP_STATUS', `File endpoint returned HTTP ${receipt.status}`);
      }
    })()]);
  } catch (error) {
    receipt.error = { code: timedOut ? 'TIMEOUT' : error.code ?? error.cause?.code ?? 'REQUEST_ERROR',
      message: timedOut ? 'File request exceeded 15 seconds' : String(error.message ?? 'Request failed').slice(0, 512) };
    controller.abort();
    reader?.cancel().catch(() => {});
    bytes = null;
  } finally {
    clearTimeout(timer);
    receipt.finishedAtUtc = new Date().toISOString();
    receipt.durationMs = Date.now() - started;
  }
  return { receipt, bytes };
}

function headersMatch(receipt, { size, mediaType, etag }) {
  const h = receipt.headers;
  return {
    contentLengthMatches: h['content-length'] === String(size),
    contentTypeMatches: h['content-type']?.toLowerCase() === mediaType.toLowerCase(),
    identityEncoding: h['content-encoding'] === null || h['content-encoding'] === 'identity',
    etagMatches: h.etag === etag,
    publicCors: h['access-control-allow-origin'] === '*',
  };
}
function allTrue(value) { return Object.values(value).every(v => v === true); }

export async function verifyFiles(baseUrl, originalBytes, options = {}) {
  const base = new URL(baseUrl);
  if (base.origin !== ORIGIN || !['', '/'].includes(base.pathname) || base.search || base.hash || base.username || base.password) {
    throw new Error('Expected the exact authorized deployed provider HTTPS origin');
  }
  const original = await inspectOriginal(originalBytes);
  const receipt = {
    schemaVersion: 'signalxOriginalFileConsumptionV1', startedAtUtc: new Date().toISOString(),
    origin: base.origin, root: ROOT, triggerOrigin: 'project_controlled_public_filename_check',
    scope: 'Original publisher filenames, directory JSON, and CID-verified directory block; no remote CAR, routing lookup, daemon, pin or announcement.',
    source: { carSha256: original.carSha256, carBytes: original.carBytes, independentlyHashedBlocks: 5,
      rootBlockBytes: original.rootBytes.length, rootBlockSha256: original.rootSha256,
      files: original.files.map(({ body, ...file }) => file) },
    maximumRequests: 10, retries: 0, requestCount: 0, files: [],
    unchangedHeliaRetrievalVerified: false, ordinaryKuboRetrievalVerified: false,
    nativeBitswapVerified: false, organicUseVerified: false, fullPathGatewayConformanceVerified: false,
  };
  const root = await boundedRequest(`${base.origin}/ipfs/${ROOT}?format=raw`, {
    ...options, method: 'GET', accept: 'application/vnd.ipld.raw', maxBytes: 4096,
  });
  receipt.requestCount++;
  const rootChecks = {
    hashMatchesOriginal: root.bytes !== null && sha256(root.bytes) === original.rootSha256,
    bytesMatchOriginal: root.bytes !== null && Buffer.from(root.bytes).equals(Buffer.from(original.rootBytes)),
    contentTypeMatches: root.receipt.headers['content-type'] === 'application/vnd.ipld.raw',
  };
  receipt.rootDag = { ...root.receipt, checks: rootChecks, verified: !root.receipt.error && allTrue(rootChecks) };
  if (receipt.rootDag.verified) {
    const listing = await boundedRequest(`${base.origin}/ipfs/${ROOT}?format=json`, {
      ...options, method: 'GET', accept: 'application/json', maxBytes: 16384,
    });
    receipt.requestCount++;
    let payload = null;
    let parseError = null;
    if (listing.bytes !== null) {
      try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(listing.bytes)); }
      catch { parseError = { code: 'LISTING_JSON', message: 'Directory response is not valid UTF-8 JSON' }; }
    }
    const entries = payload?.entries;
    const listingMatches = payload?.root === ROOT && payload?.cid === ROOT && payload?.type === 'directory' &&
      Array.isArray(entries) && entries.length === 4 && new Set(entries.map(entry => entry?.name)).size === 4 &&
      original.files.every(file => entries.some(entry => entry?.name === file.name && entry.cid === file.cid &&
        entry.type === 'file' && entry.size === file.size && entry.mediaType === file.mediaType));
    const listingChecks = {
      originalLinksMatch: Boolean(listingMatches),
      contentTypeMatches: listing.receipt.headers['content-type']?.toLowerCase() === 'application/json; charset=utf-8',
      etagMatches: listing.receipt.headers.etag === `"${ROOT}.unixfs-directory-json"`,
      publicCors: listing.receipt.headers['access-control-allow-origin'] === '*',
    };
    receipt.directoryListing = { ...listing.receipt, parseError, checks: listingChecks,
      verified: !listing.receipt.error && !parseError && allTrue(listingChecks) };
    for (const file of original.files) {
      const url = `${base.origin}/ipfs/${ROOT}/${encodeURIComponent(file.name)}`;
      const get = await boundedRequest(url, { ...options, method: 'GET', accept: '*/*', maxBytes: MAX_BYTES });
      const head = await boundedRequest(url, { ...options, method: 'HEAD', maxBytes: 0 });
      receipt.requestCount += 2;
      const expectedHeaders = { size: file.size, mediaType: file.mediaType, etag: `"${file.cid}"` };
      const getChecks = {
        hashMatchesOriginal: get.bytes !== null && sha256(get.bytes) === file.sha256,
        bytesMatchOriginal: get.bytes !== null && Buffer.from(get.bytes).equals(Buffer.from(file.body)),
        cidMultihashMatches: get.bytes !== null && sha256(get.bytes) === file.sha256,
        sizeMatchesOriginal: get.bytes?.length === file.size,
        ...headersMatch(get.receipt, expectedHeaders),
      };
      const headChecks = { noBody: head.bytes !== null && head.bytes.length === 0, ...headersMatch(head.receipt, expectedHeaders) };
      receipt.files.push({ name: file.name, cid: file.cid, expectedBytes: file.size, expectedSha256: file.sha256,
        get: { ...get.receipt, checks: getChecks, verified: !get.receipt.error && allTrue(getChecks) },
        head: { ...head.receipt, checks: headChecks, verified: !head.receipt.error && allTrue(headChecks) },
        originalFileConsumed: !get.receipt.error && allTrue(getChecks) && !head.receipt.error && allTrue(headChecks) });
    }
  }
  receipt.allFourOriginalFilesConsumed = receipt.files.length === 4 && receipt.files.every(file => file.originalFileConsumed);
  receipt.publicFilenameConsumptionVerified = receipt.rootDag.verified && receipt.directoryListing?.verified === true && receipt.allFourOriginalFilesConsumed;
  receipt.finishedAtUtc = new Date().toISOString();
  return receipt;
}

async function main(args) {
  const [url, originalPath, outputPath] = args;
  if (!url || !originalPath || !outputPath || args.length !== 3) throw new Error('Usage: file-verify.mjs DEPLOYED_HTTPS_ORIGIN ORIGINAL_PUBLISHER_CAR NEW_RECEIPT');
  const receipt = await verifyFiles(url, await readOriginal(originalPath));
  receipt.source.localArchivePath = resolve(originalPath);
  await writeFile(outputPath, `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ receiptPath: resolve(outputPath), requestCount: receipt.requestCount,
    publicFilenameConsumptionVerified: receipt.publicFilenameConsumptionVerified,
    rootDagVerified: receipt.rootDag.verified, directoryListingVerified: receipt.directoryListing?.verified ?? false,
    files: receipt.files.map(file => ({ name: file.name, consumed: file.originalFileConsumed,
      getStatus: file.get.status, headStatus: file.head.status, getError: file.get.error, headError: file.head.error })) }));
  if (!receipt.publicFilenameConsumptionVerified) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
}
