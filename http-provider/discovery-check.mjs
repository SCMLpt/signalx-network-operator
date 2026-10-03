import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CID } from 'multiformats/cid';
import { peerIdFromString } from '@libp2p/peer-id';
import { validateProviderHost, HISTORICAL_PROVIDER_HOST } from './ipni-build.mjs';

export const ROOT = 'bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle';
export const PROVIDER_ID = '12D3KooWM1CrPmUiwEJmi9YePCyAiuVxZUVJvDnyRZhMCVFadniZ';
export const ADDRESS = '/dns4/signalx-ipfs-provider.kamuitranslator.workers.dev/tcp/443/tls/http';
export const PROTOCOL = 'transport-ipfs-gateway-http';
export const MAX_BYTES = 262144;
export const MAX_DURATION_MS = 15000;
const ROUTES = [
  { id: 'ipni', base: 'https://cid.contact/routing/v1/providers' },
  { id: 'default_delegated_router', base: 'https://delegated-ipfs.dev/routing/v1/providers' },
];

function failure(code, message) { return Object.assign(new Error(message), { code }); }

export function parseProviders(body, contentType = '') {
  const mediaType = contentType.split(';', 1)[0].trim().toLowerCase();
  if (!['application/json', 'application/x-ndjson', 'application/ndjson'].includes(mediaType)) {
    throw failure('CONTENT_TYPE', 'Expected JSON or NDJSON routing response');
  }
  let parsed;
  if (mediaType === 'application/json') {
    try { parsed = JSON.parse(body); } catch { throw failure('PARSE_JSON', 'Invalid routing JSON'); }
    if (!parsed || !Array.isArray(parsed.Providers)) throw failure('SCHEMA', 'JSON response lacks a Providers array');
    return { format: 'json', providers: parsed.Providers };
  }
  const providers = [];
  for (const line of body.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try { parsed = JSON.parse(line); } catch { throw failure('PARSE_NDJSON', 'Invalid routing NDJSON line'); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw failure('SCHEMA', 'NDJSON provider is not an object');
    providers.push(parsed);
  }
  return { format: 'ndjson', providers };
}

export function providerMatch(providers, { providerId = PROVIDER_ID, address = ADDRESS } = {}) {
  const ownIdentity = providers.filter(p => p && typeof p === 'object' && p.ID === providerId);
  const exact = ownIdentity.filter(p => p.Schema === 'peer' && Array.isArray(p.Addrs) && p.Addrs.includes(address) &&
    Array.isArray(p.Protocols) && p.Protocols.includes(PROTOCOL));
  return {
    returnedProviderCount: providers.length,
    ownIdentityRecordCount: ownIdentity.length,
    ownHttpsAddressSeen: ownIdentity.some(p => Array.isArray(p.Addrs) && p.Addrs.includes(address)),
    ownHttpProtocolSeen: ownIdentity.some(p => Array.isArray(p.Protocols) && p.Protocols.includes(PROTOCOL)),
    exactProviderMatch: exact.length > 0,
    exactMatchCount: exact.length,
    // Every required field must occur in the same record; partial records cannot
    // be combined into a fictitious address/protocol match.
    matchedRecords: exact.map(() => ({ Schema: 'peer', ID: providerId, Addrs: [address], Protocols: [PROTOCOL] })),
  };
}

export async function lookup(base, cid, { fetchImpl = globalThis.fetch, providerId = PROVIDER_ID, address = ADDRESS } = {}) {
  const started = Date.now();
  const controller = new AbortController();
  let reader;
  let timedOut = false;
  let rejectDeadline;
  const deadline = new Promise((_, reject) => { rejectDeadline = reject; });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
    rejectDeadline(failure('TIMEOUT', 'Routing request exceeded 15 seconds'));
  }, MAX_DURATION_MS);
  const receipt = {
    cid, url: `${base}/${encodeURIComponent(cid)}`, method: 'GET', accept: 'application/json',
    startedAtUtc: new Date(started).toISOString(), maximumDurationMs: MAX_DURATION_MS,
    maximumBodyBytes: MAX_BYTES, requestAttempts: 1, status: null,
    contentType: null, cacheControl: null, age: null, bodyComplete: false,
    responseBytes: 0, observedBytes: 0, byteCapExceeded: false,
    responseSha256: null, parsed: false, format: null, exactProviderMatch: false,
    error: null,
  };
  try {
    await Promise.race([deadline, (async () => {
      const response = await fetchImpl(receipt.url, {
        method: 'GET', headers: { Accept: 'application/json' }, redirect: 'error', signal: controller.signal,
      });
      if (timedOut) {
        response.body?.cancel().catch(() => {});
        throw failure('TIMEOUT', 'Routing request exceeded 15 seconds');
      }
      receipt.status = response.status;
      receipt.contentType = response.headers.get('content-type');
      receipt.cacheControl = response.headers.get('cache-control');
      receipt.age = response.headers.get('age');
      const length = response.headers.get('content-length');
      receipt.contentLength = length;
      if (length !== null && /^\d+$/.test(length) && Number(length) > MAX_BYTES) {
        receipt.byteCapExceeded = true;
        response.body?.cancel().catch(() => {});
        throw failure('BYTE_CAP', 'Routing response declares more than 256 KiB');
      }
      const chunks = [];
      reader = response.body?.getReader();
      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (timedOut) throw failure('TIMEOUT', 'Routing request exceeded 15 seconds');
          if (done) break;
          receipt.observedBytes += value.byteLength;
          if (value.byteLength > MAX_BYTES - receipt.responseBytes) {
            receipt.byteCapExceeded = true;
            throw failure('BYTE_CAP', 'Routing response exceeds 256 KiB');
          }
          chunks.push(Buffer.from(value));
          receipt.responseBytes += value.byteLength;
        }
      }
      const bytes = Buffer.concat(chunks, receipt.responseBytes);
      receipt.bodyComplete = true;
      receipt.responseSha256 = createHash('sha256').update(bytes).digest('hex');
      if (response.status !== 200) {
        receipt.errorBodyPreview = bytes.toString('utf8').slice(0, 1024);
        throw failure('HTTP_STATUS', `Routing endpoint returned HTTP ${response.status}`);
      }
      let text;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
      catch { throw failure('UTF8', 'Routing response is not valid UTF-8'); }
      const parsed = parseProviders(text, receipt.contentType ?? '');
      receipt.parsed = true;
      receipt.format = parsed.format;
      Object.assign(receipt, providerMatch(parsed.providers, { providerId, address }));
    })()]);
  } catch (error) {
    receipt.error = {
      code: timedOut ? 'TIMEOUT' : error.code ?? error.cause?.code ?? 'REQUEST_ERROR',
      message: timedOut ? 'Routing request exceeded 15 seconds' : String(error.message ?? 'Routing request failed').slice(0, 1024),
    };
    receipt.exactProviderMatch = false;
    controller.abort();
    reader?.cancel().catch(() => {});
  } finally {
    clearTimeout(timer);
    receipt.finishedAtUtc = new Date().toISOString();
    receipt.durationMs = Date.now() - started;
  }
  return receipt;
}

export function providerDetails(data) {
  if (!data || typeof data.root !== 'string' || typeof data.providerId !== 'string' ||
      typeof data.blocks !== 'object' || data.blocks === null || Array.isArray(data.blocks)) {
    throw new Error('Expected approved root, provider identity and block map');
  }
  const keys = Object.keys(data.blocks);
  if (keys.length < 1 || keys.length > 64 || !Object.hasOwn(data.blocks, data.root)) throw new Error('Expected 1..64 blocks including root');
  const hashes = new Set();
  for (const key of keys) {
    if (key.length > 120) throw new Error('Content CID exceeds bound');
    const cid = CID.parse(key);
    if (cid.version !== 1 || cid.toV1().toString() !== key || ![0x55, 0x70].includes(cid.code) ||
        cid.multihash.code !== 0x12 || cid.multihash.digest.length !== 32) throw new Error('Expected canonical SHA-256 raw/DAG-PB CIDs');
    const hash = Buffer.from(cid.multihash.bytes).toString('hex');
    if (hashes.has(hash)) throw new Error('Expected distinct content multihashes');
    hashes.add(hash);
  }
  if (data.providerId.length > 120) throw new Error('Provider identity exceeds bound');
  const peer = peerIdFromString(data.providerId);
  if (peer.type !== 'Ed25519' || peer.toString() !== data.providerId) throw new Error('Expected canonical Ed25519 provider identity');
  if (data.providerHost === undefined && data.root !== ROOT) throw new Error('New publications must supply an explicit providerHost');
  const providerHost = validateProviderHost(data.providerHost === undefined ? HISTORICAL_PROVIDER_HOST : data.providerHost);
  const address = `/dns4/${providerHost}/tcp/443/tls/http`;
  return { root: data.root, cids: [data.root, ...keys.filter(cid => cid !== data.root).sort()],
    providerId: data.providerId, providerHost, address, base: `https://${providerHost}`, blockCount: keys.length };
}

export async function checkDiscovery(data, options = {}) {
  const details = providerDetails(data);
  const { cids } = details;
  const matchOptions = { ...options, providerId: details.providerId, address: details.address };
  const receipt = {
    schemaVersion: 'signalxHttpProviderDiscoveryV1', startedAtUtc: new Date().toISOString(),
    root: details.root, providerId: details.providerId, providerHost: details.providerHost,
    boundAddress: details.address, requiredProtocol: PROTOCOL, blockCount: cids.length,
    triggerOrigin: 'project_controlled_public_routing_check', maximumRequests: 2 * cids.length, retries: 0,
    scope: 'Provider records only; no dial, content retrieval, origin outage test, pin or new announcement.',
    nativeBitswapVerified: false, publicDhtServerDutyVerified: false,
    ordinaryClientRetrievalVerified: false, organicUseVerified: false, routes: [],
  };
  // Independent routers are checked concurrently; follow-up checks on each
  // router occur once, sequentially, only after that router's exact root match.
  receipt.routes = await Promise.all(ROUTES.map(async route => {
    const root = await lookup(route.base, details.root, matchOptions);
    const results = [root];
    if (root.exactProviderMatch) {
      for (const cid of cids.slice(1)) results.push(await lookup(route.base, cid, matchOptions));
    }
    return {
      id: route.id, base: route.base, rootProviderMatched: root.exactProviderMatch,
      followupBlocksChecked: results.length - 1,
      allProviderRecordsVerified: results.length === cids.length && results.every(r => r.exactProviderMatch),
      allFiveProviderRecordsVerified: cids.length === 5 && results.length === 5 && results.every(r => r.exactProviderMatch),
      requests: results,
    };
  }));
  receipt.requestCount = receipt.routes.reduce((sum, route) => sum + route.requests.length, 0);
  receipt.allProviderRecordsVerified = receipt.routes.every(route => route.allProviderRecordsVerified);
  receipt.anyRouteHasExactRoot = receipt.routes.some(route => route.rootProviderMatched);
  receipt.anyRouteHasAllBlocks = receipt.routes.some(route => route.allProviderRecordsVerified);
  receipt.ipniHasAllBlocks = receipt.routes.find(route => route.id === 'ipni').allProviderRecordsVerified;
  receipt.anyRouteHasAllFive = receipt.routes.some(route => route.allFiveProviderRecordsVerified);
  receipt.ipniHasAllFive = receipt.routes.find(route => route.id === 'ipni').allFiveProviderRecordsVerified;
  receipt.defaultRoutingDiscoveryVerified = receipt.routes.find(route => route.id === 'default_delegated_router').allProviderRecordsVerified;
  receipt.finishedAtUtc = new Date().toISOString();
  return receipt;
}

async function main(args) {
  const [dataPath, outputPath] = args;
  if (!dataPath || !outputPath || args.length !== 2) throw new Error('Supply deployed public data and a new routing receipt path');
  const raw = await readFile(dataPath);
  if (raw.length > 2097152) throw new Error('Deployment data exceeds bound');
  const receipt = await checkDiscovery(JSON.parse(raw));
  await writeFile(outputPath, `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({
    receiptPath: resolve(outputPath), requestCount: receipt.requestCount,
    ipniHasAllBlocks: receipt.ipniHasAllBlocks, ipniHasAllFive: receipt.ipniHasAllFive,
    defaultRoutingDiscoveryVerified: receipt.defaultRoutingDiscoveryVerified,
    routes: receipt.routes.map(route => ({
      id: route.id, allProviderRecordsVerified: route.allProviderRecordsVerified,
      allFiveProviderRecordsVerified: route.allFiveProviderRecordsVerified,
      requests: route.requests.map(({ cid, status, exactProviderMatch, error }) => ({ cid, status, exactProviderMatch, error })),
    })),
  }));
  if (!receipt.anyRouteHasAllBlocks) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
}
