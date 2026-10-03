import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import * as dagCbor from '@ipld/dag-cbor';
import { CID } from 'multiformats/cid';
import { multiaddr } from '@multiformats/multiaddr';
import { providerDetails, ROOT } from './discovery-check.mjs';
import { prepareRequest, verifyPublicBundle, HISTORICAL_PROVIDER_HOST, validateProviderHost } from './ipni-build.mjs';

const announceUrl = 'https://cid.contact/ingest/announce';

function publicBytes(encoded, maximum) {
  if (typeof encoded !== 'string' || encoded.length > Math.ceil(maximum / 3) * 4) throw new Error('Public IPNI body exceeds bound');
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length === 0 || bytes.length > maximum || bytes.toString('base64') !== encoded) throw new Error('Invalid public IPNI base64 body');
  return bytes;
}

export async function boundedRequest(url, options = {}, limit = 262144, { fetchImpl = globalThis.fetch } = {}) {
  const response = await fetchImpl(url, { ...options, credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(15000) });
  const chunks = [];
  let size = 0;
  const reader = response.body?.getReader();
  if (reader) {
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > limit) throw new Error('Public response exceeds byte bound');
        chunks.push(value);
      }
    } catch (error) { await reader.cancel().catch(() => {}); throw error; }
    finally { reader.releaseLock(); }
  }
  return { status: response.status, contentType: response.headers.get('content-type'), bytes: Buffer.concat(chunks, size) };
}

export async function validateActivation(bundle, data) {
  const details = providerDetails(data);
  const prepared = await prepareRequest(data);
  if (!bundle?.request || bundle.providerId !== details.providerId || bundle.request.providerId !== details.providerId ||
      bundle.request.rootCid !== details.root) throw new Error('Public provider identity mismatch');
  if (bundle.request.providerHost === undefined && bundle.request.rootCid !== ROOT) throw new Error('Bundle must bind an explicit provider host');
  const bundleHost = validateProviderHost(bundle.request.providerHost === undefined ? HISTORICAL_PROVIDER_HOST : bundle.request.providerHost);
  if (bundleHost !== details.providerHost || !isDeepStrictEqual({ ...bundle.request, providerHost: bundleHost }, prepared.request)) {
    throw new Error('Signed publication request differs from deployed dataset or provider host');
  }
  if (!Array.isArray(bundle.objects) || bundle.objects.length < 1 || bundle.objects.length > 66 ||
      !bundle.activeHead?.cid || data.ipni?.headBase64 !== bundle.activeHead.bodyBase64) throw new Error('Deployed IPNI data differs from public bundle');
  const adds = bundle.objects.filter(object => object.cid === bundle.activeHead.cid);
  if (adds.length !== 1) throw new Error('Expected one signed addition advertisement');
  const object = adds[0];
  const objectBytes = publicBytes(object.bodyBase64, 65536);
  const objectCid = CID.parse(object.cid);
  if (object.contentType !== 'application/vnd.ipld.dag-cbor' || objectCid.version !== 1 || objectCid.toString() !== object.cid || objectCid.code !== dagCbor.code ||
      objectCid.multihash.code !== 0x12 || !createHash('sha256').update(objectBytes).digest().equals(Buffer.from(objectCid.multihash.digest))) {
    throw new Error('Signed addition object does not match its CID');
  }
  const ad = dagCbor.decode(objectBytes);
  if (ad.Provider !== details.providerId || ad.IsRm !== false || !Array.isArray(ad.Addresses) ||
      ad.Addresses.length !== 1 || ad.Addresses[0] !== details.address) throw new Error('Signed provider address differs from deployed host');
  const messageBytes = publicBytes(bundle.addAnnouncement?.bodyBase64, 16384);
  if (bundle.addAnnouncement?.contentType !== 'application/json' ||
      bundle.addAnnouncement?.adCid !== bundle.activeHead.cid) throw new Error('Invalid addition announcement');
  const message = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(messageBytes));
  if (message.Cid?.['/'] !== bundle.activeHead.cid || !Array.isArray(message.Addrs) || message.Addrs.length !== 1 ||
      multiaddr(Buffer.from(message.Addrs[0], 'base64')).toString() !== `${details.address}/p2p/${details.providerId}`) {
    throw new Error('Announcement address differs from deployed provider');
  }
  return details;
}

export async function announce(bundle, data, { fetchImpl = globalThis.fetch, now = Date.now,
    verifyBundle = verifyPublicBundle, goBinary, goPath, goCache } = {}) {
  const details = await validateActivation(bundle, data);
  const sdk = await verifyBundle(bundle, { goBinary, goPath, goCache });
  if (sdk?.verified !== true || sdk.handlerMappingVerified !== true || sdk.providerId !== details.providerId ||
      sdk.providerHost !== details.providerHost || sdk.entryCount !== details.blockCount || sdk.addCid !== bundle.activeHead.cid ||
      sdk.removalCid !== (bundle.removalHead?.cid ?? null)) throw new Error('Public SDK verification differs from approved publication');
  const start = Date.parse(data.startedAtUtc); const end = Date.parse(data.termEndUtc);
  function termCheck() {
    const clock = now();
    if (!Number.isSafeInteger(clock) || clock < start || data.servingMode !== 'continuous' && clock >= end) throw new Error('Outside approved serving policy');
  }
  termCheck();
  const { base } = details;
  const bounded = (url, options, limit) => boundedRequest(url, options, limit, { fetchImpl });
  if (data.servingMode === 'continuous') {
    const health = await bounded(`${base}/health`, {}, 16384);
    let policy;
    try { policy = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(health.bytes)); }
    catch { throw new Error('Deployed continuous serving policy is unavailable'); }
    if (health.status !== 200 || policy?.root !== details.root || policy.providerId !== details.providerId ||
        policy.servingMode !== 'continuous' || policy.termEndUtc !== null || policy.startedAtUtc !== data.startedAtUtc ||
        policy.contentAvailable !== true || policy.ipni?.configured !== true || policy.ipni.head !== 'active') {
      throw new Error('Deployed continuous serving policy differs from approved publication');
    }
  }
  const head = await bounded(`${base}/ipni/v1/ad/head`, {}, 16384);
  if (head.status !== 200 || !head.bytes.equals(Buffer.from(bundle.activeHead.bodyBase64, 'base64'))) throw new Error('Deployed signed head mismatch');
  for (const object of bundle.objects.filter(object => object.cid !== bundle.removalHead?.cid)) {
    const fetched = await bounded(`${base}/ipni/v1/ad/${object.cid}`, {}, 65536);
    if (fetched.status !== 200 || !fetched.bytes.equals(Buffer.from(object.bodyBase64, 'base64'))) throw new Error('Deployed signed object mismatch');
  }
  termCheck();
  const result = await bounded(announceUrl, {
    method: 'PUT', headers: { 'Content-Type': bundle.addAnnouncement.contentType },
    body: Buffer.from(bundle.addAnnouncement.bodyBase64, 'base64'),
  }, 4096);
  return {
    recordedAtUtc: new Date().toISOString(), destination: announceUrl,
    providerId: data.providerId, providerHost: details.providerHost, boundAddress: details.address,
    root: data.root, addCid: bundle.activeHead.cid,
    deployedSignedObjectsVerified: true, status: result.status,
    deployedContinuousServingPolicyVerified: data.servingMode === 'continuous',
    publicBundleSdkVerification: sdk,
    response: result.bytes.toString('utf8'),
    admissionAccepted: result.status >= 200 && result.status < 300,
    indexed: false, ordinaryDiscoveryVerified: false, independentUseVerified: false,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [bundlePath, dataPath, output, ...runtimeArgs] = process.argv.slice(2);
  if (!bundlePath || !dataPath || !output) throw new Error('Supply public bundle, deployed public data and new receipt path');
  const runtime = {};
  const fields = { '--go': 'goBinary', '--go-path': 'goPath', '--go-cache': 'goCache' };
  for (let i = 0; i < runtimeArgs.length; i += 2) {
    const field = fields[runtimeArgs[i]];
    if (!field || !runtimeArgs[i + 1] || Object.hasOwn(runtime, field)) throw new Error('Optional runtime flags: --go EXECUTABLE --go-path GOPATH --go-cache GOCACHE');
    runtime[field] = runtimeArgs[i + 1];
  }
  const bundle = JSON.parse(await readFile(bundlePath, 'utf8'));
  const data = JSON.parse(await readFile(dataPath, 'utf8'));
  const receipt = await announce(bundle, data, runtime);
  await writeFile(output, `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify(receipt));
  if (!receipt.admissionAccepted) process.exitCode = 1;
}
