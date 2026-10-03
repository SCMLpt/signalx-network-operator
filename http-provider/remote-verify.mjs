import http2 from 'node:http2';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { CID } from 'multiformats/cid';
import * as digest from 'multiformats/hashes/digest';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { graphManifest } from '../live-evidence.mjs';
import { providerDetails } from './discovery-check.mjs';

export async function verifyRemote(data) {
const details = providerDetails(data);
const { base } = details;
if (typeof data.carBase64 !== 'string' || data.carBase64.length > Math.ceil(1048576 / 3) * 4) throw new Error('Qualified CAR exceeds bound');
const sourceCar = Buffer.from(data.carBase64, 'base64');
if (sourceCar.toString('base64') !== data.carBase64 || sourceCar.length > 1048576) throw new Error('Invalid qualified CAR');
const sourceGraph = await graphManifest(sourceCar, data.root);
if (!sourceGraph.complete || sourceGraph.reachableBlockCount !== details.blockCount || sourceGraph.blockCount !== details.blockCount ||
    data.verification?.graphDigest !== undefined && data.verification.graphDigest !== sourceGraph.graphDigest) throw new Error('Qualified graph does not match dataset');
for (const block of sourceGraph.blocks) {
  if (!Object.hasOwn(data.blocks, block.cid) || typeof data.blocks[block.cid] !== 'string') throw new Error('Qualified graph block is absent');
  const bytes = Buffer.from(data.blocks[block.cid], 'base64');
  if (bytes.toString('base64') !== data.blocks[block.cid] || bytes.length !== block.bytes ||
      createHash('sha256').update(bytes).digest('hex') !== block.sha256) throw new Error('Dataset block differs from qualified graph');
}
const report = {
  startedAtUtc: new Date().toISOString(),
  base,
  root: data.root,
  providerId: data.providerId,
  providerHost: details.providerHost,
  qualifiedBlockCount: details.blockCount,
  qualifiedGraphDigest: sourceGraph.graphDigest,
  triggerOrigin: 'project_controlled_external_http_verification',
  maximumTotalResponseBytes: 1048576,
  maximumDurationMs: 45000,
  maximumRequests: details.blockCount + 6,
  nativeBitswapVerified: false,
  publicDhtServerDutyVerified: false,
  ordinaryProviderDiscoveryVerified: false,
  organicUseVerified: false,
  requests: [],
};
let totalBytes = 0;
let requestAttempts = 0;
const session = http2.connect(base);
const globalTimer = setTimeout(() => session.destroy(new Error('Finite verification deadline exceeded')), 45000);
session.on('error', () => {});

function request(path, { method = 'GET', accept = '*/*', extraHeaders = {} } = {}) {
  return new Promise((resolve, reject) => {
    if (++requestAttempts > report.maximumRequests) return reject(new Error('Finite verification request cap exceeded'));
    const stream = session.request({ ':path': path, ':method': method, accept, 'accept-encoding': 'identity', ...extraHeaders });
    const started = Date.now();
    const chunks = [];
    let settled = false;
    let headers;
    const timer = setTimeout(() => stream.close(http2.constants.NGHTTP2_CANCEL), 10000);
    stream.on('response', value => { headers = value; });
    stream.on('data', bytes => {
      totalBytes += bytes.length;
      if (totalBytes > report.maximumTotalResponseBytes) {
        session.destroy(new Error('Finite verification byte cap exceeded'));
        return;
      }
      chunks.push(bytes);
    });
    stream.on('error', error => { settled = true; clearTimeout(timer); reject(error); });
    stream.on('close', () => { if (!settled) { settled = true; clearTimeout(timer); reject(new Error('HTTP/2 stream closed before a complete response')); } });
    stream.on('end', () => {
      settled = true;
      clearTimeout(timer);
      if (!headers || stream.rstCode !== 0) return reject(new Error('Incomplete HTTP/2 response'));
      const body = Buffer.concat(chunks);
      const item = {
        method, path,
        status: headers[':status'],
        bytes: body.length,
        contentType: headers['content-type'] ?? null,
        contentLength: headers['content-length'] ?? null,
        etag: headers.etag ?? null,
        cors: headers['access-control-allow-origin'] ?? null,
        cacheControl: headers['cache-control'] ?? null,
        responseSha256: createHash('sha256').update(body).digest('hex'),
        durationMs: Date.now() - started,
      };
      report.requests.push(item);
      resolve({ headers, body, item });
    });
  });
}

try {
  await new Promise((resolve, reject) => { session.once('connect', resolve); session.once('error', reject); });
  report.alpn = session.socket.alpnProtocol;
  if (report.alpn !== 'h2') throw new Error('The provider did not negotiate HTTP/2.');
  const health = await request('/health', { accept: 'application/json' });
  if (health.item.status !== 200) throw new Error('Provider health request failed.');
  report.health = JSON.parse(health.body);
  if (report.health.root !== data.root || report.health.providerId !== data.providerId || report.health.contentAvailable !== true) throw new Error('Deployed provider metadata differs from dataset.');
  const probe = await request('/ipfs/bafkqaaa?format=raw', { accept: 'application/vnd.ipld.raw' });
  if (probe.item.status !== 200 || probe.body.length !== 0) throw new Error('IPFS HTTP connectivity probe failed.');
  for (const cid of details.cids) {
    const encoded = data.blocks[cid];
    const raw = await request(`/ipfs/${cid}?format=raw`, { accept: 'application/vnd.ipld.raw' });
    const digest = createHash('sha256').update(raw.body).digest();
    const expected = Buffer.from(encoded, 'base64');
    if (raw.item.status !== 200 || !/^application\/vnd\.ipld\.raw(?:\s*;|$)/i.test(raw.item.contentType ?? '') ||
        raw.item.cors !== '*' || Number(raw.item.contentLength) !== expected.length ||
        !raw.body.equals(expected) || !digest.equals(Buffer.from(CID.parse(cid).multihash.digest))) {
      throw new Error(`Original block did not verify from deployed provider: ${cid}`);
    }
  }
  const car = await request(`/ipfs/${data.root}?format=car&dag-scope=all`, { accept: 'application/vnd.ipld.car' });
  if (car.item.status !== 200 || !/^application\/vnd\.ipld\.car(?:\s*;|$)/i.test(car.item.contentType ?? '')) throw new Error('Whole-publication CAR request failed.');
  const graph = await graphManifest(car.body, data.root);
  if (graph.graphDigest !== sourceGraph.graphDigest || graph.reachableBlockCount !== details.blockCount ||
      graph.blockCount !== details.blockCount || !graph.complete) throw new Error('Deployed publication graph differs from qualified original.');
  report.receivedGraph = graph;
  const head = await request(`/ipfs/${data.root}?format=raw`, { method: 'HEAD', accept: 'application/vnd.ipld.raw' });
  if (head.item.status !== 200 || head.body.length !== 0 || head.item.etag !== `"${data.root}"` ||
      Number(head.item.contentLength) !== Buffer.from(data.blocks[data.root], 'base64').length) throw new Error('HEAD response is incorrect.');
  const conditional = await request(`/ipfs/${data.root}?format=raw`, { accept: 'application/vnd.ipld.raw', extraHeaders: { 'if-none-match': head.item.etag } });
  if (conditional.item.status !== 304 || conditional.body.length !== 0) throw new Error('Conditional raw-block response is incorrect.');
  let unknownCid; let nonce = 0;
  do {
    unknownCid = CID.createV1(0x55, digest.create(0x12, createHash('sha256').update(`unapproved:${data.root}:${nonce++}`).digest())).toString();
  } while (Object.hasOwn(data.blocks, unknownCid));
  const unknown = await request(`/ipfs/${unknownCid}?format=raw`, { accept: 'application/vnd.ipld.raw' });
  if (unknown.item.status !== 404) throw new Error('Provider did not reject an unapproved block.');
  report.controlledCompleteHttpDeliveryVerified = true;
  report.originalRawBlocksVerified = true;
  report.verifiedRawBlockCount = details.blockCount;
  report.originalFiveRawBlocksVerified = details.blockCount === 5;
  report.identityProbeVerified = true;
  report.headAndConditionalVerified = true;
} catch (error) {
  report.controlledCompleteHttpDeliveryVerified = false;
  report.error = String(error.message);
  report.originalRawBlocksVerified = false;
  report.originalFiveRawBlocksVerified = false;
} finally {
  clearTimeout(globalTimer);
  session.destroy();
  report.finishedAtUtc = new Date().toISOString();
  report.totalResponseBytes = totalBytes;
  report.requestAttempts = requestAttempts;
}
return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [outputPath, dataPath] = process.argv.slice(2);
  if (!outputPath || process.argv.length > 4) throw new Error('Supply new receipt path and optional public dataset path');
  const raw = await readFile(dataPath ?? new URL('./deployment-data.json', import.meta.url));
  if (raw.length > 2097152) throw new Error('Deployment data exceeds bound');
  const report = await verifyRemote(JSON.parse(raw));
  await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ base: report.base, alpn: report.alpn, completeHttpDeliveryVerified: report.controlledCompleteHttpDeliveryVerified,
    rawBlocksVerified: report.originalRawBlocksVerified, blockCount: report.qualifiedBlockCount,
    requests: report.requestAttempts, totalResponseBytes: report.totalResponseBytes, error: report.error }));
  if (!report.controlledCompleteHttpDeliveryVerified) process.exitCode = 1;
}
