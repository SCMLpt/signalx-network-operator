import { constants } from 'node:fs';
import { open, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { CarReader } from '@ipld/car';
import { graphManifest } from '../live-evidence.mjs';
import { verifyCar } from '../car.mjs';
import { CID } from 'multiformats/cid';

export const ROOT = 'bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle';
export const CAR_SHA256 = 'd79dd33f1717beed7d7152f61170c06f318529edf193277c997a576663007078';
export const GRAPH_DIGEST = 'a90b275e228caf15f85b2425ddec07f779d362ff7efe02e044965f5c2e747647';

const MAX_CAR_BYTES = 1048576;
const MAX_BLOCKS = 64;
const DEFAULT_HOST = 'signalx-ipfs-provider.kamuitranslator.workers.dev';
const originalAttribution = {
  title: 'FS Meteor log and coordination log between RV METEOR and other platforms during BOWTIE',
  creators: ['Hans Segura', 'Allison A. Wing'], project: 'ORCESTRA / BOWTIE',
  source: `https://ipfs.orcestra-campaign.org/ipfs/${ROOT}/`,
  license: 'CC-BY-4.0', licenseUrl: 'https://creativecommons.org/licenses/by/4.0/',
  changes: 'Unmodified original content-addressed blocks and original CAR representation',
};

function qualifiedPublication(options) {
  const root = options.root ?? ROOT;
  const cid = CID.parse(root);
  if (cid.toV1().toString() !== root || cid.multihash.code !== 18 || cid.multihash.digest.length !== 32) throw new Error('Expected canonical SHA-256 root CID.');
  const original = root === ROOT;
  const carSha256 = options.carSha256 ?? (original ? CAR_SHA256 : null);
  if (!/^[0-9a-f]{64}$/.test(carSha256 ?? '')) throw new Error('Explicit original CAR SHA-256 required.');
  const attribution = options.attribution ?? (original ? originalAttribution : null);
  if (!attribution || typeof attribution !== 'object' || Array.isArray(attribution) ||
      !['title','source','license','changes'].every(key => typeof attribution[key] === 'string' && attribution[key].length > 0 && attribution[key].length <= 2000) ||
      !Array.isArray(attribution.creators) || !attribution.creators.length || attribution.creators.length > 32 ||
      attribution.creators.some(value => typeof value !== 'string' || !value.length || value.length > 200) ||
      Buffer.byteLength(JSON.stringify(attribution)) > 8192) throw new Error('Explicit bounded publisher attribution required.');
  const source = new URL(attribution.source);
  if (source.protocol !== 'https:' || source.username || source.password) throw new Error('Publisher source must be public HTTPS without credentials.');
  const providerHost = options.providerHost ?? DEFAULT_HOST;
  if (typeof providerHost !== 'string' || providerHost.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(providerHost)) throw new Error('Expected canonical public provider DNS hostname.');
  const expected = {
    carBytes: options.carBytes ?? (original ? 166374 : null),
    blocks: options.expectedBlocks ?? (original ? 5 : null),
    payloadBytes: options.payloadBytes ?? (original ? 166123 : null),
    graphDigest: options.graphDigest ?? (original ? GRAPH_DIGEST : null),
  };
  if (expected.carBytes !== null && (!Number.isSafeInteger(expected.carBytes) || expected.carBytes < 1 || expected.carBytes > MAX_CAR_BYTES) ||
      expected.blocks !== null && (!Number.isSafeInteger(expected.blocks) || expected.blocks < 1 || expected.blocks > MAX_BLOCKS) ||
      expected.payloadBytes !== null && (!Number.isSafeInteger(expected.payloadBytes) || expected.payloadBytes < 0 || expected.payloadBytes > MAX_CAR_BYTES) ||
      expected.graphDigest !== null && !/^[0-9a-f]{64}$/.test(expected.graphDigest)) throw new Error('Invalid qualification bounds.');
  return { root, carSha256, attribution: JSON.parse(JSON.stringify(attribution)), providerHost, expected };
}

async function boundedRegular(path, maximum, expectedSize = null) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size < 1 || before.size > maximum || expectedSize !== null && before.size !== expectedSize) throw new Error('Expected a bounded qualified regular file.');
    const buffer = Buffer.alloc(before.size + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, size);
      if (!bytesRead) break;
      size += bytesRead;
    }
    const after = await handle.stat();
    if (size !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
      throw new Error('Qualified file changed during read.');
    }
    return buffer.subarray(0, size);
  } finally { await handle.close(); }
}

export async function buildDataset(path, options) {
  const { startedAtUtc, termEndUtc, servingMode } = options;
  const publication = qualifiedPublication(options);
  const start = Date.parse(startedAtUtc);
  const end = Date.parse(termEndUtc);
  if (!Number.isFinite(start) || new Date(start).toISOString() !== startedAtUtc ||
      servingMode !== undefined && !['finite', 'continuous'].includes(servingMode)) {
    throw new Error('A canonical activation timestamp and valid serving mode are required.');
  }
  if (servingMode === 'continuous' ? termEndUtc !== null :
      !Number.isFinite(end) || new Date(end).toISOString() !== termEndUtc || end <= start || end - start > 7 * 86400000) {
    throw new Error('Continuous serving requires null expiry; a finite term must be positive and at most seven days.');
  }
  const bytes = await boundedRegular(path, MAX_CAR_BYTES, publication.expected.carBytes);
  if (createHash('sha256').update(bytes).digest('hex') !== publication.carSha256) throw new Error('Qualified CAR digest mismatch.');
  await verifyCar(bytes, publication.root, { maxBytes: MAX_CAR_BYTES, maxBlocks: MAX_BLOCKS, maxLinks: 256 });
  const graph = await graphManifest(bytes, publication.root);
  const expected = publication.expected;
  if (!graph.complete || graph.reachableBlockCount !== graph.blockCount ||
      expected.blocks !== null && graph.reachableBlockCount !== expected.blocks ||
      expected.graphDigest !== null && graph.graphDigest !== expected.graphDigest ||
      expected.payloadBytes !== null && graph.nonInlinePayloadBytes !== expected.payloadBytes) {
    throw new Error('The publication graph differs from its qualified original.');
  }
  const reader = await CarReader.fromBytes(bytes);
  const blocks = {};
  for await (const block of reader.blocks()) {
    const cid = block.cid.toV1().toString();
    if (block.cid.multihash.code !== 18 || block.cid.multihash.digest.length !== 32) throw new Error('Only original SHA-256 blocks can be advertised.');
    if (Object.hasOwn(blocks, cid)) throw new Error('Unexpected duplicate block in the qualified CAR.');
    blocks[cid] = Buffer.from(block.bytes).toString('base64');
  }
  if (Object.keys(blocks).length !== graph.reachableBlockCount || !Object.hasOwn(blocks, publication.root)) throw new Error('Original block coverage mismatch.');
  return {
    root: publication.root,
    providerHost: publication.providerHost,
    carBase64: bytes.toString('base64'),
    blocks,
    startedAtUtc,
    termEndUtc,
    ...(servingMode === undefined ? {} : { servingMode }),
    providerId: null,
    ipni: null,
    attribution: publication.attribution,
    verification: {
      carBytes: bytes.length,
      carSha256: publication.carSha256,
      graphDigest: graph.graphDigest,
      blocks: graph.reachableBlockCount,
      payloadBytes: graph.nonInlinePayloadBytes,
      upstreamFetchOnRead: false,
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (![6, 7].includes(process.argv.length)) throw new Error('Usage: dataset-build.mjs ORIGINAL_CAR OUTPUT_JSON START_UTC END_UTC|continuous [QUALIFIED_PUBLICATION_JSON]');
  let publication = {};
  if (process.argv[6]) {
    publication = JSON.parse((await boundedRegular(process.argv[6], 16384)).toString('utf8'));
    if (!publication || typeof publication !== 'object' || Array.isArray(publication)) throw new Error('Invalid qualification input.');
  }
  const serving = process.argv[5] === 'continuous' ? { servingMode: 'continuous', termEndUtc: null } : { termEndUtc: process.argv[5] };
  const data = await buildDataset(process.argv[2], { ...publication, startedAtUtc: process.argv[4], ...serving });
  await writeFile(process.argv[3], `${JSON.stringify(data)}\n`, { flag: 'wx', mode: 0o644 });
  console.log(JSON.stringify({ root: data.root, ...data.verification, startedAtUtc: data.startedAtUtc, termEndUtc: data.termEndUtc }));
}
