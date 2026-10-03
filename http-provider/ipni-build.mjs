import { readFile, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { CarReader } from '@ipld/car';
import { CID } from 'multiformats/cid';
import { peerIdFromString } from '@libp2p/peer-id';
import { verifyCar } from '../car.mjs';

export const ROOT = 'bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle';
export const HISTORICAL_PROVIDER_HOST = 'signalx-ipfs-provider.kamuitranslator.workers.dev';
const MAX_CAR_BYTES = 1048576;
const MAX_BLOCKS = 64;
const here = dirname(fileURLToPath(import.meta.url));
const referenceDirectory = resolve(here, 'ipni-reference');

function decodeBase64(value, allowEmpty = false) {
  if (typeof value !== 'string' || (!allowEmpty && !value.length) || value.length > 1400000 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('Expected bounded canonical base64 bytes');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) throw new Error('Expected bounded canonical base64 bytes');
  return bytes;
}

// Supply a canonical ASCII public DNS name. HTTPS on port 443 is fixed in the
// signed addresses; URLs, IP literals and local/reserved namespaces are refused.
export function validateProviderHost(value) {
  const reserved = ['localhost', 'local', 'internal', 'test', 'invalid', 'example', 'onion', 'arpa', 'example.com', 'example.net', 'example.org'];
  if (typeof value !== 'string' || value.length > 253 || value !== value.toLowerCase() ||
      value.split('.').length < 2 || value.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
      !/^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/.test(value.split('.').at(-1)) ||
      reserved.some(suffix => value === suffix || value.endsWith(`.${suffix}`))) {
    throw new Error('Provider host must be a canonical public DNS hostname for HTTPS on port 443');
  }
  return value;
}

// Check the deployed map against the hash-verified complete CAR before handing
// only its public content identifiers, hostname, identity and term to the signer.
export async function prepareRequest(data) {
  if (!data || typeof data.root !== 'string' || data.root.length > 120 || typeof data.blocks !== 'object' || data.blocks === null || Array.isArray(data.blocks)) {
    throw new Error('Expected an original complete publication CAR and exact block map');
  }
  const root = CID.parse(data.root).toV1();
  if (data.providerHost === undefined && root.toString() !== ROOT) throw new Error('New publications must supply an explicit providerHost');
  const providerHost = validateProviderHost(data.providerHost === undefined ? HISTORICAL_PROVIDER_HOST : data.providerHost);
  if (typeof data.providerId !== 'string' || data.providerId.length > 120) throw new Error('Expected a canonical Ed25519 provider identity');
  const provider = peerIdFromString(data.providerId);
  if (provider.toString() !== data.providerId || provider.type !== 'Ed25519') throw new Error('Expected a canonical Ed25519 provider identity');
  if (typeof data.startedAtUtc !== 'string' || typeof data.termEndUtc !== 'string' || data.startedAtUtc.length > 64 || data.termEndUtc.length > 64) throw new Error('Serving term must contain bounded timestamp strings');
  const archive = decodeBase64(data.carBase64);
  const verified = await verifyCar(archive, data.root, { maxBytes: MAX_CAR_BYTES, maxBlocks: MAX_BLOCKS, maxLinks: 4096 });
  const mappedCids = Object.keys(data.blocks);
  if (mappedCids.length < 1 || mappedCids.length > MAX_BLOCKS || verified.reachableBlockCount !== mappedCids.length || verified.blockCount !== mappedCids.length) {
    throw new Error('Expected 1 to 64 distinct original reachable blocks and no duplicate CAR sections');
  }
  const reader = await CarReader.fromBytes(archive);
  const observed = new Set();
  const multihashes = new Set();
  for await (const block of reader.blocks()) {
    const cid = block.cid.toV1().toString();
    const hash = block.cid.multihash;
    const hashKey = Buffer.from(hash.bytes).toString('hex');
    if (hash.code !== 0x12 || hash.digest.length !== 32 || multihashes.has(hashKey)) throw new Error('Expected distinct SHA-256 content multihashes');
    multihashes.add(hashKey);
    if (!Object.hasOwn(data.blocks, cid) || !Buffer.from(block.bytes).equals(decodeBase64(data.blocks[cid], true))) {
      throw new Error('Deployment block map differs from verified original CAR');
    }
    observed.add(cid);
  }
  if (observed.size !== mappedCids.length || mappedCids.some(cid => !observed.has(cid)) || !observed.has(root.toString())) throw new Error('Deployment block identity mismatch');
  const start = Date.parse(data.startedAtUtc);
  const end = Date.parse(data.termEndUtc);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end - start > 7 * 86400000) {
    throw new Error('Serving term must be positive and at most seven days');
  }
  return {
    request: { rootCid: root.toString(), blockCids: [...observed].sort(), providerId: data.providerId, providerHost, activatedAt: data.startedAtUtc, expiresAt: data.termEndUtc },
    integrity: { carSha256: verified.sha256, carBytes: verified.byteLength, reachableBlocks: verified.reachableBlockCount },
  };
}

// Only the reference process opens the key file. Its output is a public bundle.
// Dependency resolution is locked, toolchain downloads disabled, build parallelism
// limited to one, and execution bounded. No daemon or network announce is started.
export function referenceRun(input, { keyPath, verify = false, goBinary = 'go', goPath, goCache } = {}) {
  if (verify && keyPath) throw new Error('Public verification must not receive a private key');
  if (!verify && (typeof keyPath !== 'string' || !keyPath)) throw new Error('A separate private provider key path is required');
  if (typeof goBinary !== 'string' || !goBinary || [goPath, goCache].some(value => value !== undefined && (typeof value !== 'string' || !value))) throw new Error('Invalid Go executable or cache path');
  const json = JSON.stringify(input);
  if (typeof json !== 'string' || Buffer.byteLength(json) > 131072) throw new Error('Reference input exceeds bound');
  const executable = goBinary.includes('/') || goBinary.includes('\\') ? resolve(goBinary) : goBinary;
  const args = ['run', '-p=1', '-mod=readonly', '.', ...(verify ? ['--verify'] : ['--key', resolve(keyPath)])];
  return new Promise((accept, reject) => {
    const processEnv = {
      ...process.env, GOMAXPROCS: '1', GOTOOLCHAIN: 'local',
      ...(goPath === undefined ? {} : { GOPATH: resolve(goPath) }),
      ...(goCache === undefined ? {} : { GOCACHE: resolve(goCache) }),
    };
    const child = spawn(executable, args, { cwd: referenceDirectory, env: processEnv, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let errorOutput = '';
    let size = 0;
    let completed = false;
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(new Error('Reference builder timed out')); }, 120000);
    function finish(error, result) {
      if (completed) return;
      completed = true;
      clearTimeout(timer);
      if (error) reject(error); else accept(result);
    }
    child.on('error', () => finish(new Error('Reference Go executable unavailable')));
    child.stdin.on('error', () => {});
    child.stdout.on('data', part => {
      size += part.length;
      if (size > 131072) { child.kill('SIGKILL'); finish(new Error('Reference output exceeds bound')); return; }
      out += part.toString('utf8');
    });
    child.stderr.on('data', part => { if (errorOutput.length < 4096) errorOutput += part.toString('utf8').slice(0, 4096 - errorOutput.length); });
    child.on('close', code => {
      if (code !== 0) { finish(new Error(`Reference operation failed (${code}): ${errorOutput.trim()}`)); return; }
      try { finish(null, JSON.parse(out)); } catch { finish(new Error('Invalid reference public JSON output')); }
    });
    child.stdin.end(json);
  });
}

export function handlerIPNI(bundle) {
  const objects = {};
  const removalObjects = {};
  for (const object of bundle.objects) {
    const target = object.cid === bundle.removalHead.cid ? removalObjects : objects;
    target[object.cid] = { bodyBase64: object.bodyBase64, contentType: object.contentType };
  }
  return {
    headBase64: bundle.activeHead.bodyBase64, objects,
    removalHeadBase64: bundle.removalHead.bodyBase64, removalObjects,
  };
}

export async function buildBundle(data, keyPath, options = {}) {
  const { request, integrity } = await prepareRequest(data);
  const bundle = await referenceRun(request, { ...options, keyPath, verify: false });
  if (!isDeepStrictEqual(bundle.request, request)) throw new Error('Signed bundle differs from the verified publication request');
  await referenceRun(bundle, { ...options, keyPath: undefined, verify: true });
  return { ...bundle, sourceIntegrity: integrity, ipni: handlerIPNI(bundle) };
}

export async function verifyPublicBundle(bundle, options = {}) {
  validateProviderHost(bundle?.request?.providerHost === undefined ? HISTORICAL_PROVIDER_HOST : bundle.request.providerHost);
  const result = await referenceRun(bundle, { ...options, verify: true });
  if (!isDeepStrictEqual(bundle.ipni, handlerIPNI(bundle))) throw new Error('HTTP handler mapping differs from signed public objects');
  return { ...result, handlerMappingVerified: true };
}

async function main(args) {
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!['--data', '--key', '--output', '--verify', '--go', '--go-path', '--go-cache'].includes(args[i]) || !args[i + 1] || Object.hasOwn(options, args[i])) throw new Error('Use --data DATA.json --key PRIVATE.pb --output PUBLIC.json, or --verify PUBLIC.json; optional --go EXECUTABLE --go-path GOPATH --go-cache GOCACHE');
    options[args[i]] = args[i + 1];
  }
  const runtime = { ...(options['--go'] ? { goBinary: options['--go'] } : {}), ...(options['--go-path'] ? { goPath: options['--go-path'] } : {}), ...(options['--go-cache'] ? { goCache: options['--go-cache'] } : {}) };
  if (options['--verify']) {
    if (options['--data'] || options['--key'] || options['--output']) throw new Error('Public verification takes --verify and optional Go runtime paths only');
    const raw = await readFile(options['--verify']);
    if (raw.length > 131072) throw new Error('Public bundle exceeds bound');
    const result = await verifyPublicBundle(JSON.parse(raw), runtime);
    console.log(JSON.stringify(result));
    return;
  }
  if (!options['--data'] || !options['--key'] || !options['--output']) throw new Error('Missing build input or output');
  const raw = await readFile(options['--data']);
  if (raw.length > 3145728) throw new Error('Deployment input exceeds bound');
  const bundle = await buildBundle(JSON.parse(raw), options['--key'], runtime);
  await writeFile(options['--output'], `${JSON.stringify(bundle, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
  console.log(JSON.stringify({ publicBundleWritten: true, providerId: bundle.providerId, providerHost: bundle.request.providerHost, entries: bundle.request.blockCids.length, addCid: bundle.activeHead.cid, removalCid: bundle.removalHead.cid }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
}
