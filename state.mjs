import { CID } from 'multiformats/cid';
import { compareIpnsRecords } from './ipns.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const HASH = /^[0-9a-f]{64}$/u;
const UINT64_MAX = (1n << 64n) - 1n;
const STATUS = new Set(['unverified', 'content_verified', 'locally_pinned']);
const CODECS = new Map([[0x55, 'raw'], [0x70, 'dag-pb'], [0x71, 'dag-cbor']]);
const UNSAFE_KEYS = new Set(['__proto__', 'prototype', ...Object.getOwnPropertyNames(Object.prototype)]);
const own = (value, key) => Object.hasOwn(value, key);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function corrupt(path, detail, cause) {
  throw Object.assign(new Error(`Operator state ${path}: ${detail}`, { cause }), { code: 'OPERATOR_STATE_CORRUPT' });
}

function requireValue(condition, path, detail) {
  if (!condition) corrupt(path, detail);
}

function count(value, path, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  requireValue(Number.isSafeInteger(value) && value >= minimum && value <= maximum, path, 'invalid bounded integer');
}

function timestamp(value, path) { count(value, path, 1); }
function hash(value, path) { requireValue(typeof value === 'string' && HASH.test(value), path, 'invalid SHA-256'); }
function uuid(value, path) { requireValue(typeof value === 'string' && UUID.test(value), path, 'invalid UUID'); }

function uint64(value, path) {
  requireValue(typeof value === 'string' && /^(0|[1-9]\d{0,19})$/u.test(value) &&
    BigInt(value) <= UINT64_MAX, path, 'invalid decimal uint64');
}

function rootCid(value, path) {
  requireValue(typeof value === 'string' && value.length > 0 && value.length <= 4096, path, 'invalid root CID');
  try { return CID.parse(value).toV1(); }
  catch (cause) { corrupt(path, 'invalid root CID', cause); }
}

function sameRoot(value, expected, path) {
  requireValue(rootCid(value, path).equals(rootCid(expected, path)), path, 'root differs from its publication or verified content');
}

function source(value, path) {
  requireValue(typeof value === 'string' && value.length > 0 && value.length <= 8192, path, 'invalid source URL');
  let url;
  try { url = new URL(value); }
  catch (cause) { corrupt(path, 'invalid source URL', cause); }
  requireValue(url.protocol === 'https:' && !url.username && !url.password && !url.hash, path, 'invalid source URL');
}

// The journal already checks JSON, but callers can also pass a draft or a test
// journal. Check descriptors before reading fields so inherited/accessor values
// cannot provide evidence or execute during validation.
function safeTree(value) {
  const ancestors = new Set();
  let nodes = 0;
  function visit(entry, path, depth, arrayEntry = false) {
    requireValue(++nodes <= 100_000 && depth <= 64, path, 'structure exceeds bounds');
    if (entry === undefined && !arrayEntry) return;
    if (entry === null || typeof entry === 'string' || typeof entry === 'boolean') return;
    if (typeof entry === 'number') {
      requireValue(Number.isFinite(entry) && (!Number.isInteger(entry) || Number.isSafeInteger(entry)), path, 'invalid JSON number');
      return;
    }
    requireValue(entry && typeof entry === 'object' && !ancestors.has(entry), path, 'invalid JSON value or cycle');
    const proto = Object.getPrototypeOf(entry);
    requireValue(proto === Object.prototype || proto === null || (Array.isArray(entry) && proto === Array.prototype),
      path, 'inherited state is unsafe');
    requireValue(Object.getOwnPropertySymbols(entry).length === 0, path, 'symbol state is unsafe');
    const descriptors = Object.getOwnPropertyDescriptors(entry);
    ancestors.add(entry);
    if (Array.isArray(entry)) {
      requireValue(Object.keys(descriptors).length === entry.length + 1, path, 'array has holes or extra fields');
      for (let index = 0; index < entry.length; index++) {
        const descriptor = descriptors[index];
        requireValue(descriptor && descriptor.enumerable && own(descriptor, 'value'), path, 'array has holes or accessors');
        visit(descriptor.value, `${path}[${index}]`, depth + 1, true);
      }
    } else {
      for (const [key, descriptor] of Object.entries(descriptors)) {
        requireValue(!UNSAFE_KEYS.has(key) && descriptor.enumerable && own(descriptor, 'value'),
          `${path}.${key}`, 'unsafe key, hidden field or accessor');
        visit(descriptor.value, `${path}.${key}`, depth + 1);
      }
    }
    ancestors.delete(entry);
  }
  visit(value, 'journal', 0);
}

function verifiedRecord(record, publication, path) {
  requireValue(object(record) && publication.ipnsName, path, 'IPNS evidence requires an IPNS publication');
  try {
    compareIpnsRecords(record, record);
    compareIpnsRecords(record, { ...record, name: publication.ipnsName });
  } catch (cause) { corrupt(path, 'invalid verified IPNS history or publication name', cause); }
  requireValue(record.path.length <= 10_240, `${path}.path`, 'IPNS path exceeds record bounds');
  uint64(record.ttlNanoseconds, `${path}.ttlNanoseconds`);
  hash(record.recordSha256, `${path}.recordSha256`);
  requireValue(record.latestGloballyKnown === false, `${path}.latestGloballyKnown`, 'global freshness is unknown');
}

function verification(value, publication, limits, path) {
  requireValue(object(value) && value.complete === true, path, 'requires complete verified content');
  const root = rootCid(value.root, `${path}.root`);
  requireValue(CODECS.has(root.code) && ((root.multihash.code === 0x12 && root.multihash.digest.length === 32) ||
    (root.multihash.code === 0 && root.multihash.digest.length <= 512)), `${path}.root`, 'unsupported verified root');
  if (publication.root) sameRoot(value.root, publication.root, `${path}.root`);
  count(value.blockCount, `${path}.blockCount`, 1, limits.maxBlocks);
  count(value.reachableBlockCount, `${path}.reachableBlockCount`, 1, value.blockCount);
  count(value.byteLength, `${path}.byteLength`, 1, limits.maxCarBytes);
  requireValue(Array.isArray(value.codecs) && value.codecs.length > 0 && value.codecs.length <= 3 &&
    value.codecs.every(codec => typeof codec === 'string' && [...CODECS.values()].includes(codec)) &&
    new Set(value.codecs).size === value.codecs.length && value.codecs.includes(CODECS.get(root.code)),
  `${path}.codecs`, 'invalid verified codec coverage');
  hash(value.sha256, `${path}.sha256`);
  timestamp(value.verifiedAtMs, `${path}.verifiedAtMs`);
  source(value.source, `${path}.source`);
}

function result(value, publication, limits, path, { summary = false } = {}) {
  requireValue(object(value) && value.id === publication.id && STATUS.has(value.status), path, 'invalid publication result');
  timestamp(value.checkedAtMs, `${path}.checkedAtMs`);
  if (own(value, 'root') && value.root !== null) {
    rootCid(value.root, `${path}.root`);
    if (publication.root) sameRoot(value.root, publication.root, `${path}.root`);
  }
  if (own(value, 'error')) requireValue(typeof value.error === 'string' && value.error.length <= (summary ? 300 : 1500),
    `${path}.error`, 'invalid bounded error');
  if (value.status !== 'unverified') requireValue(typeof value.root === 'string', `${path}.root`, 'successful result requires its root');
  if (summary) return;
  requireValue(value.externalUseVerified === false, `${path}.externalUseVerified`, 'external use is unverified');
  for (const key of ['recordSource', 'contentSource']) if (own(value, key)) source(value[key], `${path}.${key}`);
  if (own(value, 'ipns')) {
    verifiedRecord(value.ipns, publication, `${path}.ipns`);
    const match = /^\/ipfs\/([^/]+)$/u.exec(value.ipns.path);
    if (typeof value.root === 'string') {
      requireValue(match, `${path}.ipns.path`, 'result root requires a complete IPFS root path');
      sameRoot(value.root, match[1], `${path}.root`);
    }
  }
  if (own(value, 'verification')) {
    verification(value.verification, publication, limits, `${path}.verification`);
    sameRoot(value.verification.root, value.root, `${path}.verification.root`);
  }
  if (value.status !== 'unverified') requireValue(own(value, 'verification'), path, 'successful result requires complete verification');
  if (own(value, 'reconciled')) requireValue(typeof value.reconciled === 'boolean', `${path}.reconciled`, 'invalid reconciliation flag');
  if (own(value, 'pin')) {
    requireValue(object(value.pin) && typeof value.pin.pinned === 'boolean', `${path}.pin`, 'invalid pin observation');
    if (own(value.pin, 'root')) sameRoot(value.pin.root, value.root, `${path}.pin.root`);
    for (const key of ['imported', 'reconciled']) if (own(value.pin, key)) {
      requireValue(typeof value.pin[key] === 'boolean', `${path}.pin.${key}`, 'invalid pin observation flag');
    }
    if (own(value.pin, 'externalUseVerified')) requireValue(value.pin.externalUseVerified === false,
      `${path}.pin.externalUseVerified`, 'external use is unverified');
  }
  if (value.status === 'locally_pinned') requireValue(value.reconciled === true || value.pin?.pinned === true,
    path, 'locally pinned result requires recursive pin confirmation');
}

/** Validate the semantics of version-1 state against a validated operator config.
 * This verifies persisted evidence shape and consistency, without refreshing
 * expired IPNS history, changing snapshots, or claiming filesystem trust.
 */
export function validateOperatorState(state, config) {
  safeTree(state);
  requireValue(object(state) && state.version === 1 && object(state.publications) && Array.isArray(state.runs),
    'journal', 'invalid operator journal schema');
  count(state.revision, 'journal.revision');
  requireValue(state.runs.length <= 100, 'journal.runs', 'run history exceeds bounds');
  requireValue(Array.isArray(config?.publications) && config.publications.length > 0 && config.publications.length <= 8 &&
    object(config.limits), 'config', 'validated operator config is required');
  const publications = new Map();
  for (const publication of config.publications) {
    requireValue(object(publication) && typeof publication.id === 'string' &&
      /^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/u.test(publication.id) && !UNSAFE_KEYS.has(publication.id) &&
      !publications.has(publication.id), 'config.publications', 'invalid or unsafe publication ID');
    requireValue(Boolean(publication.root) !== Boolean(publication.ipnsName), 'config.publications', 'publication needs one root or name');
    if (publication.root) rootCid(publication.root, 'config.publications.root');
    publications.set(publication.id, publication);
  }
  if (own(state, 'policyDigest')) hash(state.policyDigest, 'journal.policyDigest');
  if (Object.keys(state.publications).length || state.runs.length || state.activeRun != null) {
    requireValue(own(state, 'policyDigest'), 'journal.policyDigest', 'operator evidence requires its policy digest');
  }
  if (own(state, 'activeRun') && state.activeRun !== null) {
    requireValue(object(state.activeRun), 'journal.activeRun', 'invalid execution lease');
    uuid(state.activeRun.id, 'journal.activeRun.id');
    timestamp(state.activeRun.startedAtMs, 'journal.activeRun.startedAtMs');
    timestamp(state.activeRun.expiresAtMs, 'journal.activeRun.expiresAtMs');
    requireValue(state.activeRun.expiresAtMs > state.activeRun.startedAtMs, 'journal.activeRun.expiresAtMs', 'lease must expire after it starts');
  }
  for (const [id, snapshot] of Object.entries(state.publications)) {
    const path = `journal.publications.${id}`;
    const publication = publications.get(id);
    requireValue(publication && object(snapshot), path, 'unknown publication ID or invalid snapshot');
    if (own(snapshot, 'highestRecord')) verifiedRecord(snapshot.highestRecord, publication, `${path}.highestRecord`);
    if (own(snapshot, 'lastVerified')) verification(snapshot.lastVerified, publication, config.limits, `${path}.lastVerified`);
    if (publication.ipnsName && (own(snapshot, 'lastVerified') || snapshot.lastResult?.ipns)) {
      requireValue(own(snapshot, 'highestRecord'), `${path}.highestRecord`, 'IPNS verification requires its observed high-water');
      if (snapshot.lastResult?.ipns) {
        verifiedRecord(snapshot.lastResult.ipns, publication, `${path}.lastResult.ipns`);
        requireValue(compareIpnsRecords(snapshot.highestRecord, snapshot.lastResult.ipns) >= 0,
          `${path}.highestRecord`, 'high-water is behind its recorded result');
      }
    }
    if (own(snapshot, 'pinIntent')) {
      const intent = snapshot.pinIntent;
      requireValue(object(intent) && ['pending', 'outcome_unknown', 'confirmed'].includes(intent.status), `${path}.pinIntent`, 'invalid pin intent');
      uuid(intent.runId, `${path}.pinIntent.runId`);
      timestamp(intent.atMs, `${path}.pinIntent.atMs`);
      rootCid(intent.root, `${path}.pinIntent.root`);
      requireValue(own(snapshot, 'lastVerified'), `${path}.pinIntent`, 'pin intent requires complete verified content');
      sameRoot(intent.root, snapshot.lastVerified.root, `${path}.pinIntent.root`);
    }
    if (own(snapshot, 'equivocation') && snapshot.equivocation !== null) {
      const evidence = snapshot.equivocation;
      requireValue(publication.ipnsName && object(evidence) && own(snapshot, 'highestRecord'), `${path}.equivocation`, 'invalid IPNS quarantine evidence');
      uint64(evidence.sequence, `${path}.equivocation.sequence`);
      requireValue(BigInt(evidence.sequence) <= BigInt(snapshot.highestRecord.sequence), `${path}.equivocation.sequence`, 'quarantine exceeds observed high-water');
      timestamp(evidence.observedAtMs, `${path}.equivocation.observedAtMs`);
      requireValue(Array.isArray(evidence.paths) && evidence.paths.length >= 2 && evidence.paths.length <= 4 &&
        new Set(evidence.paths).size === evidence.paths.length, `${path}.equivocation.paths`, 'quarantine requires distinct conflicting paths');
      for (const candidate of evidence.paths) verifiedRecord({ ...snapshot.highestRecord, path: candidate }, publication, `${path}.equivocation.paths`);
    }
    if (own(snapshot, 'lastResult')) result(snapshot.lastResult, publication, config.limits, `${path}.lastResult`);
  }
  for (const [index, run] of state.runs.entries()) {
    const path = `journal.runs[${index}]`;
    requireValue(object(run) && ['verified', 'degraded'].includes(run.status) && Array.isArray(run.results) &&
      run.results.length > 0 && run.results.length <= publications.size, path, 'invalid retained run');
    uuid(run.runId, `${path}.runId`);
    timestamp(run.startedAtMs, `${path}.startedAtMs`);
    timestamp(run.completedAtMs, `${path}.completedAtMs`);
    count(run.downloadBytes, `${path}.downloadBytes`);
    hash(run.reportSha256, `${path}.reportSha256`);
    const seen = new Set();
    for (const [resultIndex, entry] of run.results.entries()) {
      const publication = publications.get(entry?.id);
      requireValue(publication && !seen.has(entry.id), `${path}.results`, 'unknown or duplicate publication ID');
      seen.add(entry.id);
      result(entry, publication, config.limits, `${path}.results[${resultIndex}]`, { summary: true });
    }
    requireValue((run.status === 'verified') === run.results.every(entry => entry.status !== 'unverified'),
      `${path}.status`, 'run status disagrees with its results');
  }
  return state;
}
