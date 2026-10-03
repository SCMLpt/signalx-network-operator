import { randomUUID } from 'node:crypto';
import { CID } from 'multiformats/cid';
import { FileJournal } from './journal.mjs';
import { validateOperatorState } from './state.mjs';
import { verifyIpnsRecord, compareIpnsRecords } from './ipns.mjs';
import { verifyCar } from './car.mjs';
import { KuboClient } from './kubo.mjs';
import { publicBase, readBounded, sha256 } from './io.mjs';

const defaults = { maxCarBytes: 8_388_608, maxRunBytes: 16_777_216,
  maxBlocks: 4096, maxLinks: 16384, timeoutMs: 15000, runTimeoutMs: 60000,
  maxRepoBytes: 2_147_483_648 };
const maximums = { maxCarBytes: 16_777_216, maxRunBytes: 67_108_864,
  maxBlocks: 8192, maxLinks: 32768, timeoutMs: 30000, runTimeoutMs: 300000,
  maxRepoBytes: 1_099_511_627_776 };
const idPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/;
const reservedIds = new Set(['__proto__', 'prototype', ...Object.getOwnPropertyNames(Object.prototype)]);
const validId = value => typeof value === 'string' && idPattern.test(value) && !reservedIds.has(value);

function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exactKeys(value, allowed) {
  if (!object(value) || Object.keys(value).some(key => !allowed.includes(key))) {
    throw new Error('Unknown or invalid configuration field');
  }
}

export function validateConfig(input) {
  exactKeys(input, ['version', 'operatorId', 'stateDirectory', 'pin', 'kuboUrl',
    'gateways', 'ipnsRouters', 'publications', 'limits', 'intervalSeconds']);
  if (input.version !== 1 || !validId(input.operatorId) ||
      typeof input.stateDirectory !== 'string' || !input.stateDirectory ||
      typeof input.pin !== 'boolean') throw new Error('Invalid operator configuration');
  const limits = { ...defaults, ...(input.limits ?? {}) };
  exactKeys(limits, Object.keys(defaults));
  for (const [key, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximums[key]) {
      throw new Error(`Invalid ${key}`);
    }
  }
  if (limits.maxRunBytes < limits.maxCarBytes || limits.runTimeoutMs < limits.timeoutMs) {
    throw new Error('Run budgets must cover one complete bounded read');
  }
  const bases = (values, label) => {
    if (!Array.isArray(values) || values.length < 1 || values.length > 3 ||
        values.some(value => typeof value !== 'string')) throw new Error(`Invalid ${label}`);
    const result = values.map(publicBase);
    if (new Set(result).size !== result.length) throw new Error(`Duplicate ${label}`);
    return result;
  };
  const gateways = bases(input.gateways, 'gateways');
  const ipnsRouters = bases(input.ipnsRouters, 'ipnsRouters');
  if (!Array.isArray(input.publications) || input.publications.length < 1 || input.publications.length > 8) {
    throw new Error('Configure between one and eight approved publications');
  }
  const publications = input.publications.map(publication => {
    exactKeys(publication, ['id', 'root', 'ipnsName']);
    const hasRoot = Object.hasOwn(publication, 'root');
    const hasName = Object.hasOwn(publication, 'ipnsName');
    if (!validId(publication.id) || hasRoot === hasName ||
        (hasRoot && (typeof publication.root !== 'string' || !publication.root))) {
      throw new Error('Each publication needs a unique ID and exactly one root or IPNS name');
    }
    if (hasRoot) return { id: publication.id, root: CID.parse(publication.root).toV1().toString() };
    if (typeof publication.ipnsName !== 'string' || publication.ipnsName.length > 128 ||
        !/^[a-zA-Z0-9]+$/.test(publication.ipnsName)) throw new Error('Invalid IPNS name');
    return { id: publication.id, ipnsName: publication.ipnsName };
  });
  if (new Set(publications.map(publication => publication.id)).size !== publications.length) {
    throw new Error('Duplicate publication ID');
  }
  const intervalSeconds = input.intervalSeconds ?? 300;
  if (!Number.isSafeInteger(intervalSeconds) || intervalSeconds < 60 || intervalSeconds > 86400) {
    throw new Error('Interval must be between 60 and 86400 seconds');
  }
  const kuboUrl = input.kuboUrl ?? 'http://127.0.0.1:5001';
  // Validate the administration boundary even during a read-only run.
  new KuboClient({ url: kuboUrl });
  return { version: 1, operatorId: input.operatorId, stateDirectory: input.stateDirectory,
    pin: input.pin, kuboUrl, gateways, ipnsRouters, publications, limits, intervalSeconds };
}

/** Complete-DAG verification is separate from peer traffic and independent use. */
export async function runOnce(input, { journal, fetchFn = fetch, kubo,
  now = Date.now, verifyRecord = verifyIpnsRecord, verifyContent = verifyCar } = {}) {
  const config = validateConfig(input);
  journal ??= new FileJournal(config.stateDirectory);
  const startedAtMs = now();
  if (!Number.isSafeInteger(startedAtMs) || startedAtMs <= 0) throw new Error('Invalid operator clock');
  const deadline = startedAtMs + config.limits.runTimeoutMs;
  if (!Number.isSafeInteger(deadline)) throw new Error('Run deadline exceeds the clock range');
  const runId = randomUUID();
  const policyDigest = sha256(JSON.stringify(config));
  const meter = { bytes: 0, maxBytes: config.limits.maxRunBytes };
  const runSignal = AbortSignal.timeout(config.limits.runTimeoutMs);
  let beforeContentMutation = async () => {};
  kubo ??= new KuboClient({ url: config.kuboUrl, fetchFn,
    timeoutMs: config.limits.timeoutMs, signal: runSignal,
    maxImportBytes: config.limits.maxCarBytes,
    beforeMutation: async () => {
      assertTime();
      await beforeContentMutation();
      assertTime();
      await update(() => {});
    } });
  const assertTime = () => {
    runSignal.throwIfAborted();
    if (now() >= deadline) throw new Error('Run deadline reached');
  };
  const transact = async mutator => journal.transact(state => {
    if (typeof state.policyDigest === 'string' && /^[0-9a-f]{64}$/.test(state.policyDigest) && state.policyDigest !== policyDigest) {
      throw new Error('Configuration changed: use a new state directory and preserve the old journal');
    }
    validateOperatorState(state, config);
    mutator(state);
    validateOperatorState(state, config);
  });
  const readState = async () => validateOperatorState(await journal.read(), config);
  const update = async mutator => transact(state => {
    if (state.activeRun?.id !== runId || now() >= state.activeRun.expiresAtMs) {
      throw new Error('Run lease was superseded or expired');
    }
    mutator(state);
  });
  await transact(state => {
    if (state.policyDigest && state.policyDigest !== policyDigest) {
      throw new Error('Configuration changed: use a new state directory and preserve the old journal');
    }
    if (state.activeRun && now() < state.activeRun.expiresAtMs) throw new Error('Another run holds the lease');
    state.policyDigest = policyDigest;
    state.activeRun = { id: runId, startedAtMs, expiresAtMs: deadline };
  });
  const read = async (url, maxBytes, accept) => {
    assertTime();
    return readBounded(url, { fetchFn, maxBytes, accept, meter, signal: runSignal,
      timeoutMs: Math.max(1, Math.min(config.limits.timeoutMs, deadline - now())) });
  };
  const results = [];
  try {
    for (const publication of config.publications) {
      const result = { id: publication.id, status: 'unverified', externalUseVerified: false };
      try {
        assertTime();
        let root = publication.root;
        let record = null;
        let recordBytes;
        const ensureNamingCurrent = async () => {
          if (record) await verifyRecord({ name: publication.ipnsName, bytes: recordBytes,
            nowMs: now(), prior: record });
        };
        // Import may outlive the accepted naming record while its run lease is
        // still valid. Revalidate before each distinct Kubo mutation, including
        // pin/add after import, rather than only before entering the client.
        beforeContentMutation = ensureNamingCurrent;
        let snapshot = (await readState()).publications[publication.id];
        if (publication.ipnsName) {
          const samples = await Promise.allSettled(config.ipnsRouters.map(async base => {
              const response = await read(new URL(`routing/v1/ipns/${publication.ipnsName}`, base),
                10240, 'application/vnd.ipfs.ipns-record');
              if (!/^application\/vnd\.ipfs\.ipns-record(?:;|$)/i.test(response.contentType)) {
                throw new Error('Router did not return an IPNS record');
              }
              const verifiedRecord = await verifyRecord({ name: publication.ipnsName, bytes: response.bytes,
                nowMs: now(), prior: null });
              return { record: verifiedRecord, source: response.url, bytes: response.bytes };
          }));
          const valid = samples.filter(sample => sample.status === 'fulfilled').map(sample => sample.value);
          const failures = samples.filter(sample => sample.status === 'rejected').map(sample => sample.reason.message);
          valid.sort((left, right) => -compareIpnsRecords(left.record, right.record));
          if (valid.length) {
            record = valid[0].record;
            recordBytes = valid[0].bytes;
            result.recordSource = valid[0].source;
          }
          if (!record) throw new Error(`IPNS validation failed: ${failures.join('; ')}`);
          const conflictingPaths = new Set(valid.filter(sample => sample.record.sequence === record.sequence)
            .map(sample => sample.record.path));
          if (snapshot?.highestRecord?.sequence === record.sequence) conflictingPaths.add(snapshot.highestRecord.path);
          if (conflictingPaths.size > 1) {
            await update(state => {
              const previous = state.publications[publication.id] ?? {};
              const highestRecord = previous.highestRecord &&
                compareIpnsRecords(previous.highestRecord, record) >= 0 ? previous.highestRecord : record;
              state.publications[publication.id] = { ...previous, highestRecord,
                equivocation: { sequence: record.sequence, paths: [...conflictingPaths].sort(), observedAtMs: now() } };
            });
            throw new Error('Conflicting signed IPNS values: quarantined until a strictly higher sequence is observed');
          }
          if (snapshot?.equivocation && BigInt(record.sequence) <= BigInt(snapshot.equivocation.sequence)) {
            throw new Error('IPNS sequence is quarantined after observed signed equivocation');
          }
          // Validate rollback policy after inspecting cryptographically valid
          // samples, so an equivocation cannot disappear as a router failure.
          await verifyRecord({ name: publication.ipnsName, bytes: recordBytes,
            nowMs: now(), prior: snapshot?.highestRecord ?? null });
          // Persist the highest valid naming record before attempting availability.
          // A missing new DAG must not authorize reverting to an older record.
          await update(state => {
            const previous = state.publications[publication.id] ?? {};
            state.publications[publication.id] = { ...previous, highestRecord: record, equivocation: null };
          });
          result.ipns = record;
          const match = /^\/ipfs\/([^/]+)$/.exec(record.path);
          if (!match) throw new Error('This operator only preserves complete IPFS roots, without subpaths or IPNS recursion');
          root = CID.parse(match[1]).toV1().toString();
        }
        result.root = root;
        snapshot = (await readState()).publications[publication.id];
        if (config.pin && snapshot?.lastVerified?.root === root && await kubo.isPinned(root)) {
          result.status = 'locally_pinned';
          result.verification = snapshot.lastVerified;
          result.reconciled = true;
        } else {
          let verified = null;
          let carBytes;
          const failures = [];
          for (const base of config.gateways) {
            try {
              const url = new URL(`ipfs/${root}`, base);
              url.searchParams.set('format', 'car');
              url.searchParams.set('dag-scope', 'all');
              const response = await read(url, config.limits.maxCarBytes,
                'application/vnd.ipld.car; version=1; order=dfs; dups=n');
              if (!/^application\/vnd\.ipld\.car(?:;|$)/i.test(response.contentType)) {
                throw new Error('Gateway did not return a CAR');
              }
              verified = { ...await verifyContent(response.bytes, root, {
                maxBlocks: config.limits.maxBlocks, maxBytes: config.limits.maxCarBytes,
                maxLinks: config.limits.maxLinks }), verifiedAtMs: now(), source: response.url };
              carBytes = response.bytes;
              result.contentSource = response.url;
              break;
            } catch (error) { failures.push(error.message); assertTime(); }
          }
          if (!verified) throw new Error(`Complete content verification failed: ${failures.join('; ')}`);
          result.verification = verified;
          result.status = 'content_verified';
          await update(state => {
            const previous = state.publications[publication.id] ?? {};
            state.publications[publication.id] = { ...previous, lastVerified: verified,
              ...(config.pin ? { pinIntent: { root, runId, status: 'pending', atMs: now() } } : {}) };
          });
          if (config.pin) {
            assertTime();
            const observation = await kubo.inspect();
            if (!Number.isSafeInteger(observation.repoBytes) || observation.repoBytes < 0 ||
                observation.repoBytes + carBytes.byteLength > config.limits.maxRepoBytes) {
              throw new Error('Kubo repository size is unknown or pin admission limit would be exceeded');
            }
            // Import/pin are content-addressed idempotent effects. Persisted intent
            // survives an unknown HTTP outcome; a restart checks pin/ls first.
            await ensureNamingCurrent();
            await update(() => {});
            result.pin = await kubo.importVerifiedCar(carBytes, root);
            assertTime();
            if (result.pin?.pinned !== true) throw new Error('Recursive pin was not confirmed');
            result.status = 'locally_pinned';
          }
        }
        await ensureNamingCurrent();
      } catch (error) {
        if (error.code === 'OPERATOR_STATE_CORRUPT') throw error;
        result.status = 'unverified';
        result.error = String(error.message).slice(0, 1500);
      }
      result.checkedAtMs = now();
      await update(state => {
        const previous = state.publications[publication.id] ?? {};
        state.publications[publication.id] = { ...previous, lastResult: result,
          ...(config.pin && previous.pinIntent ? { pinIntent: { ...previous.pinIntent,
            status: result.pin?.pinned === true || result.reconciled === true ? 'confirmed' : 'outcome_unknown' } } : {}) };
      });
      results.push(result);
    }
    const report = { schemaVersion: 1, operatorId: config.operatorId, runId, policyDigest, pinRequested: config.pin,
      startedAtMs, completedAtMs: now(), downloadBytes: meter.bytes, results,
      status: results.every(result => result.status !== 'unverified') ? 'verified' : 'degraded',
      networkContribution: { externalRequests: null, independentOperators: null,
        externalUseVerified: false, serviceRevenue: null },
      limitations: ['No ENS resolution in this version', 'IPNS freshness is limited to observed records',
        'A local recursive pin does not prove public reachability or delivery to an external peer',
        'Repository size admission is not an operating-system disk or network quota'] };
    await update(state => {
      state.runs.push({ runId, startedAtMs, completedAtMs: report.completedAtMs,
        status: report.status, downloadBytes: meter.bytes, reportSha256: sha256(JSON.stringify(report)),
        results: results.map(result => ({ id: result.id, root: result.root ?? null,
          status: result.status, checkedAtMs: result.checkedAtMs,
          ...(result.error ? { error: result.error.slice(0, 300) } : {}) })) });
      state.runs = state.runs.slice(-100);
      state.activeRun = null;
    });
    return report;
  } catch (error) {
    // Preserve unresolved intent and the run lease. Its expiry permits an
    // idempotent reconciliation; no missing result is promoted to success.
    throw error;
  }
}
