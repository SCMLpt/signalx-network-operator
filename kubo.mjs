import { CID } from 'multiformats/cid';
import { peerIdFromString } from '@libp2p/peer-id';
import { randomBytes } from 'node:crypto';

// Kubo v0.43.1 RPC reference and the actual pin JSON encoder:
// https://docs.ipfs.tech/reference/kubo/rpc/
// https://github.com/ipfs/kubo/blob/v0.43.1/core/commands/pin/pin.go
// No daemon, peer discovery, or public API is started by this module.
export class KuboApiError extends Error {
  constructor(code, command, { status = null, apiCode = null, apiType = null } = {}) {
    super(`Kubo ${command || 'client'}: ${code}`);
    this.name = 'KuboApiError';
    this.code = code;
    this.command = command;
    this.status = status;
    this.apiCode = apiCode;
    this.apiType = apiType;
  }
}

function positiveInteger(value, name, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`Invalid ${name}`);
  }
  return value;
}

function safeCount(value) {
  if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && value.length <= 16) value = Number(value);
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('Invalid or unsafe counter');
  return value;
}

function boundedString(value, maximum = 256) {
  if (typeof value !== 'string' || !value.length || value.length > maximum || /[\x00-\x1f\x7f]/.test(value)) {
    throw new TypeError('Invalid reported string');
  }
  return value;
}

function rootCid(root) {
  try {
    const cid = typeof root === 'string' ? CID.parse(root) : CID.asCID(root);
    if (!cid || cid.bytes.length > 128) throw new Error();
    return cid.toV1().toString();
  } catch { throw new TypeError('A valid root CID is required'); }
}

function sameCid(candidate, root) {
  try { return CID.parse(candidate).toV1().toString() === root; } catch { return false; }
}

function apiError(value) {
  return value && typeof value === 'object' && typeof value.Message === 'string' &&
    Number.isInteger(value.Code) && (value.Type === undefined || typeof value.Type === 'string');
}

function errorSummary(error) {
  return error instanceof KuboApiError
    ? { code: error.code, status: error.status, apiCode: error.apiCode, apiType: error.apiType }
    : { code: 'INVALID_REPORTED_VALUE', status: null, apiCode: null, apiType: null };
}

/** Client for an operator-configured, private Kubo admin endpoint. */
export class KuboClient {
  #base;
  #token;
  #fetch;
  #timeout;
  #maxResponse;
  #maxImport;
  #signal;
  #beforeMutation;
  #activeImport = null;

  constructor({ url = 'http://127.0.0.1:5001', token, fetchFn = globalThis.fetch,
    timeoutMs = 15_000, maxResponseBytes = 1_048_576, maxImportBytes = 16_777_216,
    allowRemoteHttps = false, signal, beforeMutation } = {}) {
    let base;
    try { base = new URL(url); } catch { throw new TypeError('Invalid Kubo endpoint'); }
    if (base.username || base.password || base.search || base.hash ||
        !['/', '/api/v0', '/api/v0/'].includes(base.pathname) || !['http:', 'https:'].includes(base.protocol)) {
      throw new TypeError('Kubo endpoint must have no credentials, query, fragment, or command path');
    }
    const host = base.hostname;
    const loopback = host === 'localhost' || host === '[::1]' || /^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(host);
    if (!loopback && !(allowRemoteHttps === true && base.protocol === 'https:')) {
      throw new TypeError('Remote Kubo requires explicit allowRemoteHttps and HTTPS');
    }
    if (token !== undefined && (typeof token !== 'string' || !/^[\x21-\x7e]{1,4096}$/.test(token))) {
      throw new TypeError('Invalid Kubo bearer token');
    }
    if (typeof fetchFn !== 'function') throw new TypeError('fetchFn is required');
    if (signal !== undefined && !(signal instanceof AbortSignal)) throw new TypeError('Invalid AbortSignal');
    if (beforeMutation !== undefined && typeof beforeMutation !== 'function') throw new TypeError('Invalid beforeMutation callback');
    this.#base = new URL('/api/v0/', base.origin);
    this.#token = token;
    this.#fetch = fetchFn;
    this.#timeout = positiveInteger(timeoutMs, 'timeoutMs', 120_000);
    this.#maxResponse = positiveInteger(maxResponseBytes, 'maxResponseBytes', 16_777_216);
    this.#maxImport = positiveInteger(maxImportBytes, 'maxImportBytes', 67_108_864);
    this.#signal = signal;
    this.#beforeMutation = beforeMutation;
  }

  async #request(command, params = {}, body, contentType) {
    if (this.#signal?.aborted) throw new KuboApiError('ABORTED', command);
    const target = new URL(command, this.#base);
    for (const [key, value] of Object.entries({ ...params, enc: 'json', timeout: `${this.#timeout}ms` })) {
      target.searchParams.set(key, String(value));
    }
    const headers = { accept: 'application/json' };
    if (this.#token) headers.authorization = `Bearer ${this.#token}`;
    if (contentType) headers['content-type'] = contentType;
    const controller = new AbortController();
    const combinedSignal = this.#signal ? AbortSignal.any([this.#signal, controller.signal]) : controller.signal;
    const checkAbort = () => {
      if (combinedSignal.aborted) throw new KuboApiError(this.#signal?.aborted ? 'ABORTED' : 'TIMEOUT', command);
    };
    let timer;
    let reader;
    let abortListener;
    const externalAbort = new Promise((_, reject) => {
      if (this.#signal) {
        abortListener = () => reject(new KuboApiError('ABORTED', command));
        this.#signal.addEventListener('abort', abortListener, { once: true });
      }
    });
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new KuboApiError('TIMEOUT', command));
      }, this.#timeout);
    });
    const work = async () => {
      checkAbort();
      const response = await this.#fetch(target.href, {
        method: 'POST', headers, body, redirect: 'manual', signal: combinedSignal,
      });
      checkAbort();
      if (response.status >= 300 && response.status < 400 || response.redirected) {
        controller.abort();
        throw new KuboApiError('REDIRECT_REJECTED', command, { status: response.status });
      }
      const advertised = response.headers?.get('content-length');
      if (advertised != null && (/^\d+$/.test(advertised) === false || Number(advertised) > this.#maxResponse)) {
        controller.abort();
        throw new KuboApiError('RESPONSE_TOO_LARGE', command, { status: response.status });
      }
      let text = '';
      if (response.body) {
        reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8', { fatal: true });
        let received = 0;
        for (;;) {
          checkAbort();
          const { value, done } = await reader.read();
          checkAbort();
          if (done) break;
          received += value.byteLength;
          if (received > this.#maxResponse) {
            controller.abort();
            throw new KuboApiError('RESPONSE_TOO_LARGE', command, { status: response.status });
          }
          text += decoder.decode(value, { stream: true });
        }
        text += decoder.decode();
      }
      let values;
      try {
        try { values = [JSON.parse(text)]; }
        catch { values = text.trim().split(/\r?\n/).map(line => JSON.parse(line)); }
      } catch { throw new KuboApiError('INVALID_JSON', command, { status: response.status }); }
      for (const value of values) {
        if (apiError(value)) {
          // The exact current Kubo pinLsKeys error is the only HTTP error that means absence.
          const missing = command === 'pin/ls' && response.status === 500 && value.Code === 0 &&
            value.Type === 'error' && value.Message === `path '${params.arg}' is not pinned`;
          throw new KuboApiError(missing ? 'PIN_NOT_FOUND' : 'API_ERROR', command, {
            status: response.status, apiCode: value.Code,
            apiType: /^[A-Za-z_-]{1,32}$/.test(value.Type || '') ? value.Type : null,
          });
        }
      }
      if (!response.ok) throw new KuboApiError('HTTP_ERROR', command, { status: response.status });
      return values;
    };
    try { return await Promise.race([work(), deadline, externalAbort]); }
    catch (error) {
      if (error instanceof KuboApiError) throw error;
      throw new KuboApiError(this.#signal?.aborted ? 'ABORTED' : controller.signal.aborted ? 'TIMEOUT' : 'TRANSPORT_ERROR', command);
    } finally {
      clearTimeout(timer);
      if (abortListener) this.#signal.removeEventListener('abort', abortListener);
      if (reader) {
        // A hostile injected stream need not cooperate with cancellation; do not await it.
        try { Promise.resolve(reader.cancel()).catch(() => {}); } catch { /* Preserve the original result. */ }
      }
    }
  }

  async inspect() {
    if (this.#signal?.aborted) throw new KuboApiError('ABORTED', 'inspect');
    const observedAt = new Date().toISOString();
    const commands = {
      id: {}, version: {}, 'swarm/peers': {}, 'stats/repo': { 'size-only': true, human: false },
      'stats/bitswap': { human: false }, config: { arg: 'Routing.Type' },
    };
    const reports = Object.fromEntries(await Promise.all(Object.entries(commands).map(async ([command, params]) => {
      try {
        const values = await this.#request(command, params);
        if (values.length !== 1 || !values[0] || typeof values[0] !== 'object' || Array.isArray(values[0])) throw new TypeError();
        return [command, { value: values[0] }];
      } catch (error) { return [command, { error: errorSummary(error) }]; }
    })));
    if (this.#signal?.aborted) throw new KuboApiError('ABORTED', 'inspect');
    const output = { observedAt, externalUseVerified: false, provenance: {}, errors: {} };
    for (const [command, report] of Object.entries(reports)) if (report.error) output.errors[command] = report.error;
    const field = (name, command, path, read) => {
      const provenance = { source: 'operator_kubo_admin_api', command: `/api/v0/${command}`, field: path, observedAt };
      try {
        if (reports[command].error) throw new Error();
        output[name] = read(reports[command].value);
        output.provenance[name] = { ...provenance, status: 'reported' };
      } catch (error) {
        output[name] = null;
        output.provenance[name] = { ...provenance, status: 'unknown', error: reports[command].error || errorSummary(error) };
      }
    };
    field('peerId', 'id', 'ID', value => peerIdFromString(boundedString(value.ID)).toString());
    field('version', 'version', 'Version', value => boundedString(value.Version, 128));
    field('peers', 'swarm/peers', 'Peers.length', value => {
      if (value.Peers === null) return 0; // Kubo serializes an empty Go peer slice as null.
      if (!Array.isArray(value.Peers) || value.Peers.some(peer => !peer || typeof peer.Peer !== 'string')) throw new TypeError();
      return value.Peers.length;
    });
    field('dhtModeReported', 'config', 'Value (Routing.Type configuration only)', value => {
      if (value.Key !== 'Routing.Type') throw new TypeError();
      return boundedString(value.Value, 64);
    });
    field('repoBytes', 'stats/repo', 'RepoSize (or SizeStat.RepoSize)', value => safeCount(value.RepoSize ?? value.SizeStat?.RepoSize));
    field('bitswapSentBytes', 'stats/bitswap', 'DataSent', value => safeCount(value.DataSent));
    field('bitswapSentBlocks', 'stats/bitswap', 'BlocksSent', value => safeCount(value.BlocksSent));
    return output;
  }

  async isPinned(root) {
    root = rootCid(root);
    let values;
    try { values = await this.#request('pin/ls', { arg: root, type: 'recursive', stream: false, offline: true }); }
    catch (error) { if (error.code === 'PIN_NOT_FOUND') return false; throw error; }
    if (values.length !== 1 || !values[0]?.Keys || typeof values[0].Keys !== 'object' || Array.isArray(values[0].Keys)) {
      throw new KuboApiError('INVALID_PIN_RESPONSE', 'pin/ls');
    }
    const entries = Object.entries(values[0].Keys);
    if (entries.length !== 1 || !sameCid(entries[0][0], root) || entries[0][1]?.Type !== 'recursive') {
      throw new KuboApiError('INVALID_PIN_RESPONSE', 'pin/ls');
    }
    return true;
  }

  /** Caller must verify CAR integrity, reachability, codecs and the root before this method. */
  async importVerifiedCar(bytes, root) {
    if (this.#signal?.aborted) throw new KuboApiError('ABORTED', 'dag/import');
    root = rootCid(root);
    if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > this.#maxImport) {
      throw new TypeError('CAR bytes are empty, invalid, or exceed maxImportBytes');
    }
    if (typeof SharedArrayBuffer !== 'undefined' && bytes.buffer instanceof SharedArrayBuffer) {
      throw new TypeError('CAR bytes must not use shared mutable memory');
    }
    if (this.#activeImport) {
      if (this.#activeImport.root === root) return this.#activeImport.promise;
      throw new KuboApiError('IMPORT_BUSY', 'dag/import');
    }
    // Snapshot before awaiting reconciliation so the caller cannot change verified bytes in flight.
    const promise = this.#import(Uint8Array.from(bytes), root);
    this.#activeImport = { root, promise };
    try { return await promise; } finally { this.#activeImport = null; }
  }

  // Content-addressed imports are idempotent, but that does not enforce an operator's
  // absolute lease or resource budget. Recheck those through this hook before each write.
  async #mutationGuard(command, root) {
    if (this.#signal?.aborted) throw new KuboApiError('ABORTED', command);
    if (!this.#beforeMutation) return;
    let abortListener;
    const externalAbort = new Promise((_, reject) => {
      if (this.#signal) {
        abortListener = () => reject(new KuboApiError('ABORTED', command));
        this.#signal.addEventListener('abort', abortListener, { once: true });
      }
    });
    try {
      await Promise.race([this.#beforeMutation({ command, root }), externalAbort]);
      if (this.#signal?.aborted) throw new KuboApiError('ABORTED', command);
    } finally {
      if (abortListener) this.#signal.removeEventListener('abort', abortListener);
    }
  }

  async #import(bytes, root) {
    const report = (imported, reconciled) => ({ root, pinned: true, imported, reconciled, externalUseVerified: false,
      provenance: { pin: { source: 'operator_kubo_admin_api', command: '/api/v0/pin/ls', type: 'recursive',
        observedAt: new Date().toISOString() }, ...(imported ? { import: { command: '/api/v0/dag/import', offline: true } } : {}) } });
    if (await this.isPinned(root)) return report(false, true);
    // Build a bounded multipart body with fixed metadata and no caller-controlled filename.
    const boundary = `signalx-kubo-${randomBytes(24).toString('hex')}`;
    const prefix = new TextEncoder().encode(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="verified.car"\r\nContent-Type: application/vnd.ipld.car\r\n\r\n`);
    const suffix = new TextEncoder().encode(`\r\n--${boundary}--\r\n`);
    const multipart = new Uint8Array(prefix.length + bytes.byteLength + suffix.length);
    multipart.set(prefix); multipart.set(bytes, prefix.length); multipart.set(suffix, prefix.length + bytes.byteLength);
    const offline = { offline: true, 'fast-provide-root': false, 'fast-provide-dag': false, 'fast-provide-wait': false };
    await this.#mutationGuard('dag/import', root);
    const imported = await this.#request('dag/import', { ...offline, 'pin-roots': false, stats: true, 'allow-big-block': false },
      multipart, `multipart/form-data; boundary=${boundary}`);
    try {
      if (imported.length !== 1 || !imported[0]?.Stats || safeCount(imported[0].Stats.BlockCount) < 1 ||
          safeCount(imported[0].Stats.BlockBytesCount) < 1) throw new TypeError();
    } catch { throw new KuboApiError('INVALID_IMPORT_RESPONSE', 'dag/import'); }
    await this.#mutationGuard('pin/add', root);
    const pinned = await this.#request('pin/add', { ...offline, arg: root, recursive: true, progress: false });
    if (pinned.length !== 1 || !Array.isArray(pinned[0]?.Pins) || pinned[0].Pins.length !== 1 || !sameCid(pinned[0].Pins[0], root)) {
      throw new KuboApiError('INVALID_PIN_RESPONSE', 'pin/add');
    }
    if (!await this.isPinned(root)) throw new KuboApiError('PIN_NOT_CONFIRMED', 'pin/ls');
    // Existing Kubo providing/reproviding runs independently; this is no proof of external retrieval.
    return report(true, false);
  }
}
