import { createHash } from 'node:crypto';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

function withAbort(promise, signal) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () => { cleanup(); reject(signal.reason); };
    const cleanup = () => signal.removeEventListener('abort', abort);
    signal.addEventListener('abort', abort, { once: true });
    Promise.resolve(promise).then(value => { cleanup(); resolve(value); },
      error => { cleanup(); reject(error); });
  });
}

function cancelQuietly(body) {
  try { Promise.resolve(body?.cancel()).catch(() => {}); } catch {}
}

/** Configuration is local operator input; this is not an arbitrary-URL proxy. */
export function publicBase(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search ||
      url.hash || url.pathname !== '/' || url.port ||
      /^(localhost|.*\.localhost|.*\.local)$/.test(url.hostname) ||
      /^[\d.]+$/.test(url.hostname) || url.hostname.includes(':')) {
    throw new Error('Source must be a public HTTPS origin without credentials, port or path');
  }
  return url.href;
}

/** Limits apply while reading, including bodies without a Content-Length. */
export async function readBounded(url, { fetchFn = fetch, maxBytes, timeoutMs,
  accept, meter, signal } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new Error('Invalid read limits');
  const timeout = AbortSignal.timeout(timeoutMs);
  const combined = signal ? AbortSignal.any([timeout, signal]) : timeout;
  combined.throwIfAborted();
  const response = await withAbort(fetchFn(url, { redirect: 'manual', signal: combined,
    headers: { accept } }), combined);
  if (!response.ok || response.status >= 300) {
    cancelQuietly(response.body);
    throw new Error(`Source HTTP ${response.status}`);
  }
  const length = response.headers.get('content-length');
  if (length !== null && (!/^[0-9]+$/.test(length) || BigInt(length) > BigInt(maxBytes))) {
    cancelQuietly(response.body);
    throw new Error('Source body exceeds limit');
  }
  if (!response.body) throw new Error('Source has no body');
  const reader = response.body.getReader();
  let received = 0;
  const chunks = [];
  try {
    for (;;) {
      combined.throwIfAborted();
      const { done, value } = await withAbort(reader.read(), combined);
      if (done) break;
      received += value.byteLength;
      if (meter) {
        meter.bytes += value.byteLength;
        if (meter.bytes > meter.maxBytes) throw new Error('Run download budget exceeded');
      }
      if (received > maxBytes) throw new Error('Source body exceeds limit');
      chunks.push(value);
    }
  } catch (error) {
    try { Promise.resolve(reader.cancel()).catch(() => {}); } catch {}
    throw error;
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return { bytes, contentType: response.headers.get('content-type') ?? '',
    url: String(url), receivedBytes: received };
}
