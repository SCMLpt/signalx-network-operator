const ANNOUNCE_URL = 'https://cid.contact/ingest/announce';
const WINDOW_MS = 300_000;
const MAX_RESPONSE_BYTES = 4_096;
const MAX_ANNOUNCEMENT_BYTES = 16_384;
const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function publicAnnouncement(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      typeof value.bodyBase64 !== 'string' ||
      !/^application\/json(?:;\s*charset=utf-8)?$/i.test(value.contentType ?? '') ||
      value.bodyBase64.length > Math.ceil(MAX_ANNOUNCEMENT_BYTES / 3) * 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.bodyBase64)) return null;
  const text = value.bodyBase64;
  if (text.endsWith('==') && (BASE64.indexOf(text.at(-3)) & 15) !== 0 ||
      text.endsWith('=') && !text.endsWith('==') && (BASE64.indexOf(text.at(-2)) & 3) !== 0) return null;
  try {
    const binary = atob(text);
    if (!binary.length || binary.length > MAX_ANNOUNCEMENT_BYTES) return null;
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const object = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!object || typeof object !== 'object' || Array.isArray(object)) return null;
    return { bytes, contentType: value.contentType };
  } catch { return null; }
}

function deadlineFrom(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return NaN;
  const parsed = Date.parse(value);
  return Number.isSafeInteger(parsed) && new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19) ? parsed : NaN;
}

/** One bounded removal PUT per admitted callback; an HTTP acknowledgement is not deindexing proof. */
export function createExpiryMaintenance(data, { fetchFn = globalThis.fetch, now = Date.now, timeoutMs = 10_000 } = {}) {
  if (typeof fetchFn !== 'function' || typeof now !== 'function' ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000) throw new TypeError('Invalid maintenance options');
  const deadline = deadlineFrom(data?.termEndUtc);
  const announcement = publicAnnouncement(data?.ipni?.removalAnnouncement);
  return {
    async run(controller) {
      const scheduledTime = controller?.scheduledTime;
      const actualTime = now();
      const result = (state, reason, extra = {}) => ({ operation: 'ipni_removal_announcement', state, reason, ...extra });
      if (!Number.isSafeInteger(deadline) || !Number.isSafeInteger(scheduledTime) || scheduledTime <= 0 ||
          !Number.isSafeInteger(actualTime) || actualTime <= 0) return result('skipped', 'invalid_time');
      const windowEnd = deadline + WINDOW_MS;
      if (scheduledTime < deadline || actualTime < deadline) return result('skipped', 'before_expiry');
      if (scheduledTime >= windowEnd || actualTime >= windowEnd) return result('skipped', 'outside_expiry_window');
      if (scheduledTime > actualTime) return result('skipped', 'future_scheduled_time');
      if (!announcement) return result('skipped', 'removal_announcement_unavailable');

      const abort = new AbortController();
      let reader;
      let timer;
      let timedOut = false;
      const admittedTime = now();
      if (!Number.isSafeInteger(admittedTime) || admittedTime < deadline || admittedTime >= windowEnd || admittedTime < scheduledTime) {
        return result('skipped', 'execution_time_changed');
      }
      const duration = Math.min(timeoutMs, windowEnd - admittedTime);
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          abort.abort();
          reject(new Error('request_timeout'));
        }, duration);
      });
      const operation = async () => {
        const response = await fetchFn(ANNOUNCE_URL, {
          method: 'PUT', redirect: 'manual', credentials: 'omit', cache: 'no-store',
          headers: { 'content-type': announcement.contentType, accept: 'application/json' },
          body: announcement.bytes.slice(), signal: abort.signal,
        });
        const length = response.headers.get('content-length');
        if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) {
          void response.body?.cancel().catch(() => {});
          throw new Error('response_limit');
        }
        let responseBytes = 0;
        if (response.body) {
          reader = response.body.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            responseBytes += value.byteLength;
            if (responseBytes > MAX_RESPONSE_BYTES) throw new Error('response_limit');
          }
        }
        return response.status >= 200 && response.status < 300
          ? result('acknowledged', 'http_acknowledgement_only', { httpStatus: response.status, responseBytes })
          : result('failed', 'http_rejected', { httpStatus: response.status, responseBytes });
      };
      try { return await Promise.race([operation(), timeout]); }
      catch (error) {
        return result('failed', timedOut ? 'request_timeout' : error.message === 'response_limit' ? 'response_limit' : 'request_failed');
      } finally {
        clearTimeout(timer);
        abort.abort();
        if (reader) void reader.cancel().catch(() => {});
      }
    },
  };
}
