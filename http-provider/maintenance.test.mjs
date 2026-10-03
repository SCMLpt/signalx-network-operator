import test from 'node:test';
import assert from 'node:assert/strict';
import deploymentData from './deployment-data.json' with { type: 'json' };
import { createExpiryMaintenance } from './maintenance.mjs';
import worker from './worker.mjs';

const deadline = Date.parse(deploymentData.termEndUtc);
const scheduledTime = deadline + 60_000;
const announcement = deploymentData.ipni.removalAnnouncement;

test('one admitted callback PUTs only exact public removal bytes to the fixed external endpoint', async () => {
  const calls = [];
  const maintenance = createExpiryMaintenance(deploymentData, { now: () => scheduledTime,
    fetchFn: async (url, options) => { calls.push({ url, options }); return new Response('', { status: 202 }); } });
  const result = await maintenance.run({ scheduledTime });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://cid.contact/ingest/announce');
  assert.equal(calls[0].options.method, 'PUT');
  assert.equal(calls[0].options.redirect, 'manual');
  assert.equal(calls[0].options.credentials, 'omit');
  assert.equal(calls[0].options.headers['content-type'], announcement.contentType);
  assert.deepEqual(Buffer.from(calls[0].options.body), Buffer.from(announcement.bodyBase64, 'base64'));
  assert.equal(calls[0].options.headers.authorization, undefined);
  assert.deepEqual(result, { operation: 'ipni_removal_announcement', state: 'acknowledged',
    reason: 'http_acknowledgement_only', httpStatus: 202, responseBytes: 0 });
});

test('preexpiry, exact window end, late callback and subsequent-year callback perform no request', async () => {
  const trials = [
    [deadline - 1, deadline - 1, 'before_expiry'], [deadline - 1, scheduledTime, 'before_expiry'],
    [scheduledTime, deadline - 1, 'before_expiry'], [deadline + 300_000, deadline + 300_000, 'outside_expiry_window'],
    [scheduledTime, deadline + 300_000, 'outside_expiry_window'],
    [deadline + 365 * 86_400_000, deadline + 365 * 86_400_000, 'outside_expiry_window'],
    [scheduledTime + 1, scheduledTime, 'future_scheduled_time'],
  ];
  for (const [scheduled, actual, reason] of trials) {
    const maintenance = createExpiryMaintenance(deploymentData, { now: () => actual,
      fetchFn: () => assert.fail('Rejected callback made a network request') });
    assert.equal((await maintenance.run({ scheduledTime: scheduled })).reason, reason);
  }
});

test('invalid times and malformed or absent announcement skip without network or invented content', async () => {
  const denied = () => assert.fail('Invalid input made a network request');
  for (const value of [NaN, Infinity, undefined, '2026-10-10', -1, 1.5]) {
    assert.equal((await createExpiryMaintenance(deploymentData, { now: () => scheduledTime, fetchFn: denied })
      .run({ scheduledTime: value })).reason, 'invalid_time');
    assert.equal((await createExpiryMaintenance(deploymentData, { now: () => value, fetchFn: denied })
      .run({ scheduledTime })).reason, 'invalid_time');
  }
  for (const termEndUtc of ['2026-02-30T00:00:00Z', 'not a date', '2026-10-10T09:50:00+00:00']) {
    assert.equal((await createExpiryMaintenance({ ...deploymentData, termEndUtc }, { now: () => scheduledTime, fetchFn: denied })
      .run({ scheduledTime })).reason, 'invalid_time');
  }
  for (const removalAnnouncement of [null, { bodyBase64: 'Zh==', contentType: 'application/json' },
    { bodyBase64: Buffer.from('[]').toString('base64'), contentType: 'application/json' },
    { ...announcement, contentType: 'application/json\r\nauthorization: leaked' }]) {
    const data = { ...deploymentData, ipni: { ...deploymentData.ipni, removalAnnouncement } };
    assert.equal((await createExpiryMaintenance(data, { now: () => scheduledTime, fetchFn: denied })
      .run({ scheduledTime })).reason, 'removal_announcement_unavailable');
  }
});

test('clock recheck rejects expiry-window movement before issuing the PUT', async () => {
  let reads = 0;
  const maintenance = createExpiryMaintenance(deploymentData, { now: () => ++reads === 1 ? scheduledTime : deadline + 300_000,
    fetchFn: () => assert.fail('Late recheck issued a request') });
  assert.equal((await maintenance.run({ scheduledTime })).reason, 'execution_time_changed');
});

test('HTTP rejection or redirect is reported without retry or follow-up', async () => {
  for (const status of [301, 400, 500]) {
    let calls = 0;
    const maintenance = createExpiryMaintenance(deploymentData, { now: () => scheduledTime, fetchFn: async () => {
      calls++; return new Response('rejected', { status, headers: { location: 'https://unapproved.example/' } });
    } });
    const result = await maintenance.run({ scheduledTime });
    assert.equal(result.state, 'failed'); assert.equal(result.reason, 'http_rejected');
    assert.equal(result.httpStatus, status); assert.equal(calls, 1);
  }
});

test('response size is enforced on declared length and streamed bytes', async () => {
  for (const response of [new Response('x', { headers: { 'content-length': '4097' } }),
    new Response(new Uint8Array(4097)), new Response('x', { headers: { 'content-length': 'invalid' } })]) {
    const maintenance = createExpiryMaintenance(deploymentData, { now: () => scheduledTime, fetchFn: async () => response });
    assert.equal((await maintenance.run({ scheduledTime })).reason, 'response_limit');
  }
});

test('bounded timeout aborts a stalled request and never retries', async () => {
  let calls = 0; let signal;
  const maintenance = createExpiryMaintenance(deploymentData, { now: () => scheduledTime, timeoutMs: 20,
    fetchFn: async (_url, options) => { calls++; signal = options.signal; return new Promise(() => {}); } });
  const result = await maintenance.run({ scheduledTime });
  assert.equal(result.reason, 'request_timeout'); assert.equal(signal.aborted, true); assert.equal(calls, 1);
  assert.throws(() => createExpiryMaintenance(deploymentData, { timeoutMs: 10_001 }));
});

test('deadline window also bounds response-body stalls and last-millisecond execution', async () => {
  const maintenance = createExpiryMaintenance(deploymentData, { now: () => deadline + 299_999,
    fetchFn: async () => new Response(new ReadableStream({ start() {} })) });
  assert.equal((await maintenance.run({ scheduledTime })).reason, 'request_timeout');
});

test('worker preserves content fetch and scheduled waitUntil with a tiny public result', async t => {
  assert.equal(typeof worker.fetch, 'function');
  assert.equal(typeof worker.scheduled, 'function');
  const logs = [];
  t.mock.method(console, 'log', value => logs.push(JSON.parse(value)));
  let pending;
  worker.scheduled({ scheduledTime: 0 }, {}, { waitUntil(value) { pending = value; } });
  await pending;
  assert.deepEqual(logs, [{ operation: 'ipni_removal_announcement', state: 'skipped', reason: 'invalid_time' }]);
  assert.equal(worker.fetch(new Request('https://provider.example/health')).status, 200);
});

test('continuous policy suppresses every historical and future expiry callback without reading the clock or fetching', async () => {
  const data = { ...deploymentData, servingMode: 'continuous', termEndUtc: null,
    ipni: { ...deploymentData.ipni, objects: { ...deploymentData.ipni.objects, ...deploymentData.ipni.removalObjects },
      removalHeadBase64: null, removalObjects: {}, removalAnnouncement: null } };
  const maintenance = createExpiryMaintenance(data, {
    now: () => assert.fail('Continuous policy evaluated an expiry clock'),
    fetchFn: () => assert.fail('Continuous policy announced removal'),
  });
  for (const time of [deadline - 1, deadline, scheduledTime, deadline + 300_000,
    deadline + 365 * 86_400_000, NaN, undefined]) {
    assert.deepEqual(await maintenance.run({ scheduledTime: time }), {
      operation: 'ipni_removal_announcement', state: 'skipped', reason: 'continuous_serving_policy',
    });
  }
});

test('invalid continuous mixtures cannot configure maintenance and explicit finite retains the existing admitted callback', async () => {
  const data = { ...deploymentData, servingMode: 'continuous', termEndUtc: null, ipni: null };
  for (const patch of [
    { servingMode: 'unknown' }, { servingMode: null }, { servingMode: 'finite' },
    { termEndUtc: undefined }, { termEndUtc: deploymentData.termEndUtc },
    { startedAtUtc: undefined }, { startedAtUtc: null }, { startedAtUtc: '2026-02-30T00:00:00Z' },
    { ipni: deploymentData.ipni },
  ]) assert.throws(() => createExpiryMaintenance({ ...data, ...patch }));
  let calls = 0;
  const maintenance = createExpiryMaintenance({ ...deploymentData, servingMode: 'finite' }, {
    now: () => scheduledTime, fetchFn: async () => { calls++; return new Response(null, { status: 204 }); },
  });
  assert.equal((await maintenance.run({ scheduledTime })).state, 'acknowledged');
  assert.equal(calls, 1);
});
