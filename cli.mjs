#!/usr/bin/env node
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { validateConfig, runOnce } from './operator.mjs';
import { KuboClient } from './kubo.mjs';

async function main() {
  const [command, file, option, ...extra] = process.argv.slice(2);
  if (!['check', 'inspect', 'run'].includes(command) || !file || extra.length ||
      (option !== undefined && (command !== 'run' || option !== '--once'))) {
    throw new Error('Usage: node cli.mjs check|inspect|run CONFIG.json [--once]');
  }
  const path = resolve(file);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let bytes;
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 16384) throw new Error('Configuration must be a regular file of at most 16 KiB');
    const buffer = Buffer.alloc(16385);
    const { bytesRead } = await handle.read(buffer, 0, buffer.byteLength, 0);
    if (bytesRead > 16384) throw new Error('Configuration exceeds 16 KiB');
    bytes = buffer.subarray(0, bytesRead);
  } finally { await handle.close(); }
  const input = JSON.parse(bytes.toString('utf8'));
  if (typeof input.stateDirectory !== 'string' || !input.stateDirectory) throw new Error('stateDirectory is required');
  input.stateDirectory = resolve(dirname(path), input.stateDirectory);
  const config = validateConfig(input);
  if (command === 'inspect') {
    console.log(JSON.stringify(await new KuboClient({ url: config.kuboUrl,
      timeoutMs: config.limits.timeoutMs }).inspect(), null, 2));
    return;
  }
  if (command === 'check' && config.pin) throw new Error('check requires pin:false; use run for approved pin effects');
  if (command === 'run' && option !== '--once' && !config.pin) {
    throw new Error('Continuous runs require pin:true and an explicitly operated Kubo node');
  }
  if (command === 'run' && option !== '--once' && config.publications.some(publication => publication.ipnsName)) {
    throw new Error('Continuous IPNS preservation requires a durable retention and release policy; use a reviewed fixed root or a one-off run');
  }
  if (command === 'check' || option === '--once') {
    const report = await runOnce(config);
    console.log(JSON.stringify(report, null, 2));
    if (report.status !== 'verified') process.exitCode = 1;
    return;
  }
  const stop = new AbortController();
  process.once('SIGINT', () => stop.abort());
  process.once('SIGTERM', () => stop.abort());
  while (!stop.signal.aborted) {
    try { console.log(JSON.stringify(await runOnce(config))); }
    catch (error) {
      console.error(JSON.stringify({ status: 'degraded', error: error.message, code: error.code ?? null }));
      if (error.code?.startsWith('JOURNAL_') || error.code === 'OPERATOR_STATE_CORRUPT' || ['ENOSPC', 'EACCES', 'EROFS', 'EIO'].includes(error.code) ||
          error instanceof AggregateError) throw error;
    }
    try { await delay(config.intervalSeconds * 1000, undefined, { signal: stop.signal }); }
    catch (error) { if (!stop.signal.aborted) throw error; }
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
