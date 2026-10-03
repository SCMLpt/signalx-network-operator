import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const cli = fileURLToPath(new URL('./cli.mjs', import.meta.url));

test('continuous pinning of example IPNS policy refuses before creating state or making requests', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'signalx-operator-cli-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = JSON.parse(await readFile(new URL('./config.example.json', import.meta.url), 'utf8'));
  const stateDirectory = join(directory, 'journal-state');
  config.pin = true;
  config.stateDirectory = stateDirectory;
  assert.ok(config.publications.some(publication => publication.ipnsName));
  const configFile = join(directory, 'config.json');
  const requestMarker = join(directory, 'unexpected-request');
  const preload = join(directory, 'deny-network.mjs');
  await writeFile(configFile, JSON.stringify(config));
  await writeFile(preload, `import { writeFileSync } from 'node:fs';
globalThis.fetch = async () => {
  writeFileSync(${JSON.stringify(requestMarker)}, 'Unexpected fetch attempt');
  throw new Error('This guard test permits no network requests');
};
`);

  await assert.rejects(execute(process.execPath, ['--import', preload, cli, 'run', configFile], {
    timeout: 5_000, maxBuffer: 16_384,
  }), error => {
    assert.equal(error.code, 1, 'the policy must fail immediately, before a continuous loop starts');
    assert.equal(error.killed, false);
    assert.equal(error.signal, null);
    assert.match(error.stderr, /retention/i);
    assert.equal(error.stdout, '', 'a rejected policy cannot report an operator run');
    return true;
  });
  await assert.rejects(access(stateDirectory), { code: 'ENOENT' }, 'refusal cannot create a journal directory');
  await assert.rejects(access(requestMarker), { code: 'ENOENT' }, 'refusal must precede every fetch attempt');
});
