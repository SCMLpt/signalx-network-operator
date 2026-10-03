import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, copyFile, link, mkdir, mkdtemp, readFile, rename, rm,
  stat, symlink, truncate, utimes, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRelease, RELEASE_FILES, verifyReleaseArchive,
  verifyReleaseDirectory, writeRelease } from './release.mjs';

const source = dirname(fileURLToPath(import.meta.url));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'signalx-release-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, 'source');
  await mkdir(join(directory, 'deploy'), { recursive: true });
  for (const path of RELEASE_FILES) await copyFile(join(source, path), join(directory, path));
  return { root, directory };
}

function records(bytes) {
  const entries = [];
  for (let offset = 0; offset < bytes.length - 1024;) {
    const name = bytes.subarray(offset, offset + 100).toString('ascii').split('\0')[0];
    const size = Number.parseInt(bytes.subarray(offset + 124, offset + 136).toString('ascii'), 8);
    entries.push({ name, offset, size, start: offset + 512 });
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return entries;
}

// Recompute a valid tar checksum so path/type tests reach semantic validation.
function replaceHeader(bytes, offset, mutate) {
  const changed = Buffer.from(bytes);
  const header = changed.subarray(offset, offset + 512);
  mutate(header);
  header.fill(0x20, 148, 156);
  const checksum = header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0');
  header.write(`${checksum}\0 `, 148, 8, 'ascii');
  return changed;
}

async function extractFixture(directory, release) {
  for (const entry of records(release.archive)) {
    const relative = entry.name.slice(entry.name.indexOf('/') + 1);
    await mkdir(dirname(join(directory, relative)), { recursive: true });
    await writeFile(join(directory, relative), release.archive.subarray(entry.start, entry.start + entry.size));
  }
}

test('offline source bundle is deterministic, locked and excludes private/workspace files', async t => {
  const { directory } = await fixture(t);
  const secret = ['release-test-private-key-canary', Date.now(), Math.random()].join('-');
  for (const path of ['.env', 'operator.json', 'state-v1/records.json', 'fixtures/key.json', 'node_modules/private.js']) {
    await mkdir(dirname(join(directory, path)), { recursive: true });
    await writeFile(join(directory, path), secret);
  }
  await symlink('/does/not/exist', join(directory, 'credentials'));
  const first = await createRelease(directory);
  await chmod(join(directory, 'cli.mjs'), 0o755);
  await utimes(join(directory, 'cli.mjs'), new Date(1), new Date(2));
  const second = await createRelease(directory);
  assert.deepEqual(first.archive, second.archive);
  assert.equal(first.sha256, hash(first.archive));
  assert.equal(first.manifest.licenseFile, null);
  assert.equal(first.manifest.lockfile.sha256, hash(await readFile(join(directory, 'package-lock.json'))));
  assert.deepEqual(first.manifest.files.map(entry => entry.path), RELEASE_FILES);
  assert.ok(first.manifest.files.every(entry => entry.mode === '0644'));
  assert.ok(!first.archive.includes(Buffer.from(secret)));
  const verified = verifyReleaseArchive(first.archive, first.sha256);
  assert.deepEqual(verified.manifest, first.manifest);
  assert.equal(verified.sha256, first.sha256);
  assert.equal(records(first.archive).length, RELEASE_FILES.length + 1);
  assert.throws(() => verifyReleaseArchive(first.archive, '0'.repeat(64)), /expected SHA-256/);
  assert.throws(() => verifyReleaseArchive(first.archive, 'not-a-hash'), /expected SHA-256/);
});

test('explicit existing package license is included; no license is invented', async t => {
  const { directory } = await fixture(t);
  const before = await createRelease(directory);
  await writeFile(join(directory, 'LICENSE'), 'Owner-selected license fixture.\n');
  const release = await createRelease(directory);
  assert.equal(release.manifest.licenseFile, 'LICENSE');
  assert.ok(release.manifest.files.some(entry => entry.path === 'LICENSE'));
  assert.notEqual(before.sha256, release.sha256);
  verifyReleaseArchive(release.archive, release.sha256);
});

test('archive verifier rejects traversal, absolute paths, ambiguous separators and extra source', async t => {
  const { directory } = await fixture(t);
  const { archive } = await createRelease(directory);
  const first = records(archive)[0];
  for (const name of ['../escape', '/absolute', 'release/../escape', 'release/./README.md',
    'release//README.md', 'release\\README.md', 'release/.env', 'release/node_modules/evil.js']) {
    const changed = replaceHeader(archive, first.offset, header => {
      header.fill(0, 0, 100);
      header.write(name, 0, 'ascii');
    });
    assert.throws(() => verifyReleaseArchive(changed), /Unsafe|allowlisted|missing|prefix/, name);
  }
});

test('archive verifier rejects links, devices, extensions, duplicate entries and metadata drift', async t => {
  const { directory } = await fixture(t);
  const { archive } = await createRelease(directory);
  const entries = records(archive);
  for (const type of ['1', '2', '3', '4', '5', '6', 'x', 'g', 'L']) {
    const changed = replaceHeader(archive, 0, header => {
      header[156] = type.charCodeAt(0);
      header.write('../../outside', 157, 'ascii');
    });
    assert.throws(() => verifyReleaseArchive(changed), /noncanonical/, `type ${type}`);
  }
  const duplicate = replaceHeader(archive, entries[1].offset, header => {
    header.fill(0, 0, 100);
    header.write(entries[0].name, 0, 'ascii');
  });
  assert.throws(() => verifyReleaseArchive(duplicate), /duplicate/);
  const timestamp = replaceHeader(archive, 0, header => header.write('00000000001\0', 136, 'ascii'));
  assert.throws(() => verifyReleaseArchive(timestamp), /noncanonical/);
});

test('archive verifier detects actual payload/manifest mutations and invalid framing', async t => {
  const { directory } = await fixture(t);
  const { archive } = await createRelease(directory);
  const changed = Buffer.from(archive);
  changed[records(archive)[0].start] ^= 1;
  assert.throws(() => verifyReleaseArchive(changed), /manifest/);
  const manifestEntry = records(archive).find(entry => entry.name.endsWith('/release-manifest.json'));
  const manifestMutation = Buffer.from(archive);
  manifestMutation[manifestEntry.start] = 0x20;
  assert.throws(() => verifyReleaseArchive(manifestMutation), /manifest/);
  const endMutation = Buffer.from(archive);
  endMutation[endMutation.length - 1] = 1;
  assert.throws(() => verifyReleaseArchive(endMutation), /end records/);
  assert.throws(() => verifyReleaseArchive(archive.subarray(0, archive.length - 512)), /limit|size|end records/);
  assert.throws(() => verifyReleaseArchive(Buffer.concat([archive, Buffer.alloc(512)])), /Unsafe|end records/);
  assert.throws(() => verifyReleaseArchive(Buffer.alloc(12 * 1024 * 1024 + 512)), /invalid size/);
});

test('source capture rejects real symlinks in source roots, files and parent directories', async t => {
  const { root, directory } = await fixture(t);
  const alias = join(root, 'alias');
  await symlink(directory, alias);
  await assert.rejects(createRelease(alias), /real directory/);
  const file = join(directory, 'operator.mjs');
  await rename(file, `${file}.original`);
  await symlink(`${file}.original`, file);
  await assert.rejects(createRelease(directory), /regular file/);
  await rm(file);
  await rename(`${file}.original`, file);
  await rename(join(directory, 'deploy'), join(root, 'deployment-files'));
  await symlink(join(root, 'deployment-files'), join(directory, 'deploy'));
  await assert.rejects(createRelease(directory), /directory is not regular/);
});

test('source capture rejects hardlinks, oversized regular files and missing required files', async t => {
  const { root, directory } = await fixture(t);
  const file = join(directory, 'operator.mjs');
  const other = join(root, 'linked-source');
  await link(file, other);
  await assert.rejects(createRelease(directory), /one link/);
  await rm(other);
  await truncate(file, 2 * 1024 * 1024 + 1);
  await assert.rejects(createRelease(directory), /bounded regular/);
  await rm(file);
  await assert.rejects(createRelease(directory), { code: 'ENOENT' });
});

test('package and lockfile validation fails on ranges, divergent pins and untrusted resolutions', async t => {
  const { directory } = await fixture(t);
  const pkgPath = join(directory, 'package.json');
  const lockPath = join(directory, 'package-lock.json');
  const originalPkg = JSON.parse(await readFile(pkgPath, 'utf8'));
  const originalLock = JSON.parse(await readFile(lockPath, 'utf8'));
  const pkg = structuredClone(originalPkg);
  pkg.dependencies.multiformats = '^14.0.5';
  await writeFile(pkgPath, JSON.stringify(pkg));
  await assert.rejects(createRelease(directory), /exact versions/);
  await writeFile(pkgPath, JSON.stringify(originalPkg));
  for (const mutate of [
    lock => { lock.packages[''].dependencies.multiformats = '14.0.4'; },
    lock => { lock.packages['node_modules/multiformats'].version = '14.0.4'; },
    lock => { delete lock.packages['node_modules/multiformats'].integrity; },
    lock => { lock.packages['node_modules/multiformats'].link = true; },
    lock => { lock.packages['node_modules/multiformats'].resolved = 'https://registry.npmjs.org@evil.example/pkg.tgz'; },
    lock => { lock.packages['node_modules/multiformats'].resolved = 'https://registry.npmjs.org/pkg.tgz?token=secret'; },
    lock => { lock.packages['node_modules/../escape'] = lock.packages['node_modules/multiformats']; },
  ]) {
    const lock = structuredClone(originalLock);
    mutate(lock);
    await writeFile(lockPath, JSON.stringify(lock));
    await assert.rejects(createRelease(directory), /disagree|locked|pinned|unsafe|Unsafe/);
  }
});

test('extracted directory verifies before installation and detects actual file and manifest mutations', async t => {
  const { root, directory } = await fixture(t);
  const release = await createRelease(directory);
  const extracted = join(root, 'extracted');
  await extractFixture(extracted, release);
  assert.equal((await verifyReleaseDirectory(extracted)).sha256, release.sha256);
  const file = join(extracted, 'operator.mjs');
  const original = await readFile(file);
  await writeFile(file, Buffer.concat([original, Buffer.from('\n// malicious changed source\n')]));
  await assert.rejects(verifyReleaseDirectory(extracted), /do not match/);
  await writeFile(file, original);
  const manifestPath = join(extracted, 'release-manifest.json');
  const manifest = structuredClone(release.manifest);
  manifest.files[0].path = '../outside';
  await writeFile(manifestPath, JSON.stringify(manifest));
  await assert.rejects(verifyReleaseDirectory(extracted), /non-allowlisted/);
});

test('output is exclusive, rejects symlinks and preserves existing artifacts on partial failure', async t => {
  const { root, directory } = await fixture(t);
  const output = join(root, 'release');
  const first = await writeRelease(output, { sourceDirectory: directory });
  const original = await readFile(first.archive);
  await assert.rejects(writeRelease(output, { sourceDirectory: directory }), { code: 'EEXIST' });
  assert.deepEqual(await readFile(first.archive), original);
  await rm(first.archive);
  await assert.rejects(writeRelease(output, { sourceDirectory: directory }), { code: 'EEXIST' });
  await assert.rejects(stat(first.archive), { code: 'ENOENT' });
  assert.equal(await readFile(first.checksum, 'utf8'), `${first.sha256}  ${basename(first.archive)}\n`);
  const alias = join(root, 'output-alias');
  await symlink(output, alias);
  await assert.rejects(writeRelease(alias, { sourceDirectory: directory }), /real directory/);
  const target = join(root, 'private-target');
  await writeFile(target, 'keep this private file');
  await symlink(target, first.archive);
  await assert.rejects(writeRelease(output, { sourceDirectory: directory }), { code: 'EEXIST' });
  assert.equal(await readFile(target, 'utf8'), 'keep this private file');
});

test('standard tar extracts the real archive, and built-in-only CLI verifies it offline', async t => {
  const { root, directory } = await fixture(t);
  const release = await writeRelease(join(root, 'artifacts'), { sourceDirectory: directory });
  const unpack = join(root, 'unpack');
  await mkdir(unpack);
  const tar = spawnSync('tar', ['-xf', release.archive, '-C', unpack], { encoding: 'utf8', timeout: 10000 });
  assert.equal(tar.status, 0, tar.stderr);
  const extracted = join(unpack, basename(release.archive, '.tar'));
  const verified = await verifyReleaseDirectory(extracted);
  assert.equal(verified.sha256, release.sha256);
  for (const args of [[release.archive, release.sha256], [extracted]]) {
    const cli = spawnSync(process.execPath, [join(extracted, 'release.mjs'), 'verify', ...args],
      { encoding: 'utf8', timeout: 10000 });
    assert.equal(cli.status, 0, cli.stderr);
    const result = JSON.parse(cli.stdout);
    assert.equal(result.status, 'source_integrity_verified');
    assert.equal(result.authenticityVerified, false);
    assert.equal(result.expectedHashMatched, args.length === 2);
    assert.equal(result.sha256, release.sha256);
  }
  const bad = spawnSync(process.execPath, [join(extracted, 'release.mjs'), 'verify', release.archive, '0'.repeat(64)],
    { encoding: 'utf8', timeout: 10000 });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /expected SHA-256/);
});
