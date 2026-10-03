#!/usr/bin/env node
// Offline source packaging. Hashes establish byte consistency; they do not
// establish the publisher's identity, a license, or a running public service.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath, unlink } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const RELEASE_FILES = Object.freeze([
  'README.md', 'car.mjs', 'car.test.mjs', 'cli.mjs', 'cli.test.mjs', 'config.example.json',
  'deploy/PILOT_QUICKSTART.md', 'deploy/README.md', 'deploy/kubo.service', 'deploy/operator.service',
  'deploy/pilot-fence.mjs', 'deploy/pilot-fence.test.mjs', 'deploy/pilot-manifest.example.json',
  'deploy/pilot-stop.service.example', 'deploy/pilot-stop.timer.example',
  'http-provider/README.md', 'http-provider/activate.mjs', 'http-provider/dataset-build.mjs',
  'http-provider/dataset-build.test.mjs',
  'http-provider/deployment-data.json', 'http-provider/discovery-check.mjs', 'http-provider/file-verify.mjs',
  'http-provider/handler.mjs', 'http-provider/handler.test.mjs',
  'http-provider/ipni-build.mjs', 'http-provider/ipni-build.test.mjs',
  'http-provider/ipni-reference/go.mod', 'http-provider/ipni-reference/go.sum',
  'http-provider/ipni-reference/main.go', 'http-provider/ipni-reference/main_test.go',
  'http-provider/maintenance.mjs', 'http-provider/maintenance.test.mjs',
  'http-provider/remote-verify.mjs', 'http-provider/unixfs.mjs', 'http-provider/unixfs.test.mjs',
  'http-provider/worker.mjs',
  'io.mjs', 'ipns.mjs', 'ipns.test.mjs', 'journal.mjs', 'journal.test.mjs',
  'kubo.mjs', 'kubo.test.mjs', 'lease.test.mjs', 'live-evidence.mjs', 'live-evidence.test.mjs',
  'operator.mjs', 'operator.test.mjs',
  'package-lock.json', 'package.json', 'release.mjs', 'release.test.mjs',
  'state.mjs', 'state.test.mjs',
].sort());
const OPTIONAL_FILES = ['LICENSE'];
const MANIFEST = 'release-manifest.json';
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 12 * 1024 * 1024;
const SOURCE_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const jsonBytes = value => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
const exactVersion = value => typeof value === 'string' &&
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/.test(value);

function checkPath(path) {
  if (typeof path !== 'string' || !/^[A-Za-z0-9@._/-]+$/.test(path) ||
      path.split('/').some(part => !part || part === '.' || part === '..')) {
    throw new Error('Unsafe release path');
  }
}

function sameFile(left, right) {
  return ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key => left[key] === right[key]);
}

async function sourceRoot(directory) {
  const requested = resolve(directory);
  const stat = await lstat(requested);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Source directory must be a real directory');
  return realpath(requested);
}

// O_NOFOLLOW protects the leaf; parent identities and canonical paths are
// checked on both sides of the read. Build from a trusted, quiescent checkout:
// Node has no portable openat API to defeat an adversarial directory-swap race.
async function readSource(root, relative, limit = MAX_FILE_BYTES) {
  checkPath(relative);
  const path = join(root, relative);
  const parents = [];
  let parent = root;
  for (const part of relative.split('/').slice(0, -1)) {
    parent = join(parent, part);
    const stat = await lstat(parent, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`Release directory is not regular: ${relative}`);
    parents.push({ path: parent, stat });
  }
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size > BigInt(limit)) {
    throw new Error(`Release source must be a bounded regular file with one link: ${relative}`);
  }
  if (await realpath(path) !== path) throw new Error(`Release source resolves outside its path: ${relative}`);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameFile(before, opened) || !opened.isFile()) throw new Error(`Release source changed: ${relative}`);
    const buffer = Buffer.alloc(Number(opened.size) + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, size);
      if (!bytesRead) break;
      size += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const current = await lstat(path, { bigint: true });
    if (size !== Number(opened.size) || !sameFile(opened, after) || !sameFile(opened, current) ||
        await realpath(path) !== path) throw new Error(`Release source changed: ${relative}`);
    for (const entry of parents) {
      const currentParent = await lstat(entry.path, { bigint: true });
      if (!currentParent.isDirectory() || currentParent.isSymbolicLink() ||
          currentParent.dev !== entry.stat.dev || currentParent.ino !== entry.stat.ino) {
        throw new Error(`Release parent changed: ${relative}`);
      }
    }
    return buffer.subarray(0, size);
  } finally { await handle.close(); }
}

function packageMetadata(files) {
  let pkg, lock;
  try {
    pkg = JSON.parse(files.get('package.json').toString('utf8'));
    lock = JSON.parse(files.get('package-lock.json').toString('utf8'));
  } catch { throw new Error('Release package metadata is invalid JSON'); }
  if (pkg.name !== 'signalx-network-operator' || !exactVersion(pkg.version) || pkg.private !== true ||
      pkg.type !== 'module' || pkg.engines?.node !== '>=22') {
    throw new Error('Release requires the private operator package and Node >=22');
  }
  const dependencies = pkg.dependencies;
  if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies) ||
      !Object.keys(dependencies).length || !Object.values(dependencies).every(exactVersion)) {
    throw new Error('Release direct dependencies must use exact versions');
  }
  const root = lock.packages?.[''];
  const sorted = value => Object.fromEntries(Object.entries(value ?? {}).sort(([a], [b]) => a.localeCompare(b)));
  if (lock.lockfileVersion !== 3 || lock.name !== pkg.name || lock.version !== pkg.version ||
      root?.name !== pkg.name || root.version !== pkg.version || root.engines?.node !== pkg.engines.node ||
      JSON.stringify(sorted(root.dependencies)) !== JSON.stringify(sorted(dependencies))) {
    throw new Error('Release package and lockfile disagree');
  }
  for (const [name, entry] of Object.entries(lock.packages)) {
    if (name === '') continue;
    checkPath(name);
    if (!name.startsWith('node_modules/') || !exactVersion(entry.version) || entry.link ||
        typeof entry.resolved !== 'string' || !entry.resolved.startsWith('https://registry.npmjs.org/') ||
        !/^sha512-[A-Za-z0-9+/]{86}==$/.test(entry.integrity ?? '')) {
      throw new Error(`Release dependency is not registry/integrity pinned: ${name}`);
    }
    const url = new URL(entry.resolved);
    if (url.origin !== 'https://registry.npmjs.org' || url.username || url.password || url.search || url.hash) {
      throw new Error(`Release dependency has an unsafe registry URL: ${name}`);
    }
  }
  for (const [name, version] of Object.entries(dependencies)) {
    if (lock.packages[`node_modules/${name}`]?.version !== version) {
      throw new Error(`Release direct dependency is not locked: ${name}`);
    }
  }
  return { name: pkg.name, version: pkg.version, node: pkg.engines.node };
}

function checkFiles(files) {
  for (const path of RELEASE_FILES) if (!files.has(path)) throw new Error(`Release file is missing: ${path}`);
  let size = 0;
  for (const [path, bytes] of files) {
    checkPath(path);
    if (![...RELEASE_FILES, ...OPTIONAL_FILES].includes(path)) throw new Error(`Release file is not allowlisted: ${path}`);
    if (bytes.length > MAX_FILE_BYTES) throw new Error(`Release file exceeds limit: ${path}`);
    size += bytes.length;
  }
  if (size > MAX_SOURCE_BYTES) throw new Error('Release source exceeds total limit');
}

function makeManifest(files) {
  checkFiles(files);
  const pkg = packageMetadata(files);
  return {
    formatVersion: 1,
    archiveFormat: 'ustar',
    package: pkg,
    licenseFile: files.has('LICENSE') ? 'LICENSE' : null,
    lockfile: { path: 'package-lock.json', sha256: digest(files.get('package-lock.json')) },
    files: [...files].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([path, bytes]) => ({ path, bytes: bytes.length, mode: '0644', sha256: digest(bytes) })),
  };
}

function putOctal(header, offset, length, value) {
  const text = value.toString(8).padStart(length - 1, '0');
  if (text.length >= length) throw new Error('Release tar field exceeds limit');
  header.write(`${text}\0`, offset, length, 'ascii');
}

function tarEntry(name, bytes) {
  checkPath(name);
  if (Buffer.byteLength(name) > 100) throw new Error('Release tar path exceeds USTAR name limit');
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'ascii');
  putOctal(header, 100, 8, 0o644);
  putOctal(header, 108, 8, 0);
  putOctal(header, 116, 8, 0);
  putOctal(header, 124, 12, bytes.length);
  putOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  putOctal(header, 329, 8, 0);
  putOctal(header, 337, 8, 0);
  const checksum = header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0');
  header.write(`${checksum}\0 `, 148, 8, 'ascii');
  return [header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512)];
}

function archiveBytes(manifest, files) {
  const prefix = `${manifest.package.name}-${manifest.package.version}`;
  const all = new Map(files);
  all.set(MANIFEST, jsonBytes(manifest));
  const chunks = [...all].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .flatMap(([path, bytes]) => tarEntry(`${prefix}/${path}`, bytes));
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}

/** All bytes are captured twice before writing; metadata is deliberately fixed. */
export async function createRelease(sourceDirectory = SOURCE_DIRECTORY) {
  const root = await sourceRoot(sourceDirectory);
  const rootStat = await lstat(root, { bigint: true });
  const paths = [...RELEASE_FILES];
  for (const path of OPTIONAL_FILES) {
    try { await lstat(join(root, path)); paths.push(path); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const files = new Map();
  for (const path of paths.sort()) files.set(path, await readSource(root, path));
  const manifest = makeManifest(files);
  for (const [path, bytes] of files) {
    if (!(await readSource(root, path)).equals(bytes)) throw new Error(`Release source changed: ${path}`);
  }
  const finalRoot = await lstat(root, { bigint: true });
  if (rootStat.dev !== finalRoot.dev || rootStat.ino !== finalRoot.ino) throw new Error('Release source directory changed');
  const archive = archiveBytes(manifest, files);
  return { manifest, archive, archiveName: `${manifest.package.name}-${manifest.package.version}.tar`, sha256: digest(archive) };
}

/** Reject all noncanonical tar records, including links, traversal and extras. */
export function verifyReleaseArchive(input, expectedSha256) {
  const bytes = Buffer.from(input);
  if (bytes.length > MAX_ARCHIVE_BYTES || bytes.length < 1024 || bytes.length % 512) {
    throw new Error('Release archive has invalid size');
  }
  const sha256 = digest(bytes);
  if (expectedSha256 !== undefined && (!/^[a-f0-9]{64}$/.test(expectedSha256) || expectedSha256 !== sha256)) {
    throw new Error('Release archive does not match the expected SHA-256');
  }
  const entries = new Map();
  let offset = 0, prefix;
  while (offset < bytes.length - 1024) {
    const header = bytes.subarray(offset, offset + 512);
    const end = header.subarray(0, 100).indexOf(0);
    if (end < 0) throw new Error('Release tar name is not terminated');
    const name = header.subarray(0, end).toString('ascii');
    checkPath(name);
    const slash = name.indexOf('/');
    if (slash < 1) throw new Error('Release tar file lacks its package prefix');
    const currentPrefix = name.slice(0, slash), path = name.slice(slash + 1);
    if (prefix !== undefined && prefix !== currentPrefix) throw new Error('Release tar has mixed package prefixes');
    prefix = currentPrefix;
    if (entries.has(path) || entries.size >= RELEASE_FILES.length + OPTIONAL_FILES.length + 1) {
      throw new Error('Release tar has duplicate or excess entries');
    }
    const sizeField = header.subarray(124, 136).toString('ascii');
    if (!/^[0-7]{11}\0$/.test(sizeField)) throw new Error('Release tar size is invalid');
    const size = Number.parseInt(sizeField, 8);
    if (size > (path === MANIFEST ? 32768 : MAX_FILE_BYTES) || offset + 512 + size > bytes.length - 1024) {
      throw new Error('Release tar entry exceeds its limit');
    }
    const data = bytes.subarray(offset + 512, offset + 512 + size);
    const canonical = Buffer.concat(tarEntry(name, data));
    if (!bytes.subarray(offset, offset + canonical.length).equals(canonical)) {
      throw new Error('Release tar contains a noncanonical header or padding');
    }
    entries.set(path, data);
    offset += canonical.length;
  }
  if (offset !== bytes.length - 1024 || bytes.subarray(offset).some(byte => byte !== 0)) {
    throw new Error('Release tar has invalid end records');
  }
  const encodedManifest = entries.get(MANIFEST);
  if (!encodedManifest) throw new Error('Release manifest is missing');
  entries.delete(MANIFEST);
  const manifest = makeManifest(entries);
  if (prefix !== `${manifest.package.name}-${manifest.package.version}` ||
      !jsonBytes(manifest).equals(encodedManifest) || !archiveBytes(manifest, entries).equals(bytes)) {
    throw new Error('Release archive does not match its canonical manifest');
  }
  return { manifest, sha256, bytes: bytes.length };
}

/** Verify covered source files before installing dependencies or running them. */
export async function verifyReleaseDirectory(directory) {
  const root = await sourceRoot(directory);
  const encodedManifest = await readSource(root, MANIFEST, 32768);
  let declared;
  try { declared = JSON.parse(encodedManifest.toString('utf8')); }
  catch { throw new Error('Release manifest is invalid JSON'); }
  if (!Array.isArray(declared.files) || declared.files.length > RELEASE_FILES.length + OPTIONAL_FILES.length) {
    throw new Error('Release manifest file count is invalid');
  }
  const files = new Map();
  for (const entry of declared.files) {
    if (!entry || ![...RELEASE_FILES, ...OPTIONAL_FILES].includes(entry.path) || files.has(entry.path)) {
      throw new Error('Release manifest contains a duplicate or non-allowlisted path');
    }
    files.set(entry.path, await readSource(root, entry.path));
  }
  const manifest = makeManifest(files);
  if (!jsonBytes(manifest).equals(encodedManifest)) throw new Error('Release files do not match their manifest');
  return { manifest, sha256: digest(archiveBytes(manifest, files)) };
}

/** Exclusive writes prevent replacing an earlier release or following a link. */
export async function writeRelease(outputDirectory, { sourceDirectory = SOURCE_DIRECTORY } = {}) {
  const release = await createRelease(sourceDirectory);
  const requested = resolve(outputDirectory);
  await mkdir(requested, { recursive: true });
  const stat = await lstat(requested);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Release output must be a real directory');
  const output = await realpath(requested);
  const writes = [
    [join(output, release.archiveName), release.archive],
    [join(output, `${release.archiveName}.sha256`), Buffer.from(`${release.sha256}  ${release.archiveName}\n`)],
  ];
  const created = [];
  try {
    for (const [path, bytes] of writes) {
      const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
      created.push(path);
      try { await handle.writeFile(bytes); await handle.sync(); }
      finally { await handle.close(); }
    }
  } catch (error) {
    // Only remove paths created by this invocation; an existing artifact stays.
    for (const path of created) await unlink(path).catch(() => {});
    throw error;
  }
  return { archive: writes[0][0], checksum: writes[1][0], sha256: release.sha256,
    bytes: release.archive.length, files: release.manifest.files.length, licenseFile: release.manifest.licenseFile };
}

async function main() {
  if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Release tool requires Node.js 22 or later');
  const [command, target, expected, ...extra] = process.argv.slice(2);
  if (!target || extra.length || !['build', 'verify'].includes(command) || command === 'build' && expected !== undefined) {
    throw new Error('Usage: node release.mjs build OUTPUT_DIRECTORY | verify ARCHIVE [EXPECTED_SHA256] | verify DIRECTORY');
  }
  if (command === 'build') { console.log(JSON.stringify(await writeRelease(target), null, 2)); return; }
  const path = resolve(target);
  const stat = await lstat(path);
  let result;
  if (stat.isDirectory()) {
    if (expected !== undefined) throw new Error('Expected archive hash is only accepted for archive verification');
    result = await verifyReleaseDirectory(path);
  } else {
    const root = await realpath(dirname(path));
    const bytes = await readSource(root, basename(path), MAX_ARCHIVE_BYTES);
    result = verifyReleaseArchive(bytes, expected);
  }
  console.log(JSON.stringify({ status: 'source_integrity_verified', sha256: result.sha256,
    package: result.manifest.package, files: result.manifest.files.length, licenseFile: result.manifest.licenseFile,
    expectedHashMatched: expected !== undefined, authenticityVerified: false }, null, 2));
}

if (process.argv[1] && await realpath(fileURLToPath(import.meta.url)) ===
    await realpath(resolve(process.argv[1]))) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
