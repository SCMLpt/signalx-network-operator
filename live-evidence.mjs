import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { CarReader } from '@ipld/car';
import { CID } from 'multiformats/cid';
import { peerIdFromString } from '@libp2p/peer-id';
import { verifyCar } from './car.mjs';
import { validateConfig } from './operator.mjs';

export const DEFAULT_ROOT = 'bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle';
const MAX_MANIFEST = 64 * 1024;
const MAX_RAW = 128 * 1024;
const MAX_CAR = 1024 * 1024;
const MAX_TOTAL = 4 * 1024 * 1024;
const REQUIRED = [
  'config', 'workerReport', 'operatorVersion', 'operatorId', 'pinLs', 'pinVerify',
  'operatorEpochBefore', 'operatorEpochAfter', 'ledgerBefore', 'ledgerAfter',
  'probeVersion', 'probeId', 'probeEpochBefore', 'probeEpochAfter', 'coldRefs',
  'routingConfig', 'bootstrapList', 'peersBefore', 'peersAfter',
  'isolationRules', 'isolationTrace', 'sourceCar', 'retrievedCar', 'bandwidthBefore', 'bandwidthAfter',
  'workerPackage', 'workerSourceHashes', 'operatorBinaryHash', 'probeBinaryHash',
];
const OPTIONAL = ['discoveryId', 'providerDiscovery', 'provideStat', 'dhtStat'];
const ARTIFACT_FILES = {
  config: 'approved-config.json', workerReport: 'worker-report.json',
  workerPackage: 'worker-package.json', workerSourceHashes: 'worker-source-hashes.txt',
  operatorBinaryHash: 'operator-binary-hash.txt', probeBinaryHash: 'probe-binary-hash.txt',
  operatorVersion: 'operator-version.json', operatorId: 'operator-id.json', pinLs: 'pin-ls.json', pinVerify: 'pin-verify.jsonl',
  operatorEpochBefore: 'operator-epoch-before.txt', operatorEpochAfter: 'operator-epoch-after.txt',
  ledgerBefore: 'ledger-before.json', ledgerAfter: 'ledger-after.json',
  probeVersion: 'probe-version.json', probeId: 'probe-id.json',
  probeEpochBefore: 'probe-epoch-before.txt', probeEpochAfter: 'probe-epoch-after.txt', coldRefs: 'cold-refs.jsonl',
  routingConfig: 'routing-config.json', bootstrapList: 'bootstrap-list.txt',
  peersBefore: 'peers-before.json', peersAfter: 'peers-after.json',
  discoveryId: 'discovery-id.json', providerDiscovery: 'provider-discovery.txt',
  isolationRules: 'isolation-rules.json', isolationTrace: 'isolation-trace.pcap',
  sourceCar: 'source.car', retrievedCar: 'retrieved.car', provideStat: 'provide-stat.json', dhtStat: 'dht-stat.json',
  bandwidthBefore: 'bandwidth-before.json', bandwidthAfter: 'bandwidth-after.json',
};
const WORKER_FILES = ['cli.mjs', 'operator.mjs', 'car.mjs', 'kubo.mjs', 'ipns.mjs', 'io.mjs',
  'journal.mjs', 'state.mjs', 'package.json', 'package-lock.json'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const canonical = value => CID.parse(value).toV1().toString();
const peer = value => peerIdFromString(value).toString();
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function demand(condition, message) { if (!condition) throw new Error(message); }
function timestamp(value) { demand(Number.isSafeInteger(value) && value > 0, 'Invalid timestamp'); return value; }

// Never follow symlinks, read devices/FIFOs, or allocate from an unbounded file size.
async function boundedFile(path, limit) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    demand(before.isFile() && before.nlink === 1 && before.size <= limit, 'Artifact must be a bounded regular file with one link');
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = await handle.read(buffer, length, buffer.length - length, length);
      if (!read.bytesRead) break;
      length += read.bytesRead;
    }
    const after = await handle.stat();
    demand(length <= limit && length === before.size && before.size === after.size &&
      before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs, 'Artifact changed during bounded read');
    return buffer.subarray(0, length);
  } finally { await handle.close(); }
}
function json(bytes) {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new Error('Invalid UTF-8 or JSON artifact'); }
}
function lines(bytes) { return new TextDecoder('utf-8', { fatal: true }).decode(bytes).split(/\r?\n/).filter(line => line.trim()); }
function jsonLines(bytes) {
  try { return lines(bytes).map(line => JSON.parse(line)); }
  catch { throw new Error('Invalid UTF-8 or newline JSON artifact'); }
}
function hashLines(bytes) {
  const result = {};
  for (const line of lines(bytes)) {
    const match = /^([0-9a-f]{64}) [ *](.+)$/.exec(line);
    demand(match, 'Invalid native sha256sum output');
    const name = basename(match[2]);
    demand(!Object.hasOwn(result, name), 'Duplicate source or binary hash');
    result[name] = match[1];
  }
  return result;
}
function unsigned(value, label) {
  demand((typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)) ||
    (Number.isSafeInteger(value) && value >= 0), `${label} must be an exact unsigned counter`);
  return BigInt(value);
}

/** Graph equality is independent of CAR order and identical duplicate sections. */
export async function graphManifest(bytes, root) {
  const verified = await verifyCar(bytes, root, { maxBytes: MAX_CAR, maxBlocks: 8192, maxLinks: 32768 });
  const reader = await CarReader.fromBytes(bytes);
  const entries = new Map();
  for await (const block of reader.blocks()) {
    entries.set(block.cid.toV1().toString(), {
      cid: block.cid.toV1().toString(), bytes: block.bytes.byteLength,
      sha256: sha256(block.bytes), inline: block.cid.multihash.code === 0,
    });
  }
  const blocks = [...entries.values()].sort((a, b) => a.cid < b.cid ? -1 : a.cid > b.cid ? 1 : 0);
  return { ...verified, blocks, graphDigest: sha256(JSON.stringify(blocks)),
    nonInlinePayloadBytes: blocks.filter(block => !block.inline).reduce((sum, block) => sum + block.bytes, 0) };
}

/**
 * This reducer checks local artifact consistency. Artifact origins, offsite
 * administration, firewall semantics and human approval still require review.
 * It cannot authenticate a live event from files supplied by an administrator.
 */
export async function verifyEvidence(manifestPath, { now = Date.now() } = {}) {
  const report = {
    schemaVersion: 1, scope: 'offline_controlled_probe_artifact_review', status: 'rejected',
    controlledRetrievalArtifactsConsistent: false, controlledDirectDeliveryVerified: false,
    providerDiscoveryArtifactsConsistent: false,
    continuousIsolation: 'unverified', publicDhtServerServing: null,
    providerRefreshOverNativeInterval: null, retainedWithoutOrigin: null,
    externalUseVerified: false, organicExternalRequests: null, independentOperators: null,
    serviceRevenue: null, issues: [], artifactDigests: {},
    limitations: [
      'Hashes bind these files; they do not authenticate capture provenance or external administration.',
      'A reviewed continuous restriction is necessary; peer snapshots alone cannot exclude transient fallback.',
      'A controlled full-graph retrieval measures delivery capability, not spontaneous demand or outage recovery.',
      'Routing.Type, a wanserver table and providing statistics cannot establish answered public DHT service.',
      'Peer ledger payload bytes exclude framing; total bandwidth includes other traffic and is not an organic numerator.',
    ],
  };
  try {
    const manifestBytes = await boundedFile(resolve(manifestPath), MAX_MANIFEST);
    const manifest = json(manifestBytes);
    report.manifestSha256 = sha256(manifestBytes);
    demand(record(manifest) && manifest.schemaVersion === 1, 'Unsupported evidence manifest');
    const root = canonical(manifest.root);
    report.root = root;
    demand(manifest.triggerOrigin === 'controlled_probe', 'Only explicitly controlled probes are supported');
    demand(record(manifest.operator) && record(manifest.probe), 'Missing participant declarations');
    const operator = peer(manifest.operator.peerId), probe = peer(manifest.probe.peerId);
    demand(operator !== probe, 'Operator and isolated probe must have distinct peer IDs');
    demand(typeof manifest.operator.site === 'string' && typeof manifest.probe.site === 'string' &&
      manifest.operator.site !== manifest.probe.site, 'Different operator/probe locations must be declared');
    const start = timestamp(manifest.window?.startAtMs), end = timestamp(manifest.window?.endAtMs);
    demand(end > start && end - start <= 30000 && end <= now && now - end <= 86400000, 'Probe must be a completed <=30-second window captured within the last day');
    const approval = manifest.approval;
    demand(record(approval) && typeof approval.reference === 'string' && approval.reference.length > 0 &&
      isAbsolute(approval.configPath) && /^[0-9a-f]{64}$/.test(approval.policyDigest), 'Missing exact policy approval declaration');
    demand(timestamp(approval.retentionUntilMs) > end, 'Approved retention must cover the probe');
    demand(record(manifest.artifacts) && REQUIRED.every(key => Object.hasOwn(manifest.artifacts, key)) &&
      Object.keys(manifest.artifacts).every(key => REQUIRED.includes(key) || OPTIONAL.includes(key)), 'Manifest needs the documented raw artifacts without unknown inputs');
    demand(Object.hasOwn(manifest.artifacts, 'discoveryId') === Object.hasOwn(manifest.artifacts, 'providerDiscovery'), 'Discovery identity and provider result must be supplied together');
    const data = {};
    let total = manifestBytes.byteLength;
    const names = new Set();
    for (const key of [...REQUIRED, ...OPTIONAL.filter(key => Object.hasOwn(manifest.artifacts, key))]) {
      const artifact = manifest.artifacts[key];
      demand(record(artifact) && typeof artifact.file === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(artifact.file) &&
        artifact.file !== '.' && artifact.file !== '..' && !names.has(artifact.file), `Invalid or reused ${key} filename`);
      names.add(artifact.file);
      demand(/^[0-9a-f]{64}$/.test(artifact.sha256) && typeof artifact.command === 'string' &&
        artifact.command.length > 0 && artifact.command.length <= 2048 && artifact.exitCode === 0, `${key} lacks successful capture provenance`);
      const captured = timestamp(artifact.capturedAtMs);
      demand(captured >= start - 600000 && captured <= end + 600000 && captured <= now, `${key} capture falls outside bounded preparation/capture interval`);
      if (['config', 'workerReport', 'operatorEpochBefore', 'ledgerBefore', 'bandwidthBefore',
        'probeEpochBefore', 'coldRefs', 'routingConfig', 'bootstrapList', 'peersBefore',
        'pinLs', 'pinVerify', 'providerDiscovery', 'sourceCar', 'workerPackage', 'workerSourceHashes',
        'operatorBinaryHash', 'probeBinaryHash', 'operatorVersion', 'probeVersion',
        'operatorId', 'probeId', 'discoveryId'].includes(key)) {
        demand(captured <= start, `${key} must be captured before the transfer`);
      }
      if (['operatorEpochAfter', 'ledgerAfter', 'bandwidthAfter', 'probeEpochAfter',
        'peersAfter', 'retrievedCar', 'isolationTrace'].includes(key)) {
        demand(captured >= end, `${key} must be captured after the transfer`);
      }
      const limit = key.endsWith('Car') ? MAX_CAR : key === 'config' ? 16384 : MAX_RAW;
      data[key] = await boundedFile(resolve(dirname(resolve(manifestPath)), artifact.file), limit);
      total += data[key].byteLength;
      demand(total <= MAX_TOTAL, 'Evidence exceeds the 4 MiB total budget');
      demand(sha256(data[key]) === artifact.sha256, `${key} digest mismatch`);
      report.artifactDigests[key] = artifact.sha256;
    }
    const configInput = json(data.config);
    demand(typeof configInput.stateDirectory === 'string', 'Config lacks state directory');
    configInput.stateDirectory = resolve(dirname(approval.configPath), configInput.stateDirectory);
    const config = validateConfig(configInput);
    demand(config.pin === true && config.publications.length === 1 && config.publications[0].root === root,
      'Approval must select exactly one fixed CID with pin:true');
    demand(config.limits.maxCarBytes <= MAX_CAR && config.limits.maxRunBytes <= MAX_TOTAL &&
      config.limits.timeoutMs <= 30000, 'Approved pilot config exceeds the narrow CAR/run/request budget');
    demand(sha256(JSON.stringify(config)) === approval.policyDigest, 'Normalized approved policy digest mismatch');
    const implementation = manifest.implementation;
    demand(record(implementation) && typeof implementation.workerVersion === 'string' &&
      /^[0-9]+\.[0-9]+\.[0-9]+$/.test(implementation.workerVersion) && implementation.workerVersion.length <= 64 &&
      record(implementation.workerFileHashes) && Object.keys(implementation.workerFileHashes).length === WORKER_FILES.length &&
      WORKER_FILES.every(key => /^[0-9a-f]{64}$/.test(implementation.workerFileHashes[key])), 'Approved deployed worker file hashes are missing');
    const sourceHashes = hashLines(data.workerSourceHashes);
    demand(Object.keys(sourceHashes).length === WORKER_FILES.length && WORKER_FILES.every(key =>
      sourceHashes[key] === implementation.workerFileHashes[key]), 'Deployed worker files differ from the approved source hashes');
    demand(json(data.workerPackage).version === implementation.workerVersion &&
      sha256(data.workerPackage) === sourceHashes['package.json'], 'Deployed package version or package file hash mismatch');
    for (const role of ['operator', 'probe']) {
      const binary = Object.values(hashLines(data[`${role}BinaryHash`]));
      demand(binary.length === 1 && /^[0-9a-f]{64}$/.test(implementation[`${role}KuboSha256`]) &&
        binary[0] === implementation[`${role}KuboSha256`], `${role} Kubo binary digest mismatch`);
    }
    report.implementation = { workerVersion: implementation.workerVersion,
      workerFileHashes: implementation.workerFileHashes, operatorKuboSha256: implementation.operatorKuboSha256,
      probeKuboSha256: implementation.probeKuboSha256 };
    const worker = json(data.workerReport);
    demand(worker.policyDigest === approval.policyDigest && worker.pinRequested === true && worker.status === 'verified' &&
      Number.isSafeInteger(worker.completedAtMs) && worker.completedAtMs <= start && worker.completedAtMs >= start - 600000 &&
      worker.results?.some(result => canonical(result.root) === root && result.status === 'locally_pinned'), 'Worker report does not confirm the approved fixed-root pin');
    for (const role of ['operator', 'probe']) {
      demand(json(data[`${role}Version`]).Version === '0.43.1', `${role} Kubo version must be 0.43.1`);
      demand(peer(json(data[`${role}Id`]).ID) === (role === 'operator' ? operator : probe), `${role} identity mismatch`);
      const before = data[`${role}EpochBefore`].toString('utf8');
      const after = data[`${role}EpochAfter`].toString('utf8');
      demand(before === after && /^MainPID=[1-9][0-9]*$/m.test(before) &&
        /^InvocationID=[0-9a-f]{32}$/m.test(before), `${role} daemon epoch is missing or changed`);
    }
    const pin = json(data.pinLs).Keys;
    demand(record(pin) && Object.entries(pin).some(([cid, value]) => canonical(cid) === root && value.Type === 'recursive'), 'Native recursive pin membership missing');
    const verifications = jsonLines(data.pinVerify).filter(item => canonical(item.Cid) === root);
    demand(verifications.length === 1 && verifications[0].Ok === true &&
      (!verifications[0].BadNodes || verifications[0].BadNodes.length === 0), 'Fresh native pin verification did not pass');
    demand(jsonLines(data.coldRefs).length === 0, 'Receiver blockstore must be completely empty before retrieval');
    const routing = json(data.routingConfig);
    demand(routing.Key === 'Routing.Type' && routing.Value === 'none', 'Isolated receiver Routing.Type must be none');
    demand(lines(data.bootstrapList).length === 0, 'Isolated receiver bootstrap list must be empty');
    for (const key of ['peersBefore', 'peersAfter']) {
      const peers = json(data[key]).Peers;
      demand(Array.isArray(peers) && peers.length > 0 && peers.every(item => peer(item.Peer) === operator), `${key} includes no target or an alternate peer`);
    }
    const source = await graphManifest(data.sourceCar, root);
    const received = await graphManifest(data.retrievedCar, root);
    demand(source.graphDigest === received.graphDigest, 'Retrieved graph differs from approved source graph');
    demand(received.nonInlinePayloadBytes > 0, 'Inline-only graph cannot establish native transfer');
    report.graph = { root, graphDigest: received.graphDigest, blocks: received.blocks,
      reachableBlockCount: received.reachableBlockCount, nonInlinePayloadBytes: received.nonInlinePayloadBytes,
      sourceCarBytes: source.byteLength, retrievedCarBytes: received.byteLength };
    const before = json(data.ledgerBefore), after = json(data.ledgerAfter);
    demand(peer(before.Peer) === probe && peer(after.Peer) === probe, 'Peer ledger targets the wrong receiver');
    const oldSent = unsigned(before.Sent, 'Sent before'), newSent = unsigned(after.Sent, 'Sent after');
    demand(newSent >= oldSent, 'Peer ledger counter reset or decreased');
    demand(newSent - oldSent >= BigInt(received.nonInlinePayloadBytes), 'Peer payload delta cannot cover the complete non-inline graph');
    report.controlledPeerPayloadBytes = (newSent - oldSent).toString();
    for (const key of ['bandwidthBefore', 'bandwidthAfter']) {
      const bandwidth = json(data[key]);
      unsigned(bandwidth.TotalIn, 'TotalIn'); unsigned(bandwidth.TotalOut, 'TotalOut');
    }
    if (data.providerDiscovery) {
      demand(record(manifest.discoveryObserver), 'Discovery observer declaration missing');
      const discovery = peer(manifest.discoveryObserver.peerId);
      demand(discovery !== operator && discovery !== probe && peer(json(data.discoveryId).ID) === discovery,
        'Discovery observer identity mismatch or reused participant');
      const providers = lines(data.providerDiscovery).map(line => peer(line.trim()));
      demand(providers.includes(operator), 'Ordinary provider lookup did not return the operator');
      report.providerDiscoveryArtifactsConsistent = true;
    }
    // Diagnostics are preserved, never promoted to actual DHT mode or renewal proof.
    for (const key of ['provideStat', 'dhtStat']) {
      if (data[key]) demand(record(json(data[key])), `${key} diagnostic must be a native JSON object`);
    }
    const isolation = manifest.isolation;
    demand(record(isolation) && isolation.allowedPeerId === operator && isolation.targetOnly === true &&
      isolation.gatewayEgressDenied === true && isolation.thirdPartyPeerEgressDenied === true &&
      timestamp(isolation.startAtMs) <= start && timestamp(isolation.endAtMs) >= end &&
      typeof isolation.reviewReference === 'string' && isolation.reviewReference.length > 0 &&
      data.isolationRules.byteLength > 0 && data.isolationTrace.byteLength > 0,
    'Continuous target-only restriction needs full-window rules, trace and an explicit reviewer reference');
    report.continuousIsolation = 'requires_review_of_raw_rules_and_trace';
    report.controlledRetrievalArtifactsConsistent = true;
    report.status = 'controlled_probe_artifacts_consistent_pending_provenance_review';
  } catch (error) {
    report.issues.push(String(error.message).slice(0, 2000));
  }
  return report;
}

/** Exact command templates for existing, approved hosts; this function executes none. */
export function acquisitionPlan(rootInput = DEFAULT_ROOT) {
  const root = canonical(rootInput);
  const api = 'ipfs --api /ip4/127.0.0.1/tcp/5001 --timeout=5s';
  return {
    schemaVersion: 1, root, executesNetworkActions: false,
    preconditions: [
      'Existing approved offsite operator and an existing outside isolated receiver, Kubo 0.43.1. Optional ordinary discovery uses another existing observer. This plan initializes no repository, daemon or signing key.',
      'Root-specific pin:true approval, private normalized config digest, finite retention/release owner, hard filesystem and egress quotas, unchanged-node runtime capacity approval.',
      'A trusted administrator must admit the current finite pilot term before capture. Stop both services at the deadline. Stopping does not delete pins or content.',
      'Use the actual report from the admitted operator.service and its existing single journal writer.',
      'A dedicated empty receiver repository in an already reviewed namespace: Routing.Type=none, no bootstrap/peering/autoconnect or delegated HTTP routes; no other tasks.',
      'Receiver Linux has existing timeout and prlimit commands. Use the actual service names and running binary paths if they differ from these reviewed deployment templates.',
      'Throughout the <=30-second receiver transfer, enforce literal target-IP/TCP-only external egress, loopback API allowance, no gateway/DNS/other-peer egress and no new alternate inbound peers. Capture rules and continuous trace; an administrator must review their semantics.',
      'For the optional discoverability gate, use a separate ordinary discovery observer with normal public routing, prior to supplying any operator multiaddress. A controlled probe remains controlled even when an outside administrator runs it.',
      'Do not enable verbose public telemetry or expose API, config, private key or raw identifying trace. Keep source artifacts private with bounded storage.',
    ],
    budgets: { retrievedCarBytes: MAX_CAR, evidenceBytes: MAX_TOTAL, transferWindowMs: 30000,
      graphBlocks: 8192, graphLinks: 32768, artifactBytes: MAX_RAW },
    commands: {
      finiteTermAdmission: [
        'sudo /opt/node-v22/bin/node /opt/signalx/network-operator/deploy/pilot-fence.mjs admit /etc/signalx-network/pilot-manifest.json kubo.service',
        'sudo /opt/node-v22/bin/node /opt/signalx/network-operator/deploy/pilot-fence.mjs admit /etc/signalx-network/pilot-manifest.json operator.service',
      ],
      preparePrivateEvidenceInputs: [
        'cp /absolute/approved/config.json approved-config.json',
        'cp /absolute/already-verified/source/publication.car source.car',
      ],
      approvedWorkerPreflight: 'node cli.mjs check /absolute/review/verification-only-config.json > source-verification-report.json',
      admittedWorkerReportCapture: {
        sourceCommand: "journalctl --namespace=signalx-network --unit=operator.service --since '-10 min' --lines=100 --no-pager --output=cat > admitted-worker-reports.jsonl",
        outputFile: 'worker-report.json',
        selection: 'Copy one complete successful report JSON from the admitted service into worker-report.json; match the approved policy digest and fixed root. Preserve the bounded private journal and record selection provenance. This plan starts no manual worker.',
      },
      operator: [
        `${api} version --enc=json > operator-version.json`, `${api} id --enc=json > operator-id.json`,
        'cat /opt/signalx/network-operator/package.json > worker-package.json',
        `sha256sum ${WORKER_FILES.map(file => `/opt/signalx/network-operator/${file}`).join(' ')} > worker-source-hashes.txt`,
        'sha256sum /proc/$(systemctl show kubo.service --property=MainPID --value)/exe > operator-binary-hash.txt',
        `${api} pin ls --type=recursive --enc=json ${root} > pin-ls.json`,
        `${api} pin verify --verbose --enc=json > pin-verify.jsonl`,
        'systemctl show kubo.service --property=MainPID --property=InvocationID > operator-epoch-before.txt',
        `${api} bitswap ledger --enc=json PROBE_PEER_ID > ledger-before.json`,
        `${api} stats bw --enc=json > bandwidth-before.json`,
      ],
      optionalRoutingDiagnostics: [`${api} provide stat --all --enc=json > provide-stat.json`,
        `${api} stats dht wanserver --enc=json > dht-stat.json`],
      ordinaryDiscoveryObserver: [
        `${api} id --enc=json > discovery-id.json`,
        `ipfs --api /ip4/127.0.0.1/tcp/5001 --timeout=15s routing findprovs --num-providers=20 ${root} > provider-discovery.txt`,
      ],
      isolatedReceiverBefore: [
        `${api} version --enc=json > probe-version.json`, `${api} id --enc=json > probe-id.json`,
        'sha256sum /proc/$(systemctl show ipfs-probe.service --property=MainPID --value)/exe > probe-binary-hash.txt',
        'systemctl show ipfs-probe.service --property=MainPID --property=InvocationID > probe-epoch-before.txt',
        `${api} refs local --enc=json > cold-refs.jsonl`,
        `${api} config Routing.Type --enc=json > routing-config.json`,
        `${api} bootstrap list > bootstrap-list.txt`,
        `${api} swarm connect /ip4/TARGET_PUBLIC_IPV4/tcp/4001/p2p/OPERATOR_PEER_ID`,
        `${api} swarm peers --enc=json > peers-before.json`,
      ],
      isolatedReceiverTransfer: `timeout --signal=TERM --kill-after=2s 28s prlimit --fsize=1048576:1048576 -- ipfs --api /ip4/127.0.0.1/tcp/5001 --timeout=25s dag export ${root} > retrieved.car`,
      isolatedReceiverAfter: [
        `${api} swarm peers --enc=json > peers-after.json`,
        'systemctl show ipfs-probe.service --property=MainPID --property=InvocationID > probe-epoch-after.txt',
      ],
      administratorIsolationCaptureTemplates: [
        'ip netns exec EXISTING_REVIEWED_NAMESPACE nft --json list ruleset > isolation-rules.json',
        'timeout --preserve-status --signal=INT --kill-after=2s 32s ip netns exec EXISTING_REVIEWED_NAMESPACE prlimit --fsize=131072:131072 -- tcpdump -nn -U -i any -s 96 -w /absolute/private/evidence/isolation-trace.pcap',
      ],
      operatorAfter: [
        `${api} bitswap ledger --enc=json PROBE_PEER_ID > ledger-after.json`,
        `${api} stats bw --enc=json > bandwidth-after.json`,
        'systemctl show kubo.service --property=MainPID --property=InvocationID > operator-epoch-after.txt',
      ],
      reduce: 'node live-evidence.mjs verify /absolute/private/evidence/manifest.json',
    },
    manifest: {
      schemaVersion: 1, root, triggerOrigin: 'controlled_probe',
      participantFields: 'operator/probe/discoveryObserver: {peerId, site}; distinct IDs are not proof of independent ownership',
      windowFields: '{startAtMs,endAtMs}: covers the actual transfer, maximum 30 seconds',
      approvalFields: '{reference,configPath,policyDigest,retentionUntilMs}: exact approved fixed-CID policy; configPath is the absolute original host path used to resolve stateDirectory',
      implementationFields: `{workerVersion,workerFileHashes:{${WORKER_FILES.join(',')}},operatorKuboSha256,probeKuboSha256}: approved exact deployed source and binary digests; native capture must match`,
      isolationFields: '{allowedPeerId,targetOnly:true,gatewayEgressDenied:true,thirdPartyPeerEgressDenied:true,startAtMs,endAtMs,reviewReference}; reviewed raw rules and continuous trace are mandatory',
      artifacts: Object.fromEntries(REQUIRED.map(key => [key, {
        file: ARTIFACT_FILES[key], sha256: 'EXACT_SHA256',
        capturedAtMs: 'ACTUAL_CAPTURE_TIME', command: 'EXACT_SUCCESSFUL_COMMAND_OR_SOURCE_ACQUISITION', exitCode: 0,
      }])),
      optionalArtifactNames: OPTIONAL,
      optionalArtifactFiles: Object.fromEntries(OPTIONAL.map(key => [key, ARTIFACT_FILES[key]])),
      assertions: {
        exactApprovedFixedRoot: ['config', 'workerReport'],
        deployedImplementationConsistency: ['workerPackage', 'workerSourceHashes', 'operatorBinaryHash',
          'probeBinaryHash', 'operatorVersion', 'probeVersion'],
        nativeParticipantIdentity: ['operatorId', 'probeId'],
        preTransferLocalPinCompleteness: ['pinLs', 'pinVerify'],
        uninterruptedCounterEpochs: ['operatorEpochBefore', 'operatorEpochAfter', 'probeEpochBefore', 'probeEpochAfter'],
        controlledPeerPayloadAccounting: ['ledgerBefore', 'ledgerAfter'],
        emptyReceiverAndDiagnosticConnectionState: ['coldRefs', 'routingConfig', 'bootstrapList', 'peersBefore', 'peersAfter'],
        graphIntegrityAndEquality: ['sourceCar', 'retrievedCar'],
        rawEvidenceForManualContinuousIsolationReview: ['isolationRules', 'isolationTrace'],
        wholeNodeTrafficContextOnly: ['bandwidthBefore', 'bandwidthAfter'],
        optionalOrdinaryProviderDiscovery: ['discoveryId', 'providerDiscovery'],
        optionalRoutingDiagnosticsWithoutServerOrRenewalInference: ['provideStat', 'dhtStat'],
      },
      rawFormats: {
        config: 'Actual reviewed worker config JSON, before stateDirectory normalization',
        workerPackage: 'Exact deployed package.json bytes', workerSourceHashes: 'Native sha256sum of each required deployed worker source file',
        operatorBinaryHash: 'Native sha256sum of actual running Kubo binary', probeBinaryHash: 'Native sha256sum of actual running receiver Kubo binary',
        workerReport: 'Actual admitted operator.service report JSON, selected from its bounded private journal with recorded provenance',
        operatorVersion: 'Native version JSON {Version}', probeVersion: 'Native version JSON {Version}',
        operatorId: 'Native id JSON {ID}', probeId: 'Native id JSON {ID}', discoveryId: 'Native id JSON {ID}',
        pinLs: 'Native pin ls JSON {Keys:{CID:{Type:recursive}}}', pinVerify: 'Native newline JSON {Cid,Ok,BadNodes?}',
        coldRefs: 'Native refs local newline JSON; must be empty', routingConfig: 'Native config JSON {Key,Value:none}',
        bootstrapList: 'Native text; must be empty', peersBefore: 'Native swarm peers JSON {Peers:[{Peer,Addr}]}',
        peersAfter: 'Native swarm peers JSON {Peers:[{Peer,Addr}]}',
        ledgerBefore: 'Native bitswap ledger JSON {Peer,Sent,Recv,Exchanged}; exact safe-integer or unsigned-decimal string counters',
        ledgerAfter: 'Same peer and daemon epoch as before', providerDiscovery: 'Native text provider PeerIDs, one per line',
        sourceCar: 'Complete independently acquired approved original CARv1, at most 1 MiB',
        retrievedCar: 'Actual cold isolated receiver native dag export stdout CARv1, at most 1 MiB',
        isolationRules: 'Actual namespace/firewall effective rules', isolationTrace: 'Continuous private packet/connection/denial capture, reviewed for the entire transfer',
        provideStat: 'Native provide stat JSON; diagnostic only', dhtStat: 'Native stats dht JSON; diagnostic only',
        bandwidthBefore: 'Native stats bw JSON {TotalIn,TotalOut}', bandwidthAfter: 'Native stats bw JSON {TotalIn,TotalOut}',
        daemonEpochFiles: 'Native systemctl show MainPID and InvocationID; unchanged before/after for operator and receiver',
      },
    },
    unresolvedGates: [
      'No real approved host, target multiaddress or live capture is supplied by this plan.',
      'The check config must have pin:false and its own journal; it has a different policy digest from the separately approved pin:true run config. Do not pass the pin:true config to check.',
      'Answered public DHT server duty needs an outside identify advertisement plus bounded actual /ipfs/kad/1.0.0 request/response and correlated inbound-message/error evidence. No native stats mode field or DHT event acquisition runner is implemented here.',
      'Native periodic provider renewal requires later bounded observations spanning its configured interval and successful ordinary rediscovery; a manual provide count cannot establish renewal.',
      'Administrator capture templates inspect an existing restricted namespace and require existing nft/tcpdump privileges. Start capture before the transfer and stop afterward; dropped packets, trace truncation, capture gaps or a failed/changed restriction make isolation unknown. These commands do not install or validate a firewall.',
      'Attributable unprompted block service needs separately captured CID/payload/session events; intentional outside workflow use needs externally attributable acceptance. Neither is inferred from this controlled trial.',
      'Same-budget plain Kubo uses the identical root, source CAR, recursive pin, pin verify, transport restriction, probe and evidence reducer. This gate establishes no operator advantage.',
    ],
  };
}

async function main(args) {
  if (args[0] === 'plan' && args.length <= 2) {
    console.log(JSON.stringify(acquisitionPlan(args[1]), null, 2));
  } else if (args[0] === 'verify' && args.length === 2) {
    const result = await verifyEvidence(args[1]);
    console.log(JSON.stringify(result, null, 2));
    if (!result.controlledRetrievalArtifactsConsistent) process.exitCode = 1;
  } else {
    throw new Error('Usage: node live-evidence.mjs plan [CID] | verify /absolute/evidence/manifest.json');
  }
}
if (process.argv[1]) {
  const [entryPath, modulePath] = await Promise.all([
    realpath(resolve(process.argv[1])).catch(() => null),
    realpath(fileURLToPath(import.meta.url)).catch(() => null),
  ]);
  if (entryPath !== null && modulePath !== null && entryPath === modulePath) {
    main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
  }
}
