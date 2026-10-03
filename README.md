# SignalX IPFS network operator

This package checks a signed IPNS record, verifies the complete reachable CID graph in a CAR, journals the result, and can pass verified content to a local Kubo node. Kubo supplies the IPFS peer protocols and can answer other peers' routing and block requests when publicly reachable. This package does not replace Kubo or create a new blockchain.

The first release covers **IPNS → CID → CAR/DAG verification** for raw, DAG-PB, and DAG-CBOR blocks. It does not reconstruct UnixFS paths or assembled website files. The example follows one SignalX IPNS name for reproducibility. ENS resolution, paid jobs, trading, SGNLX spending, and token upgrades are outside this release. Broader publication, preservation and continuity proposals remain research hypotheses. Their proposed milestones are not all implemented here.

## Requirements and local checks

- Node.js 22 or later and the dependencies pinned by `package-lock.json`.
- A separately installed [Kubo](https://docs.ipfs.tech/install/command-line/) daemon for commands that contact its API. Keep `kuboUrl` on loopback; never expose the administrative API publicly.
- For public peer service, an offsite host with dialable swarm transport, adequate RAM and persistent storage, and disk/egress limits. A localhost API or gateway fetch does not prove peer service.

From this directory:

```sh
npm ci
npm test
node cli.mjs check config.example.json
node cli.mjs inspect config.example.json
node cli.mjs run config.example.json --once
```

`check` requires `pin:false`: it validates configuration, reads and verifies the external record and CAR, and writes a local journal report without pinning. `inspect` queries a running Kubo daemon. `run --once` performs one bounded cycle and can import/pin if configured with `pin:true`. Publication status is `content_verified`, `locally_pinned`, or `unverified`; an unverified result makes the command exit unsuccessfully.

Continuous `node cli.mjs run CONFIG.json` requires reviewed `pin:true`, fixed CID roots, an offsite Kubo node, a supervisor, and capacity limits. Changing IPNS publications are restricted to one-off runs: this version has no durable retention inventory or safe automatic release policy. An initial live pilot must use a finite approved root with reserved capacity and reviewed manual retention. **No Mac daemon or offsite operator was started, and no transaction or fee was paid in this milestone.**

Kubo 0.43.1 is the reviewed RPC compatibility baseline. Its [release notes](https://github.com/ipfs/kubo/releases/tag/v0.43.1) state that the v0.43 line is Shipyard's last Kubo release and its IPFS work ended on September 30, 2026. A public operator needs an accountable patch and incident owner and a reviewed continuation or replacement path. This announcement does not establish that the IPFS network ended or that all future Kubo maintenance has stopped.

## Configuration

Copy [`config.example.json`](config.example.json) and review its sources, publications, and limits. Its `pin:false` does not persist content or advertise it as provided. Approve each CID, retention period, and capacity before changing to `pin:true`.

| Field | Meaning |
| --- | --- |
| `version`, `operatorId` | Schema version and local label; neither proves independent ownership. |
| `stateDirectory` | Journal path relative to the configuration file. Preserve the old journal and use a new directory after a policy change. |
| `kuboUrl` | Local Kubo administrative API. This is not the public swarm address. |
| `gateways`, `ipnsRouters` | External read sources; their responses must still be verified. |
| `publications` | Approved roots or IPNS names. The example checks the existing SignalX name. |
| `limits` | CAR, run-download, block, link, and time bounds. `maxRepoBytes` is a pre-import check, **not** a filesystem quota; enforce host disk/network limits separately. |
| `intervalSeconds` | Interval between continuous cycles. |

The verifier rejects expired or mismatched IPNS records, incomplete CAR graphs, bad CID hashes, and exceeded limits. A valid signature proves the **observed** record, not the latest record everywhere. Reports include source URLs, sequence, root, graph coverage, and local pin outcome; `externalUseVerified` remains false and external request counts remain unknown. HTTP 200, a gateway header, or a local pin cannot prove delivery to another peer.

## Evidence and next gates

An **external service** claim needs an offsite, publicly dialable Kubo node and evidence that another peer received valid routing responses or content blocks. Self-run probes test transport, not organic use; peer IDs are not verified people.

- **Day 30:** show restart recovery, public DHT server mode, bounded costs, inbound protocol work, and another peer's verified retrieval. Label controlled probes.
- **Day 60:** compare the additional worker against scheduled Kubo resolution, import, recursive pinning and verification, plus applicable existing diagnostics and pinning tools, under the same sources, retention obligations, polling and resource budget. Expired records and incomplete graphs are correctness controls. Qualifying added value requires a real workflow's measured improvement in artifact assurance, rollover availability, recovery or operator effort; no such improvement has been demonstrated yet.
- **Day 90:** show repeated use by an independent operator or external workflow. Otherwise, claim only a public-good IPFS node and stop expanding the SignalX-specific feature.

Next: qualify one permitted third-party publication and its native consumer, prepare an independently runnable source release, size and supervise an offsite host, then measure peer service. Revenue and SGNLX utility require separate evidence. The long-term project can continue researching a publication or continuity protocol, but a generic Kubo node alone does not establish a distinctive SignalX product.

## Offline source release

Build from a trusted, quiescent source tree with Node 22 or later:

```sh
node release.mjs build OUTPUT_DIRECTORY
node release.mjs verify OUTPUT_DIRECTORY/signalx-network-operator-0.1.0.tar EXPECTED_SHA256
```

The archive includes an exact file allowlist, locked dependency metadata, the runtime and all nine self-contained maintainer test modules. It excludes local journals, private configuration and installed dependencies. Its canonical manifest records file sizes and SHA-256 values. After verification, extract it into a fresh directory, run `node release.mjs verify .`, then install the locked dependencies with `npm ci` and run `npm test`. A successful archive check establishes byte consistency, not author identity, public service or external adoption. Obtain the expected digest from an authenticated publisher. `licenseFile:null` means the archive has no public reuse license; public licensing and publication are separate release gates.
