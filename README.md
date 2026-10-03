# SignalX IPFS network operator

This package checks a signed IPNS record, verifies the complete reachable CID graph in a CAR, journals the result, and can pass verified content to a local Kubo node. Kubo supplies the IPFS peer protocols and can answer other peers' routing and block requests when publicly reachable. This package does not replace Kubo or create a new blockchain.

The [finite HTTP provider adapter](http-provider/README.md) serves two permitted ORCESTRA publications, Meteor cruise logs and GATE buoy measurements, through HTTPS and the existing IPNI network. Its October 3, 2026 deployments hold the complete original graphs. Public discovery verified all five Meteor CIDs and all 25 GATE CIDs through IPNI and the default delegated router. Both finite terms end October 10, 2026.

Controlled retrieval verified all four Meteor filenames. A released Helia client discovered the Meteor provider and received the station CSV, with an unresolved Node stream cleanup failure preserved in the evidence. A configured, unchanged ipfsspec/xarray/Zarr reader cleanly consumed the GATE dataset and matched its original bytes and scientific arrays. Independent use and native Bitswap/DHT service remain unverified. The historical v0.1.1 source archive predates this adapter.

The core verifier covers **IPNS → CID → CAR/DAG verification** for raw, DAG-PB, and DAG-CBOR blocks. The HTTP adapter adds bounded UnixFS directory and filename handling for selected publications; this does not make the core CLI a general website assembler. The example follows one SignalX IPNS name for reproducibility. ENS resolution, paid jobs, trading, SGNLX spending, and token upgrades are outside this release. Broader publication, preservation and continuity proposals remain research hypotheses. Their proposed milestones are not all implemented here.

## Requirements and local checks

- Node.js 22 or later and the dependencies pinned by `package-lock.json`.
- A separately installed [Kubo](https://docs.ipfs.tech/install/command-line/) daemon for commands that contact its API. Keep `kuboUrl` on loopback; never expose the administrative API publicly.
- For native Bitswap and public DHT peer service, an offsite host with dialable swarm transport, adequate RAM and persistent storage, and disk/egress limits. A localhost API or gateway fetch does not prove those peer protocols. The separate HTTP/IPNI adapter has its own deployment and verification requirements.

From this directory:

```sh
npm ci
npm test
node cli.mjs check config.example.json
node cli.mjs inspect config.example.json
node cli.mjs run config.example.json --once
```

`check` requires `pin:false`: it validates configuration, reads and verifies the external record and CAR, and writes a local journal report without pinning. `inspect` queries a running Kubo daemon. `run --once` performs one bounded cycle and can import/pin if configured with `pin:true`. Publication status is `content_verified`, `locally_pinned`, or `unverified`; an unverified result makes the command exit unsuccessfully.

Continuous `node cli.mjs run CONFIG.json` requires reviewed `pin:true`, fixed CID roots, an offsite Kubo node, a supervisor, and capacity limits. Changing IPNS publications are restricted to one-off runs: this version has no durable retention inventory or safe automatic release policy. An initial live pilot must use a finite approved root with reserved capacity and reviewed manual retention. **The v0.1.1 Kubo milestone started no Mac daemon or offsite operator, and paid no transaction or fee.** The later live HTTP deployment is documented separately above.

Kubo 0.43.1 is the reviewed RPC compatibility baseline. Its [release notes](https://github.com/ipfs/kubo/releases/tag/v0.43.1) state that the v0.43 line is Shipyard's last Kubo release and its IPFS work ended on September 30, 2026. A public operator needs an accountable patch and incident owner and a reviewed continuation or replacement path. This announcement does not establish that the IPFS network ended or that all future Kubo maintenance has stopped.

## Finite pilot and evidence tools

Source version 0.1.2 retains `deploy/pilot-fence.mjs`, introduced in 0.1.1, which renders and checks systemd admission rules for an approved fixed-CID Kubo pilot lasting at most seven days. Admission requires the exact reviewed manifest/configurations, installed timer and drop-ins, Node.js **22.23.3** and Kubo **0.43.1**. A host administrator installs the generated files and records actual shutdown timing; retained data, provider records and billing need the owner's end decision. The bundled manifest/timer examples remain unapproved. The live HTTP adapter enforces its separate serving deadline without systemd.

`node live-evidence.mjs plan` prints a bounded acquisition plan without network requests. `verify` reads private capture files offline and reports their consistency pending capture-provenance review. Controlled retrieval, organic use, public DHT duty, provider renewal and improvement over plain Kubo still require their respective observations. Follow the [finite pilot guide](deploy/PILOT_QUICKSTART.md) for exact paths, approvals and evidence boundaries. The published v0.1.0 archive predates these tools.

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

An **external native peer service** claim needs an offsite, publicly dialable Kubo node and evidence that another peer received valid routing responses or content blocks. An **external HTTP/IPNI provider** claim requires deployed original content delivery and exact public routing records for that HTTP provider; the separate adapter has observed both. Self-run probes test transport and discovery, not organic use; peer IDs are not verified people.

The native Kubo pilot proposal uses these observation gates:

- **Day 30:** show restart recovery, public DHT server mode, bounded costs, inbound protocol work, and another peer's verified retrieval. Label controlled probes.
- **Day 60:** compare the additional worker against scheduled Kubo resolution, import, recursive pinning and verification, plus applicable existing diagnostics and pinning tools, under the same sources, retention obligations, polling and resource budget. Expired records and incomplete graphs are correctness controls. Qualifying added value requires a real workflow's measured improvement in artifact assurance, rollover availability, recovery or operator effort; no such improvement has been demonstrated yet.
- **Day 90:** show repeated use by an independent operator or external workflow. Otherwise, claim only a public-good IPFS node and stop expanding the SignalX-specific feature.

The HTTP adapter has qualified and served two permitted third-party publications, including a controlled Meteor Helia retrieval through default discovery and a clean configured GATE scientific reader. Next: resolve the Helia cleanup failure, observe independent use, and check actual expiry and removal; native Bitswap/DHT service still requires an offsite peer host and protocol evidence. Revenue and SGNLX utility require separate evidence. The long-term project can continue researching a publication or continuity protocol, but a generic Kubo node alone does not establish a distinctive SignalX product.

## Offline source release

Build from a trusted, quiescent source tree with Node 22 or later:

```sh
node release.mjs build OUTPUT_DIRECTORY
node release.mjs verify OUTPUT_DIRECTORY/signalx-network-operator-0.1.2.tar EXPECTED_SHA256
```

The v0.1.2 allowlist covers 54 required files, including 21 HTTP adapter files and all 16 Node maintainer test modules. The existing MIT `LICENSE` adds one optional file. The archive includes locked dependency metadata, the runtime, pilot/evidence tools, examples, original CC BY 4.0 dataset bytes and public signed IPNI objects. It excludes local journals, actual host manifests/configurations, raw evidence, credentials and installed dependencies.

Its canonical manifest records file sizes and SHA-256 values. After authenticating the archive's expected digest, verify and extract it into a fresh directory, run `node release.mjs verify .`, then install the locked dependencies with `npm ci` and run `npm test`. A successful archive check establishes byte consistency, not author identity, public service or external adoption. `licenseFile:null` records an absent license. Verify historical releases with their matching archived verifier: v0.1.0 predates the finite pilot/evidence tools, and v0.1.1 predates the HTTP adapter. Obtain actual publication status and the authenticated digest from the [versioned GitHub releases](https://github.com/SCMLpt/signalx-network-operator/releases).
