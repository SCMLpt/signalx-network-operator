# Finite IPFS HTTP providers

Two deployments of this adapter are live HTTPS content providers advertised through the existing IPNI network. On October 3, 2026, the project deployed the Meteor provider to Cloudflare Workers Free at [signalx-ipfs-provider.kamuitranslator.workers.dev](https://signalx-ipfs-provider.kamuitranslator.workers.dev/health). It holds the five original content-addressed blocks and complete 166,374-byte CAR for one permitted third-party publication. A separate GATE provider is documented below. Content requests read embedded bytes; they perform no runtime upstream fetch.

The publication is **FS Meteor log and coordination log between RV METEOR and other platforms during BOWTIE**, by Hans Segura and Allison A. Wing, from ORCESTRA / BOWTIE. The [original publication](https://ipfs.orcestra-campaign.org/ipfs/bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle/) is mirrored without changes under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The publisher's public pinlist invites mirroring.

| Public parameter | Value |
| --- | --- |
| Root CID | `bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle` |
| Provider ID | `12D3KooWM1CrPmUiwEJmi9YePCyAiuVxZUVJvDnyRZhMCVFadniZ` |
| Provider address | `/dns4/signalx-ipfs-provider.kamuitranslator.workers.dev/tcp/443/tls/http` |
| Routing protocol | `transport-ipfs-gateway-http` |
| Original CAR SHA-256 | `d79dd33f1717beed7d7152f61170c06f318529edf193277c997a576663007078` |
| Serving term, UTC | `2026-10-03T09:50:00.370Z` through `2026-10-10T09:50:00.370Z` |

The deployed provider passed a project-controlled HTTP/2 retrieval of all five raw blocks and the complete CAR, with CID hashes and reachable graph verified. Its signed IPNI announcement received HTTP 204 from `cid.contact/ingest/announce` at `2026-10-03T10:12:07.052Z`. Subsequent bounded checks at `10:15:07–10:15:13Z` returned its exact provider ID, address and HTTP protocol for all five CIDs from both `cid.contact` and the default delegated router `delegated-ipfs.dev`. A further ten-request check at `11:14:32–11:14:35Z` verified the directory listing and GET/HEAD responses for all four original filenames against the independently decoded publisher CAR.

An unchanged released Helia client (`@helia/http` 4.0.6, `@helia/unixfs` 8.0.9, `helia` 7.1.2) used default routing to discover this provider and retrieve `M203-StationList_md_new.csv` in 2.085 seconds. Four requests queried the router for the root, received the Worker's 277-byte root, queried for the leaf and received the Worker's original 45,611-byte CSV. Official receive-block events attributed both payloads to this Worker, and the CSV hash matched the publisher bytes.

Clean Node completion remains unqualified: two runs failed on an upstream locked-stream cleanup rejection. The final diagnostic run preserved that rejection with `--unhandled-rejections=warn` and completed the transfer. This is controlled evidence of default discovery and selected-provider delivery with an unresolved client cleanup failure. Independent use, origin outage survival, native Bitswap, public DHT server duty, general gateway conformance and measured improvement over another operator remain unverified.

## GATE buoy provider

A second deployment at [signalx-ipfs-provider-gate.kamuitranslator.workers.dev](https://signalx-ipfs-provider-gate.kamuitranslator.workers.dev/health) holds the complete original **GATE buoy measurements** publication, by Lutz Hasse and Ernst Augstein, under CC BY 4.0. Its [publisher root](https://ipfs.orcestra-campaign.org/ipfs/bafybeih6kxwy6twyims5fr2h76ef7tdqdepltd5qkrdaie6zu4h56yo47m/) and original metadata are preserved.

| Public parameter | Value |
| --- | --- |
| Root CID | `bafybeih6kxwy6twyims5fr2h76ef7tdqdepltd5qkrdaie6zu4h56yo47m` |
| Provider ID | `12D3KooWHoujf78JNhxCy9HShhhAKhfwXLSePnN3F1CNfvnTH8ys` |
| Original CAR | 219,951 bytes, 25 complete blocks |
| Original CAR SHA-256 | `6c4e0cb33cfdef0a8c18c023401f09131fddfe931cf2b93a8a6b059bf2780e72` |
| Serving term, UTC | `2026-10-03T11:09:35.016Z` through `2026-10-10T09:50:00.370Z` |

Its controlled HTTP/2 check verified all 25 raw blocks and the complete CAR in 31 requests, receiving 439,664 response bytes. The signed IPNI announcement received HTTP 204 at `2026-10-03T11:42:11.839Z`; 50 subsequent requests verified the exact provider identity, hostname and HTTP protocol for every CID on both public routers.

With this Worker configured as its gateway, unchanged `ipfsspec` 0.6.0, `xarray` 2026.9.0 and `Zarr` 3.4.0 cleanly read the original format-2 Zarr dataset: 13 GETs, 281,802 response bytes and 3.872 seconds, with zero warnings. Both block-scope path-proof info calls succeeded. The metadata and all six chunk hashes matched the publisher, and each of the five scientific arrays (`dbt`, `q`, `sst`, `wd`, `ws`) matched all 20,102 original decoded values. The time chunk's complete hash, decoded shape and endpoints were checked; elementwise decoded timestamp comparison remains unverified. The initial attempt failed on a missing `X-Ipfs-Roots` header; that receipt is retained, and the server fix was deployed before the successful retry. This establishes controlled configured-client compatibility and faithful data delivery. Independently chosen use, scientific validity and default routing selection by this reader remain unverified.

## Retrieve and verify

From the parent `network-operator` directory, install the locked Node dependencies and run the bounded checks with fresh output paths:

```sh
npm ci
npm test
node http-provider/remote-verify.mjs /tmp/signalx-http-verification.json
node http-provider/discovery-check.mjs http-provider/deployment-data.json /tmp/signalx-routing-verification.json
node http-provider/file-verify.mjs https://signalx-ipfs-provider.kamuitranslator.workers.dev ORIGINAL_PUBLISHER_CAR /tmp/signalx-file-verification.json
```

`remote-verify.mjs` defaults to the shipped Meteor data and accepts another public dataset as its optional second argument. It makes `blockCount + 6` requests, requires HTTP/2, caps total response bytes at 1 MiB and execution at 45 seconds, and checks block hashes, the exact complete CAR graph, HEAD, conditional response and rejection of an unapproved CID. `discovery-check.mjs` queries both fixed public routers at most once per CID: ten requests for Meteor, up to 128 for an allowed 64-block dataset. It uses no retries and a 256 KiB / 15-second limit per response, and requires identity, address and protocol together in the same provider record. Both write a new receipt and fail when their required checks fail.

The HTTP probe retrieves raw blocks and their complete CAR together. A CAR near the builder's 1 MiB admission ceiling therefore exceeds the probe's 1 MiB aggregate response cap. The two actual deployed datasets fit both limits.

`file-verify.mjs` takes a separately retained original publisher CAR matching the digest in the table. It independently decodes its directory with the official CAR and DAG-PB codecs, then checks the deployed raw root, JSON listing and all four filename GET/HEAD responses against the original bytes, CID hashes, lengths, media types and ETags. It makes at most ten requests, with no retries and a 1 MiB / 15-second maximum per response. Its receipt labels the check as project controlled and preserves failed results; success does not establish ordinary Helia/Kubo retrieval or independent use.

The read endpoint serves `GET` and `HEAD` at `/ipfs/CID?format=raw`. The complete publication is available at [`/ipfs/ROOT?format=car&dag-scope=all`](https://signalx-ipfs-provider.kamuitranslator.workers.dev/ipfs/bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle?format=car&dag-scope=all). It supports CORS and ETags. The adapter serves the approved graph and the standard empty identity probe, with no arbitrary gateway forwarding.

The v0.1.2 source adds a directory listing at `/ipfs/ROOT?format=json` and ordinary file responses at `/ipfs/ROOT/FILENAME`, without a query string. The four original filenames are:

| Filename | Original bytes |
| --- | ---: |
| [M203-StationList_md_new.csv](https://signalx-ipfs-provider.kamuitranslator.workers.dev/ipfs/bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle/M203-StationList_md_new.csv) | 45,611 |
| [coordination_log.xlsx](https://signalx-ipfs-provider.kamuitranslator.workers.dev/ipfs/bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle/coordination_log.xlsx) | 11,685 |
| [dataset_meta.yaml](https://signalx-ipfs-provider.kamuitranslator.workers.dev/ipfs/bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle/dataset_meta.yaml) | 797 |
| [met_203_1_station_book.csv](https://signalx-ipfs-provider.kamuitranslator.workers.dev/ipfs/bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle/met_203_1_station_book.csv) | 107,753 |

The resolver reads only held raw and DAG-PB UnixFS blocks, bounds paths to 16 components and reconstructed files to 1 MiB, and rejects ambiguous paths, symlinks and sharded directories. Root-anchored path proofs use `/ipfs/ROOT/PATH?format=car&dag-scope=block` or `entity`: both include the path's ancestor and terminal blocks, while a file entity includes its file chunks and a directory entity includes its directory block. Proof responses provide `X-Ipfs-Roots` as the exact comma-separated root-to-terminal path, excluding file chunk descendants; direct raw CID and complete root CAR responses use a singleton root. CORS exposes that header. The observed filename and reader checks above do not establish general gateway conformance.

`ipni-reference/` uses pinned `go-libipni` 0.9.0 and `go-libp2p` 0.50.0 to build signed advertisements, signed heads, entry chunks and HTTP transport metadata. Its public verification checks signatures, entry content, address, advertisement linkage and removal behavior with the official SDK. Run `go test -p=1 -mod=readonly ./...` from that directory with Go 1.26 or later and the pinned dependencies available. `ipni-build.mjs --verify PUBLIC_BUNDLE.json` also checks the HTTP handler mapping. The builder uses `go` on PATH and normal Go cache defaults; `--go`, `--go-path` and `--go-cache` provide explicit executable and cache paths. Public verification takes no private key.

## Expiry

At the exact term end, the handler returns HTTP 410 for content and switches its signed IPNI head to the prepared removal advertisement. Cache lifetime is capped by the remaining serving term. Both deployed Workers have the Cron expression `51 9 10 10 *`, admitting a removal announcement on October 10 at 09:51 UTC. The maintenance handler permits execution only in the five minutes after expiry, performs one bounded PUT per admitted callback, and carries no private key.

HTTP expiry works independently of the scheduled announcement. Cron delivery, a removal acknowledgement and disappearance from routing indexes are separate observations; deindexing has not yet been verified. The annual Cron expression is fenced by the fixed 2026 deadline, so callbacks outside that window do no work. Expiry stops this provider's content service; it does not delete embedded bytes, the Worker deployment, or copies retained by others.

## Public source boundary

The v0.1.2 source allowlist includes 21 adapter files; the historical v0.1.1 archive contains none of them. `deployment-data.json` contains public original content, attribution, provider identity and signed public IPNI objects. The source archive excludes `tmp/`, `.wrangler/`, private keys, credentials, account configuration, the local deployment `wrangler.toml`, installed dependencies and raw capture receipts.

For a separate provider, supply a qualified publication JSON with `root`, `carSha256`, `providerHost` and `attribution` containing `title`, `creators`, a public HTTPS `source`, `license` and `changes`. Optional `carBytes`, `expectedBlocks`, `payloadBytes` and `graphDigest` bind prior qualification measurements. The builder verifies a complete original CAR of at most 1 MiB and 64 SHA-256 blocks, excludes duplicates and unreachable blocks, and requires a canonical UTC term lasting at most seven days.

```sh
node http-provider/dataset-build.mjs ORIGINAL_CAR DATA.json START_UTC END_UTC QUALIFIED_PUBLICATION.json
```

Record the PeerID corresponding to a separately supplied libp2p Ed25519 private key in the generated data's `providerId`. There is no bundled key-generation command. Sign and verify the public objects:

```sh
node http-provider/ipni-build.mjs --data DATA.json --key PRIVATE.pb --output PUBLIC_BUNDLE.json
node http-provider/ipni-build.mjs --verify PUBLIC_BUNDLE.json
```

Prepare the Worker's `deployment-data.json` with the bundle's `ipni` mapping and its `removalAnnouncement` under `ipni.removalAnnouncement`. The signing key remains separate. New providers require an explicit canonical public DNS `providerHost`; the signed transport uses HTTPS port 443. Remote delivery and routing checks accept the operator's dataset. The filename verifier remains bound to the exact Meteor publisher CAR and deployment.

A minimal account-free Worker configuration can be saved beside `worker.mjs`:

```toml
name = "my-finite-ipfs-provider"
main = "worker.mjs"
compatibility_date = "2026-10-03"
compatibility_flags = ["nodejs_compat"]
workers_dev = true
```

The operator supplies their own account access and a Cron matching the reviewed term. After deploying the prepared Worker, use its public data and bundle:

```sh
node http-provider/remote-verify.mjs NEW_HTTP_RECEIPT.json deployment-data.json
node http-provider/activate.mjs PUBLIC_BUNDLE.json deployment-data.json NEW_ANNOUNCEMENT_RECEIPT.json
node http-provider/discovery-check.mjs deployment-data.json NEW_ROUTING_RECEIPT.json
```

Activation invokes the existing official SDK public verifier before any HTTP request, binds the complete dataset, signed advertisement, hostname and provider identity, checks the deployed signed head and objects, and rechecks the serving term before sending the announcement. It accepts the same optional `--go`, `--go-path` and `--go-cache` arguments as the signer. An HTTP acknowledgement establishes admission acceptance; routing readback establishes observed discoverability separately.
