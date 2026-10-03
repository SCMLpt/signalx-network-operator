# Offsite Linux supervisor reference

These files describe a future Linux deployment of the existing operator and Kubo. **No host was provisioned, service started, repository initialized, key generated, publication pinned, or fee paid by adding these artifacts.** A provider, public IP, cost budget, retention policy and operator are still required. This is not evidence of a running public node.

## Host and paths

Use a dedicated offsite Linux host with systemd 256 or later, unified cgroup v2, Node.js 22 or later and an already installed Kubo **0.43.1**. Verify the actual binary versions; versioned example paths alone do not verify them. Package dependencies must already match `package-lock.json` before activation. The services never install packages or download executables.

Kubo 0.43.1 is a compatibility baseline. Its [release announcement](https://github.com/ipfs/kubo/releases/tag/v0.43.1) identifies v0.43 as Shipyard's final Kubo line and September 30, 2026 as the end of its IPFS work. Qualify an accountable patch and incident owner and a continuation or replacement path before public operation. This is a maintainer transition, not evidence that the IPFS network stopped.

| Path/account | Required arrangement |
| --- | --- |
| `signalx-network` user/group | Fixed nonroot service account, no interactive login or privileged groups; provisioned by the host administrator. |
| `/opt/node-v22/bin/node` | Existing Node executable, root owned and not writable by the service account. Adjust both units together if its path differs. |
| `/opt/kubo-v0.43.1/ipfs` | Existing verified Kubo 0.43.1 executable, root owned. |
| `/opt/signalx/network-operator` | Reviewed source plus locked dependencies, root owned and read only to the service. |
| `/etc/signalx-network/operator.json` | Root owned regular file, readable by `signalx-network`; the CLI rejects symlinks and files above 16 KiB. |
| `/var/lib/signalx-operator` | Local persistent POSIX filesystem for the journal, owned by the service account, mode `0700`; not NFS or a shared multi-host volume. |
| `/var/lib/signalx-kubo` | Existing initialized Kubo repository compatible with 0.43.1, owned by the service account, mode `0700`; contains its existing peer identity. |

`StateDirectory=` creates the state directories if missing; it does **not** initialize Kubo. Startup requires the existing Kubo `config` and `version`. Initialization, identity creation, migrations and owner wallet credentials are absent from these units. Keep backups and repository identity under the host operator's access policy. Do not paste the repository's private configuration into logs or reports.

## Reviewed configuration and activation gate

Start from `../config.example.json` with these deployment paths. This JSON is a complete **verification-only example**, not a continuous service configuration:

```json
{
  "version": 1,
  "operatorId": "signalx-publication",
  "stateDirectory": "/var/lib/signalx-operator",
  "pin": false,
  "kuboUrl": "http://127.0.0.1:5001",
  "gateways": ["https://trustless-gateway.link/"],
  "ipnsRouters": ["https://delegated-ipfs.dev/"],
  "publications": [{
    "id": "signalx-ipns",
    "ipnsName": "k51qzi5uqu5dhrgbb3tfnfg0hgu7ju0h30onynyiffss8iwtkxbqipwxye41qw"
  }],
  "limits": {
    "maxCarBytes": 8388608,
    "maxRunBytes": 16777216,
    "maxBlocks": 4096,
    "maxLinks": 16384,
    "timeoutMs": 15000,
    "runTimeoutMs": 60000,
    "maxRepoBytes": 2147483648
  },
  "intervalSeconds": 300
}
```

The current CLI permits `check` or `run --once` with `pin:false`. It rejects continuous `run` with `pin:false` and continuous changing-IPNS preservation before a cycle. Accordingly, copying this example and starting `operator.service` will fail; it cannot silently become a public content provider. The intended activation requires the host operator to approve a fixed CID root, reserved capacity and finite manual retention, then review an actual configuration with `pin:true`. No example in this directory grants that approval or changes the configuration automatically. The Node interval is the existing application loop; no extra timer or cron is needed.

The current package retains imported pins and has no automatic pin expiry or ownership inventory. Changing-IPNS continuous preservation requires a new durable retention implementation and remains disabled in the CLI. Garbage collection cannot reclaim recursively pinned blocks. A policy change requires preserving the old journal and using a new state directory; update the unit's `StateDirectory=` and the configuration together. Recovery must reconcile existing pin effects, rather than erasing the journal.

## Public swarm and local administration

Review the existing Kubo configuration while stopped. Merge the following **nonsecret fragment** into its existing fields; this is not a replacement repository configuration and contains no identity. The unit refuses startup unless the API is bound only to `127.0.0.1:5001`.

```json
{
  "Addresses": {
    "API": "/ip4/127.0.0.1/tcp/5001",
    "Gateway": "/ip4/127.0.0.1/tcp/8080",
    "Swarm": [
      "/ip4/0.0.0.0/tcp/4001",
      "/ip4/0.0.0.0/udp/4001/quic-v1"
    ]
  },
  "Routing": {"Type": "auto"},
  "Provide": {"Enabled": true, "Strategy": "pinned"},
  "Datastore": {"StorageMax": "2GB", "StorageGCWatermark": 80}
}
```

The provider must supply a stable public address or an explicit inbound mapping, and permit inbound **TCP 4001 and UDP 4001** as well as necessary outbound DNS/HTTPS/IPFS traffic. A wildcard listener is not proof of public reachability. For a mapped host, review `Addresses.Announce`/`AppendAnnounce` against its actual public multiaddresses; no public IP has been selected here. Keep TCP 5001 and 8080 private, and do not place an unauthenticated proxy in front of the administrative API. This unauthenticated loopback API assumes a dedicated trusted host; a local untrusted process would still be able to call it.

Preserve Kubo's reviewed native bootstrap/AutoConf settings. Do not replace public bootstrap peers with a SignalX-only peer list. `Routing.Type=auto` can become a public DHT server when reachability is detected; configured mode alone is insufficient evidence. Kubo supplies discovery, routing, Bitswap and periodic provider announcements while Node verifies its approved publications. Kubo 0.43.1 uses `Provide.DHT.Interval`; `Reprovider.Interval` and `Reprovider.Strategy` were removed. Leave the native periodic interval at its default, never `0` to simulate an active service through manual announcements. `Provide.Strategy=pinned` announces recursively pinned roots and children. The application does not provide an independent reprovider or bootstrap protocol.

## Capacity and log retention

All numbers below are **starting examples, not measured workload requirements**. Profile a bounded offsite pilot before claiming sustainable operation. A candidate host would need headroom beyond the combined limits, for example at least 8 GiB RAM and 2 vCPUs; no provider or price has been chosen.

| Control | Operator | Kubo | Meaning |
| --- | --- | --- | --- |
| `MemoryHigh` / `MemoryMax` | 256 / 512 MiB | 4 / 6 GiB | Pressure threshold / hard cgroup bound; hitting the bound can kill the process. |
| `MemorySwapMax` | 0 | 0 | Avoid unbounded swap use. |
| `CPUQuota` | 50% | 200% | Half a CPU / two CPUs worth of time, not dedicated cores or promised throughput. |
| `TasksMax` | 64 | 512 | Bounds kernel tasks, including threads. |
| `LimitNOFILE` | 1,024 | 4,096 | Bounds open descriptors; connection failures still need monitoring. |

The units use the `signalx-network` journal namespace. Before activation, the host administrator must configure `/etc/systemd/journald@signalx-network.conf.d/limits.conf` and apply it to that journal instance:

```ini
[Journal]
Storage=persistent
SystemMaxUse=256M
SystemMaxFileSize=16M
RuntimeMaxUse=32M
RuntimeMaxFileSize=4M
SystemKeepFree=1G
MaxRetentionSec=7day
MaxFileSec=1day
RateLimitIntervalSec=30s
RateLimitBurst=1000
```

Unit output also has a 100-message/30-second rate limit. Suppression and rotation can remove evidence; a gap is unknown coverage. Journald rotates/deletes archived files and can exceed its target by active file space, so a host filesystem quota remains necessary. A seven-day local log window cannot establish 30/60/90-day retention or independent use. If those milestones are pursued, keep bounded, access-controlled offsite summaries with timestamps, coverage and provenance; do not expose keys or raw private configuration.

**Service units do not enforce total disk or egress spending.** `maxRepoBytes` is a pre-import check, and Kubo `Datastore.StorageMax` is a GC trigger for block storage, not a hard filesystem quota. Pins and metadata can fill a volume despite either value. Set actual filesystem/project quotas or dedicated capped volumes, with capacity/free-space alerts and a reserved root filesystem. An unmeasured starting budget might be 8 GiB for Kubo, 256 MiB for operator state and a separate log allowance with rotation headroom. This is not a promise that the workload fits. Likewise, obtain a provider bandwidth allowance and spending cap or host traffic shaping; measure total Kubo traffic, not just the application's bounded downloads. A disk quota failure, egress cap or dropped packets makes the node degraded, not continuously available.

## Process recovery and operational evidence

Only after the host, approved pin policy, repository, public exposure and cost/log controls are reviewed should a host administrator verify and install the units. Example **future host commands**, not executed by this work:

```sh
systemd-analyze verify /etc/systemd/system/operator.service /etc/systemd/system/kubo.service
systemctl daemon-reload
systemctl enable --now kubo.service operator.service
systemctl status kubo.service operator.service
journalctl --namespace=signalx-network -u operator.service -u kubo.service
```

`Restart=on-failure` restarts crashes after 30 seconds, with at most five starts in 15 minutes. A normal exit or manual stop stays stopped; a start-limit failure requires investigation before `reset-failed`/restart. Kubo will refuse a repository migration rather than run one automatically. SIGTERM gives Node up to 330 seconds to finish its bounded cycle, and Kubo 90 seconds for shutdown; forced termination may leave an uncertain journal operation. `Wants`/`After` order startup without treating Kubo's PID as API readiness: Node can report degraded cycles while Kubo recovers. Planned maintenance should stop `operator.service` first and Kubo second; do not run a second writer against the same journal.

The continuous CLI catches recoverable cycle errors and remains running; semantic state corruption and fatal storage errors exit for supervisor investigation. A green `systemctl` state therefore proves only process uptime. Monitor the latest completed report, per-publication outcome, time bounds, repeated degraded results, disk/egress headroom, API reachability, public reachability and the status of native provider refresh. The local journal keeps at most 100 run records; long-term coverage requires the separately bounded evidence store. An expired run lease can be reconciled by a subsequent cycle, but a stuck filesystem lock requires explicit inspected recovery. Stop all writers, inspect the same-host lock identity and use the journal's `recoverLock()` procedure; it refuses live/reused PIDs or unverifiable owners. These units neither delete locks nor promise unattended recovery of every filesystem failure.

| Claim | Minimum evidence |
| --- | --- |
| Process availability | Timestamped service state and resource/restart history. |
| Publication verification | Fresh completed report with signed IPNS and complete CID graph checks. |
| Public protocol service | Another offsite peer directly dials the advertised swarm, receives the approved blocks and verifies CID hashes; record routing/transfer outcome, peer IDs, timestamps and probe provenance. A cached HTTP gateway response is insufficient. |
| Organic external use | Incoming protocol requests and successful delivery tied to an external workflow, excluding our own probes and health checks. Bytes, peer connections or advertisements alone are insufficient. |
| Independent operator | Evidence of independent administration and repeated use; extra peer IDs or keys do not prove extra people. |

An independent-location controlled probe demonstrates transport and block delivery; label it as a controlled probe. It does not demonstrate organic adoption. Current application reports keep `externalUseVerified:false` and external requests, independent operators and service revenue unknown. No unit changes these fields or demonstrates a fee-paying workflow. The architecture can provide a public IPFS service without SGNLX sales, but uptime does not establish demand or payment.

## Primary references

- [Kubo 0.43.1 configuration](https://github.com/ipfs/kubo/blob/v0.43.1/docs/config.md): addresses, bootstrap, routing, providing and GC limits.
- [Kubo 0.43.1 daemon source](https://github.com/ipfs/kubo/blob/v0.43.1/cmd/ipfs/kubo/daemon.go): explicit initialization, migration and shutdown behavior.
- [systemd 256 service behavior](https://github.com/systemd/systemd/blob/v256/man/systemd.service.xml), [execution settings](https://github.com/systemd/systemd/blob/v256/man/systemd.exec.xml) and [resource controls](https://github.com/systemd/systemd/blob/v256/man/systemd.resource-control.xml).
- [systemd 256 journal configuration](https://github.com/systemd/systemd/blob/v256/man/journald.conf.xml): namespaces, rotation and storage limits.
