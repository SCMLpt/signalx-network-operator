# Finite ORCESTRA pilot

Serve the Meteor cruise station and coordination logs under their original CID from one offsite IPFS node for a fixed period. On 3 October 2026, the local qualification verified all five reachable blocks in the **166,374-byte CAR**. A temporary offline Kubo 0.39.0 check also reconstructed the four original files. No offsite host, peer delivery, researcher use or added worker benefit has been demonstrated.

Before starting, use an authenticated release that includes the pilot termination and evidence tools. **Published v0.1.0 does not include them.** The commands below describe the reviewed source interfaces; they are not evidence of an activated host.

Ordinary package tools require Node.js 22 or later. **This finite pilot admits only the reviewed Node.js 22.23.3 and Kubo 0.43.1 runtimes.** Set the manifest's `nodeVersion` to `"22.23.3"`; admission checks the executing Node version and installed Kubo binary, so another patch version is refused.

## 1. Record the actual host and end decision

Choose an already controlled offsite Linux host. Complete [pilot-manifest.example.json](pilot-manifest.example.json) at `/etc/signalx-network/pilot-manifest.json`; its unapproved example cannot activate a pilot.

| Required input | Record before activation |
| --- | --- |
| Host | Provider instance/lease ID, approved administration channel, public swarm addresses, persistent dedicated Kubo repository and actual peer ID. |
| Owners | Named operation/patch/incident owner and named stop owner; who decides retained-data disposal/export and provider billing at the end. |
| Period | Absolute UTC start and end, at most 168 hours apart. No seven-day period has already been approved. |
| Caps | Enforced host disk, RAM/CPU and total egress limits, provider spending ceiling, evidence/log budget and measured remaining capacity. `maxRepoBytes` alone is not a disk quota. |
| Integrity | Actual operator/Kubo configuration hashes and repository version; baseline pins and any continuing obligations. `dedicatedRepoConfirmed` is an owner attestation. |

Use the host controls in [deploy/README.md](README.md). Enforce caps through the host/provider and record their readbacks; `admit` reports `hardTrafficCapVerified:false`. Keep the Kubo administrative API on loopback. Stopping processes leaves stored data, distributed provider records and provider billing to settle.

## 2. Check the exact publication once

Authenticate the archive hash before running included scripts. From the extracted package directory, verify its manifest, install locked dependencies, and run the included tests:

```sh
node release.mjs verify .
npm ci
npm test
cp config.example.json orcestra-check.json
```

Edit `orcestra-check.json` with `pin:false`, `stateDirectory` pointing to a fresh journal, and these exact inputs:

```json
{
  "gateways": ["https://ipfs.orcestra-campaign.org/"],
  "publications": [{
    "id": "orcestra-meteor-log",
    "root": "bafybeianebwhw4uzkqnaekl5kyoau7hubxaens7azrftgqtz2mccciejle"
  }]
}
```

This patches the complete example. Set `maxCarBytes:1048576`, `maxRunBytes:2097152`, `maxBlocks:64`, `maxLinks:256`, `timeoutMs:15000`, `runTimeoutMs:60000`, `maxRepoBytes:268435456`; keep the other fields. The fixed CID does not query IPNS.

```sh
node cli.mjs check orcestra-check.json > orcestra-check-report.json
```

Proceed only with `status:verified`, the exact root, and `verification.complete:true`. Preserve the report and actual configuration. Keep **Hans Segura and Allison A. Wing, ORCESTRA/BOWTIE, CC-BY-4.0**, and the original metadata as attribution. The publisher's pinning invitation does not establish a SignalX SLA.

## 3. Check the stop time and restart policy

Prepare the separate reviewed `pin:true` configuration at `/etc/signalx-network/operator-pilot.json`, using the same exact root/source/bounds and `stateDirectory:/var/lib/signalx-operator-pilot`. The dedicated initialized Kubo repository must be `/var/lib/signalx-kubo-pilot`. Record configuration hashes, actual peer ID and repository version in the manifest. Keep deadline fields out of the version `1` operator configuration.

```sh
node deploy/pilot-fence.mjs render /etc/signalx-network/pilot-manifest.json > pilot-units.json
```

As root, install the four emitted `files[].content` strings at their `files[].path`, mode `0644`: `signalx-pilot-stop.timer`, `signalx-pilot-stop.service`, and both `/etc/systemd/system/{kubo,operator}.service.d/90-pilot.conf` drop-ins. The manifest and operator configuration also require root ownership without group/world write. Prepare the control/state directories, then activate the timer before either service:

```sh
install -d -o root -g root -m 0755 /var/lib/signalx-pilot-control
install -d -o signalx-network -g signalx-network -m 0700 /var/lib/signalx-operator-pilot
systemctl daemon-reload
systemctl enable --now signalx-pilot-stop.timer
```

Check admission against the installed host state, then start the services only if both checks pass:

```sh
node deploy/pilot-fence.mjs admit /etc/signalx-network/pilot-manifest.json kubo.service
node deploy/pilot-fence.mjs admit /etc/signalx-network/pilot-manifest.json operator.service
systemctl start kubo.service operator.service
```

Both service starts/restarts must pass these checks. The deadline triggers shutdown with 1 second of timer accuracy and **5 seconds of grace per service**, followed by forced termination; scheduling/order can delay actual cessation. Record actual stopped times. Direct manual execution remains under administrator control. Keep the expired marker and journal; retained blocks/pins and billing need the owner's recorded follow-up decision.

## 4. Collect provider evidence separately

```sh
node live-evidence.mjs plan > acquisition-plan.json
```

This prints instructions/schema without network requests. Collect within the admitted term on the actual operator and a cold isolated receiver; normal-discovery proof additionally needs a separate observer. Capture source/received CARs, actual daemon epochs, transfer counters, deployed source/binary hashes, and reviewed isolation rules/trace. Replace template IDs, addresses, service names and binary/source paths with actual values. Keep raw evidence private within its cap. Any manual worker invocation needs administrator supervision and must stop before the deadline.

After actual capture, fill the evidence manifest with the recorded hashes, commands, times and outcomes, then run:

```sh
node live-evidence.mjs verify /absolute/private/evidence/manifest.json
```

This checks evidence files offline. Its strongest result is `controlled_probe_artifacts_consistent_pending_provenance_review`. Passing fixtures or this parser does not create a live provider observation.

Record separate outcomes:

- Local retention.
- Controlled complete retrieval attributed to this node.
- Native requests/responses outside controlled probes.
- Deliberate independent use of the CSV/XLSX logs.
- Measured improvement over plain Kubo using the same budget.

The evidence tool does not establish DHT server duty, periodic provider renewal, organic use or added worker benefit.
