<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Kaia

Researched 2026-10-26 against Kaia **v2.2.2**. Documentation was read on that
date; explicit page update dates are preserved in Sources where available. [S1]

## erpc implementation

The [endpoint-node backend](../kaia-rpc.md) implements all twelve RPC lifecycle
verbs with a pinned official AMD64 OCI image, immutable network/genesis and
bootstrap ownership, original peer identity, staged official snapshots and
separate firewall confirmation. Full genesis synchronization is an explicit
alternative to the live-pruned default. The [core-cell backend](../kaia-core-cell.md)
adds separate CN/PN hosts, original sealed secp256k1/BLS custody, verified concealed
backups and native qualified-membership observations. CN uses the full-retention
profile; optional native financial transaction generation is disabled. Team
admission, registration and funding remain external; live acceptance is deferred.

## Networks

Mainnet (legacy name Cypress) uses ID **8217**; Kairos testnet (legacy Baobab)
uses **1001**. `NETWORK` selects `mainnet` or `kairos`; setting `NETWORK_ID`
instead creates a private-network configuration. [S2], [S3]

## RPC node

- **Clients:** official Go implementation `kaiachain/kaia`; `ken` is the Endpoint
  Node (EN), `kcn` the Consensus Node (CN), and `kpn` the Proxy Node (PN).
  Library code is LGPL-3.0; command/binary code is GPL-3.0. The release page and
  pinned tree are linked below. [S2], [S1]
- **Latest stable release:** `v2.2.2`, commit
  `ac7c81f3a9759704b5ce77b42ae91851ce45a9c3`, published 2026-03-10.
  Its release notes mandate the mainnet Osaka upgrade at block **213333000**;
  their estimated activation time was 2026-04-07 01:03 UTC. [S1], [S2]
- **Verification:** the release links the official download catalog rather than
  GitHub binary assets. A documented checksum/signature verification procedure,
  release-signing GPG fingerprint, or reproducible-build recipe was **not
  documented** in the inspected release, catalog and install guide; verification
  route found there: **none**. This does not establish that every package lacks
  an embedded package-manager signature. [S1], [S4], [S5]
- **Install:** archives, RPMs, source builds (`make` with Go and a C compiler),
  or the official Docker workflow. EN hardware documentation recommends Amazon
  Linux 2; macOS is for development. The Docker guide supports linux/amd64 and
  warns about Windows/macOS hosts. A glibc floor and required CPU ISA flags are
  **not documented** in these install sources. [S2], [S5], [S6], [S7]
- **Hardware, read 2026-10-26:** EN recommendation is 8 vCPUs, 64 GiB RAM,
  more than 4,000 GiB storage, 3,500 Mbps disk bandwidth and up to 10 Gbps
  network bandwidth. The page does not specify the disk technology or a lower
  bound for network bandwidth. CN guidance separately recommends 16 cores/
  32 threads, 128 GB RAM and at least 4 TB SSD; PN 8 cores/16 threads and
  64 GB RAM. Do not substitute CN sizing for EN or vice versa. [S6], [S8]
- **Node types:** full is the default; archive retains historical state.
  Official bootstrap snapshots are now live-pruned only. Full/archive data
  must be synced from genesis or requested from the team. [S2], [S9]
- **Initial sync:** the official snapshot guide links the current catalog and
  per-network manifests containing size, checksum and creation time; reserve
  space for compressed and extracted data. This research did not download a
  snapshot. The 2026-10-26 manifests list mainnet snapshot
  `20261026010012` at **2,497,720,630,732 bytes compressed /
  3,148,568,052,186 bytes extracted**, and Kairos `20261026010014` at
  **652,782,389,315 / 821,336,252,176 bytes**. Both manifests supply MD5
  while their SHA-256 field is null. A guaranteed synchronization duration
  and community snapshot providers are **not documented** in the guide. [S9], [S19], [S20]
- **Config:** package installs use `/etc/kend/conf/kend.conf`; archive installs
  use their own `conf` directory. Set `DATA_DIR` (the install example uses
  `/var/kend/data`) and `LOG_DIR`, then run `kend start`. The official install
  guide covers service status and the Docker guide provides a complete
  container invocation. [S3], [S5], [S7]
- **Ports:** P2P 32323, optional multichannel 32324; HTTP RPC 8551 (localhost
  by default), WS 8552. Enable HTTP/WS explicitly and choose API allowlists.
  These are configurable defaults, not an instruction to expose administrative
  RPC publicly. CN/PN public reachability is governed by the core-cell network
  design; only the intended peering interfaces should cross its boundary. [S3], [S10]
- **APIs:** Kaia/legacy Klaytn and Ethereum-compatible JSON-RPC plus admin,
  debug, governance, net and txpool namespaces. `RPC_API`/`WS_API` choose exposed
  modules; `METRICS` and `PROMETHEUS` enable telemetry. The core-cell monitoring guide
  uses port 61001 and `/metrics`; the gRPC default port is **not documented**
  in the inspected configuration page, though the README lists the transport.
  A separate transaction-index requirement for debug/trace is **not documented**
  in these sources. [S3], [S2], [S11], [S18]
- **Upgrades:** monitor GitHub release notices for network-specific block-height
  deadlines. v2.2.2's mandatory mainnet deadline is recorded above. A fixed
  release cadence or a later mandatory deadline is **not documented** in that
  release notice. [S1]
- **Health:** `kaia_syncing` returns synchronization details or `false` when
  not syncing; the installation guide also checks continuing imported blocks
  and `kend`/service status. `false` alone is not evidence of a fresh chain tip. [S11], [S5]

## Validator

- **Participation:** classify as **permissioned / transition documented**.
  The current onboarding page still describes Phase 1 administrative approval;
  its overview forecasts Phase 2 for late September, but does not confirm
  activation. Do not infer permissionless availability from that forecast.
  The token-economy page requires qualification and at least **5 million KAIA**
  for Governance Council membership. [S12], [S13], [S14]
- **Registration:** run the CN, deploy/initialize a staking contract and submit
  an onboarding request through the Validator Management Portal; Phase 1
  registration is completed by the Kaia Team. The page distinguishes validator
  manager, staking admin, temporary contract-validator and reward accounts. [S13]
- **Keys:** node identity `nodekey` resides in the data directory; account
  keystores are under `<DATADIR>/keystore`. Registration also records BLS
  information in `SimpleBlsRegistry`. A supported remote-signer integration
  is **not documented** in the inspected installation/onboarding guides. [S15], [S16], [S13]
- **Slashing:** governance describes exclusion from rewards and offboarding
  for misconduct, faulty operation or participation failures. Exact automated
  double-sign slashing conditions/amounts are **not documented** in the
  inspected governance and onboarding pages; do not equate offboarding with
  stake confiscation. [S17], [S13]
- **Processes:** a core cell includes a CN plus one or more PNs; this is
  additional infrastructure beyond an EN. Use the official core-cell and
  validator onboarding guides. A mandatory external MEV process is **not
  documented** in those guides. [S2], [S12]

## Pitfalls

- Snapshot URLs formerly under the package host are no longer updated; use
  the catalog linked by the current snapshot guide. Only live-pruned data is
  published now, so it cannot provide arbitrary historical state. [S9]
- Stop `ken` gracefully before stopping/removing its container to avoid
  database corruption. [S7]
- Permissionless Phase 2 is a plan in the inspected onboarding text, not an
  observed mainnet state; the older enrollment instructions also retain legacy
  branding. Reconfirm onboarding requirements before implementation. [S12], [S13], [S15]

## Sources

[S1]: https://github.com/kaiachain/kaia/releases/tag/v2.2.2 "Latest stable release, 2026-03-10; mainnet Osaka schedule"
[S2]: https://github.com/kaiachain/kaia/tree/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3 "Pinned client source, README, binaries and licenses"
[S3]: https://docs.kaia.io/misc/operation/configuration/ "Config paths, network IDs, ports and module flags; updated 2025-06-04"
[S4]: https://docs.kaia.io/nodes/downloads/ "Official package catalog; read 2026-10-26"
[S5]: https://docs.kaia.io/nodes/endpoint-node/install-endpoint-nodes/ "Installation, service and health checks; read 2026-10-26"
[S6]: https://docs.kaia.io/nodes/endpoint-node/system-requirements/ "EN hardware/OS; updated 2024-05-27, read 2026-10-26"
[S7]: https://docs.kaia.io/nodes/endpoint-node/docker-setup/ "Docker platform, config and clean shutdown; read 2026-10-26"
[S8]: https://docs.kaia.io/nodes/core-cell/system-requirements/ "Separate CN/PN hardware; read 2026-10-26"
[S9]: https://docs.kaia.io/misc/operation/chaindata-snapshot/ "Official snapshot catalog, manifests and migration; read 2026-10-26"
[S10]: https://docs.kaia.io/nodes/core-cell/network-configuration/ "Core-cell network boundaries and P2P rules; read 2026-10-26"
[S11]: https://docs.kaia.io/references/json-rpc/kaia/syncing/ "Sync method and RPC namespace index; read 2026-10-26"
[S12]: https://docs.kaia.io/nodes/core-cell/become-a-validator/ "Phase 1 scope and planned Phase 2; updated 2026-07-20"
[S13]: https://docs.kaia.io/nodes/core-cell/become-a-validator/onboarding/ "Staking contracts, accounts, BLS registration and approval; read 2026-10-26"
[S14]: https://docs.kaia.io/learn/token-economics/token-economy/ "Governance Council qualification and minimum stake; read 2026-10-26"
[S15]: https://docs.kaia.io/nodes/core-cell/install/before-you-install/ "Node identity key and legacy enrollment; updated 2024-06-11"
[S16]: https://docs.kaia.io/nodes/endpoint-node/ken-cli-commands/ "Account keystore location and encryption; read 2026-10-26"
[S17]: https://docs.kaia.io/learn/governance/ "Governance penalties and offboarding; read 2026-10-26"
[S18]: https://docs.kaia.io/nodes/core-cell/monitoring-setup/ "Metrics endpoint and monitoring agent; updated 2024-09-04, read 2026-10-26"
[S19]: https://snapshots.node.kaia.io/mainnet/pruning-chaindata/manifest.json "Mainnet snapshot size and checksum metadata; generated 2026-10-26"
[S20]: https://snapshots.node.kaia.io/kairos/pruning-chaindata/manifest.json "Kairos snapshot size and checksum metadata; generated 2026-10-26"
