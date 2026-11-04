<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Avalanche

Researched 2026-10-26 against AvalancheGo v1.15.2; documentation pages were read on that date. [S1], [S2]

## Networks

Mainnet and Fuji both include P/X/C chains. The EVM C-Chain IDs are 43114 and 43113 respectively; these are not identifiers for the P/X chains. Network selection uses `--network-id=mainnet` or `fuji`. [S3], [S4]

## RPC node

- **Client:** Ava Labs' AvalancheGo is the official node implementation for P/X/C, with repository and releases linked below. Its top-level license is BSD-3-Clause; grafted components have their own licenses. The pinned release integrates the C-Chain implementation, so do not independently deploy an obsolete Coreth binary. [S1], [S5]
- **Latest stable:** `v1.15.2`, commit `4bb5c1dc13e1b6ff4eaf49fe8674666fbb342a17`, published 2026-10-22. The official release matrix recommends it for Mainnet and Fuji; Fuji prereleases are a separate choice. [S1], [S2], [S6]
- **Verification:** Release archives have detached `.sig` assets. The official download key has fingerprint `5395 BDA1 129C AC3E 7469 9D07 D930 80B0 C0D5 FE8B`; the Linux amd64 signature's issuer fingerprint matches it. This research inspected the small key/signature files only, without downloading or verifying the binary. A separate checksum manifest and reproducible-build attestation are **not documented** in this release. [S1], [S7], [S8]
- **Install:** Prebuilt Linux amd64/arm64 and macOS archives, package installation, Docker, or source build are documented. At this commit Linux amd64/arm64 are tier 1, macOS arm64 tier 2; macOS amd64 and native Windows are unsupported. Go 1.26.10 is the release minimum. A glibc floor and CPU instruction-set floor are **not documented** in the installation/platform guidance. [S1], [S5], [S9]
- **Hardware, read 2026-10-26:** The current Primary Network baseline is 4 cores/8 threads, 16 GB RAM, 1 TB local NVMe (at least 3,000 IOPS), and symmetric 100 Mbps; the higher-stake tier is 8+ cores/16 threads, 32 GB, 2 TB NVMe, symmetric 1 Gbps. RPC load needs separate sizing; a dedicated RPC throughput guarantee is **not documented** there. The page estimates active state around 500 GB and full archive around 12.5 TB. [S10]
- **Node types:** Non-validating API nodes follow chains; validators additionally participate in consensus. Archive retains history, pruning discards old state, and state sync starts from state summaries rather than genesis replay. For C-Chain archive, disable both `pruning-enabled` and `state-sync-enabled`; state-synced nodes cannot answer earlier-state queries. [S11], [S12]
- **Initial sync:** Use built-in state sync for a new non-archive node. The official baseline above is an estimate, not a downloadable snapshot manifest. A fixed sync duration and an endorsed external/community snapshot service are **not documented** in the setup and requirements pages. [S9], [S10]
- **Config:** Base data directory is `~/.avalanchego`, database `~/.avalanchego/db`; `--config-file` loads node JSON, while C-Chain settings live separately under `configs/chains/C/config.json`. The installer creates `configs/node.json`; a manual source install does not. An official `avalanchego.service` example is available. [S4], [S12], [S13]
- **Ports/APIs:** Public inbound TCP 9651 is required for P2P. HTTP/WS APIs share port 9650 (HTTP defaults to loopback); restrict access to trusted clients or an appropriately controlled RPC gateway. C-Chain exposes Ethereum-compatible RPC, including configurable `trace`; use the `apis` setting. P/X have their own APIs. `eth-apis` is removed in v1.15.2, not an enablement mechanism. A gRPC node listener is **not documented** in the linked configuration/API guidance. [S4], [S10], [S12], [S1]
- **Upgrades:** Follow GitHub releases and Avalanche Notify. A fixed release cadence is **not documented**. v1.15.2 is optional but encouraged; Helicon required Mainnet nodes to upgrade to v1.15.0 before 2026-09-22 15:00 UTC. Plugin protocol is now 47, requiring matching plugins. [S1], [S2]
- **Health:** Check `/ext/health` and chain bootstrap status before admitting traffic; the official troubleshooting guide explains startup health failures. Prometheus scrapes `/ext/metrics` on the API port when metrics are enabled. [S14], [S15]

## Validator

- **Participation:** Permissionless Primary Network staking: Mainnet minimum 2,000 AVAX for 48 hours–1 year; Fuji minimum 1 AVAX for 12 hours. Register the NodeID, BLS public key/proof, stake, end time, rewards address and delegation fee through the P-Chain staking procedure. After Helicon, new validations require 90% measured uptime for rewards; pre-activation validations retain the former 80% rule. Principal is returned at completion; reward withholding is the documented penalty rather than principal slashing. [S16]
- **Keys:** `staker.crt`/`staker.key` establish NodeID; `signer.key` is the BLS identity, normally in `~/.avalanchego/staking/`. Back up all three. Optional CubeSigner remote BLS signing uses a sidecar; its guide documents the remote-key setup. [S17], [S18]
- **Processes:** The same AvalancheGo process validates the Primary Network's P/C/X chains. Separate L1 validation has chain-specific rules and continuous fees, so the 2,000 AVAX rule must not be applied indiscriminately to L1-only nodes. No mandatory MEV process is **documented** in the node-role or staking guides. [S11], [S16]


## ERPC today

**Lifecycle code implemented; live acceptance deferred.** The Avalanche backend
supports `erpc r --chain avax`, the compatible `erpc n` alias, and explicit
`erpc v` Primary Network validator intent on Mainnet/Fuji. All twelve lifecycle
verbs operate, with verified release installation, restricted API exposure,
identity backup/same-host recovery and P-Chain health/admission observations.
Registration is prepared/validated for external signing and submission; no
transaction is signed or sent by deploy. See the [operator guide](../avalanche.md)
and [implementation roadmap][R25]. Offline tests do not certify a running
production node, Fuji activation or Mainnet acceptance. [R20], [R21], [R23], [R24]

## Pitfalls

- A database last run before Helicon must first bootstrap beyond Helicon using v1.15.0/v1.15.1, or be replaced by a fresh sync, before v1.15.2. [S1]
- Local NVMe is required by current guidance; cloud block-storage latency can cause missed work or benching. Storage continues growing after state sync. [S10]
- Adding archive/index options after the fact requires a new bootstrap. Restoring without the staking identity changes the node's identity. [S19], [S17]

## Sources

[S1]: https://github.com/ava-labs/avalanchego/releases/tag/v1.15.2 "Release, date, assets and migration warnings"
[S2]: https://build.avax.network/docs/nodes/releases "Network release recommendations and announcements; read 2026-10-26"
[S3]: https://build.avax.network/docs/primary-network "P/X/C and C-Chain network IDs; read 2026-10-26"
[S4]: https://build.avax.network/docs/nodes/configure/configs-flags "Network/configuration/data/API defaults; read 2026-10-26"
[S5]: https://github.com/ava-labs/avalanchego/blob/4bb5c1dc13e1b6ff4eaf49fe8674666fbb342a17/README.md "Pinned official client, platforms, installation and licenses"
[S6]: https://github.com/ava-labs/avalanchego/commit/4bb5c1dc13e1b6ff4eaf49fe8674666fbb342a17 "Resolved release commit"
[S7]: https://downloads.avax.network/avalanchego.gpg.key "Official public release key; fingerprint inspected 2026-10-26"
[S8]: https://github.com/ava-labs/avalanchego/releases/download/v1.15.2/avalanchego-linux-amd64-v1.15.2.tar.gz.sig "Detached signature; issuer packet inspected 2026-10-26"
[S9]: https://build.avax.network/docs/nodes/run-a-node "Installation alternatives; read 2026-10-26"
[S10]: https://build.avax.network/docs/nodes/system-requirements "Hardware, storage estimates and public P2P port; read 2026-10-26"
[S11]: https://build.avax.network/docs/nodes "Node roles, archive/pruning/state sync and L1 distinction; read 2026-10-26"
[S12]: https://build.avax.network/docs/primary-network/exchange-integration "Archive configuration and C-Chain API groups; read 2026-10-26"
[S13]: https://build.avax.network/docs/nodes/maintain/run-as-background-service "Official systemd example; read 2026-10-26"
[S14]: https://build.avax.network/docs/nodes/run-a-node/common-errors "Health and bootstrap failure diagnosis; read 2026-10-26"
[S15]: https://build.avax.network/docs/nodes/maintain/monitoring "Prometheus scrape configuration; read 2026-10-26"
[S16]: https://build.avax.network/docs/primary-network/validate/how-to-stake "Official validator guide and post-Helicon rules; read 2026-10-26"
[S17]: https://build.avax.network/docs/nodes/maintain/backup-restore "Node and BLS key identity; read 2026-10-26"
[S18]: https://build.avax.network/docs/nodes/maintain/cube-signer-sidecar "Remote BLS signer; read 2026-10-26"
[S19]: https://build.avax.network/docs/nodes/run-a-node/using-install-script/node-config-maintenance "Archive/index rebuild caveat; read 2026-10-26"

[R20]: ../../crates/erpc-skills/skills/avalanche-node/SKILL.md "Existing repository existing skill"

[R21]: ../../crates/erpc/src/main.rs "Existing repository CLI dispatch"

[R22]: ../plans/2026-10-24-eth-rpc.md "Existing repository node-command plan"

[R23]: ../../crates/erpc-core/src/chain.rs "Avalanche exposes a Node role only"
[R24]: ../../crates/erpc/src/tree.rs "Unimplemented node command fallback"
[R25]: ../plans/2026-10-26-chain-implementation.md "Avalanche node AVN1-AVN4 and validator AVV1-AVV4 plan"
