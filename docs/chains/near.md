<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# NEAR

Researched 2026-10-26 against nearcore 2.13.4. Operator documentation is pinned to `near/node-docs` commit `db6103b400ab056c12a5716d6cef1dca519c442b`; other pages were read on this date. [S1], [S2]

## Networks

Public networks use string chain IDs `mainnet` and `testnet`. The official initialization guide downloads each network's genesis and RPC configuration; localnet is a separate development choice. An EVM numeric chain ID does not apply to this nearcore deployment. [S3]

## RPC node

- **Client:** `near/nearcore` is NEAR's reference implementation; the executable is `neard`. The workspace declares `MIT OR Apache-2.0`. [S4], [S5]
- **Latest stable:** `2.13.4`, commit `44f7ae6cd7ef08bab604e20a473bf77e35d4c993`, published 2026-09-03. It is marked `CODE_RED_MAINNET, CODE_RED_TESTNET` for a critical crash/DoS fix. Testnet guidance selects the latest RC: `2.14.0-rc.6`, commit `d37c9e9ed3412dfab319e2e56bde24fd38e62ef1`, published 2026-10-22, is explicitly a prerelease, not the latest stable Mainnet release. [S1], [S6], [S3]
- **Release verification:** The stable GitHub release has no binary assets. A signed checksum manifest, published release-GPG fingerprint and reproducible-build attestation are **not documented** in the release or installation guides. Build from the resolved source revision or pin a documented version/commit container tag; a tag alone does not authenticate a binary. [S1], [S3], [S7]
- **Install:** Build with `make release`, yielding `target/release/neard`; official prerequisites cover Linux and macOS. Docker image `nearprotocol/nearcore` provides network and version tags; `latest` is unavailable. A production glibc floor is **not documented** in these guides. [S3], [S7]
- **Hardware, read 2026-10-26:** Mainnet RPC recommendation: 8 cores/16 threads, 32 GB DDR4, 4 TB NVMe; minimum 16 GB RAM and 2.5 TB SSD with 15k IOPS/800 MiB/s. Required CPU features listed are CMPXCHG16B, POPCNT, SSE4.1, SSE4.2, AVX, SHA-NI. Testnet recommendation: same CPU, 16 GB RAM, 1.5 TB NVMe. Network bandwidth minimum is **not documented** on this hardware page. [S8]
- **Node types:** RPC nodes track state for queries; archive nodes retain historical blockchain/state data; validators produce/validate blocks or chunks. RPC garbage collection normally retains five epochs, minimum three. A light configuration with no tracked shards cannot serve state queries. Archive history needs a separate archive deployment, not merely a larger RPC retention window. [S9], [S8], [S3]
- **Initial sync:** Current operator guidance favors Epoch Sync using current boot peers, followed by state sync. The old free FastNEAR community snapshot service is explicitly deprecated from 2025-06-01; do not copy its download commands as the default. The docs describe external state-part storage but mix older Pagoda and newer FastNEAR examples; select the network-generated configuration. A current fixed snapshot size and guaranteed sync duration are **not documented** in the Epoch Sync guide. [S10], [S3], [S11], [S12]
- **Config:** Initialize with `neard --home ~/.near init --chain-id <network> --download-genesis --download-config rpc`, then run with the same home. It contains `config.json`, `genesis.json`, `node_key.json`, and `data/`. The operator guide supplies a systemd example, and Docker guidance gives an official container invocation. Use current generated configuration rather than copying the old release-number examples. [S3], [S7], [S12]
- **Ports/APIs:** TCP 24567 is P2P, TCP 3030 is HTTP JSON-RPC; match `network.addr` and `rpc.addr`. P2P needs peer reachability, while public RPC is an operator service choice. Restrict metrics/debug/admin access when publishing RPC. Native WS/gRPC listener ports are **not documented** in this Docker/RPC setup. Ethereum `debug`/`trace` flags are not part of these documented APIs. [S7], [S3], [S13]
- **Upgrades:** The maintenance guide describes typically five weeks from Testnet to Mainnet and color-coded announcements on GitHub and the Validator Announcement Discord channel. Protocol/database/security upgrade fields govern rollout; `CODE_RED` expects immediate response, ideally within 30 minutes. The 2.13.4 release says to upgrade as soon as possible, with no fixed timestamp. [S14], [S1]
- **Health:** Inspect RPC status/health responses for syncing and no-new-block errors; use advancing block/state progress rather than process liveness alone. Metrics are served at `http://localhost:3030/metrics`. [S13], [S12]

## Validator

- **Participation:** Permissionless stake-based selection. The current network guide describes up to 300 proposals with a 25,500 NEAR floor and a dynamic seat threshold; the threshold is not a permanently sufficient deposit. Submit a stake action with the validator public key; delegation uses a staking-pool contract. The official onboarding guide covers pool deployment and proposals. [S16], [S17], [S12]
- **Keys:** `validator_key.json` in the node home supplies block/chunk signing; `node_key.json` supplies peer identity; account access keys authorize account/staking transactions. The block-production key must be ed25519. A supported remote-validator-signer deployment is **not documented** in the key/onboarding guides. [S18], [S3], [S16]
- **Slashing:** Current high-level docs describe penalties for malicious consensus behavior, including invalid blocks/alternative chains, but an exact active-network slashing schedule and failover-safe double-sign protection are **not documented** there. The older launch article says slashing was disabled **at launch**; that is not evidence of the 2026 status. Treat current enforcement details as an unresolved deployment prerequisite, not an assertion that slashing is absent. [S16], [S19]
- **Processes/hardware:** `neard` also performs validation; a separate Ethereum-style consensus client is unnecessary. Staking-pool operation includes periodic proposal/ping work described in onboarding. Mainnet producer recommendation is 8 physical cores, 48 GB RAM, 3 TB NVMe plus memory headroom; chunk-only validators have a separate smaller profile. A mandatory MEV sidecar is **not documented** in the guide. [S3], [S12], [S20]

## Pitfalls

- Stale documentation examples use nearcore 1.25.0 and deprecated snapshots; select the pinned stable/RC release according to the target network. [S3]
- Changing a validator key while that key is expected by the active epoch causes signature rejection and loss of validator position. [S18]
- Testnet validator storage recommendations contain inconsistent minimum/recommended values; do not derive a production size from the smaller row without resolving that upstream inconsistency. [S20]

## Sources

[S1]: https://github.com/near/nearcore/releases/tag/2.13.4 "Stable release, timestamp and urgent upgrade classification"
[S2]: https://github.com/near/node-docs/commit/db6103b400ab056c12a5716d6cef1dca519c442b "Operator documentation revision read 2026-10-26"
[S3]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/rpc/run-rpc-node.md "Build, network IDs, genesis/configuration, light mode and obsolete snapshot warning"
[S4]: https://github.com/near/nearcore/blob/44f7ae6cd7ef08bab604e20a473bf77e35d4c993/README.md "Reference implementation at resolved stable commit"
[S5]: https://github.com/near/nearcore/blob/44f7ae6cd7ef08bab604e20a473bf77e35d4c993/Cargo.toml "Workspace dual-license declaration"
[S6]: https://github.com/near/nearcore/releases/tag/2.14.0-rc.6 "Testnet prerelease, resolved to d37c9e9ed3412dfab319e2e56bde24fd38e62ef1"
[S7]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/validator/docker-setup.md "Official image tags, invocation and ports"
[S8]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/rpc/hardware-rpc.md "RPC hardware and retention requirements"
[S9]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/intro/types-of-node.md "RPC/archive/validator responsibilities"
[S10]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/intro/epoch_sync.md "Official Epoch Sync bootstrap procedure"
[S11]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/rpc/state-sync.md "State-part synchronization and configuration"
[S12]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/validator/guide.md "Onboarding, systemd, current state-sync discussion and metrics"
[S13]: https://github.com/near/nearcore/blob/44f7ae6cd7ef08bab604e20a473bf77e35d4c993/chain/jsonrpc-primitives/src/types/status.rs "RPC status/debug types"
[S14]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/maintenance/node-maintenance.md "Release cadence and emergency response guidance"
[S16]: https://docs.near.org/protocol/network/validators "Current role, threshold and high-level slashing description; read 2026-10-26"
[S17]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/validator/staking-and-delegation.md "Stake transactions and delegated staking"
[S18]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/intro/keys.md "Account/node/validator key distinctions and rotation caveat"
[S19]: https://near.org/blog/mainnet-roadmap "Historical launch-only slashing status, not current-network proof"
[S20]: https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/validator/hardware-validator.md "Producer and chunk-validator hardware"
