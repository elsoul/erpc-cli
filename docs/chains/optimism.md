<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Optimism (OP Mainnet)

Researched 2026-10-26 against `op-node/v1.19.11` and `op-reth/v2.6.1`. Web pages were read on that date; versioned sources below take precedence over old example image tags. [S2], [S3], [S7]

## Networks

OP Mainnet: **10**, Ethereum parent; OP Sepolia: **11155420**, Ethereum Sepolia parent. Both use ETH. Public RPC is rate limited and does not provide WebSockets. [S1], [S7]

## RPC node

- **Clients:** production reference pairing is `op-node` plus primary execution client `op-reth`, now both in the Optimism monorepo. `op-node` is MIT; the Rust workspace is MIT OR Apache-2.0. `kona-node` is an experimental consensus alternative, explicitly not production-ready. Nethermind is an independently maintained execution alternative; its OP configurations are documented in the official source-build guide. [S4], [S5], [S6], [S8], [S9]
- **Latest stable releases:** `op-node/v1.19.11`, **2026-10-22**, commit `43c071cbff8ad7512581561aa2d43c990544b650`; `op-reth/v2.6.1`, **2026-10-22**, commit `e16bffa18420c86dbab693097bc33117f74a5f7d`. These non-prerelease component tags resolve to different commits: pin each component separately instead of assuming every coordinated release shares one SHA. `kona-node/v1.7.3` shares the latter SHA and publication date but remains experimental despite GitHub not marking the tag a prerelease. [S2], [S3], [S9]
- **Alternative release:** Nethermind `2.2.1`, **2026-10-22**, commit `c4f1015be8b989dd609803cc50d3928d6e0dfd4f`; its license files are GPL and LGPL. This is an upstream release pin, not evidence of an OP-specific production qualification. [S10], [S11], [S12]
- **Release verification:** the selected op-node/op-reth release records publish Docker image coordinates and no downloadable checksum/GPG assets. A release-signing GPG fingerprint or reproducible operator-binary verification recipe is **not documented in those records or the source-build guide**; do not confuse fault-proof reproducible prestates with operator-image verification. [S2], [S3], [S8]
- **Install:** official Docker images under `us-docker.pkg.dev/oplabs-tools-artifacts/images`, or source using the monorepo's toolchain configuration. Minimum host OS/glibc and CPU instruction-set matrix are not documented in the Docker/source tutorials. [S7], [S8]
- **Hardware:** read 2026-10-26: 16 GB RAM suggested minimum, modern CPU, SSD; archive needs NVMe and multiple TB. The source guide's **June 2025** estimates are 700 GB full (+100 GB/6 months) and 14 TB archive (+3.5 TB/6 months); these are historical figures, not current op-reth measurements. Numeric bandwidth and core counts are not documented there. [S13], [S8]
- **Node types:** op-reth is archival by default; `--full` prunes state. Body pruning is unsupported in the selection guide. Historical-proof service requires a separate proofs-history store; decide that retention before sync. [S4]
- **Initial sync:** OP Mainnet requires pre-Bedrock state import or a compatible snapshot; OP Sepolia does not. The official snapshot directory and restore guide cover SHA256 verification; the directory listed mainnet storage-v2 full **424.7 GiB** (2026-10-22) and archive **530.5 GiB** (2026-10-23), compressed archive sizes rather than disk-capacity requirements. The restore guide estimates minutes to hours after restoration, depending on snapshot age; it gives no completion guarantee. No community snapshot is required. [S7], [S14], [S15]
- **Config:** the official Docker tutorial contains a complete Compose example: shared JWT, `./reth-data` → `/data`, L1 execution and beacon endpoints, `--network=op-mainnet` for op-node and `--chain=optimism` for op-reth. Use current component tags, not the tutorial's older image examples. [S7]
- **Ports:** example HTTP **8545**, WS **8546**, Engine **8551**; consensus RPC host **9545** → container **7000**; metrics **9001** and **7300**; peer TCP/UDP **30303** and **9222**. Restrict RPC/Engine/metrics to intended clients as a deployment choice; peer ports are the P2P services. [S7]
- **APIs served:** Ethereum JSON-RPC plus OP receipt/deposit fields; select modules with `--http.api`/`--ws.api` for debug/trace/txpool exposure. REST/gRPC and Bitcoin-style `txindex` are not documented in the RPC reference. [S16]
- **Upgrades:** follow component releases and network notices; a fixed cadence is not documented. v1.19.11/v2.6.1 are strongly recommended security releases. Lagoon interop is **targeted**, pending governance, for **2026-12-03** Sepolia and **2026-12-15** mainnet; exact activation timestamps/releases were not yet pinned. The notice requires supernode plus Light-CL topology and a second execution client for the Unichain dependency; this is future work, not the October topology. [S2], [S3], [S17]
- **Health:** check advancing `eth_blockNumber` and `optimism_syncStatus` unsafe/safe/finalized heads. The op-reth API reference documents a structured `eth_syncing` response even at head; compare stage/current/highest progress rather than requiring `false`. Metrics ports are listed above; the tutorial does not specify their scrape path. [S7], [S16]

## Validator

**N/A for an independent PoS validator set.** The relevant public security role is fault-proof challenger, separate from operating the sequencer or a follower RPC. The official challenger guide describes permissionless participation on chains with permissionless games; admission follows the deployed game type, not ownership of an OP token stake. [S18]

- **Bonds and keys:** an Ethereum transaction signer funds each claim and gas. Bonds on correct claims are refunded; incorrect claims pay the counter-claimer. There is no fixed universally sufficient minimum stake. Private key, mnemonic or `op-signer` are documented signing options; a universal key-storage directory is not documented. [S18]
- **Processes:** `op-challenger`, Cannon with kona-client prestate/kona-host, SafeDB-enabled op-node, archive op-reth with debug/historical proofs, L1 execution and beacon services; `op-dispute-mon` monitors games. Use the official challenger guide and deployment-specific prestate rather than treating the RPC-only configuration as a validator. [S18]

## Pitfalls

- op-geth reached end of support on **2026-05-31** and cannot follow the active Karst chain; its newer-looking library releases are not supported node releases. [S4]
- An empty OP Mainnet datadir fails without the pre-Bedrock import; a reachable Engine API alone does not prove synchronization. [S7]
- Never restore a challenger's SafeDB from a snapshot: inconsistent L1 safety data can make it challenge valid outputs. [S18]

## ERPC implementation

The follower RPC backend implements all twelve lifecycle verbs, sealed persistent
peer identities, operation-bound firewall confirmation and guarded bootstrap recovery.
It does not activate a sequencer or challenger. See [the operations guide](../op-follower-rpc.md)
for exact qualified clients, identity/capacity boundaries and deferred live acceptance.

## Sources

[S1]: https://docs.optimism.io/op-mainnet/network-information/connecting-to-op "Network reference; read 2026-10-26"
[S2]: https://github.com/ethereum-optimism/optimism/releases/tag/op-node/v1.19.11 "op-node stable release; tag resolved through GitHub commits API"
[S3]: https://github.com/ethereum-optimism/optimism/releases/tag/op-reth/v2.6.1 "op-reth stable release; tag resolved through GitHub commits API"
[S4]: https://docs.optimism.io/use-cases/choose-your-node-stack "Current client selection and deprecations; read 2026-10-26"
[S5]: https://github.com/ethereum-optimism/optimism/blob/43c071cbff8ad7512581561aa2d43c990544b650/LICENSE "Pinned MIT license"
[S6]: https://github.com/ethereum-optimism/optimism/blob/e16bffa18420c86dbab693097bc33117f74a5f7d/rust/Cargo.toml "Pinned Rust workspace license and compiler"
[S7]: https://docs.optimism.io/node-operators/tutorials/node-from-docker "Official Compose, ports and bootstrap caveat; read 2026-10-26"
[S8]: https://docs.optimism.io/node-operators/tutorials/run-node-from-source "Source builds, alternative client and dated hardware figures; read 2026-10-26"
[S9]: https://github.com/ethereum-optimism/optimism/releases/tag/kona-node/v1.7.3 "Experimental consensus client release"
[S10]: https://github.com/NethermindEth/nethermind/releases/tag/2.2.1 "Alternative execution release; tag resolved through GitHub commits API"
[S11]: https://github.com/NethermindEth/nethermind/blob/c4f1015be8b989dd609803cc50d3928d6e0dfd4f/LICENSE-GPL "Pinned alternative-client GPL license"
[S12]: https://github.com/NethermindEth/nethermind/blob/c4f1015be8b989dd609803cc50d3928d6e0dfd4f/LICENSE-LGPL "Pinned alternative-client LGPL license"
[S13]: https://docs.optimism.io/node-operators/overview "Hardware baseline; read 2026-10-26"
[S14]: https://docs.optimism.io/node-operators/guides/management/restore-from-snapshot "Snapshot verification; read 2026-10-26"
[S15]: https://datadirs.optimism.io/ "Official snapshot directory linked by operator docs"
[S16]: https://docs.optimism.io/node-operators/reference/op-reth-json-rpc "RPC reference, tested upstream with v2.2.3; read 2026-10-26"
[S17]: https://docs.optimism.io/notices/interop-prep "Pending Lagoon topology and activation notice; read 2026-10-26"
[S18]: https://docs.optimism.io/use-cases/run-a-fault-proof-challenger "Challenger roles, bonds, signer and infrastructure; read 2026-10-26"
