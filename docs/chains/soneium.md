<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Soneium

Researched 2026-10-26 against upstream `op-node/v1.19.11`, `op-reth/v2.6.1`, and Superchain Registry commit `08d6deb24d26b1177f0d0c85b9cef2e5193f47bd`. These are source pins, not a verified Soneium-operated deployment version. Web pages were read on that date. [S3], [S4], [S5], [S6]

## Networks

Soneium Mainnet: **1868**, Ethereum parent; Soneium Minato testnet: **1946**, Sepolia parent. ETH is the gas token. Both have their own registry genesis and hardfork records. The Soneium network page lists HTTP RPC but no public WS endpoint. [S1], [S3], [S4]

## RPC node

- **Clients:** the Soneium FAQ still names op-geth, but the current upstream OP Stack guide explicitly supports Soneium with **op-reth + op-node**. Treat the FAQ's client recommendation as stale: both registry records include Karst, which op-geth does not support. op-node is the reference rollup implementation (MIT); op-reth is the primary supported execution client (MIT OR Apache-2.0 Rust workspace). [S2], [S3], [S4], [S7], [S8], [S9], [S10]
- **Latest stable upstream releases:** `op-node/v1.19.11`, published **2026-10-22**, commit `43c071cbff8ad7512581561aa2d43c990544b650`; `op-reth/v2.6.1`, published **2026-10-22**, commit `e16bffa18420c86dbab693097bc33117f74a5f7d`. Soneium-specific approved version pins are **not documented** in the network page or FAQ; these GitHub non-prerelease versions must not be represented as Soneium's approved rollout. [S1], [S2], [S5], [S6]
- **Release verification:** selected upstream release records contain container locations and no checksum/signature assets. A Soneium release-signing key/fingerprint or reproducible operator-build procedure is **not documented** in the FAQ or those records. [S2], [S5], [S6]
- **Install:** official upstream Docker Compose and source-build paths exist. A current Soneium-owned standalone installer, supported host OS/glibc matrix and CPU flags are **not documented** in the Soneium pages checked. The registry-aware upstream guide is an implementation starting point, not a locally tested deployment recipe. [S1], [S2], [S7], [S11]
- **Hardware:** the Soneium FAQ recommends AWS `i3.2xlarge` or equivalent and scaling resources for public RPC load. Numeric Soneium-specific CPU/RAM/disk/bandwidth values and present chain size are **not documented** there. Do not silently substitute OP Mainnet's storage numbers for Soneium. Read 2026-10-26. [S2]
- **Node types:** upstream op-reth defaults to archive; `--full` provides pruned state. Soneium-specific historical retention guarantees and archive storage estimates are **not documented** in its FAQ. [S8], [S2]
- **Initial sync:** the FAQ says public snapshots are unavailable, but it contains pre-mainnet-era wording; a current official snapshot catalog, sizes and Soneium completion time are **not documented** in the pages checked. Upstream execution-layer sync obtains blocks from peers; it still requires L1 execution/beacon access for derivation. No community snapshot has been adopted as an authoritative bootstrap source here. [S2], [S12]
- **Config:** registry records provide network identity, genesis, sequencer RPC and activation times. The official upstream Compose tutorial explicitly gives `soneium` for op-reth and `soneium-mainnet` for op-node, shared JWT and persistent `./reth-data` → `/data`. For Minato, resolve the registry-aware client's exact network spelling rather than copying the mainnet selector. An official Soneium-specific systemd unit/Compose file is **not documented** in the Soneium pages checked. [S3], [S4], [S7], [S2]
- **Ports:** upstream example uses HTTP **8545**, WS **8546**, private Engine **8551**, rollup RPC host **9545**, metrics **9001/7300**, and TCP/UDP P2P **30303/9222**. These are example configurable ports, not Soneium network constants. Public RPC/Engine/metrics exposure is unnecessary for a private follower; allow peer connectivity as appropriate. Soneium-specific firewall requirements are **not documented** in its FAQ. [S7], [S2]
- **APIs served:** Ethereum JSON-RPC; archive/debug/trace availability depends on execution-client modules and retained history. The upstream op-reth API reference covers module selection; Soneium-specific REST/gRPC and `txindex` options are **not documented** in its FAQ. [S2], [S13]
- **Upgrades:** watch upstream releases and the chain-specific registry. Mainnet Karst is recorded at **2026-07-08 16:00:01 UTC**, Minato at **2026-06-17 16:00:01 UTC**. A later mandatory Soneium deadline and fixed release cadence are **not documented** in these pinned records. Other chains' Lagoon dates do not establish Soneium activation. [S3], [S4], [S5], [S6]
- **Health:** upstream rollup RPC `optimism_syncStatus` exposes safe/finalized/unsafe progress; execution `eth_blockNumber` must advance. Monitor the configured metrics ports. Soneium-specific health endpoint/scrape-path instructions are **not documented** in its FAQ. [S7], [S2]

## Validator

**N/A for an independent PoS validator set:** Soneium's FAQ describes an optimistic rollup inheriting parent-chain consensus. A follower RPC node does not join a PoS validator set. Public sequencer registration, minimum stake, validator key custody, remote signer and PoS slashing rules are **not documented** there. The registry includes a dispute-game factory, but that address alone does not establish permissionless challenger admission or a current game/bond configuration; those details remain **not documented** in the Soneium pages reviewed. [S2], [S3], [S4]

## Pitfalls

- The FAQ speaks of mainnet as future and names op-geth; the current network directory and pinned registry show live mainnet and Karst. Do not use that FAQ as a current binary compatibility matrix. [S1], [S2], [S3]
- Registry membership and an upstream stable release do not establish the chain operator's supported version combination. Obtain the current Soneium rollout requirements before later live deployment acceptance. [S3], [S4], [S5], [S6]

## ERPC implementation

The follower RPC backend implements all twelve lifecycle verbs, sealed persistent
peer identities, operation-bound firewall confirmation and guarded bootstrap recovery.
It does not activate a sequencer or challenger. See [the operations guide](../op-follower-rpc.md)
for exact qualified clients, identity/capacity boundaries and deferred live acceptance.

## Sources

[S1]: https://docs.soneium.org/docs/builders/sfa "Soneium network information; read 2026-10-26"
[S2]: https://docs.soneium.org/docs/builders/faq "Soneium FAQ, with stale pre-mainnet/client wording; read 2026-10-26"
[S3]: https://github.com/ethereum-optimism/superchain-registry/blob/08d6deb24d26b1177f0d0c85b9cef2e5193f47bd/superchain/configs/mainnet/soneium.toml "Pinned mainnet identity and hardfork configuration"
[S4]: https://github.com/ethereum-optimism/superchain-registry/blob/08d6deb24d26b1177f0d0c85b9cef2e5193f47bd/superchain/configs/sepolia/soneium-minato.toml "Pinned Minato identity and hardfork configuration"
[S5]: https://github.com/ethereum-optimism/optimism/releases/tag/op-node/v1.19.11 "Upstream stable op-node release; tag resolved with GitHub commits API"
[S6]: https://github.com/ethereum-optimism/optimism/releases/tag/op-reth/v2.6.1 "Upstream stable op-reth release; tag resolved with GitHub commits API"
[S7]: https://docs.optimism.io/node-operators/tutorials/node-from-docker "Official upstream Compose explicitly naming Soneium; read 2026-10-26"
[S8]: https://docs.optimism.io/use-cases/choose-your-node-stack "Current upstream compatibility and pruning; read 2026-10-26"
[S9]: https://github.com/ethereum-optimism/optimism/blob/43c071cbff8ad7512581561aa2d43c990544b650/LICENSE "Pinned op-node MIT license"
[S10]: https://github.com/ethereum-optimism/optimism/blob/e16bffa18420c86dbab693097bc33117f74a5f7d/rust/Cargo.toml "Pinned op-reth Rust license metadata"
[S11]: https://docs.optimism.io/node-operators/tutorials/run-node-from-source "Upstream source-install reference; read 2026-10-26"
[S12]: https://docs.optimism.io/node-operators/guides/management/restore-from-snapshot "Upstream execution-layer sync and snapshot prerequisites; read 2026-10-26"
[S13]: https://docs.optimism.io/node-operators/reference/op-reth-json-rpc "Upstream RPC modules and behavior; read 2026-10-26"
