<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Robinhood Chain

Researched 2026-10-26 against upstream Nitro `v3.12.1` and Robinhood's documented example `v3.11.2`. These are different pins; the newest upstream release is not automatically the chain's endorsed deployment. Web documentation was read on that date. [S2], [S3], [S4]

## Networks

Robinhood Chain mainnet: **4663**; Robinhood Chain Testnet: **46630**. It is an Ethereum-settled Arbitrum L2 using Ethereum blobs and ETH for gas. The official directory supplies network-specific RPC, sequencer and feed endpoints. [S1]

## RPC node

- **Clients:** Robinhood uses reference **Arbitrum Nitro**, maintained in `OffchainLabs/nitro`. The pinned Nitro license is **Business Source License 1.1**, with an additional use grant and later Apache-2.0 change license; this map does not reinterpret its production-use conditions. [S2], [S5]
- **Latest stable upstream release:** `v3.12.1`, published **2026-10-02**, commit `70fa99a6e711f09eedd96a907290c3df0f3bcf7d`; image `offchainlabs/nitro-node:v3.12.1-70fa99a`. Robinhood's guide instead uses `v3.11.2-3599aca`: tag `v3.11.2`, published **2026-07-06**, commit `3599acae1ad2fab4059fc46453c9cd3294126641`. The newer official software notice recommends `v3.11.4-7d5ac27-stripped`; the full v3.11.4 source release was published **2026-09-16**, commit `7d5ac271b400f710f6267ad759c6afc3e12d7059`. The guide identifies ArbOS **61**. ERPC source-qualifies 3.12.1 without presenting it as a newer chain endorsement. [S2], [S3], [S4], [S15], [S20]
- **Release verification:** selected Nitro release records have no attached checksum/signature assets. A Robinhood/Nitro release GPG fingerprint or reproducible operator-binary attestation is **not documented** in those records or the build guide. Nitro's snapshot checksum verification is separate. [S3], [S4], [S6], [S8]
- **Install:** Robinhood documents Docker; Nitro's source-build guide covers Debian 12, Ubuntu 24.04 amd64 and macOS 15. Minimum glibc and CPU instruction-set flags for Robinhood are **not documented** in its guide. Upstream provides a Compose example, but it must be adapted with Robinhood's chain files. [S2], [S6], [S7]
- **Hardware:** read 2026-10-26: modern **8+ cores**, **64 GB RAM** (128 GB recommended), local NVMe, capacity **2 × current chain size + 20%**, several TB. Archive needs more disk. Numeric bandwidth minimum is **not documented**. [S2]
- **Node types:** Robinhood publishes pruned full-node snapshots; archive nodes must start from scratch. In upstream Nitro, `--execution.caching.archive=true` preserves historical state; switching it on later does not restore already-pruned history. [S2], [S9]
- **Initial sync:** official guide links Arbitrum's snapshot explorer for mainnet/testnet; pass the selected snapshot to `--init.url`. No current size or measured completion time could be established from the rendered catalog, and the guide does not specify either. Nitro verifies SHA256 sidecars/manifests by default. No community snapshot is used here. [S2], [S8], [S10], [S11]
- **Config:** obtain Robinhood's chain-info JSON from links in its guide and pass `--chain.info-files`; mainnet additionally requires its custom `--init.genesis-json-file`, testnet does not. Supply synced L1 execution/beacon services. **Data-dir conflict:** Robinhood says `/home/nitro/.arbitrum`, while its pinned upstream Dockerfile creates user `user` with home `/home/user`; do not adopt the former mount without resolving the actual image datadir. [S2], [S12]
- **Ports:** the guide maps HTTP **8547** and WS **8548**. Upstream additionally documents authenticated RPC **8549**, feed output **9642**, metrics **6070**; these are configurable defaults. A follower connects outbound to its sequencer feed/L1; no generic public P2P listener is required by the documented recipe. Upstream warns against exposing RPC publicly without controls. [S2], [S7], [S13]
- **APIs served:** the Robinhood example exposes JSON-RPC `net,web3,eth`; Nitro allows explicit HTTP/WS module selection and WS subscriptions. Enable debug modules deliberately; upstream `--execution.tx-indexer.tx-lookup-limit=0` retains all transaction-hash lookup history. REST/gRPC node APIs are **not documented** in the chain guide. [S2], [S7], [S18]
- **Upgrades:** watch Robinhood Notices & Upgrades and Nitro releases. Fixed cadence and a next chain-specific mandatory deadline are **not documented** in the node guide. The upstream support policy lists 3.12.x and 3.11.5 (the latter through **2026-10-28**), not the guide's 3.11.2; resolve this stale example before implementation. [S2], [S3], [S14], [S15]
- **Health:** `eth_syncing=false` indicates caught-up Nitro; also check advancing block height and L1 connectivity. With `--metrics`, scrape **6070** `/debug/metrics/prometheus`; a successful RPC liveness response is not proof of synchronization. [S2], [S16]

## Validator

**Permissioned.** Robinhood uses BoLD with an allowlisted validator set and **1 WETH bond**; its guide encourages defensive validators. This is not permissionless Arbitrum One admission. A public application/approval workflow is **not documented** in that guide. [S2]

- **Registration:** chain administrators control the Rollup allowlist; Nitro's generic guide describes that mechanism. A prospective Robinhood operator cannot self-register merely by funding the bond. [S17], [S2]
- **Keys:** upstream Nitro uses a funded parent-chain transaction wallet, with private-key or encrypted-wallet/password configuration. Wallet files live under the chain-specific `wallet/` directory; public follower RPC does not need that staker key. Nitro exposes `--node.staker.data-poster.external-signer.url` and related address/method/TLS flags. Robinhood-specific signer custody instructions are **not documented**. [S17], [S2], [S18]
- **Slashing/bond loss:** generic BoLD penalizes incorrect claims through bond forfeiture. Robinhood-specific additional penalties and payout parameters are **not documented** in its guide; do not copy Arbitrum One's 3,600 WETH bond or reward rules. [S19], [S2]
- **Extra processes:** active validation adds WASM validation; upstream supports an integrated `-validator` image or separate JWT-authenticated `nitro-val`. Use the official Nitro validator guide alongside Robinhood's permissioned admission rules. [S7], [S9], [S17]

## Pitfalls

- Robinhood's mount example conflicts with the pinned image home directory. ERPC uses explicit `/data` persistence and the supported 3.12.1 image digest after source qualification; the older chain notice and the newer upstream selection remain distinct. [S12], [S14], [S2], [S15]
- Mainnet requires custom genesis while testnet omits it. Applying one network's bootstrap files to the other is not a supported configuration. [S2]
- Public RPC is rate limited; the mainnet delayed backup feed is about 500 ms behind the primary. Sequencer feed URLs use WS, not HTTP. [S1], [S2]

## ERPC implementation

The follower backend implements all twelve RPC lifecycle verbs for mainnet and
testnet. Mainnet's custom genesis and each network's chain file have independent
byte pins. The 3.12.1 selection is supported by its ArbOS 61 source path, with live
compatibility explicitly deferred; it is not claimed as a Robinhood endorsement.
The backend has no validator wallet or bond activation. See
[the operator guide](../nitro-rpc.md) for image provenance, private L1 transport,
network ownership and the deferred acceptance checklist.

The validator `registration` command observes the public allowlist and prepares
or validates a single-address unsigned administrator intent using the existing
RPC host's authenticated parent provider. See the
[admission guide](../robinhood-admission.md) for the external administrator review
and finalized-block checks. Admission output does not authorize activation.

The dedicated validator backend implements all twelve lifecycle verbs for both
networks using its separately source-qualified Nitro 3.12.2 catalog. It defaults
to Watchtower; explicit activation grants only the original admitted EOA's native
Defensive rival assertion/stake sends. It excludes MakeNodes, confirmations and
challenge-edge submission. Funding, wrapping, approvals, withdrawals and
administrator admission remain external. See the
[Defensive operator guide](../robinhood-defensive-validator.md) for exact source,
image, custody, financial bounds and deferred real-host acceptance. This profile
does not convert a follower or reuse Arbitrum One custody.

## Sources

[S1]: https://docs.robinhood.com/chain/connecting/ "Network IDs, parent chain and endpoint roles; read 2026-10-26"
[S2]: https://docs.robinhood.com/chain/run-a-full-node/ "Official node/validator guide, configuration-file links and hardware; read 2026-10-26"
[S3]: https://github.com/OffchainLabs/nitro/releases/tag/v3.12.1 "Latest stable upstream release; tag resolved with GitHub commits API"
[S4]: https://github.com/OffchainLabs/nitro/releases/tag/v3.11.2 "Robinhood example release; tag resolved with GitHub commits API"
[S5]: https://github.com/OffchainLabs/nitro/blob/70fa99a6e711f09eedd96a907290c3df0f3bcf7d/LICENSE.md "Pinned upstream BSL license"
[S6]: https://docs.arbitrum.io/run-a-node/nitro/build-nitro-locally "Upstream source-build environments; read 2026-10-26"
[S7]: https://docs.arbitrum.io/run-a-node/nitro/docker-and-cli-binaries "Upstream official Compose and image roles; read 2026-10-26"
[S8]: https://docs.arbitrum.io/run-a-node/nitro/nitro-database-snapshots "Snapshot checksum and restore behavior; read 2026-10-26"
[S9]: https://docs.arbitrum.io/run-a-node/assign-node-roles "Archive transitions and split validation; read 2026-10-26"
[S10]: https://snapshot-explorer.arbitrum.io/?chain=Robinhood+Chain "Officially linked mainnet snapshot catalog; rendered listing lacked sizes on 2026-10-26"
[S11]: https://snapshot-explorer.arbitrum.io/?chain=Robinhood+Chain+Sepolia "Officially linked testnet snapshot catalog"
[S12]: https://github.com/OffchainLabs/nitro/blob/3599acae1ad2fab4059fc46453c9cd3294126641/Dockerfile "Pinned image home-directory evidence contradicting chain guide"
[S13]: https://docs.arbitrum.io/run-a-node/overview "Upstream RPC exposure guidance; read 2026-10-26"
[S14]: https://docs.arbitrum.io/run-a-node/nitro-support-policy "Upstream supported versions; read 2026-10-26"
[S15]: https://docs.robinhood.com/chain/notices-and-upgrades/ "Official announcement index linked from node docs; read 2026-10-26"
[S16]: https://docs.arbitrum.io/run-a-node/nitro/node-tuning-and-monitoring "Prometheus and liveness semantics; read 2026-10-26"
[S17]: https://docs.arbitrum.io/run-a-node/more-types/run-validator-node "Generic Nitro validator keys and administrator allowlisting; read 2026-10-26"
[S18]: https://docs.arbitrum.io/run-a-node/nitro/cli-flags-reference "Nitro v3.12.1 flag reference; read 2026-10-26"
[S19]: https://docs.arbitrum.io/how-arbitrum-works/bold/bold-faq "Generic BoLD bond-loss mechanism; read 2026-10-26"

[S20]: https://github.com/OffchainLabs/nitro/releases/tag/v3.11.4 "Official full source release behind the newer Robinhood notice"
