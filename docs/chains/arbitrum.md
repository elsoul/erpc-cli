<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Arbitrum

Researched 2026-10-26 against Nitro `v3.12.1`. Web documentation was read on that date; mutable pages do not expose a revision date unless stated. [S2]

## Networks

Arbitrum One: **42161**, Ethereum parent, Nitro Rollup. Arbitrum Nova: **42170**, Ethereum parent, Nitro AnyTrust. Arbitrum Sepolia testnet: **421614**, Sepolia parent, Nitro Rollup. This deployment map primarily targets One; Nova's AnyTrust data availability must not be treated as identical. [S1]

## RPC node

- **Clients:** official reference node is Offchain Labs **Nitro**. The pinned license is **Business Source License 1.1**, with an additional use grant and later Apache-2.0 change license; it is not simply Apache-2.0 today. [S2], [S3]
- **Latest stable release:** `v3.12.1`, published **2026-10-02** (changelog dated September 29), commit `70fa99a6e711f09eedd96a907290c3df0f3bcf7d`; Docker `offchainlabs/nitro-node:v3.12.1-70fa99a`. GitHub latest-release selection excludes prereleases. [S2], [S4]
- **Release verification:** no attached binary checksum/GPG assets or release-signing fingerprint are documented in this release record. Source builds are documented, but a reproducible-build attestation workflow is **not documented** in the build guide. Snapshot SHA256 verification is a different mechanism. [S2], [S5], [S8]
- **Install:** upstream recommends Docker; native/source builds cover Debian 12, Ubuntu 24.04 amd64 and macOS Sequoia 15. Minimum glibc and CPU instruction-set flags are **not documented** in the build/hardware guides. The binaries guide supplies official Compose. [S5], [S6], [S7]
- **Hardware:** read 2026-10-26: full node minimum 8-core third-generation CPU, 64 GB DDR5 RAM, local NVMe and several TB; recommended 16+ newer cores and 128+ GB. RPC load increases requirements. Snapshot extraction needs roughly twice snapshot size. A numeric network-bandwidth minimum is **not documented** on this page. [S6]
- **Node types:** HashDB is default and needs offline pruning; PathDB prunes online. Archive preserves historical state; enabling archive later does not recover pruned history. PathDB cannot run the block validator. [S9], [S10]
- **Initial sync:** One **requires a snapshot** because Nitro cannot replay pre-Nitro Classic history. The mutable guide describes `--init.latest=pruned`/`archive` as HashDB-only, but pinned Nitro 3.12.1 explicitly maps those kinds to `full-path`/`archive-path` when PathDB is selected. ERPC follows that fixed resolver with checksum validation enabled. Explicit `--init.url` remains available upstream. [S20] The full-node guide gives approximate One snapshots of **2.3 TB HashDB / 2.4 TB PathDB**, not immutable current sizes. Exact completion time is **not documented**; monitoring guidance describes days/weeks depending on history. No community snapshot is needed. [S8], [S9], [S11]
- **Config:** `--chain.id=42161`, L1 execution `--parent-chain.connection.url`, beacon `--parent-chain.blob-client.beacon-url`, initial snapshot and selected RPC modules. Persist Docker data at `/home/user/.arbitrum`; source default is `$HOME/.arbitrum/<chain>/nitro`. `--conf.file` loads JSON configuration; the official Compose example is linked. [S7], [S8], [S9]
- **Ports:** HTTP **8547**, WS **8548**, authenticated RPC **8549**, optional feed output **9642**, metrics **6070**. Standard follower configuration consumes sequencer feeds and parent-chain endpoints; no generic Ethereum-style public P2P listener is specified by the follower guide. Public RPC exposure is explicitly discouraged by upstream; feed output is for downstream clients when acting as a relay. [S7], [S12]
- **APIs served:** JSON-RPC `eth`, `net`, `web3`, `arb`, configured via `--http.api` and `--ws.api`; WS subscriptions require WS configuration. Add the intended debug module explicitly for tracing; transaction-hash lookup retention uses `--execution.tx-indexer.tx-lookup-limit` (0 retains all blocks). Public gRPC/REST node APIs are **not documented** in the binaries guide. [S7], [S19]
- **Upgrades:** the support policy currently lists 3.12.x and 3.11.5, with **3.11.5 support ending 2026-10-28**; its 3.12.x row describes a 30-day support window. These are support dates, not inferred fork activation deadlines. Only active-mainnet ArbOS receives security updates; follow Foundation network-upgrade notices for required activation versions. A fixed release cadence is **not documented**. [S13]
- **Health:** `eth_syncing` returns `false` at head; compare latest blocks with a trusted independent view. With `--metrics`, Prometheus is at port **6070**, path `/debug/metrics/prometheus`; RPC responsiveness is liveness, not proof of synchronization. [S14], [S11]

## Validator

**Yes — permissionless rollup validation on Arbitrum One through BoLD**, distinct from the sequencer. The official chain table lists a **3,600 ETH-denominated assertion bond**, while the validator guide identifies the actual bonding token as **WETH**; challenges need additional bonds and L1 ETH for gas. Bond pooling is supported. The same admission assumptions must not be copied to other Nitro chains. [S1], [S15], [S16]

- **Registration:** configure an active staker strategy (`Defensive`, `ResolveNodes`, `MakeNodes`) and funded parent-chain wallet. Default `Watchtower` only detects/logs bad assertions, takes no onchain action and needs no wallet/bond. [S15]
- **Keys:** Nitro can create an encrypted wallet under `<chain-name>/wallet/` (One: `arb1/wallet/`); back it up to retain withdrawal ability. The guide supports private-key or password-based wallet configuration. The CLI reference exposes `--node.staker.data-poster.external-signer.url`, `.address`, `.method` (default `eth_signTransaction`) and TLS certificate options. Do not substitute the development-only `mockexternalsigner`. [S15], [S7], [S19]
- **Slashing/bond loss:** incorrect assertion/challenge participants can lose their entire bond; this is rollup dispute collateral, not Ethereum PoS double-sign slashing. Watchtower has no posted collateral. [S16], [S15]
- **Extra processes:** block validation uses WASM machines; the `-validator` image launches `nitro-val` alongside Nitro, or validation can be split to a separate JWT-authenticated server. That server holds no wallet/bond; onchain responsibility remains on the staker node. [S2], [S10]
- **Guide:** follow the official validator guide and BoLD economic rules; the default full-node recipe alone is not an active defensive validator. [S15], [S17]

## Pitfalls

- PathDB with block validation fails startup. Snapshot scheme must match; Nitro 3.12.1's source resolves path snapshots differently from the mutable guide's HashDB-only statement. [S9], [S20]
- Overriding the Docker entrypoint drops the default allowed-WASM-roots flags, which must be restored when validation requires them. [S2]
- Unsynced/offline nodes can require historical L1 blobs beyond standard retention. A parent RPC without the necessary history can stall recovery. [S6]
- The support matrix and chain-parameter page are mutable; recheck them before deployment instead of treating this dated map as an upgrade schedule. [S1], [S13]

## ERPC implementation

The follower backend now implements all twelve RPC lifecycle verbs for One, Nova
and Sepolia with reviewed OCI image digests, PathDB, private RPC/WS, concealed L1
transport and persistent ownership/operation fencing. It disables staker, block
validator, batch poster and sequencer roles. This is not active BoLD validation.
See [the operator guide](../nitro-rpc.md) for source qualification, recovery and
explicitly deferred real-host acceptance.

## Sources

[S1]: https://docs.arbitrum.io/chain-info "Network and bond table; read 2026-10-26"
[S2]: https://github.com/OffchainLabs/nitro/releases/tag/v3.12.1 "Stable release, image and validation entrypoint"
[S3]: https://github.com/OffchainLabs/nitro/blob/70fa99a6e711f09eedd96a907290c3df0f3bcf7d/LICENSE.md "Pinned BSL license"
[S4]: https://github.com/OffchainLabs/nitro/commit/70fa99a6e711f09eedd96a907290c3df0f3bcf7d "Resolved release commit"
[S5]: https://docs.arbitrum.io/run-a-node/nitro/build-nitro-locally "Supported build environments; read 2026-10-26"
[S6]: https://docs.arbitrum.io/run-a-node/start-here "Hardware and parent-chain requirements; read 2026-10-26"
[S7]: https://docs.arbitrum.io/run-a-node/nitro/docker-and-cli-binaries "Official Compose, image variants and ports; read 2026-10-26"
[S8]: https://docs.arbitrum.io/run-a-node/nitro/nitro-database-snapshots "Snapshot sources, integrity and Classic bootstrap; read 2026-10-26"
[S9]: https://docs.arbitrum.io/run-a-node/run-full-node "Node types, state schemes and snapshot sizes; read 2026-10-26"
[S10]: https://docs.arbitrum.io/run-a-node/assign-node-roles "Archive transitions and split validation; read 2026-10-26"
[S11]: https://docs.arbitrum.io/run-a-node/nitro/node-tuning-and-monitoring "Metrics, liveness and initial-sync guidance; read 2026-10-26"
[S12]: https://docs.arbitrum.io/run-a-node/overview "Public API exposure warning; read 2026-10-26"
[S13]: https://docs.arbitrum.io/run-a-node/nitro-support-policy "Support periods and upgrade-announcement source; read 2026-10-26"
[S14]: https://docs.arbitrum.io/run-a-node/faq "Sync checks and database handling; read 2026-10-26"
[S15]: https://docs.arbitrum.io/run-a-node/more-types/run-validator-node "Official validator setup, key storage and admission; read 2026-10-26"
[S16]: https://docs.arbitrum.io/how-arbitrum-works/bold/bold-faq "Permissionless One validation and bond loss; read 2026-10-26"
[S17]: https://docs.arbitrum.io/how-arbitrum-works/bold/bold-economics-of-disputes "Assertion and challenge economics; read 2026-10-26"
[S19]: https://docs.arbitrum.io/run-a-node/nitro/cli-flags-reference "Nitro CLI reference; read 2026-10-26"

[S20]: https://github.com/OffchainLabs/nitro/blob/70fa99a6e711f09eedd96a907290c3df0f3bcf7d/cmd/nitro/init/init.go "Pinned snapshot-kind mapping and database identity checks"
