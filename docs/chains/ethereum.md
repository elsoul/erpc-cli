<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Ethereum

Researched 2026-10-26 against Reth v2.8.1 and Lighthouse v8.3.2, with the alternative-client release inventory below. Web pages were read on that date; client sources are pinned. [C1b], [C7b]

## Networks

Mainnet chain ID **1**; Sepolia **11155111** (application testing); Hoodi **560048** (validator/infrastructure testing). The networks page identifies supported test networks; Reth and Hoodi's configuration repository supply identifiers. Network support in an executable is not an assurance that an obsolete testnet is maintained. [S1], [S2], [S3]

## RPC node

### Clients, licenses and latest stable release pins

Ethereum has multiple peer implementations rather than a single reference executable. A current node needs **one execution client (EL) plus one consensus client (CL)**. The operational example here is Reth + Lighthouse, matching ERPC; the other implementations are mapped for future deployment work. [S4], [R1]

These are the latest non-prerelease releases returned by each project's GitHub release API on the research date. The sources column links repository, release, release history and license respectively. Component licenses/notices still apply. [C1b], [C2b], [C3b], [C4b], [C5b], [C6b], [C7b], [C8b], [C9b], [C10b], [C11b], [C12b]

| Client | Stable tag; publication date (UTC) | Resolved commit | License | Sources |
|---|---|---|---|---|
| Reth (EL) | `v2.8.1`; 2026-10-23 | `d763342fa185e4e90ee79dc65f6a5706168b0bcb` | Apache-2.0 / MIT | [C1a], [C1b], [C1c], [C1d] |
| Geth (EL) | `v1.17.10`; 2026-10-23 | `1df30b18d9ed35ee9d28ffd4648442c2204554ad` | LGPL-3.0 library; GPL-3.0 tools | [C2a], [C2b], [C2c], [C2d] |
| Nethermind (EL) | `2.2.1`; 2026-10-22 | `c4f1015be8b989dd609803cc50d3928d6e0dfd4f` | LGPL-3.0 | [C3a], [C3b], [C3c], [C3d] |
| Besu (EL) | `26.10.1`; 2026-10-22 | `e83703cdf863093b98ebe1d8719cd77cdf8639d8` | Apache-2.0 | [C4a], [C4b], [C4c], [C4d] |
| Erigon (EL) | `v3.8.1`; 2026-10-23 | `cf6f14132ff042df33b8ce64b0114daeb0d15145` | LGPL-3.0 (see component COPYING files) | [C5a], [C5b], [C5c], [C5d] |
| ethrex (EL) | `v30.0.1`; 2026-10-23 | `391a2cdefee0e77184ff7d7fae5bf0abc34bd42c` | Apache-2.0 / MIT | [C6a], [C6b], [C6c], [C6d] |
| Lighthouse (CL) | `v8.3.2`; 2026-10-23 | `a376defa30470923556d91bdeb15a802e297f31f` | Apache-2.0 | [C7a], [C7b], [C7c], [C7d] |
| Lodestar (CL) | `v1.50.1`; 2026-10-22 | `56cf1ab7b16a2805a985e104f2e7fcbaad98a22b` | Apache-2.0 in pinned LICENSE | [C8a], [C8b], [C8c], [C8d] |
| Nimbus (CL) | `v26.10.2`; 2026-10-23 | `0abc0dd0fc0750a8875c49089d074f7d7197b62c` | Apache-2.0 / MIT | [C9a], [C9b], [C9c], [C9d] |
| Prysm (CL) | `v7.3.1`; 2026-10-22 | `96d418cd964b083e37519a9df274030a1beac7db` | GPL-3.0 | [C10a], [C10b], [C10c], [C10d] |
| Teku (CL) | `26.10.2`; 2026-10-22 | `3369f5d094a4b50d1311ba2738525806b043e1af` | Apache-2.0 | [C11a], [C11b], [C11c], [C11d] |
| Grandine (CL) | `2.0.6`; 2026-08-03 | `70a5c7ea6fbf07c22ecea09b7cdd71c3af93cbb0` | GPL-3.0 | [C12a], [C12b], [C12c], [C12d] |

**Network qualification:** Grandine's stable 2.0.6 is not the Hoodi cancellation release: EF names **v3.0.0-rc.2** for that network. “Latest stable” is not a universal network recommendation. Ethereum.org's client table has older license labels for some clients; the pinned license files above are used here. [S5], [S4], [C8d], [C12b]

### Verification and installation

- **Reth:** release `.asc` signatures and GitHub asset SHA-256 digests; signing fingerprint `50FB7CC55B2E8AFA59FE03B7AA5ED56A7FBF253E`, with the public key on the binary-install page. The v2.8.1 assets target Linux x86-64/ARM64 and macOS ARM64. The release workflow targets `x86-64-v3` plus `pclmulqdq` on Ubuntu 24.04. A glibc minimum is **not documented in the selected release notes**; ERPC separately checks 2.38 and Ubuntu 24.04+. Source and Docker installation are also available. [C1b], [S6], [S7], [R1]
- **Lighthouse:** release `.asc` signatures use Sigma Prime fingerprint `15E66D941F697E28F49381F426416DC3F30674B0`; GitHub also publishes asset SHA-256 digests. The release supplies Linux x86-64/ARM64 and macOS ARM64 binaries and Docker images. Source builds default to runtime CPU-feature detection (`portable`). A numeric glibc minimum is **not documented** in the reviewed installation sources. Windows is not officially supported by the binary guide. [C7b], [S8], [S9]
The alternative-client packaging map below is based on the pinned READMEs and release assets. Unless a row says otherwise, a numerical glibc floor, CPU flag baseline and release-signing fingerprint are **not documented in those cited sources**; this does not establish that no verification procedure exists elsewhere. The detailed operational flags below remain specific to Reth + Lighthouse.

| Alternative | Install/platform and verification evidence |
|---|---|
| Geth | Official downloads, Docker, packages or Go 1.25+ source build; release page links platform installers. No assets are attached to the GitHub release itself; verify the separately hosted download using its published signature/checksum procedure. [C2a], [C2b] |
| Nethermind | ZIP binaries for Linux x64/ARM64, macOS x64/ARM64 and Windows x64; Docker/packages or .NET 10+ source build. Archives have detached `.asc` signatures and GitHub SHA-256 digests. [C3a], [C3b] |
| Besu | Java client with tar/ZIP distributions and source-build instructions; release supplies `.sha256` sidecars and printed hashes. Detached release signature: **none** among the selected assets. [C4a], [C4b] |
| Erigon | Linux amd64/ARM64 archives and DEB packages; README also maps Docker, macOS and Windows builds. Source baseline is x86-64-v2 (SSE4.2/POPCNT), Go 1.26+, GCC 11+/Clang 13+. Release has a checksum manifest. [C5a], [C5b] |
| ethrex | Separate L1 and L2 binaries; L1 assets include Linux x86-64/ARM64 and macOS ARM64 with GitHub SHA-256 digests. The `.minisig` files in this release sign stateless-validator proof artifacts, not the ordinary L1 node binary. [C6b] |
| Lodestar | Linux amd64/ARM64 archives and Docker; release requires Node.js 24.22.1+ for source users and bundles it in distributed binaries/images. Asset digests are present; detached release signatures: **none** in these assets. [C8a], [C8b] |
| Nimbus | Linux amd64/ARM64/ARM32, macOS ARM64 and Windows amd64 archives plus Linux packages, with GitHub SHA-256 digests. Detached signatures: **none** in these assets. [C9b] |
| Prysm | Separate beacon/validator binaries for Linux, macOS and Windows, with `.sha256` and `.sig` files. Pinned installer verifies GPG fingerprint `0AE0051D647BA3C1A917AF4072E33E4DF1A5036E`; retain verification rather than its bypass option. [C10b], [S27] |
| Teku | Java 25+ source/Gradle build, tar/ZIP releases and Docker. Selected release publishes `.sha256` sidecars; detached signatures: **none** in those assets. [C11a], [C11b] |
| Grandine | Rust source/Docker builds; stable release assets cover Linux/macOS x64/ARM64 and Windows x64, with GitHub digests. Detached signatures: **none** in that stable release. Hoodi still needs the network-specific candidate described above. [C12a], [C12b], [S5] |

The shared upstream setup index links each client's full installation guide. [S10]

### Resources, synchronization and operation

- **Hardware (read 2026-10-26):** Reth's dated **2025-06-23** mainnet baseline is full 1.2 TB TLC NVMe / 8 GB+ RAM, archive 2.8 TB / 16 GB+, stable 24 Mbps+, favoring CPU clock speed without a core-count minimum. It is an EL-only historical baseline, not a current combined-node capacity promise. ERPC's combined host policy is 32 GB and Ubuntu 24.04+, with separate CL disk. [S11], [R1]
- **Node types:** Reth archive is default without pruning configuration; full keeps current state plus a 10,064-block state/receipt window and prunes pre-Merge bodies; minimal prunes more aggressively. Pruning can break old receipts, logs, tracing and state queries; changing flags cannot recover removed data. [S12]
- **Initial sync:** Reth publishes official modular snapshots with minimal/full/archive profiles through `reth download`; size depends on selected components and published block, and the snapshot UI lists current estimates. A fixed October 26 size or sync duration is **not documented** on the guide. Lighthouse checkpoint-syncs from a trusted finalized checkpoint, then backfills; Reth's paired-node guide uses Sigma Prime's checkpoint service. Community alternatives are linked by that guide, not vouched for here. [S13], [S14], [S15]
- **Config/service:** use a shared Engine JWT, matching `--chain`/`--network`, explicit datadirs, and the intended pruning profile. Reth's Linux default is under `~/.local/share/reth`; Lighthouse uses `~/.lighthouse/<network>`. The pinned upstream Compose example and ERPC's separate systemd units are linked below. [S15], [S16], [S17], [S26], [R2]
- **Ports:** Reth P2P TCP/discv4 UDP 30303 (discv5 has separate configurable port 9200); HTTP 8545 and WS 8546 only when enabled; JWT Engine 8551 stays private. Lighthouse P2P TCP/UDP 9000 and QUIC UDP 9001 should be reachable for peering. Beacon REST 5052 and metrics need not be public. [S16], [S18], [S19]
- **APIs:** Reth `--http`/`--ws` enable transport; `--http.api`/`--ws.api` select `eth`, `net`, `web3`, `debug`, `trace` and other namespaces. Retention constrains what those APIs can answer. Lighthouse exposes Beacon REST with `--http`; a native gRPC service is **not documented** in these selected client API guides. [S12], [S15], [S19]
- **Upgrades:** monitor client releases and EF protocol announcements; there is no single fixed release cadence across clients. **Hoodi operators must remove the cancelled Glamsterdam schedule before 2026-10-26 17:42:48 UTC**: Reth v2.8.1 and Lighthouse v8.3.2 do so. Update the beacon node, validator client and EL as applicable. A replacement activation date is **not yet documented** by EF. [C1b], [C7b], [S5]
- **Health:** combine EL `eth_syncing`, advancing/recent head and peer checks with Beacon `/eth/v1/node/syncing` and `/eth/v1/node/health`; check execution optimism as well as CL sync. Reth metrics require an explicit `--metrics` bind address; Lighthouse `--metrics` serves BN port 5054 and VC port 5064 at `/metrics`. ERPC's status path checks both layers. [S16], [S19], [S20], [S21], [R3]

## Validator

**Yes, permissionless on mainnet.** Minimum activation stake is **32 ETH**. The official Lighthouse guide covers generating deposit data, running a synced EL and beacon node, importing signing keystores, starting `lighthouse vc`, and submitting the deposit through the staking launchpad. Sepolia validator admission is restricted; Hoodi is the public staking test network. [S1], [S22]

- **Keys:** validator signing keys are encrypted EIP-2335 keystores; Lighthouse stores definitions under `~/.lighthouse/<network>/validators`, with separate password-file options. Withdrawal authority/recovery material must be kept separate from online validator operation. Web3Signer is a documented remote-signing option. [S17], [S22], [S23]
- **Slashing:** double proposal, double vote and surround vote are slashable. Ordinary missed duties have penalties distinct from slashing. Preserve and migrate slashing history with keys; two concurrently running copies on different machines are not protected by one local database. [S24], [S25]
- **Extra processes:** a validator client is additional to the EL + beacon node; a remote signer is optional. MEV/builder services are not required by the basic validator guide. [S22], [S23]

## Pitfalls

- The older Hoodi Glamsterdam activation announcement is superseded by the October 22 postponement. A client with the old schedule can fork away at the cancelled activation time. [S5], [C1b]
- Reth alone does not follow the post-Merge canonical head; an authenticated, working CL connection is required. [S15]
- Archive answers cannot be promised after pruning or restoration from a pruned snapshot. [S12]
- Never expose the Beacon API or Engine API as an unrestricted public RPC service; never start duplicate signing keys during migration. [S19], [S25]

## ERPC today

**RPC implemented; validator backend implemented with live acceptance deferred.** The RPC path still runs mainnet Reth plus Lighthouse BN. The separate `erpc v --chain eth` path owns a dedicated EL/BN/VC host on Hoodi or mainnet, imports a new encrypted keystore with matching history, fences managed migrations, and reviews public deposit data without broadcasting. Alternate-client backends and testnet RPC remain outside the RPC path. [R1], [R2], [R3], [R5], [R6], [R8]

Offline validation and the deferred Hoodi/mainnet real-host acceptance are described in the [validator guide][R8].

## Sources

[C1a]: https://github.com/paradigmxyz/reth/tree/d763342fa185e4e90ee79dc65f6a5706168b0bcb "Reth source repository at release commit"
[C1b]: https://github.com/paradigmxyz/reth/releases/tag/v2.8.1 "Reth release and assets"
[C1c]: https://github.com/paradigmxyz/reth/releases "Reth release history"
[C1d]: https://github.com/paradigmxyz/reth/blob/d763342fa185e4e90ee79dc65f6a5706168b0bcb/LICENSE-APACHE "Reth license"
[C2a]: https://github.com/ethereum/go-ethereum/tree/1df30b18d9ed35ee9d28ffd4648442c2204554ad "Geth source repository at release commit"
[C2b]: https://github.com/ethereum/go-ethereum/releases/tag/v1.17.10 "Geth release and assets"
[C2c]: https://github.com/ethereum/go-ethereum/releases "Geth release history"
[C2d]: https://github.com/ethereum/go-ethereum/blob/1df30b18d9ed35ee9d28ffd4648442c2204554ad/COPYING "Geth license"
[C3a]: https://github.com/NethermindEth/nethermind/tree/c4f1015be8b989dd609803cc50d3928d6e0dfd4f "Nethermind source repository at release commit"
[C3b]: https://github.com/NethermindEth/nethermind/releases/tag/2.2.1 "Nethermind release and assets"
[C3c]: https://github.com/NethermindEth/nethermind/releases "Nethermind release history"
[C3d]: https://github.com/NethermindEth/nethermind/blob/c4f1015be8b989dd609803cc50d3928d6e0dfd4f/LICENSE-LGPL "Nethermind license"
[C4a]: https://github.com/besu-eth/besu/tree/e83703cdf863093b98ebe1d8719cd77cdf8639d8 "Besu source repository at release commit"
[C4b]: https://github.com/besu-eth/besu/releases/tag/26.10.1 "Besu release and assets"
[C4c]: https://github.com/besu-eth/besu/releases "Besu release history"
[C4d]: https://github.com/besu-eth/besu/blob/e83703cdf863093b98ebe1d8719cd77cdf8639d8/LICENSE "Besu license"
[C5a]: https://github.com/erigontech/erigon/tree/cf6f14132ff042df33b8ce64b0114daeb0d15145 "Erigon source repository at release commit"
[C5b]: https://github.com/erigontech/erigon/releases/tag/v3.8.1 "Erigon release and assets"
[C5c]: https://github.com/erigontech/erigon/releases "Erigon release history"
[C5d]: https://github.com/erigontech/erigon/blob/cf6f14132ff042df33b8ce64b0114daeb0d15145/COPYING "Erigon license"
[C6a]: https://github.com/lambdaclass/ethrex/tree/391a2cdefee0e77184ff7d7fae5bf0abc34bd42c "ethrex source repository at release commit"
[C6b]: https://github.com/lambdaclass/ethrex/releases/tag/v30.0.1 "ethrex release and assets"
[C6c]: https://github.com/lambdaclass/ethrex/releases "ethrex release history"
[C6d]: https://github.com/lambdaclass/ethrex/blob/391a2cdefee0e77184ff7d7fae5bf0abc34bd42c/LICENSE-APACHE "ethrex license"
[C7a]: https://github.com/sigp/lighthouse/tree/a376defa30470923556d91bdeb15a802e297f31f "Lighthouse source repository at release commit"
[C7b]: https://github.com/sigp/lighthouse/releases/tag/v8.3.2 "Lighthouse release and assets"
[C7c]: https://github.com/sigp/lighthouse/releases "Lighthouse release history"
[C7d]: https://github.com/sigp/lighthouse/blob/a376defa30470923556d91bdeb15a802e297f31f/LICENSE "Lighthouse license"
[C8a]: https://github.com/ChainSafe/lodestar/tree/56cf1ab7b16a2805a985e104f2e7fcbaad98a22b "Lodestar source repository at release commit"
[C8b]: https://github.com/ChainSafe/lodestar/releases/tag/v1.50.1 "Lodestar release and assets"
[C8c]: https://github.com/ChainSafe/lodestar/releases "Lodestar release history"
[C8d]: https://github.com/ChainSafe/lodestar/blob/56cf1ab7b16a2805a985e104f2e7fcbaad98a22b/LICENSE "Lodestar license"
[C9a]: https://github.com/status-im/nimbus-eth2/tree/0abc0dd0fc0750a8875c49089d074f7d7197b62c "Nimbus source repository at release commit"
[C9b]: https://github.com/status-im/nimbus-eth2/releases/tag/v26.10.2 "Nimbus release and assets"
[C9c]: https://github.com/status-im/nimbus-eth2/releases "Nimbus release history"
[C9d]: https://github.com/status-im/nimbus-eth2/blob/0abc0dd0fc0750a8875c49089d074f7d7197b62c/LICENSE-APACHEv2 "Nimbus license"
[C10a]: https://github.com/OffchainLabs/prysm/tree/96d418cd964b083e37519a9df274030a1beac7db "Prysm source repository at release commit"
[C10b]: https://github.com/OffchainLabs/prysm/releases/tag/v7.3.1 "Prysm release and assets"
[C10c]: https://github.com/OffchainLabs/prysm/releases "Prysm release history"
[C10d]: https://github.com/OffchainLabs/prysm/blob/96d418cd964b083e37519a9df274030a1beac7db/LICENSE.md "Prysm license"
[C11a]: https://github.com/Consensys/teku/tree/3369f5d094a4b50d1311ba2738525806b043e1af "Teku source repository at release commit"
[C11b]: https://github.com/Consensys-Incorporated/teku/releases/tag/26.10.2 "Teku release and assets"
[C11c]: https://github.com/Consensys/teku/releases "Teku release history"
[C11d]: https://github.com/Consensys/teku/blob/3369f5d094a4b50d1311ba2738525806b043e1af/LICENSE "Teku license"
[C12a]: https://github.com/grandinetech/grandine/tree/70a5c7ea6fbf07c22ecea09b7cdd71c3af93cbb0 "Grandine source repository at release commit"
[C12b]: https://github.com/grandinetech/grandine/releases/tag/2.0.6 "Grandine release and assets"
[C12c]: https://github.com/grandinetech/grandine/releases "Grandine release history"
[C12d]: https://github.com/grandinetech/grandine/blob/70a5c7ea6fbf07c22ecea09b7cdd71c3af93cbb0/LICENSE.md "Grandine license"
[S1]: https://ethereum.org/developers/docs/networks/ "Network roles and testnet validator admission; read 2026-10-26"
[S2]: https://reth.rs/run/overview/ "Mainnet/Sepolia identifiers; read 2026-10-26"
[S3]: https://github.com/eth-clients/hoodi "Hoodi network identifier; read 2026-10-26"
[S4]: https://ethereum.org/developers/docs/nodes-and-clients "EL/CL inventory and client documentation index; read 2026-10-26"
[S5]: https://blog.ethereum.org/2026/10/22/glamsterdam-hoodi-delay "EF postponement, dated 2026-10-22; read 2026-10-26"
[S6]: https://reth.rs/installation/binaries/ "Reth signing key and binary verification; read 2026-10-26"
[S7]: https://github.com/paradigmxyz/reth/blob/d763342fa185e4e90ee79dc65f6a5706168b0bcb/.github/workflows/release.yml "Pinned Reth CPU target and build platform"
[S8]: https://lighthouse-book.sigmaprime.io/installation_binaries.html "Lighthouse binary platforms; read 2026-10-26"
[S9]: https://github.com/sigp/lighthouse/blob/a376defa30470923556d91bdeb15a802e297f31f/book/src/installation_source.md "Pinned source-build and portable CPU configuration"
[S10]: https://ethereum.org/developers/docs/nodes-and-clients/run-a-node "Installation and operational guide index; read 2026-10-26"
[S11]: https://reth.rs/run/system-requirements/ "Hardware baseline dated 2025-06-23; read 2026-10-26"
[S12]: https://reth.rs/run/storage/pruning/ "v2.8.1 profiles and API retention; read 2026-10-26"
[S13]: https://reth.rs/run/storage/snapshots/ "Official modular snapshots and size discovery; read 2026-10-26"
[S14]: https://github.com/sigp/lighthouse/blob/a376defa30470923556d91bdeb15a802e297f31f/book/src/advanced_checkpoint_sync.md "Pinned checkpoint trust and backfill guide"
[S15]: https://reth.rs/run/ethereum/ "EL/CL connection, JWT and checkpoint example; read 2026-10-26"
[S16]: https://reth.rs/cli/reth/node/ "Reth datadir, ports, namespaces and metrics flags; read 2026-10-26"
[S17]: https://lighthouse-book.sigmaprime.io/validator_management.html "Datadirs, encrypted keystores and password files; read 2026-10-26"
[S18]: https://lighthouse-book.sigmaprime.io/advanced_networking.html "Lighthouse public P2P ports; read 2026-10-26"
[S19]: https://lighthouse-book.sigmaprime.io/api_bn.html "Beacon REST API and access restrictions; read 2026-10-26"
[S20]: https://github.com/ethereum/beacon-APIs "Standard node sync/health endpoint schemas; read 2026-10-26"
[S21]: https://github.com/sigp/lighthouse/blob/a376defa30470923556d91bdeb15a802e297f31f/book/src/api_metrics.md "Pinned BN and VC metric endpoints"
[S22]: https://lighthouse-book.sigmaprime.io/mainnet_validator.html "Official validator guide and minimum stake; read 2026-10-26"
[S23]: https://github.com/sigp/lighthouse/blob/a376defa30470923556d91bdeb15a802e297f31f/book/src/advanced_web3signer.md "Remote signer and slashing protection"
[S24]: https://ethereum.org/developers/docs/consensus-mechanisms/pos/rewards-and-penalties/ "Slashing conditions; page updated 2026-09-28, read 2026-10-26"
[S25]: https://lighthouse-book.sigmaprime.io/validator_slashing_protection.html "Slashing database and migration rules; read 2026-10-26"
[S26]: https://github.com/paradigmxyz/reth/blob/d763342fa185e4e90ee79dc65f6a5706168b0bcb/etc/docker-compose.yml "Official pinned Compose example"
[R1]: ../../crates/erpc-skills/skills/ethereum-node/SKILL.md "Existing ERPC mainnet RPC scope and host checks"
[R2]: ../../crates/erpc-chain-eth/templates/ "Existing Reth and Lighthouse systemd units and plays"
[R3]: ../../crates/erpc-chain-eth/src/ "Existing release pinning and both-layer status checks"

[S27]: https://github.com/OffchainLabs/prysm/blob/96d418cd964b083e37519a9df274030a1beac7db/prysm.sh "Pinned Prysm signing fingerprint and verification procedure"

[R5]: ../../crates/erpc-core/src/chain.rs "Current Ethereum RPC and validator role registry"
[R6]: ../../crates/erpc/src/tree.rs "Current role-specific dispatch"

[R8]: ../ethereum-validator.md "Dedicated Ethereum validator lifecycle and deferred live acceptance"
