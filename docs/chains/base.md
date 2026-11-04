<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Base

Researched 2026-10-26 against `base/base v1.5.1`; web documentation was read on that date and has no displayed revision date unless stated below. [S2]

## Networks

Base Mainnet: chain ID **8453**; Base Sepolia: **84532**, using ETH. The network directory distinguishes general RPC from transaction-submission endpoints. [S1]

## RPC node

- **Clients:** the current operator distribution is `base-reth-node` (execution) plus `base-consensus`, in the official `base/base` repository, MIT licensed. `base/node` is a historical repository; new installations and upgrades use `base/base`. [S3], [S4]
- **Latest stable release:** `v1.5.1`, published **2026-10-22**, resolved commit `5476069f1eb74a56bccb56fdefd4b4bb0e3cda42`. This is the non-prerelease release selected by GitHub's latest-release API, not an assertion about the version every network operator currently runs. [S2], [S5]
- **Release verification:** release archives have `.sha256` and detached `.asc` signatures. The pinned installer embeds the Base Releases public key; expected fingerprint **5EFE 7BCF CD85 6827 11F9 FC30 9048 41FF EBD3 8BAD**. `baseup` checks checksums and GPG signatures, and GitHub SLSA provenance when authenticated `gh` is available. Reproducible-build instructions are not documented in the installer guide. [S6], [S7]
- **Install:** prebuilt Linux x86-64/ARM64 and macOS ARM64 binaries via `baseup`, or the official Docker Compose image `ghcr.io/base/node` pinned with `NODE_TAG=v1.5.1`; source builds are supported. Minimum glibc and CPU instruction-set requirements are not documented in the release/installer guide. [S2], [S3], [S6]
- **Hardware:** read 2026-10-26: modern 8+ core CPU with good single-thread performance; 32 GB RAM minimum, 64 GB recommended; local NVMe. Capacity formula: twice current chain size plus snapshot size plus 20% buffer. Production archive example: i7i.12xlarge or larger, local NVMe RAID 0, ext4. Numeric bandwidth minimum is not documented. [S8]
- **Node types:** minimal snapshots retain current state and headers with minimum history; full snapshots retain a bounded history window; archive retains transactions, receipts and historical state. Custom pruning needs a sufficiently complete initial snapshot. [S9]
- **Initial sync:** official V2 segmented snapshots are restored with `base-reth-node download --chain base --full --datadir ./reth-data --resumable` (use `base-sepolia` or another documented preset as appropriate). The catalog on 2026-10-26 listed mainnet minimal **781.6 GB**, full **905.6 GB**, archive **4.3 TB**, archive plus proofs **5.1 TB**, at block 53,091,727; these are catalog estimates, not verified download measurements. Unsnapshotted sync can take days. No community snapshot is needed for this map. [S9], [S10], [S4]
- **Config:** official root Compose file and `.env.mainnet`/`.env.sepolia`; configure `BASE_NODE_L1_ETH_RPC` and `BASE_NODE_L1_BEACON` against synced Ethereum L1 services. `HOST_DATA_DIR` defaults to `./reth-data`, mounted at `/data`. Do not copy the example's shared JWT into an exposed Engine API. [S3], [S11], [S12]
- **Ports:** pinned Compose publishes execution HTTP **8545**, WS **8546**, metrics host **7301** → container **6060**; consensus RPC host **7545** → container **8545**, metrics **7300**, pprof **6060**. Peer ports **30303** and **9222** are TCP/UDP. Only peer connectivity is required publicly; retain RPC/metrics/pprof on trusted interfaces as an operator deployment choice. The guide additionally requires outbound bootnode traffic on UDP 9200 and TCP/UDP 30301. [S11], [S4]
- **APIs served:** Ethereum JSON-RPC and optional Flashblocks methods/subscriptions. Historical `eth_getProof`, `debug_executionWitness` and `debug_executePayload` support uses `RETH_HISTORICAL_PROOFS=true` and a separate proofs database. REST/gRPC service and a Bitcoin-style `txindex` switch are not documented in the operator guide. [S4]
- **Upgrades:** watch the release page and Base upgrade notices; a fixed release cadence is not documented. **Mainnet must upgrade to v1.5.1 by 2026-11-05 18:00 UTC for Denim**. Sepolia Denim was already activated. The overview's broader “November” planning date is less precise than this release deadline. [S2], [S13]
- **Health:** use `optimism_syncStatus` on consensus RPC and compare its unsafe timestamp with current time; check advancing blocks on execution RPC. The Compose metrics endpoints above are explicit; the metrics HTTP path is not documented in that file. [S4], [S11]

## Validator

**N/A for a public PoS validator role.** Base's operator distribution is a rollup follower, not a registration path into an independent staking consensus set. The current node guide does not document public sequencer admission, minimum validator stake, validator signing keys, remote signing, or slashing rules. Do not equate running `base-consensus` with becoming the sequencer. Azul instead has permissioned TEE provers (enclave-held signing keys), permissionless ZK provers and challengers. An invalid TEE proposal can lose its bond to a successful ZK challenge; a fixed public bond amount and turnkey external signer setup are not documented in that specification. [S3], [S4], [S14]

## Pitfalls

- Snapshot documentation and the pinned release disagree on the `--full` retention window: the guide still states 10,064 blocks, while v1.5.1's configuration states 13,392,000 blocks for Denim. Neither setting restores history absent from a downloaded snapshot; verify the snapshot before choosing retention. [S9], [S12]
- V1-to-V2 storage migration is required; in-place migration is archive-only and slower than a fresh V2 snapshot. A download interrupted by newly published snapshot files can be resumed by rerunning the command. [S9]
- Denim replaces Flashblocks with native 200 ms blocks; reassess Flashblocks-specific consumers for each network's activation rather than blindly following the older node tutorial. [S13]

## ERPC implementation

The follower RPC backend implements all twelve lifecycle verbs, sealed persistent
peer identities, operation-bound firewall confirmation and guarded bootstrap recovery.
It does not activate a sequencer or challenger. See [the operations guide](../op-follower-rpc.md)
for exact qualified clients, identity/capacity boundaries and deferred live acceptance.

## Sources

[S1]: https://docs.base.org/get-started/connect-to-base "Network IDs; read 2026-10-26"
[S2]: https://github.com/base/base/releases/tag/v1.5.1 "Stable release, assets and mandatory Denim deadline"
[S3]: https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/README.md "Pinned official repository, install and license summary"
[S4]: https://docs.base.org/specifications/node-operators/run-a-node "Operator guide; read 2026-10-26"
[S5]: https://github.com/base/base/commit/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42 "Resolved v1.5.1 commit"
[S6]: https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/baseup/README.md "Pinned verification and target documentation"
[S7]: https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/baseup/baseup "Pinned installer with embedded public signing key"
[S8]: https://docs.base.org/specifications/node-operators/performance-tuning "Hardware guidance; read 2026-10-26"
[S9]: https://docs.base.org/specifications/node-operators/snapshots "V2 snapshot and retention guidance; read 2026-10-26"
[S10]: https://chain.base.org/snapshots "Official snapshot catalog linked by the operator guide"
[S11]: https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/docker-compose.yml "Pinned official Compose ports and volumes"
[S12]: https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/.env.mainnet "Pinned network configuration and retention caveat"
[S13]: https://docs.base.org/upgrades/denim/overview "Denim overview; read 2026-10-26"
[S14]: https://docs.base.org/upgrades/azul/proofs "Base proof-system role; read 2026-10-26"
