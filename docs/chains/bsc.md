<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# BNB Smart Chain

Researched 2026-10-26 against BSC Geth **v1.8.1**, with **v1.7.8** the latest
release explicitly addressed to mainnet and testnet users, and Reth-BSC
**v0.1.3**. Documentation below was read on 2026-10-26. [S1], [S2], [S3]

## Networks

BNB Smart Chain mainnet ID is **56**; Chapel testnet ID is **97**. These
are BSC networks, not opBNB or the retired Beacon Chain. [S4]

## RPC node

- **Clients:** reference Go client `bnb-chain/bsc` (library LGPL-3.0,
  command/binary GPL-3.0); alternative `bnb-chain/reth-bsc` (MIT), built on
  Reth. Legacy `node-real/bsc-erigon` (LGPL-3.0 repository) announced end of
  maintenance after 2025-12-31 and recommends migration to Reth-BSC; do not
  treat the older full-node page's Erigon recommendation as current support. [S5], [S6], [S7], [S8], [S16]
- **Latest stable release pins:** Geth `v1.8.1`, commit
  `947ba1cb1ef05d4a5f71b738113a3d8b4c16f6b7`, published 2026-10-16;
  Geth `v1.7.8`, commit `cdb7548b5baacfdae92f9f63437d6456411665f3`,
  published 2026-08-11. Reth-BSC `v0.1.3`, commit
  `f0b444ffa133dab7690fed834a42986a5aad1dbf`, published 2026-10-16.
  Legacy Erigon's last listed release is `v1.4.3`, commit
  `b00927fed86a4d6d24070b599c1efcb50daf5125`, published 2025-12-09.
  The two latest actively developed releases target Chapel's Jenner fork,
  not a scheduled mainnet activation. [S1], [S2], [S3], [S9]
- **Verification:** Geth release notes publish SHA-256 checksums for binaries
  and network ZIPs. Detached GPG signatures, a signing fingerprint and a
  reproducible-build check are **not documented** in those notes. Reth-BSC's
  release/README likewise do not document a GPG verification procedure. [S1], [S2], [S3], [S6]
- **Install:** Geth supports Linux, macOS and Windows, with prebuilt release
  assets and source builds. Download the matching network's genesis/config
  ZIP. Reth-BSC supports source builds with Cargo or Make. A portable glibc
  floor and minimum CPU flags are **not documented** by these install guides;
  `make maxperf` is specifically recommended for Reth-BSC mainnet sync. [S5], [S8], [S6]
- **Hardware, read 2026-10-26:** the BSC best-practices page lists full node
  16 cores, 64 GB RAM, 3 TB SSD and 5 MB/s network; archive 16 cores,
  128 GB RAM and 10 TB SSD. These storage figures conflict with newer snapshot
  and client guidance: Reth-BSC sync recommends 24 vCPUs, 192 GiB RAM, local
  NVMe, 8 TB+ full or 20 TB+ archive, with RPC disabled during catch-up.
  Size from the selected current dataset, not the older generic minimum. [S10], [S6], [S11]
- **Node types:** Geth full nodes validate current state; fast mode disables
  trie verification and changes the trust/performance trade-off. Pruned
  snapshots omit old block history. Reth-BSC `--full` retains recent state;
  default archive mode retains complete history/state and is required by its
  trace API guidance. [S8], [S11], [S6]
- **Initial sync:** official `bnb-chain/bsc-snapshots` catalog has Geth full
  mainnet snapshot 2026-10-09 at about **7.4 TB compressed**, or **1.9 TB**
  pruned; Chapel 2026-09-17 about **520 GB / 180 GB**. Extracted data needs
  additional room. Catalog scripts verify MD5, not signed provenance.
  The catalog also links explicitly community-provided BNB48Club snapshots
  and official Reth-BSC datasets. Geth's guide recommends snapshots; Reth-BSC
  says genesis sync can take weeks. A guaranteed snapshot sync time is
  **not documented**. [S11], [S8], [S6]
- **Config:** Geth uses the release's `config.toml`, matching `genesis.json`
  and explicit `--datadir`; Reth-BSC selects `--chain bsc` or
  `--chain bsc-testnet`. The snapshot guide shows recent-history retention
  through `--history.blocks`, `--history.transactions` and `--history.logs`;
  zero transaction retention limit means retaining the whole index in the
  Geth full-node example. An official systemd/compose unit is **not documented**
  in these particular full-node guides. [S8], [S11], [S6]
- **Ports/APIs:** Geth default P2P port 30303; HTTP 8545 and WS 8546 require
  explicit enabling/module selection. Reth-BSC lists `eth`, `net`, `web3`,
  `txpool`, `debug`, `trace` and `admin`; choose modules using `--http.api`
  and `--ws.api`. Its metrics example uses 6060 `/metrics`. Geth v1.8.1 adds
  optional MEV builder gRPC on 8552, not a generic public RPC service.
  Validator HTTP RPC must not be public; P2P can be direct or sentry-mediated. [S5], [S6], [S12], [S1], [S13]
- **Upgrades:** Chapel operators must install the Jenner-compatible release
  before **2026-10-29 02:30 UTC**. Mainnet activation is not scheduled in
  v1.8.1. Read the audience and mandatory-update fields on GitHub releases;
  a fixed release cadence is **not documented**. The `v1.8.0-alpha` notes
  explicitly describe a preview not intended for production, regardless of
  its GitHub prerelease metadata. [S1], [S3], [S14]
- **Health:** check `eth_syncing`, advancing `eth_blockNumber`, and logs.
  Reth-BSC exposes Prometheus when `--metrics` is configured; Geth uses
  `--metrics.addr`/`--metrics.port` for the standalone server, with the address
  required to start it. [S6], [S12]

## Validator

- **Participation:** public StakeHub registration, with at least **2,000 BNB**
  self-delegated; the creation form requires **2,001 BNB**, including 1 BNB
  locked to a dead address, plus transaction fees. Registration does not
  guarantee election: stake ranking selects the active set. [S4]
- **Keys:** separate operator, consensus and BLS vote identities; the create
  guide covers encrypted consensus accounts, BLS wallets under the chosen
  data directory and proof-of-possession. Start Geth with mining and voting
  enabled and separate account/BLS password files. Remote signing is **not
  documented** in the inspected creation/run guides. [S4], [S15]
- **Slashing:** the validator overview specifies malicious voting (including
  concurrently running the same consensus/BLS keys), downtime and insufficient
  self-delegation penalties. It lists 200 BNB/30-day jail for malicious votes,
  and 10 BNB/two-day jail after more than 150 missed blocks in 24 hours;
  these are documentation values, not live contract queries. [S13]
- **Processes/hardware:** reference validator path is Geth plus optional
  sentries. The run guide specifies mainnet 128 GB RAM, 7 TB NVMe,
  40k IOPS, 500 MB/s disk throughput and at least 512 Mbps networking, with
  compute meeting its 400 mgasps target. Reth-BSC README still marks validator
  support as unavailable while newer release notes discuss mining/MEV changes;
  do not infer production validator readiness from those changes. [S15], [S6], [S3]
- **Official guides:** Create BSC Validator and Run BSC Validator are the
  registration/key and operational entry points. [S4], [S15]

## Pitfalls

- Latest release does not mean latest mainnet target. v1.8.1's `prevRandao`
  override validation changes apply immediately, before Jenner activation. [S1]
- A pruned snapshot cannot serve deleted historical requests; deprecated
  `--pruneancient` is not needed with current retention flags. [S11]
- Generic hardware, old Erigon advice and Reth-BSC's dated validator-status
  section disagree with newer material. Keep those limitations visible when
  implementing deployment support. [S10], [S7], [S6], [S3]

## Sources

[S1]: https://github.com/bnb-chain/bsc/releases/tag/v1.8.1 "Geth release, 2026-10-16; Chapel deadline, checksums and API changes"
[S2]: https://github.com/bnb-chain/bsc/releases/tag/v1.7.8 "Latest explicitly mainnet/testnet maintenance release, 2026-08-11"
[S3]: https://github.com/bnb-chain/reth-bsc/releases/tag/v0.1.3 "Reth-BSC release, 2026-10-16; Chapel upgrade"
[S4]: https://docs.bnbchain.org/bnb-smart-chain/validator/create-val/ "Network IDs, stake, registration and key creation; read 2026-10-26"
[S5]: https://github.com/bnb-chain/bsc/blob/947ba1cb1ef05d4a5f71b738113a3d8b4c16f6b7/README.md "Pinned reference-client README, license and RPC flags"
[S6]: https://github.com/bnb-chain/reth-bsc "Alternative client README, hardware, APIs, sync and validator caveat; read 2026-10-26"
[S7]: https://github.com/node-real/bsc-erigon "Maintainer end-of-life notice and LGPL-3.0 license; read 2026-10-26"
[S8]: https://docs.bnbchain.org/bnb-smart-chain/developers/node_operators/full_node/ "Full/fast node behavior and install; read 2026-10-26"
[S9]: https://github.com/node-real/bsc-erigon/releases/tag/v1.4.3 "Last legacy release, 2025-12-09; commit b00927fed86a4d6d24070b599c1efcb50daf5125"
[S10]: https://docs.bnbchain.org/bnb-smart-chain/developers/node_operators/node_best_practices/ "Generic hardware guidance, contrasted with current snapshot sizes; read 2026-10-26"
[S11]: https://github.com/bnb-chain/bsc-snapshots "Official catalog, dated sizes, checksums, retention and community links; read 2026-10-26"
[S12]: https://github.com/bnb-chain/bsc/blob/947ba1cb1ef05d4a5f71b738113a3d8b4c16f6b7/cmd/utils/flags.go "Pinned P2P and metrics flag definitions"
[S13]: https://docs.bnbchain.org/bnb-smart-chain/validator/overview/ "Topology, election and slashing; read 2026-10-26"
[S14]: https://github.com/bnb-chain/bsc/releases/tag/v1.8.0-alpha "Explicit nonproduction preview warning, 2026-08-13"
[S15]: https://docs.bnbchain.org/bnb-smart-chain/validator/run-val/ "Validator processes, keys and hardware; read 2026-10-26"
[S16]: https://github.com/bnb-chain/reth-bsc/blob/f0b444ffa133dab7690fed834a42986a5aad1dbf/LICENSE "Pinned Reth-BSC MIT license"
