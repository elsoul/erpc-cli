<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# TRON

Researched 2026-10-26 against java-tron GreatVoyage-v4.8.2.4; documentation pages were read on that date. [S1]

## ERPC implementation

Mainnet and Nile full-node RPC and delegated SR lifecycle are implemented with
all twelve common operations and external registration preparation/validation/status.
The [operations guide](../../crates/erpc-chain-tron/templates/README.md) describes
network/architecture pins, native encrypted Witness-only custody, original-key
same-host recovery, restricted APIs and confirmed firewall activation. Nile pins
`GreatVoyage-Nile-v4.8.2.4-PQ1-build1` at
`bc7752b638d9aa4da413c78645dcff1a1aa8e40a`; the ECDSA profile does not claim support
for its additional post-quantum signer modes. Default synchronization replays
genesis; unauthenticated snapshot imports are not automated. Real-host acceptance
remains deferred. [S16]

## Networks

Mainnet, Shasta and Nile are distinct networks. Their JSON-RPC chain IDs are `0x2b6653dc`, `0x94a9059e` and `0xcd8690dc`, derived from the final four bytes of their genesis hashes. Shasta does not accept independent public node peers; use its hosted API. Nile may run code ahead of Mainnet, so its configuration/client must come from the Nile instructions rather than assuming Mainnet parity. [S2], [S3]

## RPC node

- **Client:** The official Java implementation is `tronprotocol/java-tron`, producing `FullNode.jar` and `Toolkit.jar`; it uses LGPLv3. The same node executable supports RPC and block-production roles. [S3], [S4]
- **Latest stable:** `GreatVoyage-v4.8.2.4`, commit `4e8389f159d0782f1ebcd9dab2fd88388c0e6fe9`, published 2026-10-22. The release says **mandatory upgrade**, but a specific deadline timestamp is **not documented** in its notes. This pin is not a claim of Nile/Shasta deployment-version equivalence. [S1], [S5], [S3]
- **Release verification:** Every JAR has a corresponding GPG `.sig`. Verify against the official key fingerprint `1254 F859 D2B1 BD9F 66E7 107D F859 BCB4 4A28 290B` (UID `build@tron.network`). The integrity guide distinguishes GPG releases from the pre-2023 TRON-address signature mechanism. A separate checksum manifest and reproducible-build guarantee are **not documented** in the current release. [S1], [S6]
- **Install:** Download the architecture-specific signed JAR or build with Gradle. Linux/macOS are supported; native Windows is not. x86_64 requires JDK 8, ARM64 JDK 17; the versions are architecture-dependent, not interchangeable choices. A glibc floor and required CPU flags are **not documented** in the README/deployment guide. [S3], [S7]
- **Hardware, read 2026-10-26:** Deployment guidance recommends 16 cores, 32 GB RAM, 4 TB+ SSD, 100 Mbps for Fullnode; SRs use 32 cores/64 GB. The pinned README gives at least 50 Mbps for its recommended tier, so use the newer operational page's 100 Mbps figure while recording the discrepancy. An archive-specific sizing guarantee is **not documented** there. [S7], [S3]
- **Node types:** Fullnode retains its synchronized database. Lite Fullnode boots from state plus the latest 65,536 blocks, then grows again; filtered historical APIs are disabled unless `node.openHistoryQueryWhenLiteFN=true`, and removed history does not return when enabled. Solidity/PBFT APIs are views of confirmed data, not automatically separate mandatory daemons. [S15], [S8]
- **Initial sync:** Mainnet genesis replay can take weeks to months. The official backup guide catalogs official Mainnet snapshots by region, LevelDB/RocksDB and optional history, and community Nile snapshots. Use that catalog as the source; it currently contains plaintext-IP download links, which this document does not reproduce or promote to verified HTTPS endpoints. Exact current archive sizes and download times are **not documented**. Match the database engine and historical-data options before restoring. [S7], [S9]
- **Config/data/service:** Start with the complete version-matched Mainnet `config.conf`; external `-c` files fall back to packaged `reference.conf`, not Mainnet defaults. `-d`/`--output-directory` selects data storage, default `output-directory`, with a `database/` child. The guide describes JVM startup and systemd constraints, but a complete canonical production unit/compose file is **not documented** there. [S7], [S9], [S10]
- **Ports:** Mainnet defaults: P2P 18888; HTTP Full/Solidity/PBFT 8090/8091/8092; gRPC Full/Solidity/PBFT 50051/50061/50071. Public P2P reachability is needed; keep query and backup ports restricted to trusted networks or controlled gateways. [S10], [S7]
- **APIs:** Native HTTP wallet APIs and gRPC; optional Ethereum-compatible JSON-RPC uses `/jsonrpc`, Fullnode 8545 and Solidity 8555, enabled with `node.jsonrpc.httpFullNodeEnable`/`httpSolidityEnable`. These default off in `reference.conf`. Compatibility is partial: historical-state selectors for balance/storage/code/call are unsupported. Native WS and Ethereum `debug`/`trace` coverage are **not documented** in this JSON-RPC catalog. `vm.saveInternalTx` controls stored internal-transaction data. [S8], [S9]
- **Upgrades:** Follow java-tron releases and protocol-proposal announcements. Stop cleanly, replace matching JAR/toolkit, restart; an SR switches production to its standby first. Do not roll back after a mandatory upgrade's fork proposal passes. A fixed release cadence is **not documented** in these release/operations sources. [S1], [S11]
- **Health:** Inspect `wallet/getnowblock` for the latest locally produced block (which may not yet be solidified) and track block-height drift rather than process uptime alone. Prometheus is opt-in via `node.metrics.prometheus.enable=true`; scrape `/metrics` on default 9527 privately. [S12], [S11], [S13]

## Validator

- **Participation:** **Yes, elected DPoS**: any account may register an SR candidate with `WitnessCreateContract` and the documented 9,999 TRX burned application fee. The top 27 by votes produce blocks; the cited guide describes Mainnet six-hour maintenance intervals. ERPC observes current network parameters rather than applying that interval to Nile. The fee is not minimum bonded stake, and votes rather than a fixed self-stake threshold determine activation. [S14]
- **Keys:** Use a dedicated hot `witness_permission` signing key and keep the owner key offline. `localwitness` stores a raw key; `localwitnesskeystore` supports an encrypted keystore with password delivery requirements. A concrete remote-signer integration is **not documented** in the cited deployment/best-practice pages; their hardware-backed-storage advice is not an implementation specification. [S7], [S11]
- **Slashing:** Missed production loses block rewards and can lose votes. A bonded-stake slashing schedule or equivocation penalty is **not documented** in the official SR overview/best-practice guides; do not infer its absence from that gap. [S14], [S11]
- **Processes/guide:** Run `FullNode.jar --witness` with the matching signing configuration. No separate consensus client or mandatory MEV daemon is **documented**. The official SR guide and operational best practices are the onboarding sources; use one active producer and a synchronized standby. [S3], [S14], [S11]

## Pitfalls

- A sparse override config can silently omit Mainnet values; use the full matched network config. SIGKILL risks database corruption; stop with SIGTERM. [S7]
- LevelDB/RocksDB snapshots are not interchangeable, and choosing a snapshot without internal transactions cannot manufacture that historical data later. [S9]
- JSON-RPC names do not imply full Ethereum API or historical-state compatibility; check the method-specific supported selectors. [S8]

## Sources

[S1]: https://github.com/tronprotocol/java-tron/releases/tag/GreatVoyage-v4.8.2.4 "Release date, mandatory upgrade and signed JAR assets"
[S2]: https://developers.tron.network/reference/eth_chainid "Official network chain IDs; read 2026-10-26"
[S3]: https://github.com/tronprotocol/java-tron/blob/4e8389f159d0782f1ebcd9dab2fd88388c0e6fe9/README.md "Pinned client, installation, networks, hardware and roles"
[S4]: https://github.com/tronprotocol/java-tron/blob/4e8389f159d0782f1ebcd9dab2fd88388c0e6fe9/LICENSE "LGPLv3 license"
[S5]: https://github.com/tronprotocol/java-tron/commit/4e8389f159d0782f1ebcd9dab2fd88388c0e6fe9 "Resolved release commit"
[S6]: https://tronprotocol.github.io/documentation-en/releases/signature_verification/ "GPG fingerprint and verification; read 2026-10-26"
[S7]: https://developers.tron.network/docs/deploy-the-fullnode-or-supernode "Current deployment, Lite mode, JVM, keys and operational guidance; read 2026-10-26"
[S8]: https://tronprotocol.github.io/documentation-en/api/json-rpc/ "API compatibility, switches and ports; read 2026-10-26"
[S9]: https://tronprotocol.github.io/documentation-en/using_javatron/backup_restore/ "Official/community snapshot catalog, data paths and database compatibility; read 2026-10-26"
[S10]: https://github.com/tronprotocol/java-tron/blob/4e8389f159d0782f1ebcd9dab2fd88388c0e6fe9/framework/src/main/resources/config.conf "Pinned Mainnet config and listener defaults"
[S11]: https://developers.tron.network/docs/sr-best-practices "Key separation, active/standby, penalties and upgrade procedures; read 2026-10-26"
[S12]: https://developers.tron.network/reference/wallet-getnowblock "Latest local block API; read 2026-10-26"
[S13]: https://tronprotocol.github.io/documentation-en/using_javatron/metrics/ "Prometheus setup; page dated 2026-08-13, read 2026-10-26"
[S14]: https://developers.tron.network/docs/super-representatives "Official SR eligibility, registration and election guide; read 2026-10-26"

[S15]: https://tronprotocol.github.io/documentation-en/using_javatron/litefullnode/ "Lite retention, APIs and growth; page dated 2026-07-30, read 2026-10-26"

[S16]: https://github.com/tron-nile-testnet/nile-testnet/releases/tag/GreatVoyage-Nile-v4.8.2.4-PQ1-build1 "Pinned Nile release, independent of Mainnet"
