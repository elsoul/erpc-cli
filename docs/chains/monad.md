<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Monad

Researched 2026-10-26 against Monad package/consensus **v0.16.5** and execution
repository **v0.16.1**. These are separate release series, not interchangeable
binary versions. Documentation below was read on 2026-10-26. [S1], [S2], [S3]

## Networks

Mainnet uses chain ID **143**; Monad Testnet uses **10143**. The network pages
currently list mainnet `v0.15.2 / MONAD_NINE` and testnet
`v0.16.5 / MONAD_TEN`, while the installation page specifies package 0.16.5 for
both. The upgrade page says deployment dates are announced separately. Treat this
as a documentation discrepancy and confirm the signed network announcement before
choosing a production version. Testnet was reset on 2025-12-16. [S4], [S5], [S1], [S6]

## RPC node

- **Clients:** Category Labs' reference implementation comprises `monad`
  execution and `monad-bft` consensus/RPC; both repositories are GPL-3.0.
  Their release pages and pinned source trees are linked below. [S2], [S3], [S7], [S8]
- **Latest stable GitHub releases:** consensus `v0.16.5`, commit
  `33d9d5c0314eff8c6409a810b9dbf1b6381c6b5c`, published 2026-10-13;
  execution `v0.16.1`, commit
  `7279dfc7b6e88ee2f23b1cff4eba384016cde2f0`, published 2026-08-25.
  The package 0.16.5 guide independently identifies the consensus commit above;
  it does not establish that execution tag v0.16.1 is its bundled execution
  revision. [S2], [S3], [S1]
- **Verification:** the APT repository uses a dedicated signed-by keyring.
  The published package-signing key's primary fingerprint, inspected on the
  research date, is `D9FA 4D9B B7CD 9328 005E 2698 0802 DFD2 634A E7F0`.
  Detached per-binary signatures or reproducible-build verification are
  **not documented** in the installation/release instructions. [S6], [S9], [S1]
- **Install:** Ubuntu 24.04+, APT `monad` package, systemd units and `monad`
  service account. Source builds are available; the execution README requires
  x86-64-v3/AVX2-class instructions. A standalone glibc minimum is
  **not documented** in the installation page. [S6], [S7]
- **Hardware, read 2026-10-26:** bare metal; 16 cores at 4.5 GHz+ base,
  32 GB+ RAM, separate 2 TB execution and 500 GB OS/consensus disks, both
  PCIe Gen4x4 NVMe or faster. Bandwidth: 100 Mbit/s full node,
  300 Mbit/s validator. Cloud VMs are not officially supported. [S10]
- **Node types:** a normal node serves recent local state; historical data
  requires the archive data infrastructure described separately. Local artifact
  retention is controlled by `monad-cruft`. Archive transaction data does not
  itself reconstruct all historical execution state; use the linked archive
  and genesis-replay guides. Archive servers store transactions, receipts, logs
  and traces, not historical state tries. [S6], [S11], [S19]
- **Initial sync:** official Foundation and Category Labs snapshots bootstrap
  TrieDB, followed by statesync/blocksync. The reset page claims mainnet restore
  in 1–5 minutes and tip catch-up usually under five minutes for a recent
  snapshot; its testnet estimates conflict (up to one hour in the overview,
  under five minutes later). Snapshot sizes and a guaranteed total sync time
  are **not documented** there. Community providers are referred through
  validator channels, without a fixed inventory. [S12]
- **Config:** `/home/monad/monad-bft/config/node.toml`, runtime forkpoint and
  validator files, `/home/monad/.env`, and dedicated raw TrieDB device
  `/dev/triedb`. Packaged services include `monad-bft`, `monad-execution`,
  `monad-rpc` and cleanup/monitoring helpers. The installation guide is the
  official systemd/config source. [S6]
- **Ports:** P2P uses 8000 TCP/UDP and authenticated UDP 8001; the newer peer
  record example also includes direct authenticated UDP 8002. Apply the
  network-specific template, not a generic Ethereum firewall. JSON-RPC listens
  on 8080 after statesync. Native Prometheus is 9143 `/metrics`; the metrics
  migration guide deprecates the installation page's older OTel port 8889 and
  explicitly says to wait for the official migration announcement. Metrics
  must be restricted to approved monitoring sources. [S6], [S13], [S14]
- **APIs:** Ethereum-compatible JSON-RPC is implemented by `monad-rpc`;
  WebSockets require the execution-event setup. Historical requests require
  archive configuration. The archive RPC guide recommends execution
  `--trace_calls` for detailed tracing errors and RPC `--use-eth-get-logs-index`
  with MongoDB. Archive integration is for RPC full nodes, not validators.
  A public gRPC service is **not documented** in these node guides. [S8], [S15], [S20]
- **Upgrades:** package hold prevents unattended upgrades to an unapproved
  network version. v0.16.5 is a rolling upgrade from v0.16.4, with dates announced
  separately. Foundation announcements have at least two GPG signatures and
  severity categories: orange recommends action within 24–48 hours; red means
  immediate action. A fixed release cadence is **not documented**. [S1], [S16]
- **Health:** inspect the three main services, query `eth_blockNumber`, and
  compare continuing block progress; RPC starts listening only after statesync.
  Scrape native `/metrics` on 9143 when applicable to the deployed version. [S13], [S14]

## Validator

- **Participation:** public registration through staking precompile
  `addValidator`; 100,000 MON self-stake, 10,000,000 MON total stake and ranking
  within the top 200 are required for the active set. Use the validator-specific
  config and set the reward beneficiary. [S17]
- **Keys:** encrypted SECP and BLS keystores at
  `/home/monad/monad-bft/config/id-secp` and `id-bls`; the install workflow also
  creates key/password backups. Remote signing is **not documented** in the
  installation or validator guides. Registration/account authorization is
  distinct from the consensus keys. [S6], [S17], [S18]
- **Slashing:** automated protocol slashing is not currently implemented;
  logging provides accountability for malicious offenses. Losing eligibility
  removes a validator at the next epoch boundary. [S18]
- **Processes:** the same consensus/execution/RPC services as a full node;
  additional mandatory MEV software is **not documented** by the official
  validator installation guide. [S17]

## Pitfalls

- v0.16.5 requires `--triedb-path` to point to the device, not its containing
  directory; custom units can fail at startup. TrieDB stats producer/consumer
  flags must agree or metrics silently stop updating. [S1]
- The hardware page records SSD overheating and random latency problems;
  advertised disk capacity alone is insufficient. [S10]
- Network/version and metrics documentation disagree as described above;
  release existence is not proof of mainnet activation. [S4], [S5], [S6], [S14]

## Sources

[S1]: https://docs.monad.xyz/node-ops/upgrade-instructions/v0.16.5 "Package version, consensus commit, deployment caveat and upgrade pitfalls; read 2026-10-26"
[S2]: https://github.com/category-labs/monad-bft/releases/tag/v0.16.5 "Latest non-prerelease consensus release; published 2026-10-13"
[S3]: https://github.com/category-labs/monad/releases/tag/v0.16.1 "Latest non-prerelease execution release; published 2026-08-25"
[S4]: https://docs.monad.xyz/developer-essentials/network-information/index.md "Mainnet ID and advertised network revision; read 2026-10-26"
[S5]: https://docs.monad.xyz/developer-essentials/testnet.md "Testnet ID, reset and advertised network revision; read 2026-10-26"
[S6]: https://docs.monad.xyz/node-ops/full-node-installation "Installation, configuration, keys and ports; read 2026-10-26"
[S7]: https://github.com/category-labs/monad/tree/7279dfc7b6e88ee2f23b1cff4eba384016cde2f0 "Pinned execution source, build instructions and GPL-3.0 license"
[S8]: https://github.com/category-labs/monad-bft/tree/33d9d5c0314eff8c6409a810b9dbf1b6381c6b5c "Pinned consensus/RPC source and GPL-3.0 license"
[S9]: https://pkg.category.xyz/keys/public-key.asc "Package-signing public key; fingerprint inspected 2026-10-26"
[S10]: https://docs.monad.xyz/node-ops/hardware-requirements "Full-node/validator hardware and SSD pitfalls; read 2026-10-26"
[S11]: https://docs.monad.xyz/node-ops/archive-data "Archive data and genesis replay guide index; read 2026-10-26"
[S12]: https://docs.monad.xyz/node-ops/node-recovery/hard-reset "Official bootstrap snapshot sources and timing estimates; read 2026-10-26"
[S13]: https://docs.monad.xyz/node-ops/general-operations "Services, synchronization and diagnostics; read 2026-10-26"
[S14]: https://docs.monad.xyz/node-ops/upgrade-instructions/prometheus-metrics-migration "Native metrics, old collector deprecation and rollout warning; read 2026-10-26"
[S15]: https://docs.monad.xyz/node-ops/events-and-websockets "Execution-event and WebSocket setup; read 2026-10-26"
[S16]: https://docs.monad.xyz/node-ops/announcements "Signed announcements and urgency policy; read 2026-10-26"
[S17]: https://docs.monad.xyz/node-ops/validator-installation "Validator registration and configuration; read 2026-10-26"
[S18]: https://docs.monad.xyz/monad-arch/consensus/staking "Eligibility, authorization and slashing status; read 2026-10-26"
[S19]: https://docs.monad.xyz/node-ops/archive-data/data-waterfall "Local retention and archive transaction/state distinction; read 2026-10-26"
[S20]: https://docs.monad.xyz/node-ops/archive-data/configuring-rpc "Archive RPC, trace_calls and log-index configuration; read 2026-10-26"
