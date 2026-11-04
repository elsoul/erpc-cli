<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Hyperliquid

Researched 2026-10-26 against the official node distribution instructions at
commit `405cc08b17a727ee51b0f9128918955a84439915`. A stable release tag and a
source commit corresponding to the distributed node binary are **not documented**;
the repository publishes instructions and signed rolling binaries, not a tagged
node source release. Documentation below was read on that date. [S1], [S2]

## Networks

HyperEVM mainnet uses chain ID **999**; testnet uses **998**. HyperCore and
HyperEVM share HyperBFT consensus; this is an L1 validator, not an independently
operated L2 sequencer. [S3]

## RPC node

- **Clients:** `hl-visor` supervises and upgrades `hl-node`; the official
  `hyperliquid-dex/node` repository contains deployment instructions. Its
  Apache-2.0 license covers repository material; a source-build procedure or
  license grant covering published node binary internals is **not documented**
  there. Releases page: no stable tagged release available at research time. [S1], [S2], [S4]
- **Release verification:** detached OpenPGP signatures accompany binaries as
  `.asc` files. `hl-visor` verifies downloaded `hl-node` and refuses an upgrade
  when verification fails. The public key is pinned below; its primary fingerprint,
  read with `gpg --show-keys --with-colons`, is
  `CF2C 2EA3 DC3E 8F04 2A55 FB65 0325 4A93 49F1 820B`.
  Reproducible builds and an immutable binary release manifest are **not documented**. [S1], [S5]
- **Install:** official mainnet/testnet binary locations and signature instructions
  are in the repository. Only Ubuntu 24.04 is supported. A glibc floor, CPU ISA
  flags are **not documented** in that guide. The repository includes an
  official systemd example and Docker Compose setup; the Dockerfile defaults
  to Testnet and includes signature verification. [S1], [S9], [S10], [S11]
- **Hardware, read 2026-10-26:** non-validator: 16 vCPUs, 128 GB RAM, 500 GB SSD;
  validator: 32 vCPUs, 128 GB RAM, 1 TB SSD. A minimum network bandwidth is
  **not documented**. The separate latency guide recommends at least 32 logical
  cores and 500 MB/s disk throughput for latency-sensitive workloads. [S1], [S6]
- **Node types:** validating and non-validating modes share the binary. Local
  `/info` serves a subset of state queries; historical time-series queries and
  WebSockets are not supported by that local server. A conventional full/archive/
  pruned EVM service matrix is **not documented**; do not infer an archive RPC
  from retained HyperCore output files. [S1]
- **Initial sync:** a non-validator discovers a peer and streams state/blocks;
  mainnet requires root-peer configuration. The guide lists community root peers
  and a `gossipRootIps` discovery request. Local state snapshots are saved every
  10,000 blocks. A downloadable bootstrap snapshot size or bounded sync duration
  is **not documented**. [S1]
- **Config:** select `Mainnet` or `Testnet` in `~/visor.json`; use
  `~/override_gossip_config.json` for peers. Runtime output is under `~/hl/data`.
  Start mode is `hl-visor run-non-validator`; add `--serve-eth-rpc` and/or
  `--serve-info` when needed. [S1]
- **Ports and APIs:** gossip ports 4001/4002 must be public for non-validator
  peering. The local HTTP server uses port 3001, `/evm` for EVM JSON-RPC and
  `/info` for supported HyperCore queries. Debug/trace/transaction-index enablement,
  gRPC and a metrics port are **not documented** in the node guide. Official
  hosted HyperEVM RPC also lacks WebSocket support. [S1], [S3]
- **Upgrades:** visor manages signed child-binary upgrades. A release cadence,
  immutable version-to-commit map, and future hard-fork deadlines are
  **not documented** in the repository/release listing. [S1], [S2]
- **Health:** `applied block` logs show live data ingestion; poll `exchangeStatus`
  and compare its L1 and local timestamps to detect stale responses. Check
  `eth_getBlockByNumber` for EVM progress. A Prometheus endpoint is
  **not documented**. [S1]

## Validator

- **Participation:** permissionless; the active set is the top 24 by stake in
  the validator guide. Self-delegation is at least 10,000 HYPE, locked for one
  year. Register with `CValidatorAction`, then
  unjail only after confirming consensus logs. [S7], [S8], [S1]
- **Keys:** separate cold validator and hot signer wallets; the signer key is
  configured in `~/hl/hyperliquid_data/node_config.json`. Both accounts need a
  nonzero perps USDC balance for signed actions. A remote-signer integration is
  **not documented**. [S1]
- **Slashing:** automatic slashing is currently absent. [S8] Jailing stops
  voting and proposing while the node can still forward messages; the node guide
  describes `unjailSelf` after the jailed-until time. Exact quorum thresholds,
  reward effects and a double-sign penalty schedule are **not documented** in
  these reviewed sources. [S1], [S8]
- **Processes/network:** use `run-validator`, with ports 4000–4010 reachable by
  peer validators; do not treat that range as a requirement for public RPC.
  The guide recommends owned sentry nodes for RPC and public peering. It also
  directs validators to run `aqa-publisher` on a separate machine, with a
  dedicated agent key, for aligned quote asset rate votes. [S1]
- **Official guide:** the validator overview links the detailed node repository
  instructions. [S7], [S1]

## Pitfalls

- Default data output can grow by about 100 GB/day; configure retention. An
  increasing block count alone does not prove the API response is fresh. [S1]
- The repository's delegation example mentions a five-minute unbonding period,
  whereas the staking reference specifies seven days for staking-to-spot
  transfers. Use the network-specific staking rules; do not apply the example
  timeout universally. [S1], [S8]
- Visor crash output is under `~/hl/data/visor_child_stderr`; repeated jailing
  merits checking consensus and status logs plus peer latency. [S1]

## Sources

[S1]: https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/README.md "Pinned official node, validator, API and operating guide; read 2026-10-26"
[S2]: https://github.com/hyperliquid-dex/node/releases "Release listing checked 2026-10-26; no latest tagged node release"
[S3]: https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm "Network IDs, shared consensus and RPC limitations; read 2026-10-26"
[S4]: https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/LICENSE "Repository license"
[S5]: https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/pub_key.asc "Official binary-signing public key; fingerprint read 2026-10-26"
[S6]: https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/optimizing-latency "Latency-specific hardware advice; read 2026-10-26"
[S7]: https://hyperliquid.gitbook.io/hyperliquid-docs/validators/running-a-validator "Permissionless participation and active set; read 2026-10-26"
[S8]: https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/staking "Stake threshold, locking and slashing; read 2026-10-26"
[S9]: https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/README_misc.md "Pinned systemd and Docker usage guide"
[S10]: https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/Dockerfile "Pinned official Testnet Docker build and binary verification"
[S11]: https://github.com/hyperliquid-dex/node/blob/405cc08b17a727ee51b0f9128918955a84439915/docker-compose.yml "Pinned Compose services and data retention sidecar"
