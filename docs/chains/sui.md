<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Sui

Researched 2026-10-26 against Sui mainnet-v1.82.3; Testnet source and protocol qualification refreshed 2026-11-04. [S1], [S6]

## Networks

Mainnet, Testnet and Devnet use different `genesis.blob` files from MystenLabs' genesis repository. The pinned client recognizes short chain identifiers Mainnet `35834a8a` and Testnet `4c78adac`; identity derives from the genesis checkpoint digest, not an EVM chain ID. A durable Devnet identifier is **not documented** in the genesis guide; select the current network genesis rather than reusing Mainnet/Testnet data. [S2], [S3]

## RPC node

- **Client:** MystenLabs' `sui` repository supplies the reference `sui-node` for full nodes and validators, under Apache-2.0. Repository, release and license sources are below. [S1], [S4], [S5]
- **Latest stable by network:** Mainnet `mainnet-v1.82.3`, commit `bf4073918ed33cfa0b09c500658fa116a774bcfd`, published 2026-10-21. Testnet `testnet-v1.83.1`, commit `0e0ede4cbf48c6d7654b613f62fdca71542ace03`, published 2026-11-03. Its maximum protocol is 140; official Testnet gRPC reported protocol 140 on 2026-11-04, requiring an update from the previous max-139 1.82.2 client. Mainnet remained protocol 139 in the separate observation. Mainnet/Testnet releases are distinct despite both being non-prereleases; Devnet tags are not Mainnet recommendations. [S1], [S6]
- **Verification:** The Mainnet release exposes OS/architecture archives but no separate signed checksum/GPG assets. A normal-release checksum-signing fingerprint or reproducible-build guarantee is **not documented** there. The operator guide separately documents signed private security releases with out-of-band announcements; that process must not be conflated with ordinary public-release verification. No binary was downloaded. [S1], [S7]
- **Install/OS:** Use a prebuilt archive/container or build the pinned source with `cargo build --release --bin sui-node`. Official systemd instructions and unit are available. Production guidance favors Linux (Ubuntu/Debian); macOS is for development. A glibc floor and CPU-instruction requirement are **not documented** in the cited installation/operator pages. [S1], [S8], [S9]
- **Hardware, read 2026-10-26:** Full-node minimum recommendation is 8 physical cores/16 vCPUs, 128 GB RAM, 4 TB NVMe. A bandwidth minimum is **not documented** on the full-node page. Retention/indexing can substantially increase storage requirements. [S9]
- **Node types:** Full nodes verify certified checkpoints and serve state/history; retention depends on pruning. Formal snapshots contain live objects without historical indexes, whereas RocksDB snapshots preserve the database's retained state/indexes. A formal restore is unsuitable by itself for historical RPC lookups. Archive serving/indexing is a separate data-management concern. [S9], [S10], [S11]
- **Initial sync:** Use checkpoint state sync or the official snapshot procedure. Mysten-managed RocksDB snapshots use Requester Pays storage; formal snapshots also have free R2 access through `sui-tool download-formal-snapshot --no-sign-request`. The official data-store catalog distinguishes full-retention checkpoint buckets from 30-day public endpoints. Snapshot sizes and guaranteed sync times are **not documented** there; verify the current manifest/retention before restore. No community snapshot is required by this path. [S10], [S12]
- **Config/data/service:** `sui-node --config-path <file>` selects YAML. The pinned full-node template uses `db-path: /opt/sui/db`, genesis at `/opt/sui/config/genesis.blob`, metrics 9184 and API listener 9000. Use the official systemd example or reviewed compose template; the pinned compose file's image tag is stale and must be replaced with the selected network/release. [S8], [S13], [S14]
- **Ports:** Full-node public P2P is UDP 8084. Serve gRPC via HTTP/2 TLS on TCP 443 forwarding privately to 9000; keep metrics TCP 9184 and admin TCP 1337 private. The template binds metrics to all interfaces, so restrict it explicitly. [S9], [S13]
- **APIs:** **v1.82.3 removes the full-node JSON-RPC service and deletes its old database on startup.** Do not promise legacy `sui_*`/`suix_*` RPC based on stale docs/config names. Use gRPC; historical list methods require `rpc.enable-indexing=true`. GraphQL requires the documented indexer/serving stack. EVM `debug`/`trace` flags and a legacy WS API are not a supported substitute. [S1], [S9], [S11]
- **Upgrades:** Typical schedule: Devnet Mondays weekly, Testnet Tuesdays weekly, Mainnet Wednesdays every two weeks. Subscribe to the network's official Discord announcements and node-operators group listed in the update guide. Apply protocol-changing releases before activation at an epoch boundary after sufficient validator stake upgrades. A fixed future deadline for this pinned release is **not documented** in its notes. [S15], [S1]
- **Health:** Compare gRPC `LedgerService/GetCheckpoint` with progressing `last_executed_checkpoint` and `highest_synced_checkpoint`; check the `uptime` metric's chain identity. Metrics are at `http://localhost:9184/metrics`. [S9], [S7]

## Validator

- **Participation:** Permissionless candidacy subject to stake/voting-power selection. The official page is internally transitional: it describes SIP-39 joining at 3 voting power, removal below 2 after seven epochs or below 1 immediately, but still gives a 30M SUI staking step. The prose alone does not establish the active threshold. The implemented observer resolves the pinned Move admission phases against live `VotingPowerAdmissionStartEpochKey`: read-only protocol-139 observations on 2026-10-26 put Mainnet epoch 1292/start 743 and Testnet epoch 1264/start 707 in the 3-voting-power phase. This is not a fixed SUI amount; actual eligibility requires an external transaction dry-run. [S4], [R23]
- **Registration/keys:** Submit `request_add_validator_candidate`, fund its pool, then `request_add_validator` when eligible. Key roles are `protocol.key` (BLS), `account.key` (staking assets), `network.key` (state sync), `worker.key` (consensus); the latter three are ed25519. The systemd guide places node keys under `/opt/sui/key-pairs`. Account operation capabilities can be delegated while keeping the account key offline. A production remote-protocol-signer integration is **not documented** in these guides. [S7], [S8]
- **Slashing:** After reports from `2f + 1` other validators by voting power, staking rewards are reduced. The cited guide does not document this as destruction of principal; an independent principal-slashing schedule is **not documented** there. [S7]
- **Processes/hardware:** Validator `sui-node` handles consensus; no separate mandatory MEV process is **documented**. Recommended minimum is 24 physical cores/48 vCPUs, 128 GB RAM, 4 TB NVMe, 1 Gbps. Open TCP 8080/8081 for validator traffic and UDP 8084 for state sync; keep metrics private. The official deployment and management guides cover onboarding. [S4], [S7]
- **erpc today:** **Partial**: the [CLI][R21] and [skill][R20] expose a full-node lifecycle with a compatible node alias; validator lifecycle and external registration preparation/validation/status are implemented; real-host acceptance remains deferred. See the [embedded operations guide][R23].

## Pitfalls

- Some current full-node prose still discusses deprecated JSON-RPC while the pinned release removes it; the release notes govern this version. The pinned compose example even contains `mainnet-v1.19.1`, so copying it unchanged selects the wrong software. [S1], [S9], [S14]
- Wrong genesis causes chain-identity mismatch, and changing the genesis after database initialization requires restoring the correct network database. [S2]
- Free checkpoint endpoints retain only 30 days and are not production archive backfill sources. Formal snapshots do not reconstruct old query indexes. [S12], [S10]

## Sources

[S1]: https://github.com/MystenLabs/sui/releases/tag/mainnet-v1.82.3 "Mainnet release date/assets, protocol and JSON-RPC removal"
[S2]: https://docs.sui.io/operators/genesis "Network genesis sources and identity; read 2026-10-26"
[S3]: https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui-types/src/digests.rs "Pinned genesis checkpoint identifiers and short-ID tests"
[S4]: https://docs.sui.io/operators/validator/validator-config "Official validator deployment, hardware and transitional stake requirements; read 2026-10-26"
[S5]: https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/LICENSE "Apache-2.0 license at resolved Mainnet commit"
[S6]: https://github.com/MystenLabs/sui/releases/tag/testnet-v1.83.1 "Testnet release resolved to 0e0ede4cbf48c6d7654b613f62fdca71542ace03"
[S7]: https://docs.sui.io/operators/validator/validator-tasks "Keys, reward penalties, metrics and private security releases; read 2026-10-26"
[S8]: https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/nre/systemd/README.md "Pinned official build/systemd/key-path procedure"
[S9]: https://docs.sui.io/operators/full-node/sui-full-node "Full-node hardware, ports, gRPC and readiness; read 2026-10-26"
[S10]: https://docs.sui.io/operators/snapshots "Formal/RocksDB snapshot roles and restore procedure; read 2026-10-26"
[S11]: https://docs.sui.io/operators/data-management/indexer-stack-setup "GraphQL/indexer serving stack; read 2026-10-26"
[S12]: https://docs.sui.io/operators/data-management/available-data-stores "Official snapshot/checkpoint catalog and retention; read 2026-10-26"
[S13]: https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui-config/data/fullnode-template.yaml "Pinned paths and listener defaults"
[S14]: https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/docker/fullnode/docker-compose.yaml "Pinned official compose example; stale image tag recorded"
[S15]: https://docs.sui.io/operators/full-node/updates "Release cadence, channels and protocol-activation deadline policy; read 2026-10-26"

[R20]: ../../crates/erpc-skills/skills/sui-node/SKILL.md "Existing repository skill"

[R21]: ../../crates/erpc/src/main.rs "Existing repository CLI"


[R23]: ../../crates/erpc-chain-sui/templates/README.md "Sui full-node lifecycle and deferred live acceptance"
