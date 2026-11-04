<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Bitcoin

Researched 2026-10-26 against Bitcoin Core v31.1; mutable documentation was read on that date. [S1]

## Networks

Bitcoin Core names its networks `main`, `test` (testnet3), `testnet4`, `signet`, and `regtest`; their pinned genesis identifiers are in the client's chain parameters. Testnet3 is deprecated in the example configuration in favor of testnet4. Bitcoin does not use an EVM chain ID. [S2], [S3]

| Network | Genesis block hash |
| --- | --- |
| Mainnet | `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` [S2] |
| Testnet3 | `000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943` [S2] |
| Testnet4 | `00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043` [S2] |
| Default signet | `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6` [S2] |
| Regtest | `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206` [S2] |

## RPC node

- **Client:** Bitcoin Core (`bitcoin/bitcoin`), the implementation documented by the Bitcoin developer guide; MIT license. Repository, release and license sources are below. [S4], [S5], [S6]
- **Latest stable:** The official download page identifies 31.1. Tag `v31.1`, commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`, published 2026-07-08. GitHub also publishes maintenance releases for older major lines; the first item in a release listing is not necessarily the recommended major line. [S1], [S4], [S7]
- **Release verification:** Download binaries from Bitcoin Core, not GitHub's generated source archives. Verify the artifact against `SHA256SUMS` and authenticate that manifest with `SHA256SUMS.asc` using trusted Guix builder keys. The download guide's example signer is Michael Ford/fanquake, fingerprint `E777 299F C265 DD04 7930 70EB 944D 35F9 AC3D B76A`; its public key was inspected. The guide recommends trusting several independent signers. No binary was downloaded or verified in this research. [S1], [S4], [S8]
- **Install/OS:** Official prebuilt downloads cover Linux, macOS, Windows and several CPU architectures; source is in the repository. v31.1 supports/tests Linux kernel 3.17+, macOS 14+, Windows 10 version 1903+. A glibc floor and CPU-flag floor are **not documented** in these release/download pages; consult the matching build configuration before producing another platform's binaries. [S1], [S9]
- **Hardware, read 2026-10-26:** The full-node guide lists 2 GB RAM, 100 MB/s disk access and at least 400 kbit/s upload, with about 740 GB initial download and around 7 GB pruned storage; it gives no core-count minimum or SSD requirement. The download page has different approximate storage/bandwidth figures, so these are documentation estimates, not a measured 2026 archive capacity or production-RPC sizing guarantee. [S10], [S1]
- **Node types:** Both pruned and unpruned nodes validate blocks. `prune=0` retains block files; `prune=<MiB>` discards older block/undo files, with a 550 MiB minimum target that excludes chainstate/index overhead. `txindex=1` builds a complete transaction lookup index and is incompatible with pruning. Retained blocks do not themselves mean every historical query has an index. [S3], [S10]
- **Initial sync:** Normal initial block download validates history. AssumeUTXO can load a state snapshot with `loadtxoutset`, then validate earlier history in the background; `getchainstates` tracks both chains. The pinned guide explicitly has **no canonical snapshot source**. A community snapshot must match a source-coded hash, and indexes still build from genesis. Snapshot sizes and a reliable completion time are **not documented** in that guide. [S11]
- **Config/service:** Use `bitcoin.conf`, `server=1` where required, and `-datadir` for an explicit data location. The official systemd example uses `/etc/bitcoin/bitcoin.conf` and `/var/lib/bitcoind`, under the `bitcoin` service user; these service paths are not universal desktop defaults. Prefer cookie authentication or `rpcauth`. [S3], [S12], [S13]
- **Ports:** Mainnet TCP P2P/RPC: 8333/8332; testnet3: 18333/18332; testnet4: 48333/48332; signet: 38333/38332; regtest: 18444/18443. Public inbound P2P helps peers; outbound-only operation is possible. RPC must stay off the public Internet, including when Docker publishes ports. [S3], [S10], [S13]
- **APIs:** HTTP JSON-RPC 2.0 and legacy 1.1 compatibility; blockchain, network, transaction, wallet and mining methods are documented. Optional REST and ZMQ settings are in the example config. Native WS, gRPC and Prometheus listener are **not documented** in these client-interface/config sources; do not invent ports for them. Bitcoin has no EVM `debug`/`trace` namespaces. [S3], [S13], [S14]
- **Upgrades:** Shut down cleanly, replace binaries, restart; database migration can take time and downgrade safety requires the release notes. Subscribe to official security/update announcements. A fixed release cadence and a mandatory hard-fork deadline for 31.1 are **not documented** in its release notes. [S9]
- **Health:** `getblockchaininfo` exposes `chain`, `blocks`, `headers`, `verificationprogress` and `initialblockdownload`; compare tip progress and peers before serving traffic. No dedicated metrics endpoint is **documented** in the pinned example configuration. [S14], [S3]

## Validator

**N/A as a staking-validator role.** Bitcoin uses proof-of-work miners for block production and full nodes independently enforce consensus rules. There is no validator registration, minimum stake, validator signing key, remote validator signer or stake-slashing process to configure for an RPC node. Mining is a separate role, not a prerequisite for running Bitcoin Core. [S6]

## Pitfalls

- RPC credentials permit powerful operations, including wallet access; the official interface guide explicitly prohibits direct public-Internet exposure. [S13]
- AssumeUTXO does not instantly create historical indexes; temporary double chainstate and delayed pruning can consume additional disk. [S11]
- v31.1 fixes excessive chainstate disk I/O and a privacy-network bypass in private broadcast. For low-memory/container installations also review v31.0's increased automatic `dbcache` default. [S9], [S15]

## ERPC today

The dedicated Bitcoin Core RPC lifecycle is implemented for mainnet, testnet4,
default signet and regtest, with offline tests and **deferred real-host acceptance**.
It uses a two-signer release manifest, private cookie RPC, immutable full/pruned
retention and a persistent ownership contract before remote mutations. See the
[operator guide](../bitcoin-rpc.md); this does not add a mining/validator role.

## Sources

[S1]: https://bitcoincore.org/en/download/ "Current stable download and verification instructions; read 2026-10-26"
[S2]: https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/kernel/chainparams.cpp "Pinned network genesis hashes and P2P defaults"
[S3]: https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/share/examples/bitcoin.conf "Pinned configuration, ports, indexes and optional interfaces"
[S4]: https://github.com/bitcoin/bitcoin/releases/tag/v31.1 "Release date and canonical binary-download policy"
[S5]: https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/COPYING "MIT license"
[S6]: https://developer.bitcoin.org/devguide/block_chain.html "Full-node validation and proof-of-work; read 2026-10-26"
[S7]: https://github.com/bitcoin/bitcoin/commit/9be056a8a72b624dae9623b2f7bded92c2a21c91 "Resolved release commit"
[S8]: https://github.com/bitcoin-core/guix.sigs/blob/main/builder-keys/fanquake.gpg "Public Guix builder key; fingerprint inspected 2026-10-26"
[S9]: https://bitcoincore.org/en/releases/31.1/ "Supported OS, upgrade steps, fixes and announcements; read 2026-10-26"
[S10]: https://bitcoin.org/en/full-node "Hardware, pruning and connectivity guidance; read 2026-10-26"
[S11]: https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/doc/assumeutxo.md "Pinned state-snapshot trust and indexing constraints"
[S12]: https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/contrib/init/bitcoind.service "Official systemd example"
[S13]: https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/doc/JSON-RPC-interface.md "Pinned RPC protocol and security requirements"
[S14]: https://bitcoincore.org/en/doc/31.0.0/rpc/blockchain/getblockchaininfo/ "31.x RPC sync/chain status schema; read 2026-10-26"
[S15]: https://bitcoincore.org/en/releases/31.0/ "Major-version memory change; read 2026-10-26"
