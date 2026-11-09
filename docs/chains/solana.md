<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Solana

Researched 2026-10-26 against Agave v4.3.2, Jito-Solana v4.3.2-jito and Firedancer v26.10.4. Documentation pages were read on this date; release pins are below. [A2], [J2], [F2]

## Networks

Solana uses genesis hashes rather than EVM chain IDs. The official cluster examples give these identifiers; devnet/testnet may reset. [S1]

| Cluster | Genesis hash |
|---|---|
| Mainnet Beta | `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d` |
| Devnet | `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG` |
| Testnet | `4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY` |

## RPC node

### Clients and release pins

Agave is Anza's validator/RPC implementation; Jito-Solana is an Agave derivative adding block-engine integration. Firedancer is an independent validator implementation, not an assumed replacement for every Agave RPC or plugin feature. All three carry Apache-2.0 licenses with component notices. [A1], [A4], [J1], [J4], [F1], [F4], [S10], [S11]

Latest stable releases returned by the projects' release APIs on the research date (not a claim that every release is suitable for every cluster):

| Client | Tag | Resolved commit | Published (UTC) | Repository / release / history / license |
|---|---|---|---|---|
| Agave | `v4.3.2` | `a203300045b405f86c9c84308b2eae76af69ac3b` | 2026-10-15 | [A1], [A2], [A3], [A4] |
| Jito-Solana | `v4.3.2-jito` | `013a4306f585cbd213ee5071550339af766f930c` | 2026-10-16 | [J1], [J2], [J3], [J4] |
| Firedancer | `v26.10.4` | `b14bff444e37977ad5eddcf811bf74e027203ac1` | 2026-10-21 | [F1], [F2], [F3], [F4] |

Agave's release explicitly recommends v4.3.2 for testnet, devnet and mainnet-beta; Firedancer calls v26.10.4 mainnet-ready. Jito directs older 4.3.x operators to v4.3.2-jito ahead of Alpenglow. [A2], [F2], [J2]

Implementation qualification additionally examined Agave Testnet `v4.4.0-beta.1`,
commit `3ad9da2c390eb7ad2630ed15afcd463e72e007a8`, whose release explicitly names
Testnet. The exact source toolchains are Rust `1.97.1` for v4.3.2 and `1.98.1`
for v4.4.0-beta.1. [A5], [A6], [A7]

The official Linux x86-64 CLI archives for both versions were streamed and
SHA256-checked on 2026-10-26 without extracting or executing their binaries.
Each contains 17 members, including `solana`, `solana-keygen` and
`solana-test-validator`, but **no production `agave-validator`**. Their compressed
SHA256 values are `5c9599d7fa397375df69d58e8d4f550ee45463dd6d1ecad9e5a1f053ce8e0933`
and `a872a3c08a490a32adbe47baaf9fb4111cd60a97fe019040784d1cab4f638070`, respectively.
Production validator installation therefore needs a qualified source build.
The upstream install script separates production binaries from developer tools
to prevent unintended `dev-context-only-utils` feature activation. [A2], [A5], [A8]

New native hosts are built from Agave `4.4.0`, commit
`9ef63128134af559561f6a91a641ec01e665c70d`, with Rust `1.98.1`, on both Mainnet
and Testnet: that is what the carried catalog pins. `v4.3.2` and `v4.4.0-beta.1`
remain as the sources an existing Solv host can be migrated from.
[A13], [R4], [R5]

- **Verification:** Agave release assets expose GitHub SHA-256 digests; Jito also publishes archive `.sha256` files. An upstream GPG signing fingerprint or reproducible-build procedure is **not documented** in those releases. Firedancer supplies source, with no prebuilt assets in v26.10.4; signed-binary verification is therefore **N/A**, and reproducible-build verification is **not documented** in its getting-started guide. [A2], [J2], [F2], [S6]
- **Install/OS:** Agave supports source builds and release assets. Its requirements page tests Ubuntu 24.04, requires AVX2 for official binaries, and has older text about retiring Ubuntu 20.04 binaries; the selected release's actual assets are the availability record. A specific current glibc floor is **not documented** on that page. Docker for production Agave validators is not recommended. [A2], [S2]
- **Hardware (read 2026-10-26):** Agave validator: 12 cores/24 threads, 2.8 GHz+, SHA extensions, 256 GB+ RAM; RPC: 16 cores/32 threads and 512 GB+ for all account indexes. Separate high-endurance NVMe: accounts 1 TB+, ledger 1 TB+, snapshots 500 GB+. Public IPv4; unstaked 1 Gbps symmetric, staked at least 2 Gbps with 10 Gbps recommended. These are upstream guidelines, not RPC throughput guarantees. [S2]
- **Firedancer install/hardware:** source-only Linux, kernel 4.18+, GCC 10+; minimum 24 cores above 2.8 GHz, 256 GB RAM, 2 TB NVMe. Recommended 32 cores above 3 GHz, AVX512, 512 GB ECC and 1 Gbps. Build on the target host or set `MACHINE`; native builds can use instructions unavailable on another host. [S6]
- **Node types/APIs:** Agave RPC uses `--no-voting`, `--full-rpc-api`, `--private-rpc`; bounded ledger history uses `--limit-ledger-size`. Full RPC is not a historical-state archive. Older ledger history needs a separate history backend such as the documented Bigtable integration. Account indexes are explicit `--account-index program-id/spl-token-mint/spl-token-owner` choices. [S3]
- **Initial sync:** Agave fetches snapshots from selected known validators; `--only-known-rpc` limits RPC sources. Avoid fetching fresh snapshots on routine restarts with usable local state. Snapshot size and completion time are **not documented as fixed guarantees**. ERPC also has its own/community mirrors; see the existing allowlist rather than treating those mirrors as Anza-operated. [S3], [S4], [R6]
- **Config/service:** official startup script and systemd example are in the validator guide; set identity, ledger/accounts directories, cluster entrypoints and expected genesis. RPC guide demonstrates `/mnt/ledger`, `/mnt/accounts`, port 8899. Firedancer has separate TOML configuration and path settings. [S3], [S5], [S7]
- **Ports:** Agave public P2P TCP/UDP 8000–8030, configurable via `--dynamic-port-range`; HTTP RPC 8899 in the example and WebSocket at RPC port + 1. Keep RPC access behind an appropriately protected service; `--private-rpc` hides advertisement, not network access. [S2], [S3], [S16]
- **Extra APIs:** transaction history and extended metadata require explicit flags in ERPC's Agave template. Geyser gRPC is a plugin integration, not a native Agave gRPC promise; ERPC pins Yellowstone against the Agave base version. [R1], [R2]
- **Upgrades:** follow each client's release notes and the validator announcements linked by Anza; no fixed cadence is promised. Build before stopping, restart outside leader slots, then check the running version. The reviewed Jito release calls for an Alpenglow upgrade but gives **no precise activation deadline**; do not infer one from a tag. [S4], [J2]
- **Health/metrics:** `getHealth` evaluates slot lag against the cluster tip; `solana catchup <identity>` checks progress. Agave's cluster examples configure a metrics push destination; a built-in Prometheus scrape endpoint is **not documented** there. Firedancer exposes `http://localhost:7999/metrics` and `firedancer monitor`. [S8], [S4], [S1], [S9]

## Validator

**Yes, permissionless.** Create/register a vote account and obtain delegated stake; the requirements page states no strict stake minimum, with vote-account rent and operational vote costs. Its quoted rent/cost figures are not an assurance of post-upgrade economics. [S1], [S2], [S5]

Identity, vote-account and authorized-withdrawer keys are distinct. The official guide keeps the withdrawer off the validator host; validator startup uses the identity and vote account. A production remote-signer protocol for this Agave release is **not documented** in that guide. [S5]

The staking reference says there is no automatic in-protocol slashing; the Foundation FAQ separately describes possible slashing at a restart following an attack that halts the network. Treat these as documented qualifications, not a guarantee of zero penalties. A current automatic slashing schedule is **not documented** in these sources. [S12], [S13]

Agave/Jito combine execution and validator duties in the validator process, unlike Ethereum's EL/CL pair. Jito adds block-engine connectivity. Firedancer uses its own validator and TOML configuration. Official guides: [S5], [S6], [S7], [S10].

## Pitfalls

- Do not assume full RPC is safe on an unrestricted public listener or co-locate heavy RPC indexing with voting without capacity planning. [S3]
- Avoid resetting snapshots on every upgrade; first test whether the existing ledger catches up. [S4]
- Firedancer's FAQ says Frankendancer support ended with Alpenglow activation; older hybrid setup pages do not describe the current full client. [S11]
- A native Firedancer build moved between machines can fail due to CPU-specific instructions. [S6]

## ERPC today

For the Agave 4.3.2 and 4.4.0-beta.1 sources, the minimum dynamic
port-range width is 26. The older `8000-8020` command example in the cluster
guide is narrower than the current native parser accepts. The isolated native
service template uses `8000-8032` (upper bound exclusive), UDP socket operation
with `--no-xdp`, loopback RPC and the current `--limit-blockstore-size` option.
The bootstrap catalog fixes the official network entrypoints and known-validator
identities inspected on 2026-10-27. These are source/configuration qualifications;
they do not constitute Linux or chain-synchronization acceptance. [S1], [A11], [A12]

**Implemented:** new mainnet and testnet validators and RPC nodes use the native
backend, with all twelve lifecycle verbs: Agave built on the host from the pinned
source, operator-supplied identities, and no client or version selection. The
[operations guide](../solana-native.md) has the host requirements and commands.
A validator first runs a separate synchronization identity with voting disabled;
`deploy --activate-validator` switches it to its registered identity.
[Public registration checks](../solana-registration.md) prepare intent and validate
account bindings for official external signing tools.
Hosts recorded on the Solv backend keep their earlier commands, including the
client and version chosen at initialization, key creation or import and the
testnet `vote-account` workflow; an explicit migration moves a qualified one to
the native backend. Native Tower and Alpenglow vote-history
files must remain with their original identity through restart and recovery;
the native CLI enables mandatory vote-history checks by default, with qualified
new-account exceptions. Do not infer safe history erasure from a syncing host.
[A9], [A10] Existing RPC code also contains plugin/version compatibility checks
and archive integration. Existing plays: [R1], [R2], [R3].

## Sources

[A1]: https://github.com/anza-xyz/agave/tree/a203300045b405f86c9c84308b2eae76af69ac3b "Client repository pinned to release commit"
[A2]: https://github.com/anza-xyz/agave/releases/tag/v4.3.2 "Release tag, publication date and assets"
[A3]: https://github.com/anza-xyz/agave/releases "Release history"
[A4]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/LICENSE "Client license (Apache-2.0 with notices)"
[J1]: https://github.com/jito-foundation/jito-solana/tree/013a4306f585cbd213ee5071550339af766f930c "Client repository pinned to release commit"
[J2]: https://github.com/jito-foundation/jito-solana/releases/tag/v4.3.2-jito "Release tag, publication date and assets"
[J3]: https://github.com/jito-foundation/jito-solana/releases "Release history"
[J4]: https://github.com/jito-foundation/jito-solana/blob/013a4306f585cbd213ee5071550339af766f930c/LICENSE "Client license (Apache-2.0 with notices)"
[F1]: https://github.com/firedancer-io/firedancer/tree/b14bff444e37977ad5eddcf811bf74e027203ac1 "Client repository pinned to release commit"
[F2]: https://github.com/firedancer-io/firedancer/releases/tag/v26.10.4 "Release tag, publication date and assets"
[F3]: https://github.com/firedancer-io/firedancer/releases "Release history"
[F4]: https://github.com/firedancer-io/firedancer/blob/b14bff444e37977ad5eddcf811bf74e027203ac1/LICENSE "Client license (Apache-2.0 with notices)"
[S1]: https://docs.anza.xyz/clusters/available "Clusters, genesis hashes, entrypoints and metrics; read 2026-10-26"
[S2]: https://docs.anza.xyz/operations/requirements "Stake, hardware, OS and P2P; read 2026-10-26"
[S3]: https://docs.anza.xyz/operations/setup-an-rpc-node "RPC flags, history and indexes; read 2026-10-26"
[S4]: https://docs.anza.xyz/operations/best-practices/general "Snapshots, catchup, upgrades and announcements; read 2026-10-26"
[S5]: https://docs.anza.xyz/operations/setup-a-validator "Registration, key custody and systemd example; read 2026-10-26"
[S6]: https://docs.firedancer.io/guide/getting-started.html "Build and hardware; read 2026-10-26"
[S7]: https://docs.firedancer.io/guide/configuring.html "Firedancer TOML and paths; read 2026-10-26"
[S8]: https://solana.com/docs/rpc/http/gethealth "Health JSON-RPC method; read 2026-10-26"
[S9]: https://docs.firedancer.io/guide/monitoring.html "Metrics and monitor command; read 2026-10-26"
[S10]: https://docs.jito.wtf/lowlatencytxnsend/ "Jito validator/block-engine architecture; read 2026-10-26"
[S11]: https://docs.firedancer.io/guide/faq.html "Full Firedancer versus retired Frankendancer; read 2026-10-26"
[S12]: https://solana.com/docs/references/staking "In-protocol slashing status; read 2026-10-26"
[S13]: https://solana.com/staking "Network-restart slashing qualification; read 2026-10-26"
[S16]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/validator/src/cli.rs "Pinned RPC port flag and WebSocket port convention"
[R1]: ../../crates/erpc-chain-solana/templates/jinja/mainnet-rpc/start-validator.sh.j2 "Existing RPC flags and optional Geyser plugin"
[R2]: ../../crates/erpc-chain-solana/src/rpc.rs "Existing RPC modes and plugin compatibility selection"
[R3]: ../../crates/erpc-chain-solana/templates/ansible/ "Existing RPC and validator playbooks"
[R4]: ../../crates/erpc-chain-solana-native/templates/node/catalog.json "Carried native source and compiler catalog"
[R5]: ../../crates/erpc-chain-solana-native/templates/node/migration-sources.json "Sources an existing Solv host can be migrated from"
[R6]: ../public-hosts.md "ERPC and explicitly identified third-party snapshot mirrors"

[A5]: https://github.com/anza-xyz/agave/releases/tag/v4.4.0-beta.1 "Testnet source and CLI release assets"
[A6]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/rust-toolchain.toml "Mainnet source toolchain"
[A7]: https://github.com/anza-xyz/agave/blob/3ad9da2c390eb7ad2630ed15afcd463e72e007a8/rust-toolchain.toml "Testnet source toolchain"
[A8]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/scripts/cargo-install-all.sh "Production/developer build separation"
[A9]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/core/src/validator.rs "Native Tower/vote-history restoration conditions"
[A10]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/votor/src/vote_history_storage.rs "Signed native vote history and filesystem persistence semantics"
[A11]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/net-utils/src/lib.rs "Mainnet minimum native port-range width"
[A12]: https://github.com/anza-xyz/agave/blob/3ad9da2c390eb7ad2630ed15afcd463e72e007a8/net-utils/src/lib.rs "Testnet minimum native port-range width"
[A13]: https://github.com/anza-xyz/agave/releases/tag/v4.4.0 "Release the native catalog pins for both networks"
