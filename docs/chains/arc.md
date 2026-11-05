<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Arc

Researched 2026-10-26 against arc-node v0.8.1. Web documentation was read on that date; release source links are pinned to its commit. The website's v0.8.0 banner and older version tables in the tagged source are not the latest-release record. [S1], [S2], [S3]

## Networks

Mainnet chain ID **5042**; testnet **5042002**. Both use USDC for gas. The current connection page documents both networks, although the tagged repository's introduction still says testnet/alpha. [S4], [S5]

## RPC node

- **Client:** Circle's reference `circlefin/arc-node`, Apache-2.0; one release contains Reth-derived execution, Malachite-derived consensus and snapshot tools. Repository, license and release history: [S1], [S5], [S6], [S7].
- **Latest stable release:** `v0.8.1`, commit `ab09dbfd9553a7ad48f9c134ec5e808c36512c74`, published **2026-10-07**. It fixes the post-quantum precompile's base-gas reservation. [S1], [S8]
- **Verification:** release archives have `.sha256` files and GitHub asset SHA-256 digests. `arcup` checks the checksum. GPG verification: **none** in this release; the installation guide explicitly says it is disabled pending publication of a signing key. Reproducible-build instructions: **not documented** there. [S1], [S3]
- **Install:** `arcup`, tagged source builds or the documented execution/consensus Docker images. Release targets: Linux x86-64 and ARM64, macOS ARM64. Tagged installation instructions require **glibc 2.39+** for Linux binaries; this is stricter than the website's Ubuntu 22.04+/Debian 12+ OS baseline. Required CPU instruction flags: **not documented** in those sources. [S1], [S3], [S9]
- **Hardware (read 2026-10-26):** 64 GB+ RAM, 1 TB+ TLC NVMe, stable 24 Mbps+; CPU clock speed is emphasized without a numeric core minimum. [S9]
- **Node types:** follower full nodes independently verify finalized blocks without voting; EL `--full` prunes, while retaining archive history needs the matching archive snapshot/profile. The snapshot tool distinguishes `minimal`, `full`, `archive`; disabling pruning cannot recreate discarded history. A relay/provider is a separate onboarded role in ERPC. [S10], [S11], [R1]
- **Initial sync:** use `arc-snapshots download` with explicit chain and EL profile; genesis sync is unsupported by the public guide. Official snapshot selection is built into the tool. Website testnet estimates are 68 GB compressed EL + 16 GB CL (103 GB + 36 GB extracted). Its claimed 10–15 minutes at 100 Mbps is inconsistent with those byte sizes; **no reliable sync-time guarantee is documented**. No community snapshot is endorsed here. [S9], [S11]
- **Config:** official systemd units use `~/.arc/execution`, `~/.arc/consensus` and `/run/arc/{reth,auth}.ipc`. Start execution before consensus; use the matching `--chain`, `--rpc.forwarder`, consensus `--follow.endpoint`, and metrics flags. Adjust `ExecStart` for `arcup`'s `~/.arc/bin` installation. Official Compose is linked from the pinned run guide; the website describes it as testnet-only. [S2], [S11], [S12]
- **Ports/exposure:** follower nodes fetch signed blocks from relays without joining consensus gossip. HTTP RPC 8545; optional Engine RPC 8551; CL RPC 31000; EL/CL metrics 9001/29000. These service listeners need not be public. The separated-host guide additionally configures WS 8546 and restricts all EL RPC ports to the CL host. [S9], [S10], [S11]
- **APIs:** Ethereum JSON-RPC; `--http.api` / `--ws.api` select namespaces. Public-facing nodes use `--public-api` and the documented `eth,net,web3,rpc` set; `debug`/`trace` are explicit private-service choices. Native gRPC: **not documented** in the operator guide. [S9], [S11], [S12]
- **Upgrades:** monitor GitHub releases and the versioned breaking-change ledger; fixed cadence is **not documented**. The published v0.8.0 deadlines were **2026-09-03 15:00 UTC** testnet and **2026-09-10 15:00 UTC** mainnet; both have passed. [S1], [S2], [S13]
- **Health:** check both services, advancing `eth_blockNumber` and recent block timestamps; advancement alone does not prove the node has reached the network head. Metrics require `--metrics`: EL `http://localhost:9001/`, CL `http://localhost:29000/metrics`. Inspect relay connection and IPC failures. [S14]

## Validator

**Permissioned.** A permissionless follower RPC node is not a consensus validator. Public admission procedure, minimum stake, production validator-key custody/remote-signer policy and slashing conditions are **not documented** in the cited public node guide. Do not interpret this as zero stake or no slashing. [S10]

The breaking-change ledger documents validator mode: CL requires `--validator` and `--suggested-fee-recipient`, in addition to the execution process. These flags alone do not grant admission. Public production validator onboarding guide: **not documented** in the reviewed operator sources. [S10], [S13]

## Pitfalls

- Tagged instructions deprecate separated-host Engine HTTP transport in v0.8.0 and announce removal in v0.9.0; prefer the documented same-host IPC arrangement. [S11]
- Snapshot restores can replace newer local data; interrupted restores and `--force` have destructive semantics. Re-running Compose can select a newer snapshot and restart the download. [S11]
- Invalid CL environment values now fail startup; snapshot downloads need an explicit chain, and CL admin routes require `--rpc.admin`. [S13]
- The website hardware/size estimates, tagged source and release banners are not perfectly synchronized. Use the release pin above, preserve the network distinction, and recheck the source before implementation. [S1], [S3], [S9]

## ERPC today

**Implemented for RPC**, including mainnet/testnet full, archive and onboarded provider roles; validator deployment is not supplied by this RPC path. Existing playbooks, templates and release pins are linked below. This research adds no deploy behavior. [R1], [R2]

## Sources

[S1]: https://github.com/circlefin/arc-node/releases/tag/v0.8.1 "Release, publication date and assets"
[S2]: https://docs.arc.io/arc/tutorials/run-an-arc-node "Current network setup and mandatory fork deadlines; read 2026-10-26"
[S3]: https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/docs/installation.md "Pinned binary targets, glibc, verification and installation"
[S4]: https://docs.arc.io/arc/references/connect-to-arc "Network identifiers; read 2026-10-26"
[S5]: https://github.com/circlefin/arc-node/tree/ab09dbfd9553a7ad48f9c134ec5e808c36512c74 "Client repository and tagged introduction"
[S6]: https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/LICENSE "Apache-2.0 license"
[S7]: https://github.com/circlefin/arc-node/releases "Release history"
[S8]: https://github.com/circlefin/arc-node/commit/ab09dbfd9553a7ad48f9c134ec5e808c36512c74 "Resolved release commit"
[S9]: https://docs.arc.io/arc/references/node-requirements "Hardware, ports and snapshot estimates; read 2026-10-26"
[S10]: https://docs.arc.io/arc/concepts/running-a-node "Follower architecture and permissioned validators; read 2026-10-26"
[S11]: https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/docs/running-an-arc-node.md "Pinned config, snapshot profiles, Docker and transport caveats"
[S12]: https://docs.arc.io/arc/tutorials/deploy-node-as-service "Official systemd units; read 2026-10-26"
[S13]: https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/BREAKING_CHANGES.md "Upgrade and validator flag changes"
[S14]: https://docs.arc.io/arc/tutorials/monitor-a-node "Health checks and metrics paths; read 2026-10-26"
[R1]: ../../crates/erpc-skills/skills/arc-rpc/SKILL.md "Existing ERPC Arc RPC behavior"
[R2]: ../../crates/erpc-chain-arc/templates/ "Existing Arc playbooks and systemd templates"
