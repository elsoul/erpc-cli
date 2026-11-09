<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Polygon PoS

Researched 2026-10-26 against **Bor v2.10.3** and **Heimdall v2 v0.12.2**.
All operational pages below were read on 2026-10-26. This file covers Polygon
PoS, not Polygon zkEVM or a CDK chain. [S1], [S2], [S3]

## erpc implementation

RPC/sentry operations now cover both Bor and Heimdall v2 on Mainnet and Amoy,
with all twelve common verbs, persistent identities, separate synchronization
status, authenticated native packages, immutable official genesis and retained
history recovery. [Operations and verification limits](../../crates/erpc-chain-polygon/templates/README.md)
describe the implementation. Live-host acceptance remains deferred. Validator
admission and signing are not implemented by the RPC role. The separate
[validator lifecycle](../polygon-validator.md) connects original 1Password-backed
hot custody, an observing first deployment, current admission validation and
explicit native checkpoint activation. Staking/registration/funding stay external;
real-host and financial acceptance remain deferred.

The source-verified package workflow clarifies the research-era verification
gap below: public `.sig`/`.pem` companions are Sigstore keyless artifacts. The
implementation checks workflow identity, tag, commit and issuer; it does not
interpret them as GPG signatures. [Bor workflow](https://github.com/0xPolygon/bor/blob/a16f123d9b4f41a552a3a98d93a0340430838576/.github/workflows/packager_deb.yml),
[Heimdall workflow](https://github.com/0xPolygon/heimdall-v2/blob/ced0710a3f6e269b8d5e996eb7d2b740fd9f80c5/.github/workflows/packager_deb.yml).

## Networks

Polygon PoS mainnet chain ID is **137**, with Ethereum as parent; Amoy testnet
uses **80002**, with Sepolia as parent. Both use POL for gas. [S3]

## RPC node

- **Clients:** reference stack is Bor execution plus Heimdall v2 consensus
  (CometBFT/Cosmos SDK). Bor libraries are LGPL-3.0 and command/binary code
  GPL-3.0; Heimdall v2 is GPL-3.0. Release pages and pinned source trees are
  linked below. Polygon's Erigon support sunset notice recommends Bor PBSS
  for archive nodes; old Erigon hardware tables do not establish ongoing
  support. [S4], [S5], [S6], [S7], [S16]
- **Latest stable releases:** Bor `v2.10.3`, commit
  `a16f123d9b4f41a552a3a98d93a0340430838576`, published 2026-10-15;
  Heimdall `v0.12.2`, commit
  `ced0710a3f6e269b8d5e996eb7d2b740fd9f80c5`, published 2026-10-14.
  The Heimdall announcement explicitly covers mainnet and Amoy; the earlier
  `v0.12.2-beta-2` is an Amoy prerelease, not this stable release. [S1], [S2], [S8]
- **Verification:** both releases attach `.checksum`, `.sig` and `.pem`
  companions to Debian packages. An operator-facing verification command,
  GPG fingerprint, or reproducible-build procedure for these public packages
  is **not documented** in the inspected release notes. Do not infer that a
  `.sig` is an OpenPGP signature. Private Lugano packages were explicitly
  described as GPG-signed, a separate distribution channel. [S1], [S2], [S9]
- **Install:** official Debian packages for amd64/arm64, installer scripts,
  systemd templates, and source trees. The binary guide is Linux/APT based;
  supported distro versions, minimum glibc and required CPU ISA flags are
  **not documented** in the inspected binary guide/releases. [S1], [S2], [S10], [S11]
- **Hardware, read 2026-10-26:** mainnet full/sentry and validator minimum /
  recommended: 8/16 cores, 32/64 GB RAM, 4/6 TB disk, 1 Gbit/s network.
  Amoy: 8/16 cores, 8/16 GB RAM, 1/2 TB disk, 1 Gbit/s.
  Snapshot guidance favors direct-attached storage or provisioned SSD I/O;
  its mainnet example needs 4.5 TB extracted and recommends an 8 TB disk,
  exceeding the prerequisite table's minimum. [S7], [S12]
- **Node types:** full/sentry serves ordinary current-state RPC. Bor archive
  PBSS uses Pebble, `state.scheme=path`, `gcmode=archive`, and
  `history.state=0`; a finite history retains only recent states.
  Historical state availability does not guarantee historical `eth_getProof`:
  the archive migration notice limits proofs to the latest 128 blocks. [S6]
- **Initial sync:** current official guidance delegates snapshot production to
  community providers (including Stakepool, Stakecraft and PublicNode), with
  the provider inventory linked from the official guide. Mainnet example is
  3.5 TB compressed / 4.5 TB extracted; Amoy 285 GB / 400 GB. These are
  approximate guidance, not pinned downloadable artifacts. Snapshot sync is
  described as hours; fresh network sync as several days. Current
  provider-specific checksums and exact completion time are **not documented**
  on the overview page. [S12], [S10]
- **Config:** Heimdall uses `/var/lib/heimdall/config`, the network's migrated
  v2 genesis and configured seeds/persistent peers. Bor uses
  `/var/lib/bor/config.toml`, bootnodes and data under `/var/lib/bor/data`.
  The official Bor unit runs `bor server -config ...` as `bor`; the installer
  sets up Heimdall/Bor services. Wait for Heimdall to sync before starting Bor. [S10], [S11]
- **Ports:** public sentry P2P: Bor 30303 TCP/UDP, Heimdall 26656 TCP.
  Bor HTTP/WS 8545/8546 and Heimdall REST 1317 are optional service exposure;
  Heimdall status RPC is 26657. Monitoring ports are Heimdall 26660 and Bor
  7071, restricted to monitoring systems. Validator P2P is reachable only
  from its sentries, not the public internet. [S7], [S10]
- **APIs:** Bor JSON-RPC modules include `eth`, `net`, `web3`, `txpool`,
  `bor`, `debug` and `trace`, explicitly selected in HTTP config; WS is
  separately enabled. Archive retention flags control transaction/log/state
  history. Heimdall provides REST and CometBFT status RPC. A public gRPC
  deployment requirement is **not documented** in these guides. [S6], [S7], [S10]
- **Upgrades:** monitor Polygon's official forum announcements and both
  clients' releases. Bor v2.10.3 needs no hardfork, schema change or resync.
  Lugano already required Heimdall v0.12.1 at mainnet height **54,627,000**
  (2026-10-01) and Amoy height **47,105,000** (2026-09-23); v0.12.2 is
  recommended afterward. A fixed release cadence or future mandatory
  deadline is **not documented** in these notices. [S1], [S8], [S9]
- **Health:** Heimdall `/status` on 26657 must report `catching_up=false`;
  check both systemd services and continuing chain progress. Monitor Bor and
  Heimdall independently rather than treating one healthy process as a healthy
  stack. Metrics ports are above; the inspected prerequisite guide does not
  give a complete metrics-path/API health contract (**not documented**). [S10], [S7], [S13]

## Validator

- **Participation:** **permissioned admission process / capped active set**,
  rather than guaranteed entry upon staking. The official guide requires an
  application and an available slot within the maximum 105 validators;
  minimum self-stake for new validators is **100,000 POL**, staked through
  Ethereum contracts. PIP-91 proposes an on-chain ValidatorPass gate but is
  marked Peer Review: do not present its activation as established. [S4], [S14]
- **Keys:** separate owner wallet for Ethereum staking/reward administration
  and on-node signer for consensus/checkpoints. The signer needs POL on
  Heimdall and ETH on Ethereum. Remote-signer integration is **not documented**
  in the inspected best-practices guide. [S13]
- **Slashing:** the guide describes missed-signature performance scoring and
  possible removal for poor performance. Exact currently enforced stake-slashing
  amounts, double-sign conditions and penalty activation are **not documented**
  in the inspected validator, rewards and best-practices pages; do not convert
  removal or lost rewards into an unsupported slashing claim. [S4], [S13], [S15]
- **Processes:** operate separate sentry and validator stacks, each with Bor
  and Heimdall. Validator infrastructure additionally uses RabbitMQ and access
  to the parent Ethereum chain for staking/checkpoints. The official validator
  guide links binary/Ansible setup and staking instructions. [S4], [S7], [S13]

## Pitfalls

- Starting Bor before Heimdall is synchronized causes recurring issues;
  use the migrated v2 genesis rather than a v1 configuration. [S10]
- The pinned Bor README has much smaller hardware figures than the operational
  prerequisite/snapshot pages. Preserve this discrepancy and plan from the
  actual chosen dataset. [S5], [S7], [S12]
- Erigon archive recommendations in old tables are superseded by the 2026-05-12
  sunset announcement (support ending August 1). PBSS archive retains historical
  state but the cited notice does not promise historical proofs. [S6]
- v2.10.3 starts honoring the Heimdall timeout; old templates with five seconds
  may need adjustment to the documented 30-second default. [S1]

## Sources

[S1]: https://github.com/0xPolygon/bor/releases/tag/v2.10.3 "Latest Bor stable release, packages and operator notes; 2026-10-15"
[S2]: https://github.com/0xPolygon/heimdall-v2/releases/tag/v0.12.2 "Latest Heimdall stable release and signed package companions; 2026-10-14"
[S3]: https://docs.polygon.technology/pos/reference/rpc-endpoints "Mainnet/Amoy IDs and parent networks; read 2026-10-26"
[S4]: https://docs.polygon.technology/pos/get-started/becoming-a-validator "Reference stack, admission, minimum stake and validator responsibilities; read 2026-10-26"
[S5]: https://github.com/0xPolygon/bor/tree/a16f123d9b4f41a552a3a98d93a0340430838576 "Pinned Bor source, README and licenses"
[S6]: https://forum.polygon.technology/t/sunsetting-erigon-support/21872 "Polygon Labs Erigon sunset and Bor PBSS archive configuration; 2026-05-12"
[S7]: https://docs.polygon.technology/pos/how-to/prerequisites "Hardware, exposure policy and RabbitMQ; read 2026-10-26"
[S8]: https://forum.polygon.technology/t/heimdall-v0-12-2/22369 "Stable v0.12.2 covers mainnet and Amoy; 2026-10-14"
[S9]: https://forum.polygon.technology/t/security-release-review-heimdall-v0-12-1-lugano-hf/22389 "Mandatory Lugano activation heights and private GPG distribution; 2026-10-16"
[S10]: https://docs.polygon.technology/pos/how-to/full-node/full-node-binaries "Install, genesis, paths and sync order; read 2026-10-26"
[S11]: https://github.com/0xPolygon/bor/blob/a16f123d9b4f41a552a3a98d93a0340430838576/packaging/templates/systemd/bor.service "Pinned official Bor systemd unit"
[S12]: https://docs.polygon.technology/pos/how-to/snapshots "Community snapshot inventory, approximate sizes and disk guidance; read 2026-10-26"
[S13]: https://docs.polygon.technology/pos/how-to/validator/validator-best-practices "Keys, sentry isolation and monitoring; read 2026-10-26"
[S14]: https://forum.polygon.technology/t/permissioned-validator-entry-via-validatorpass/22108 "PIP-91 proposal, Peer Review status and existing admission policy; 2026-08-18"
[S15]: https://docs.polygon.technology/pos/reference/rewards "Validator/delegator rewards and staking context; read 2026-10-26"
[S16]: https://github.com/0xPolygon/heimdall-v2/tree/ced0710a3f6e269b8d5e996eb7d2b740fd9f80c5 "Pinned Heimdall v2 source and GPL-3.0 license"
