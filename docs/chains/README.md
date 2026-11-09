<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Chain deployment source map

Research date: **2026-10-26**. Scope: the **18 chain families in the erpc-sdk
0.11.0 read matrix**. This is an operator-source inventory for later RPC/validator
implementation, not a statement that the CLI deploys all these chains. Each
linked file contains its own first-party sources, release/commit pins, network
qualifications and unresolved documentation gaps.

The networks column records relevant public networks, including test networks
outside the SDK's bounded read matrix. Release versions are research snapshots:
check the chain-specific rollout instructions before deploying. A newer upstream
release is not automatically approved by every network using that client.

| Chain | Networks | RPC client(s) | Validator on the network | erpc today | File | Researched |
|---|---|---|---|---|---|---|
| solana | Mainnet Beta, Devnet, Testnet | Agave / Jito-Solana; Firedancer validator mapped separately | yes | native RPC and explicit voting lifecycle; qualified original-copy migration; live acceptance deferred | [Solana](solana.md) | 2026-10-26 |
| ethereum | Mainnet, Sepolia, Hoodi | Reth + Lighthouse; alternative EL/CL clients listed | yes (mainnet/Hoodi; Sepolia restricted) | partial: mainnet RPC; Hoodi/mainnet validator backend, live acceptance deferred | [Ethereum](ethereum.md) | 2026-10-26 |
| avalanche | Mainnet, Fuji; C/P/X chains | AvalancheGo | yes | implemented code: RPC/node + validator lifecycle; external registration; live acceptance deferred | [Avalanche](avalanche.md) | 2026-10-26 |
| bitcoin | Mainnet, testnet4, signet, regtest; deprecated testnet3 | Bitcoin Core | N/A: proof-of-work mining | implemented backend; live acceptance deferred | [Bitcoin](bitcoin.md) | 2026-10-26 |
| base | Mainnet, Sepolia | base-reth-node + base-consensus | N/A: sequencer L2; dispute roles in file | RPC follower lifecycle; offline checks; live acceptance deferred | [Base](base.md) | 2026-10-26 |
| arbitrum | One, Nova, Sepolia | Nitro | yes: permissionless on One; other chains qualified in file | follower backend and separate One assertion-validator lifecycle; observing default, explicit native signing; live acceptance deferred | [Arbitrum](arbitrum.md) | 2026-10-26 |
| polygon | PoS mainnet, Amoy | Bor + Heimdall v2 | permissioned admission / capped set | RPC/sentry and explicit admitted-validator lifecycle; external owner registration, live acceptance deferred | [Polygon](polygon.md) | 2026-10-26 |
| bsc | Mainnet, Chapel | BSC Geth; Reth-BSC alternative | yes: stake/election requirements | implemented RPC and fresh-validator backends; live acceptance deferred | [BNB Smart Chain](bsc.md) | 2026-10-26 |
| optimism | OP Mainnet, OP Sepolia | op-reth + op-node; Nethermind alternative | N/A: sequencer L2; challenger role in file | RPC follower lifecycle; offline checks; live acceptance deferred | [Optimism](optimism.md) | 2026-10-26 |
| kaia | Mainnet, Kairos | Kaia `ken` endpoint node | permissioned in current documented phase | RPC and [CN/PN lifecycle](../kaia-core-cell.md); admission external; live acceptance deferred | [Kaia](kaia.md) | 2026-10-27 |
| soneium | Mainnet, Minato | Upstream op-reth + op-node; chain-approved pin not documented | N/A: sequencer L2 | RPC follower lifecycle; offline checks; live acceptance deferred | [Soneium](soneium.md) | 2026-10-26 |
| monad | Mainnet, Testnet | Monad execution + monad-bft / monad-rpc | yes: stake/rank requirements | RPC/validator lifecycle; external registration; live acceptance deferred | [Monad](monad.md) | 2026-10-26 |
| hyperliquid | Mainnet, Testnet (HyperCore / HyperEVM) | hl-node via hl-visor | yes: stake/rank requirements | [RPC](../hyperliquid-rpc.md), [validator](../hyperliquid-validator.md) and separate [AQA](../hyperliquid-aqa.md); live acceptance deferred | [Hyperliquid](hyperliquid.md) | 2026-10-27 |
| arc | Mainnet, Testnet | arc-node execution + consensus follower | permissioned | RPC and dedicated validator preparation; production signing held | [Arc](arc.md) | 2026-10-26 |
| robinhood | Mainnet, Testnet | Nitro with Robinhood chain configuration | permissioned BoLD validators | RPC follower, public admission preparation and admitted Defensive lifecycle; live acceptance deferred | [Robinhood Chain](robinhood.md) | 2026-10-26 |
| near | Mainnet, Testnet | nearcore / neard | yes: stake/seat requirements | RPC and validator lifecycle; external registration; live acceptance deferred | [NEAR](near.md) | 2026-10-26 |
| tron | Mainnet, Nile; Shasta hosted-only | java-tron | yes: elected Super Representatives | implemented code: RPC + delegated SR lifecycle; external registration; live acceptance deferred | [TRON](tron.md) | 2026-10-26 |
| sui | Mainnet, Testnet, Devnet | sui-node; gRPC and separate GraphQL stack | yes: stake/voting-power requirements | implemented code: RPC/node + validator lifecycle; external registration; live acceptance deferred | [Sui](sui.md) | 2026-11-04 |

`Validator` distinguishes PoS/consensus validators and explicitly documented L2
assertion validators. `N/A` does not mean that an L2 has no dispute/challenger
mechanism: see the individual Validator section. Admission, active-set selection
and stake are separate questions; `yes` does not guarantee a slot.

`erpc today` is based on the existing [chain/role registry][R1],
[CLI declarations][R2], [command dispatch][R3] and the implementation links in
the chain files. `implemented` describes an existing working deployment path,
`partial` a limited implemented subset or a declared node role without deployment,
and `none` the absence of a chain deployment backend. These labels do not certify
that every newly researched release is supported by the current CLI.

## Deployment implementation status

Implementation snapshot updated **2026-11-04** from the command tree and each
chain's offline tests. Research dates in the table above remain source-research
dates. The snapshot does not certify a live deployment.
The network's
validator capability above is separate from what `erpc` can deploy. A consensus
client running for RPC does not mean validator signing/registration is implemented.
The command registry and dispatch are the implementation evidence. [R1], [R2], [R3]

| Chain | RPC/node deployment in erpc | Validator deployment in erpc | Validation / remaining work |
|---|---|---|---|
| Solana | Native Agave RPC and isolated ingress | Explicit original-identity voting activation | Native lifecycle and qualified original-copy migration: offline checks; live acceptance deferred |
| Ethereum | Mainnet Reth + Lighthouse | Hoodi/mainnet VC and external deposit review | RPC and validator authority: offline checks; live acceptance deferred |
| Avalanche | Mainnet/Fuji C/P/X node; node alias | Original NodeID/BLS custody and external registration | Offline checks; live acceptance deferred |
| Bitcoin | Core with original runtime authority and full/pruned retention | N/A: proof-of-work mining | Cancellation, source floor and recovery: offline checks; live acceptance deferred |
| Base | Network-qualified follower pair | N/A for standalone PoS validator; sequencer/dispute roles separate | Offline checks; live acceptance deferred |
| Arbitrum | One/Nova/Sepolia Nitro follower | Separate One MakeNodes signer; observing default, external funding | Original filesystem, custody staging and parent-provider recovery: offline checks; live acceptance deferred |
| Polygon | Bor + Heimdall v2 RPC/sentry | Admitted validator with dedicated checkpoint signer; owner registration external | Lifecycle, Karwar release qualification and interrupted-update recovery: offline checks; live acceptance deferred |
| BSC | Network-qualified Geth and fixed bootstrap | Fresh consensus/BLS custody, recovery and external registration | Lifecycle and Jenner release/expiry recovery: offline checks; live acceptance deferred |
| Optimism | Network-qualified follower pair | N/A for standalone PoS validator; sequencer/challenger roles separate | Offline checks; live acceptance deferred |
| Kaia | Endpoint node | Dedicated CN/PN lifecycle; admission external | Offline checks; live acceptance deferred |
| Soneium | Source-qualified follower pair | N/A for standalone PoS validator; sequencer roles separate | Offline checks; live acceptance deferred |
| Monad | Qualified native execution/consensus/RPC | Original consensus custody and external registration | Original filesystem recovery: offline checks; live acceptance deferred |
| Hyperliquid | Supervised non-validator node and RPC | Dedicated hot signer and separate AQA agent publisher | Original filesystem recovery: offline checks; live acceptance deferred |
| Arc | Original follower/provider runtime, typed custody and explicit legacy migration | Dedicated observer preparation, peer custody and public Remote/governance checks; production signing held | Runtime and preparation: offline checks; production requires qualified signing-history protection; live acceptance deferred |
| Robinhood | Mainnet/testnet Nitro follower | Dedicated admitted Defensive lifecycle plus public admission observation and unsigned administrator intent | Offline checks; funded participation and live acceptance deferred |
| NEAR | nearcore all-shard follower | Dedicated key custody and external pool registration | Lifecycle and Mainnet protocol 87/88 forward-update recovery: offline checks; live acceptance deferred |
| TRON | Native HTTP/gRPC and partial JSON-RPC | Dedicated Witness custody and external SR registration | Offline checks; live acceptance deferred |
| Sui | Full node with gRPC; node alias | Original validator custody and external registration | Lifecycle, Testnet protocol 140 and retained source-history recovery: offline checks; live acceptance deferred |

The RPC command-routing check exercises all twelve common verbs for all eighteen
families with empty local configuration and no host name or credentials. It
checks JSON output and refusal of incomplete host operations, not successful
node deployment. Chain-specific lifecycle, recovery and custody tests provide
separate offline evidence; none of these checks runs a node on a real host.

## Reading and maintaining the map

- Read the chain's Networks and release qualifications before selecting a binary.
- `not documented` identifies a gap in the named reviewed sources, not proof that
  a feature, penalty or requirement does not exist.
- Numeric hardware/snapshot figures carry their source's date and scope; estimates
  are not measured results from this research. No node was run or large snapshot
  downloaded for this task.
- Keep new HTTPS hosts in `DOCUMENTATION_HOSTS`, explain them in
  [public-hosts.md](../public-hosts.md), and update the pinned page digest in the
  same commit. Run `scripts/check-endpoints.sh` and the core/auth tests.

## Sources

All network/client/validator cells link to their chain's sourced report above.
The inventory's CLI-support classification uses the following repository sources:

[R1]: ../../crates/erpc-core/src/chain.rs "Existing chain variants and allowed node roles"
[R2]: ../../crates/erpc/src/main.rs "CLI declarations and chain role dispatch"
[R3]: ../../crates/erpc/src/tree.rs "Implemented command dispatch and unimplemented fallback"
