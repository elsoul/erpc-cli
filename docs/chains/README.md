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
| solana | Mainnet Beta, Devnet, Testnet | Agave / Jito-Solana; Firedancer validator mapped separately | yes | implemented: RPC + validator within existing network/client scope | [Solana](solana.md) | 2026-10-26 |
| ethereum | Mainnet, Sepolia, Hoodi | Reth + Lighthouse; alternative EL/CL clients listed | yes (mainnet/Hoodi; Sepolia restricted) | partial: mainnet RPC; Hoodi/mainnet validator backend, live acceptance deferred | [Ethereum](ethereum.md) | 2026-10-26 |
| avalanche | Mainnet, Fuji; C/P/X chains | AvalancheGo | yes | implemented code: RPC/node + validator lifecycle; external registration; live acceptance deferred | [Avalanche](avalanche.md) | 2026-10-26 |
| bitcoin | Mainnet, testnet4, signet, regtest; deprecated testnet3 | Bitcoin Core | N/A: proof-of-work mining | implemented backend; live acceptance deferred | [Bitcoin](bitcoin.md) | 2026-10-26 |
| base | Mainnet, Sepolia | base-reth-node + base-consensus | N/A: sequencer L2; dispute roles in file | RPC follower lifecycle; offline checks; live acceptance deferred | [Base](base.md) | 2026-10-26 |
| arbitrum | One, Nova, Sepolia | Nitro | yes: permissionless on One; other chains qualified in file | implemented follower backend; validator separate; live acceptance deferred | [Arbitrum](arbitrum.md) | 2026-10-26 |
| polygon | PoS mainnet, Amoy | Bor + Heimdall v2 | permissioned admission / capped set | none | [Polygon](polygon.md) | 2026-10-26 |
| bsc | Mainnet, Chapel | BSC Geth; Reth-BSC alternative | yes: stake/election requirements | none | [BNB Smart Chain](bsc.md) | 2026-10-26 |
| optimism | OP Mainnet, OP Sepolia | op-reth + op-node; Nethermind alternative | N/A: sequencer L2; challenger role in file | RPC follower lifecycle; offline checks; live acceptance deferred | [Optimism](optimism.md) | 2026-10-26 |
| kaia | Mainnet, Kairos | Kaia `ken` endpoint node | permissioned in current documented phase | none | [Kaia](kaia.md) | 2026-10-26 |
| soneium | Mainnet, Minato | Upstream op-reth + op-node; chain-approved pin not documented | N/A: sequencer L2 | RPC follower lifecycle; offline checks; live acceptance deferred | [Soneium](soneium.md) | 2026-10-26 |
| monad | Mainnet, Testnet | Monad execution + monad-bft / monad-rpc | yes: stake/rank requirements | none | [Monad](monad.md) | 2026-10-26 |
| hyperliquid | Mainnet, Testnet (HyperCore / HyperEVM) | hl-node via hl-visor | yes: stake/rank requirements | none | [Hyperliquid](hyperliquid.md) | 2026-10-26 |
| arc | Mainnet, Testnet | arc-node execution + consensus follower | permissioned | implemented: RPC; validator not implemented | [Arc](arc.md) | 2026-10-26 |
| robinhood | Mainnet, Testnet | Nitro with Robinhood chain configuration | permissioned BoLD validators | implemented follower backend; validator separate; live acceptance deferred | [Robinhood Chain](robinhood.md) | 2026-10-26 |
| near | Mainnet, Testnet | nearcore / neard | yes: stake/seat requirements | none | [NEAR](near.md) | 2026-10-26 |
| tron | Mainnet, Nile; Shasta hosted-only | java-tron | yes: elected Super Representatives | implemented code: RPC + delegated SR lifecycle; external registration; live acceptance deferred | [TRON](tron.md) | 2026-10-26 |
| sui | Mainnet, Testnet, Devnet | sui-node; gRPC and separate GraphQL stack | yes: stake/voting-power requirements | implemented code: RPC/node + validator lifecycle; external registration; live acceptance deferred | [Sui](sui.md) | 2026-10-26 |

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

Baseline checked at `73d835d` on **2026-10-26**; the Ethereum row includes the subsequent validator backend and its explicit acceptance limits. The network's
validator capability above is separate from what `erpc` can deploy. A consensus
client running for RPC does not mean validator signing/registration is implemented.
The command registry and dispatch are the implementation evidence. [R1], [R2], [R3]

| Chain | RPC/node deployment in erpc | Validator deployment in erpc | Next work |
|---|---|---|---|
| Ethereum | Implemented: Reth + Lighthouse beacon node, mainnet | Implemented backend: dedicated Hoodi/mainnet VC and deposit review; live acceptance deferred | Independent review and the deferred live test batch |
| Avalanche | Implemented lifecycle code: Mainnet/Fuji, RPC/node alias | Implemented identity lifecycle and external registration preparation/status | Offline checks passed; real-host/Fuji/Mainnet acceptance deferred |
| Sui | Implemented: full node with gRPC; node alias | Implemented: validator custody and external registration preparation/validation/status | Real-host acceptance deferred |
| TRON | Implemented: native HTTP/gRPC and partial JSON-RPC full node | Implemented: dedicated Witness custody and external registration preparation/validation/status | Real-host acceptance deferred |
| Solana | Implemented within the existing RPC scope | Implemented within the existing validator scope | Preserve existing behavior while adding backends |
| Arc | Implemented: follower/provider RPC | **Not implemented**: permissioned admission is separate | Maintain RPC; validator work waits for onboarding evidence |
| Bitcoin | Implemented backend: Core with immutable full/pruned retention | N/A: proof-of-work | Independent review and deferred live acceptance |
| Arbitrum | Implemented: Nitro One/Nova/Sepolia follower | Not activated by follower deployment; BoLD signer/bond lifecycle is separate | Independent review and deferred live acceptance |
| Robinhood | Implemented: Nitro mainnet/testnet follower with separate genesis pins | Permissioned admission and signing remain separate | Independent review and deferred live acceptance |
| Other 10 researched families | **Not implemented** | **Not implemented**, or N/A for the mapped network role | Follow the ordered roadmap |

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
