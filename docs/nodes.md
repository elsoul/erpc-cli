<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Running nodes: `erpc validator` and `erpc rpc`

Every node type has the same verbs:

| Verb | What it does |
|---|---|
| `init` | Check the server, pin client releases, store the node in 1Password and prepare the host |
| `deploy` | Install the client, fetch a snapshot, apply the firewall and start the node |
| `list`, `status`, `logs` | Inventory, health and journal |
| `start`, `stop`, `restart` | Service control, in the right order for nodes with several layers |
| `update` | Move to another client release; rollback policy depends on the client |
| `update-config` | Write the configuration and firewall again, restarting only on a change |
| `plan` | Show what `deploy`, `update` or `update-config` would change |
| `destroy` | Stop and remove services; chain data only with `--purge-data`; Avalanche preserves identities and firewall |

## Choosing the chain, network and host

Pick the chain with `--chain`, `ERPC_CHAIN` or the `default_chain` setting,
the network with `-n`, and the host with `--name`. A change to mainnet needs
`--chain` written on the command line.

| Chain | Command | Clients | Networks |
|---|---|---|---|
| Solana | `erpc validator` | Agave, Jito, Firedancer | mainnet, testnet, devnet |
| Solana | `erpc rpc --chain solana` | Agave, Jito, Firedancer | mainnet, testnet, devnet |
| Ethereum | `erpc validator --chain eth` | Reth + Lighthouse BN/VC; see [validator guide](ethereum-validator.md) | Hoodi, mainnet (live acceptance deferred) |
| Ethereum | `erpc rpc --chain eth` | Reth + Lighthouse; `--type full` or `archive` | mainnet |
| Sui | `erpc rpc/node/validator --chain sui` | Full node with gRPC; validator custody and external registration; [operations guide](../crates/erpc-chain-sui/templates/README.md) | mainnet, testnet (live acceptance deferred) |
| TRON | `erpc rpc/validator --chain tron` | Native full-node APIs; delegated SR custody and external registration; [operations guide](../crates/erpc-chain-tron/templates/README.md) | mainnet, nile (live acceptance deferred) |
| Avalanche | `erpc rpc/node/validator --chain avax` | AvalancheGo; [operations and external registration](avalanche.md) | mainnet, fuji (live acceptance deferred) |
| Bitcoin | `erpc rpc --chain bitcoin` | Bitcoin Core; full/txindex or explicit pruned | mainnet, testnet4, signet, regtest (live acceptance deferred) |
| Optimism | `erpc rpc --chain optimism` | op-reth + op-node follower; [operations guide](op-follower-rpc.md) | mainnet, sepolia (live acceptance deferred) |
| Base | `erpc rpc --chain base` | Base-specific execution/consensus follower | mainnet, sepolia (live acceptance deferred) |
| Soneium | `erpc rpc --chain soneium` | Source-qualified OP-family follower | mainnet, minato (live acceptance deferred) |
| Arbitrum | `erpc rpc --chain arbitrum` | Nitro follower; [operations guide](nitro-rpc.md) | mainnet, nova, sepolia (live acceptance deferred) |
| Robinhood | `erpc rpc --chain robinhood` | Nitro follower with network-specific chain/genesis pins | mainnet, testnet (live acceptance deferred) |
| Arc | `erpc rpc --chain arc` | Arc execution + consensus; `--type full`, `archive` or `provider` | testnet |

The [chain source map](chains/README.md) separates network capabilities from
CLI implementation. The [implementation roadmap](plans/2026-10-26-chain-implementation.md)
starts with Ethereum validators, then Avalanche nodes and validators.

Bitcoin setup and acceptance limits are in the [Bitcoin RPC guide](bitcoin-rpc.md).

Solana validators also have `keys` (show, make or import the vote account
key and withdraw authority) and `vote-account` (create it on chain).

How erpc handles a server:

- It logs in over SSH as a sudo user (`ubuntu` by default) with your key,
  from the 1Password SSH agent or `SSH_AUTH_SOCK`, and pins the host key the
  first time.
- The client runs as its own system user that cannot log in. Solana is the
  exception: its clients run as `solv`, a login user with an SSH key and
  passwordless sudo, and erpc logs in as that user after the first run.
- Client releases are pinned by version and checksum, and checked before they
  are installed. Solana is the exception: its plays install `node_exporter`
  and rustup without checking a checksum.
- The firewall is nftables, on RPC nodes other than Bitcoin and on Avalanche,
  Sui and TRON validators. erpc applies no firewall to Solana validators,
  Ethereum validators or Bitcoin nodes, so filtering those hosts is yours to
  do. Where it applies, it has a timed rollback that is cancelled
  only once a fresh connection gets in. For Ethereum, Arc and Solana RPC,
  a short preparation is confirmed before long deployment work starts.
  Confirmation is bound to the submitted run and bundle digest and checks the
  live rules. The deployment checks the same receipt before its first mutation. Delayed confirmations and superseded rollback timers cannot accept
  a different operation. If rollback cannot restore a previous policy, the
  affected node services are stopped and disabled before filtering is removed.
  Root-owned startup guard overrides are installed before applying a policy,
  including when upgrading legacy services. Destroy uses the same fence.
  Startup requires matching live rules, and boot recovery loads only a confirmed
  policy;
  retry deployment after correcting the management ranges.
- Keys and the node inventory are kept in 1Password. Secrets reach the
  server over standard input, never on a command line.

