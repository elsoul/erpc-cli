<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Running nodes: `erpc validator` and `erpc rpc`

Node types share these verbs. Solana validators have only `init`, `deploy`,
`list` and `status` of them so far, plus `keys` and `vote-account`.

| Verb | What it does |
|---|---|
| `init` | Check the server, pin client releases, store the node in 1Password and prepare the host |
| `deploy` | Install the client, fetch a snapshot, apply the firewall where erpc has one for that node, and start the node |
| `list`, `status`, `logs` | Inventory, health and journal |
| `start`, `stop`, `restart` | Service control, in the right order for nodes with several layers |
| `update` | Move to another client release; rollback policy depends on the client |
| `update-config` | Write the configuration, and the firewall where there is one, again, restarting only on a change |
| `plan` | Show what `deploy`, `update` or `update-config` would change |
| `destroy` | Stop and remove services; chain data only with `--purge-data`; Avalanche preserves identities and firewall |

## Choosing the chain, network and host

Pick the chain with `--chain`, `ERPC_CHAIN` or the `default_chain` setting,
the network with `-n`, and the host with `--name`. A change to mainnet needs
`--chain` written on the command line.

| Chain | Command | Clients | Networks |
|---|---|---|---|
| Solana | `erpc validator` | Agave, Jito, Firedancer | mainnet, testnet, devnet |
| Solana | `erpc rpc --chain solana` | Agave, Jito | mainnet |
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
CLI implementation.

Bitcoin setup and acceptance limits are in the [Bitcoin RPC guide](bitcoin-rpc.md).

Solana validators also have `keys` (show, make or import the vote account
key and withdraw authority) and `vote-account` (create it on chain).

How erpc handles a server:

- It logs in over SSH as a sudo user (`ubuntu` by default) with your key,
  from the 1Password SSH agent or `SSH_AUTH_SOCK`, and pins the host key the
  first time.
- The client runs as its own system user that cannot log in. Solana is the
  exception: its clients run as `solv`, a login user with an SSH key and
  passwordless sudo (Firedancer's service starts as root and is configured to
  run as `solv`), and erpc logs in as that user after the first run.
- Client releases are pinned by version and checksum, and checked before they
  are installed. Solana is the exception: its clients are built from source at
  a pinned tag and commit, with no checksum. Its plays also download
  `node_exporter` at a fixed version with no checksum, and run the rustup
  installer unpinned.
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
- The node inventory is kept in 1Password. Secrets reach the server over
  standard input, never on a command line.

## Where keys are kept

This table is about node hosts; `SECURITY.md` covers the operator's machine. Not
every key is in 1Password, and a node may hold a key it needs to run. Back up
what is on a host yourself: rebuilding that host without a backup loses it. An
active Sui validator or an elected TRON witness also refuses to move to a new
host, so rebuilding one is not a quick redeploy.

| Node | In 1Password | On the host |
|---|---|---|
| Solana validator | Staked identity, and the withdraw authority unless you give only its public key. The vote account key is deleted once the account is verified | A throwaway `unstaked-identity.json` in plain text. A deploy never copies the staked key or the withdraw authority there; the staked key arrives only if you put it on with SLV |
| Solana RPC | The inventory | The identity, made there; it never leaves |
| Ethereum validator | The inventory | Keystores, their unlock password and the slashing history; keep your original backups, and never restore keys without that history |
| Arc RPC | The consensus key | The consensus key, encrypted |
| Avalanche | A backup of the staking and BLS keys | The same keys, made there on the first deploy |
| Sui validator | The protocol, network and worker keys, made on your own machine | The same three keys, encrypted with `systemd-creds` to that host; never the account key |
| Sui full node | The inventory | The network credential, encrypted to that host; there is no other copy |
| TRON witness | The encrypted keystore and its password | The same, as encrypted systemd credentials |
| OP-family RPC | The inventory and provider values | Provider credential, engine JWT and peer identities, encrypted; back up the owner record and the host's encryption secret |
| Nitro RPC | The inventory and upstream credential | The upstream credential, encrypted |

Other RPC nodes hold no signing key for a validator, but their hosts keep what
the client makes for itself, such as an engine JWT, a peer identity or an RPC
cookie.

