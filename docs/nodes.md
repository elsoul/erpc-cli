<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Running nodes: `erpc validator` and `erpc rpc`

Every node type has the same verbs. The exception is a Solana validator
recorded on the Solv backend, which has only `init`, `deploy`, `list` and
`status` of them:

| Verb | What it does |
|---|---|
| `init` | Check the server, pin client releases, store the node in 1Password and prepare the host |
| `deploy` | Install or build the client, fetch a snapshot, apply the firewall where erpc has one for that node, and start the node |
| `list`, `status`, `logs` | Inventory, health and journal |
| `start`, `stop`, `restart` | Service control, in the right order for nodes with several layers |
| `update` | Move to another client release; rollback policy depends on the client |
| `update-config` | Apply configuration and access changes using the chain's restart rules |
| `plan` | Show the chain's deployment or configuration plan |
| `destroy` | Stop or retire owned services; data, key and firewall retention follow the chain's operations guide |

## Choosing the chain, network and host

Pick the chain with `--chain`, `ERPC_CHAIN` or the `default_chain` setting,
the network with `-n`, and the host with `--name`. A change to mainnet needs
`--chain` written on the command line.

| Chain | Command | Clients | Networks |
|---|---|---|---|
| Solana | `erpc validator --chain solana` | Isolated native Agave, explicit voting activation; [operations guide](solana-native.md). Existing Solv hosts keep their recorded backend. | mainnet, testnet (native live acceptance deferred) |
| Solana | `erpc rpc --chain solana` | Isolated native Agave with HTTP/WebSocket ingress; existing Solv configurations remain explicit | mainnet, testnet (native live acceptance deferred) |
| Ethereum | `erpc validator --chain eth` | Reth + Lighthouse BN/VC; see [validator guide](ethereum-validator.md) | Hoodi, mainnet (live acceptance deferred) |
| Ethereum | `erpc rpc --chain eth` | Reth + Lighthouse; `--type full` or `archive`; [original authority and migration](ethereum-rpc.md) | mainnet (new authority live acceptance deferred) |
| Sui | `erpc rpc/node/validator --chain sui` | Full node with gRPC; validator custody and external registration; [operations guide](../crates/erpc-chain-sui/templates/README.md) | mainnet, testnet (live acceptance deferred) |
| Polygon PoS | `erpc rpc/validator --chain polygon` | Bor + Heimdall v2 RPC/sentry and admitted validator; [RPC guide](../crates/erpc-chain-polygon/templates/README.md), [validator guide](polygon-validator.md) | mainnet, amoy (live acceptance deferred) |
| TRON | `erpc rpc/validator --chain tron` | Native full-node APIs; delegated SR custody and external registration; [operations guide](../crates/erpc-chain-tron/templates/README.md) | mainnet, nile (live acceptance deferred) |
| Monad | `erpc rpc/validator --chain monad` | Native execution, consensus and RPC; dedicated raw partition and external validator registration; [operations guide](monad-node.md) | mainnet, testnet (live acceptance deferred) |
| Avalanche | `erpc rpc/node/validator --chain avax` | AvalancheGo; [operations and external registration](avalanche.md) | mainnet, fuji (live acceptance deferred) |
| Kaia | `erpc rpc --chain kaia`, `erpc validator --chain kaia` | Qualified endpoint node and dedicated CN/PN; [RPC](kaia-rpc.md), [core-cell operations](kaia-core-cell.md) | mainnet, kairos (live acceptance deferred) |
| Bitcoin | `erpc rpc --chain bitcoin` | Bitcoin Core; full/txindex or explicit pruned | mainnet, testnet4, signet, regtest (live acceptance deferred) |
| Optimism | `erpc rpc --chain optimism` | op-reth + op-node follower; [operations guide](op-follower-rpc.md) | mainnet, sepolia (live acceptance deferred) |
| Base | `erpc rpc --chain base` | Base-specific execution/consensus follower | mainnet, sepolia (live acceptance deferred) |
| Soneium | `erpc rpc --chain soneium` | Source-qualified OP-family follower | mainnet, minato (live acceptance deferred) |
| BSC | `erpc rpc --chain bsc`, `erpc validator --chain bsc` | Network-qualified Geth; [RPC](bsc-rpc.md), [validator](bsc-validator.md) | mainnet, chapel (live acceptance deferred) |
| Arbitrum | `erpc rpc --chain arbitrum` | Nitro follower; [operations guide](nitro-rpc.md) | mainnet, nova, sepolia (live acceptance deferred) |
| Arbitrum One | `erpc validator --chain arbitrum` | Original dedicated MakeNodes signer; observing default and external funding; [operations guide](arbitrum-validator.md) | mainnet only (live acceptance deferred) |
| Robinhood | `erpc rpc --chain robinhood` | Nitro follower with network-specific chain/genesis pins | mainnet, testnet (live acceptance deferred) |
| Robinhood admission | `erpc v --chain robinhood registration` | Public allowlist observation and unsigned external administrator intent; [guide](robinhood-admission.md) | mainnet, testnet (live acceptance deferred) |
| Robinhood Defensive | `erpc v --chain robinhood` | Dedicated admitted validator; observing default, explicit original-key Defensive activation; [guide](robinhood-defensive-validator.md) | mainnet, testnet (live acceptance deferred) |
| NEAR | `erpc rpc --chain near`, `erpc validator --chain near` | nearcore follower and dedicated validator; [RPC](near-rpc.md), [validator](near-validator.md) | mainnet, testnet (live acceptance deferred) |
| Hyperliquid | `erpc rpc --chain hyperliquid`, `erpc validator --chain hyperliquid` | Signed supervisor, dedicated consensus hot signer and separate AQA publisher; [RPC](hyperliquid-rpc.md), [validator](hyperliquid-validator.md), [AQA](hyperliquid-aqa.md) | mainnet, testnet (live acceptance deferred) |
| Arc | `erpc rpc --chain arc`; `erpc v --chain arc` | [Original RPC runtime](arc-runtime.md); [dedicated validator preparation](arc-validator.md), production signing held | mainnet, testnet (live acceptance deferred) |

The [chain source map](chains/README.md) separates network capabilities from
CLI implementation and says where each chain stands.

Bitcoin setup and acceptance limits are in the [Bitcoin RPC guide](bitcoin-rpc.md).

For native Solana validators, `keys` shows the original public accounts without
inspecting custody. Existing Solv validators retain their legacy key create/import
and testnet `vote-account` workflows; a pending migration fences those operations.
[Public registration checks](solana-registration.md) prepare and validate actions
signed and submitted with official external tools.

How erpc handles a server:

- It logs in over SSH as a sudo user (`ubuntu` by default) with your key,
  from the 1Password SSH agent or `SSH_AUTH_SOCK`, and pins the host key the
  first time.
- Every file it uploads is written by a Python program run through `sudo`, so
  the server needs `/usr/bin/python3` and a login whose `sudo` asks for no
  password. `/opt` must already be a real directory owned by root that neither
  its group nor others can write, as Ubuntu ships it; erpc does not create it.
  `/opt/erpc` and the `runs` and `uploads` directories erpc makes in it are
  held to the same rule, and none of these may be a symbolic link: to keep
  them on another volume, mount the volume at `/opt/erpc`. For a node, the
  filesystem that holds `/opt/erpc` must also keep POSIX ACLs (ext4 and XFS
  do by default): erpc grants the login read access to each run's files with
  an ACL and stops if the filesystem does not keep it.
- New native backends use dedicated, unprivileged runtime accounts. Existing
  Solv hosts retain their recorded account layout until an explicit qualified
  migration: the client runs as `solv`, a login user with an SSH key and
  passwordless sudo, and erpc logs in as that user after the first run.
- Releases are pinned by version and checksum, and checked before they are
  installed. A new Solana node is built on the server from a pinned source
  commit instead, with its `Cargo.lock` and the compiler archives checked by
  digest. A host on the Solv backend is the exception: its client is built at
  a pinned tag and commit with no checksum, and its plays download
  `node_exporter` at a fixed version with no checksum and run the rustup
  installer unpinned.
- erpc applies no firewall to Solana validators on the Solv backend, Ethereum
  validators or Bitcoin nodes, so filtering those hosts is yours to do. Where
  it applies one, the firewall is nftables, with a timed rollback that is
  cancelled only once a fresh connection gets in. For Ethereum, Arc and Solana RPC,
  a short preparation is confirmed before long deployment work starts.
  Confirmation is bound to the submitted run and bundle digest and checks the
  live rules. The deployment checks the same receipt before its first mutation. Delayed confirmations and superseded rollback timers cannot accept
  a different operation. If rollback cannot restore a previous policy, the
  affected node services are stopped and disabled before filtering is removed.
  Root-owned startup guard overrides are installed before applying a policy,
  including when upgrading legacy services. Destroy uses the same fence.
  Newly generated guards and rollback timers validate every helper-path ancestor
  and the opened root-owned, nonwritable regular file before interpreting its
  bytes. Unrelated sibling release pointers remain supported. Exact known legacy
  guards are upgraded before filter-removing rollback; a rollback that finds
  a changed guard or another drop-in leaves the filter in place. Replacing a
  helper alone does not rewrite already scheduled legacy timer commands.
  The guard is a drop-in, `50-erpc-firewall-guard.conf`, in
  `/etc/systemd/system/<unit>.d/` of each service the firewall protects, and it
  must be the only file there. While one of those directories holds any other
  file, such as an `override.conf` that `systemctl edit` made, the firewall step
  refuses and changes nothing, and on every node erpc filters the command that
  applies or removes the firewall stops there: on a Solana RPC node on the
  Solv backend, for example, `deploy`, `update`, `update-config` and
  `destroy`. Move your drop-in out of the directory and run the command again.
  Startup requires matching live rules, and boot recovery loads only a confirmed
  policy;
  retry deployment after correcting the management ranges.
- The node inventory and the original-key backups specified by each chain's
  guide are kept in 1Password. Runtime credentials and some persistent peer
  identities also reside on the node. Preserve original host keys, chain data
  and signing history according to that guide. Secrets sent by the controller
  reach the server over standard input, never on a command line.

For new Solana hosts, see [native RPC and validator nodes](solana-native.md).
Existing Solv hosts keep their recorded backend until an explicit qualified migration.

## Where keys are kept

This table is about node hosts; `SECURITY.md` covers the operator's machine. Not
every key is in 1Password, and a node may hold a key it needs to run. Back up
what is on a host yourself: rebuilding that host without a backup loses it. An
active Sui validator or an elected TRON witness also refuses to move to a new
host, so rebuilding one is not a quick redeploy. Each chain's guide says how to
restore its keys.

| Node | In 1Password | On the host |
|---|---|---|
| Solana validator (native) | The identity and the sync keypair you made. The vote account and withdraw authority are given to erpc as public keys only | The sync keypair, encrypted to that host, and from `--activate-validator` on the identity too. The vote account and withdrawal keys are never imported |
| Solana validator (solv) | Staked identity, and the withdraw authority unless you give only its public key. The vote account key is deleted once the account is verified | A throwaway `unstaked-identity.json` in plain text. A deploy never copies the staked key or the withdraw authority to the node |
| Solana RPC (native) | The identity you made | The same identity, encrypted to that host |
| Solana RPC (solv) | The inventory | The identity, made there; it never leaves |
| Ethereum validator | The inventory | Keystores, their unlock password and the slashing history. A backup's history stops at its snapshot, so restoring a key that signed after it can be slashed: move a signer with `erpc v --chain eth migrate` |
| Arc RPC | The consensus key | The consensus key, encrypted |
| Arc validator | The local peer identity | The same identity, encrypted to that host. Consensus signing stays with the external signer |
| Avalanche | A backup of the staking and BLS keys | The same keys, made there on the first deploy |
| Sui validator | The protocol, network and worker keys, made on your own machine | The same three keys, encrypted with `systemd-creds` to that host; never the account key |
| Sui full node | The inventory | The network credential, encrypted to that host; there is no other copy |
| TRON witness | The encrypted keystore and its password | The same, as encrypted systemd credentials |
| Polygon validator | The signer key `init` generates. The staking owner's key is never asked for | The same key, encrypted to that host. While it only observes, the node runs under a separate identity |
| BNB Chain validator | A backup of the signing material and the peer identity | The consensus key in an encrypted keystore, the vote key in an encrypted wallet, and their passwords encrypted to that host |
| Kaia validator (consensus or proxy node) | A backup of the node identity | The node identity, made on the host and encrypted to it. The operator's wallets stay outside erpc |
| Monad node (RPC or validator) | Both original keystores | The same keystores, encrypted to that host |
| Hyperliquid validator | The hot consensus key. The cold account's key is never asked for | The hot key, encrypted to that host and loaded only by activated validator units |
| Hyperliquid AQA publisher | Its dedicated API or agent key | The same key, encrypted to that host |
| NEAR validator | The consensus key | The same key, encrypted to that host |
| Arbitrum validator | The wallet `init` generates, and the provider credential | The provider credential, encrypted, and from `--activate-signer` on the wallet too, root-owned and encrypted |
| Robinhood Chain validator | The wallet `init` generates, and the provider configuration | The provider configuration, encrypted, and from `--activate-signer` on the wallet too, root-owned and encrypted |
| OP-family RPC | The inventory and provider values | Provider credential, engine JWT and peer identities, encrypted; back up the owner record and the host's encryption secret |
| Nitro RPC | The inventory and upstream credential | The upstream credential, encrypted |

Other RPC nodes hold no signing key for a validator, but their hosts keep what
the client makes for itself, such as an engine JWT, a peer identity or an RPC
cookie.
