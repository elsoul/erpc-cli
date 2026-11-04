---
name: erpc-nodes
description: What every chain's node commands in erpc share -- erpc v / erpc r / erpc n, choosing the chain and network, the inventory in 1Password and where keys are kept, logging in over SSH (agent, --ssh-key, the host key), which nodes get the nftables firewall and its rollback, plan, --yes, --json, repeating a command safely, and reading a failure.
---

# Node commands: what every chain shares

The chain skills (`arc-rpc`, `solana-rpc-mainnet`, `solana-validator-testnet`,
`solana-validator-mainnet`, `ethereum-node`) say what is particular to each. This is the rest.

## Which command

- `erpc validator` (`erpc v`): validators on Solana, Ethereum, Avalanche, Sui and TRON.
- `erpc rpc` (`erpc r`): RPC nodes on Solana, Ethereum, Base, Optimism, Soneium, Arbitrum,
  Robinhood Chain, Avalanche, Bitcoin, Sui, TRON and Arc.
- `erpc node` (`erpc n`): Avalanche and Sui.

The chain comes from `--chain`, then `ERPC_CHAIN`, then `default_chain` in the config
(`erpc config set default_chain solana`). `erpc r` serves several chains, so without any of
these it asks at a terminal and fails in a script or with `--json`. A change on mainnet needs
`--chain` on the command line itself. `-n` (`--network`) and `--name` (the node's name in the
inventory) can go anywhere; a verb's own flags, the login ones included, come after the verb:

```sh
erpc r --chain arc -n testnet --name arc1 deploy --ssh-key ~/.ssh/id_ed25519.pub
```

## Where things are kept

The inventory (each node: address, SSH user and port, pinned host key, release pins, allow
lists, type) lives in 1Password, in one vault per network shared by every
chain: the first `init` on a network asks for it (`--vault`), and a different `--vault` later is
refused. erpc keeps none of it on the operator's disk. 1Password is the desktop app, or on a
machine without one a service account (`OP_SERVICE_ACCOUNT_TOKEN`), which reaches testnet only.

Keys differ by chain, and `docs/nodes.md` has the table. A Solana validator's staked identity is in
1Password, and so is its withdraw authority unless only a public key was given; a deploy never
copies either to the node. A Solana RPC
node's identity and an Ethereum validator's keystores and unlock password stay on the host, so
those hosts need backups. Keys sent to a node go over SSH standard input, never on a command
line; some hosts then store them.

## Logging in to the node

- erpc logs in through an SSH agent only: 1Password's agent when it runs, else `SSH_AUTH_SOCK`,
  or `--ssh-agent <socket>`. `--ssh-key` names the public key (`.pub`) the agent holds.
- The first contact shows the server's host key fingerprint; compare it with the provider's
  console, or pass `--fingerprint SHA256:…`. It is pinned in the inventory, and a different key
  later is refused.
- The SSH user needs passwordless sudo (`--user`, `ubuntu` by default; `--port` for another
  SSH port).
- `list` reads the inventory only and needs no login.

## The firewall

erpc applies no firewall to Solana validators, Ethereum validators or Bitcoin nodes: filtering
those hosts is the operator's job, so say so. Every other node gets an nftables firewall. On Solana,
Arc and Ethereum RPC nodes it is a table of its own with policy drop: SSH from `--management-allow`
and the address erpc connects from, the RPC ports from `--rpc-allow`, metrics from
`--monitoring-allow`, the chain's peer-to-peer ports as the chain needs, nothing else. A new
table rolls itself back after two minutes unless erpc reaches the node again over a fresh SSH
connection, so a mistake cannot lock the operator out for good; an established session survives
either way. Without `--management-allow` the only SSH source is the address erpc runs from: if
that changes, only the provider's console gets in, so suggest a stable range. `update-config`
replaces each list it is given and keeps the others.

## Asking first, seeing first, scripts

- Every verb that changes a node says what it will do and asks; `--yes` (`-y`) skips the
  question, for scripts.
- `plan --change deploy|update|update-config` (with the same flags) says what would change and
  changes nothing.
- `erpc --json …` (or `ERPC_JSON=true`) prints JSON. A failure is
  `{"error":{"code","exit","message","hint"}}` on stdout; branch on `code` (see "Exit codes").

## Repeating, and reading a failure

- Every verb is safe to run again: `init` resumes, `deploy` changes nothing when nothing changed
  and restarts a service only when its unit changed.
- The plays run on the node itself; a failed one names its run (`r-<time>-<id>`), the task that
  failed and the node's message. Fix the cause and run the same command again.
- An update that fails leaves the node on the release that ran (Arc and Ethereum put it back
  when the new release does not come up; Solana RPC builds the new one beside it first), and the
  pin in 1Password stays on the old release.
- `status` exits 5 (`problems_found`) and names each problem; `logs` shows the services' journal
  (`-f` follows).

## Exit codes

Every erpc command: 0 ok, 1 `failed`, 2 `usage`, 3 `needs_terminal` (pass `--yes`, or ask the
person to run it), 4 `not_signed_in` (`erpc login`), 5 `problems_found` (the report says which),
6 `declined` (the person said no: nothing was changed; do not retry on your own), 7 `network`
(retry later). Follow the `hint` when there is one.
