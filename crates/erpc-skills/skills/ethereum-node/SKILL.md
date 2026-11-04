---
name: ethereum-node
description: Running an Ethereum node -- hardware, and the Ethereum mainnet RPC node erpc runs (Reth and Lighthouse, full or archive) with `erpc r --chain eth`.
---

# Ethereum node

| Node | CPU | RAM | Disk |
|---|---|---|---|
| Full node | 4 cores or more | 32 GB | 4 TB NVMe, plus about 200 GB for the beacon chain |
| Validating | 8 cores or more | 64 GB | as above |

Source: ethereum.org (EIP-7870). Compare with ERPC's catalogue and stock (`server_catalog`, `server_stock`); say plainly
when no product meets it.

## Ethereum RPC node with erpc (mainnet)

`erpc rpc --chain eth` (`erpc r --chain eth`) runs an Ethereum mainnet RPC node: Reth (execution,
serves JSON-RPC on 8545 and WebSocket on 8546) and Lighthouse (consensus, checkpoint-synced from
Sigma Prime's server), on one Ubuntu 24.04+ host.

- `init -n mainnet --name <name> --host <ip> --type full|archive --rpc-allow <cidrs>`: checks the
  server (Ubuntu 24.04 or later, because Reth's release needs glibc 2.38; an x86-64-v3
  processor; 32 GB memory; sudo), pins the Reth and Lighthouse releases (tag, commit, archive
  SHA-256), stores the node in 1Password and prepares the host (users `reth` and `lighthouse`,
  the free disk at /var/lib/ethereum). `full` is pruned (the usual RPC; about 1 TB today, give it
  2 TB): every block and transaction, but receipts, logs and state history for the last 10,064
  blocks only (about 1.4 days), so older `eth_getTransactionReceipt` answers null and older
  `eth_getLogs` nothing; `archive` keeps everything and serves `debug` and `trace` (about 3 TB today, give it
  4 TB). The type is fixed once stored.
- `deploy`: installs both releases, each checked against its digest and its GPG signature, makes
  the engine JWT on the node, fetches Reth's official snapshot into the empty datadir (about
  730 GB for full, 1.8 TB for archive), starts Reth then Lighthouse, and applies the firewall
  (RPC only from `--rpc-allow`, SSH from `--management-allow` and erpc's own address, metrics
  from `--monitoring-allow`, peer-to-peer open) under a rollback timer.
- `status` (both layers, Reth's head against Lighthouse's, sync, peers, disk; exits 5 on a
  problem), `logs [--layer execution|consensus|both] [--lines N] [-f]`, `start`, `stop`,
  `restart [--layer …]`, `update [--reth-version …] [--lighthouse-version …]` (rolls back when
  the new pair does not come up), `update-config` (allow lists), `plan`, `destroy [--purge-data
  [--forget]]`, `list`.
- Mainnet changes need `--chain eth` on the command line itself. the RPC backend runs on
  mainnet only; the separately owned validator backend supports Hoodi and mainnet.

What every chain's commands share (1Password, the SSH agent and `--ssh-key` after the verb, the
firewall's two-minute rollback, `plan`, `--yes`, `--json`, repeating a verb) is in the skill
`erpc-nodes`.

## Sizes and times

Measured on mainnet in October 2026 (32 cpus, 128 GB, a 1.7 TB NVMe), type `full`:

- `init`: two or three minutes. `deploy` to both layers up: about 37 minutes, most of it Reth's
  snapshot (680 GB in 749 archives, about 31 minutes at some 350 MB/s, then unpacking).
- On disk afterwards: about 990 GB, leaving some 860 GB of the 1.7 TB free.
- Lighthouse is synced within a couple of minutes of starting (checkpoint sync).
- Reth then rebuilds its transaction lookup from block 0 before its head moves: its head stays
  at the snapshot's block for hours (about 2.5 hours from the last restart to caught up), and a
  restart in that time starts the rebuild again. That is expected, not a stuck node.
- Memory: Reth uses about 7 GB (`status` may show far more, which is page cache); Lighthouse 1
  to 7 GB.
- `archive` was not measured: its snapshot is about 1.8 TB to download and about 3 TB on disk.

## When something fails

- `update` that does not come up puts the node back on the pair that ran, and 1Password keeps
  the old pins. `logs --layer execution` or `--layer consensus` says why.
- Reth's head not moving for hours right after deploy is the lookup rebuild above; restarting
  it only starts it over.
- After a reboot both layers and the firewall come back on their own.

For RPC access without a node, ERPC's shared RPC covers Ethereum (skill `erpc-services`).

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a node erpc runs, the release it
pinned is the one `init`, `update` and `status` show.

- https://github.com/paradigmxyz/reth and https://reth.rs/run/system-requirements: Reth, the
  execution client
- https://github.com/sigp/lighthouse and https://lighthouse-book.sigmaprime.io/installation.html:
  Lighthouse, the consensus client

## Ethereum validator backend

`erpc v --chain eth` owns a dedicated Reth/Lighthouse BN/VC host, separate from RPC
inventory. Hoodi and mainnet code paths have offline checks; real-host acceptance
is deferred. Use `init`, `deploy`, `list`, `status`, `logs`, `start`, `stop`, `restart`,
`plan`, `update`, `update-config`, and `destroy`. Mainnet mutations need explicit
`--chain eth`. Deploy and updates leave the signer stopped; start is explicit.

One key per host: `keys-import --keystore <file> --password-file <file>
--slashing-history <file> --new-key` accepts only never-used keys with matching empty
EIP-3076 history and a synced network check. Existing managed keys move with
`migrate --to <prepared-host>`: fence/stop the source, export current history, import
the target, leave it stopped. Never recreate missing history, bypass a fence or use
withdrawal recovery material online. Original key/password files and host custody
need backups; the metadata inventory does not store signing secrets.

`deposit-review --deposit-data <file> --withdrawal-address <address>` validates
network, amount, withdrawals, SSZ and BLS for one initial 32 ETH deposit. It never
submits. Check pending deposits outside beacon state before signing/broadcasting
through the official staking launchpad. `status` distinguishes service readiness
from beacon activation. Downgrades/prereleases are refused, automatic database
rollback is not used, and destroy retains custody/history. Use one controller per
network vault; local inventory locks do not provide a distributed global key lease.

Operator instructions: `docs/ethereum-validator.md` in this repository.
