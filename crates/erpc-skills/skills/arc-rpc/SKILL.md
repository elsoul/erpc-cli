---
name: arc-rpc
description: Running an Arc RPC node (mainnet or testnet) with erpc r --chain arc -- its types (full, archive, provider), the server and disk it needs, how long and how big, init, deploy, status, logs, start/stop/restart, update and its rollback, update-config, plan, destroy -- its firewall, and reading what went wrong.
---

# Arc RPC node

All verbs are implemented, on mainnet and testnet alike, and were run on a real testnet
server (full and archive). A node is the execution layer (`arc-node-execution`, a Reth;
JSON-RPC on 8545 and WebSocket on 8546) and the consensus layer (`arc-node-consensus`),
joined over IPC sockets in /run/arc and run by systemd as the `arc` user.

## Types

`init --type` picks one, and it is fixed once stored (it decides what history the data holds):

- `full` (default): follows Arc's public relays, keeps the last 237,600 blocks; transactions go
  out through the relays.
- `archive`: follows the same way and keeps every block's history and state; the data only
  grows. Old state answers (`eth_getBalance` at an old block).
- `provider`: an RPC provider (relay) node Arc has onboarded: peers with Arc's sentries
  (`--trusted-peers <enode URLs>`, `--sentry-peers <multiaddrs>`, both from onboarding), opens
  30303 to everyone and 27000 to the sentries, and serves only `eth,net,web3,rpc`. Without
  onboarding there is nothing to peer with; suggest `full`.

`--debug-api` adds `debug` and `trace` (useful mostly on `archive`); refused on `provider`.
Keep `--rpc-allow` to your own proxies when it is on. `update-config --debug-api false` turns
it off, and `update-config` also replaces a provider's peers.

To change the type: `destroy --purge-data --forget`, then `init --type …` (the consensus key is
reused).

## The server

Ubuntu 24.04 or later (systemd 250+, for the encrypted consensus key; a TPM is used when there
is one), 64 GB of memory, an SSH user with passwordless sudo (`ubuntu` by default), and a data
disk: init takes a free NVMe of 800 GB or more for /var/lib/arc (mounted by UUID, so a change
of device names at boot does not matter). A disk with a file system on it is not free; a disk
with only empty partitions is, and init says it will remove them before it does. Without a
free disk the data goes on the root disk.

Sizes and times on testnet (October 2026):

| type | snapshot restore | execution | consensus |
|---|---|---|---|
| full | about 30 min | about 150 GB | about 105 GB |
| archive | about 50 min | about 730 GB | about 105 GB |

After the restore the node catches up from the snapshot's block at about 80 blocks a second,
a few minutes. Memory in use settles at 5 to 10 GB for the execution layer and well under 1 GB for the consensus layer.

## Commands

What every chain's commands share -- the inventory in 1Password and where keys are kept, logging in through an
SSH agent with the verb's `--ssh-key`, the host key, `plan`, `--yes`, `--json`, repeating a verb
-- is in the skill `erpc-nodes`. For Arc: pass `--chain arc` every time, and a node is named by
`-n` and `--name`:

```sh
erpc r --chain arc -n testnet --name arc1 <verb> --ssh-key ~/.ssh/id_ed25519.pub …
```

The consensus key lives in 1Password with the node's item; deploy puts it on the node encrypted
with systemd-creds.

## The path

1. `init --host <ip> [--type full|archive|provider] --rpc-allow <proxy ips>
   --management-allow <stable ssh range> [--monitoring-allow <ips>] [--version vX.Y.Z]`: shows
   the server's host key to check against its console (or takes `--fingerprint SHA256:…`),
   checks the server, pins the newest arc-node release (or `--version`) with its commit and
   archive digest, makes the consensus key in 1Password, and prepares the host. Running it
   again resumes and changes nothing.
2. `deploy`: installs the pinned release, restores the snapshot for the type, puts the
   consensus key in place encrypted with systemd-creds, starts both layers, applies the
   firewall, and confirms it from a fresh connection. Running it again changes nothing and
   restarts nothing; it restarts a layer only when its unit changed.
3. Operate:
   - `status`: both layers, the release that is actually serving, head and lag behind the
     public endpoint, data used and free, firewall and key. Exits 1 on a problem. Right after a
     start a lag of a few dozen blocks is normal; in steady state it is 0 or 1.
   - `logs [--layer execution|consensus|both] [--lines N] [-f]`.
   - `start|stop|restart [--layer execution|consensus]`: always in dependency order (the
     consensus layer needs the execution layer, so restarting execution restarts both).
   - `update [--version vX.Y.Z]`: installs beside the running release and restarts on it;
     going back to an older tag works the same way.
   - `update-config --rpc-allow … --management-allow … --monitoring-allow … --debug-api`:
     each list given replaces the stored one; ones not given stay. Opening monitoring also
     moves the metrics (9001, 29000) off loopback, so the layers restart once.
   - `plan --change deploy|update|update-config` (same flags): says what would change, changes
     nothing.
   - `destroy`: removes units, releases, firewall and the encrypted key; the data and the
     1Password items stay, and `deploy` brings the node back without a new snapshot (in under
     a minute). `--purge-data` deletes the chain data too; `--forget` (only with
     `--purge-data`) also removes the node's item and its pinned host key, so the next `init`
     asks for the host key again. The consensus key's item always stays. The `arc` user, the
     data disk's mount and the kernel and journald settings stay as well.

## The firewall

The table is `inet erpc_arc` (the rules and the two-minute rollback are in `erpc-nodes`): SSH from
`--management-allow` and erpc's own address, 8545 and 8546 from `--rpc-allow`, 9001 and 29000 from
`--monitoring-allow`; a provider node also opens 30303 to everyone and 27000 to its sentries.
After a reboot the table, the key and both layers come back on their own.

## When something fails

- `update` that does not come up rolls back by itself: erpc says "vX did not come up and was
  rolled back: arc1 runs vY again", and 1Password keeps the old pin. Read `logs` for why;
  running the same `update` again only repeats it.
- `start` that waits for "the execution layer made no IPC sockets": the execution layer did not
  come up; its `logs --layer execution` say why.
- A snapshot restore that stops: `logs` shows `arc-snapshots`; deploy again starts the fetch
  again (it is marked done only when it finishes).
- `status` problems name what is wrong: a layer inactive, the release serving not the pinned
  one, too far behind, less than 100 GB free, an unconfirmed firewall change.

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a node erpc runs, the release it
pinned is the one `init`, `update` and `status` show.

- https://github.com/circlefin/arc-node: the node's source; releases (tag, commit, archives)
  at https://github.com/circlefin/arc-node/releases
- https://docs.arc.io/arc/references/node-requirements: hardware and network; with
  https://docs.arc.io/arc/tutorials/run-an-arc-node and
  https://docs.arc.io/arc/tutorials/deploy-node-as-service (each page also as `.md`)
