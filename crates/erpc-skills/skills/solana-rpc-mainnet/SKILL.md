---
name: solana-rpc-mainnet
description: Running a Solana mainnet RPC node of one's own with erpc r --chain solana -- a new node on the native backend (Agave, HTTP and WebSocket for the addresses allowed), a node already recorded on the solv backend (index, Geyser gRPC, Old Faithful), the server and ERPC bare metal it needs, the tuning it shares with validators, and when ERPC's RPC, gRPC or shreds plans fit better than a node.
---

# Solana RPC node, mainnet

First ask what the node is for. An app or a bot that only calls RPC usually does better with
ERPC's plans than with a node of its own (skill `erpc-services`): shared RPC, Unlimited RPC on a
VPS of its own, Dedicated RPC on bare metal run by ERPC, Geyser gRPC or shreds when data must be
pushed or arrive sooner. A node of their own is for full control.

## Two backends

`erpc rpc --chain solana` (`erpc r --chain solana`) runs the node. How depends on what the
inventory holds under its name:

- Nothing yet: a **native** node. Agave built on the server, serving JSON-RPC on 7211 and
  WebSocket on 7212 to the addresses in `--rpc-allow`, with transaction history. It has no
  types: no account indexes, no Geyser gRPC, no Old Faithful, and no client but Agave. Every new
  node is one; `--backend solv` cannot start a new node. For indexes or gRPC, point to ERPC's
  plans.
- A node that an earlier erpc set up: the **solv** backend, with the type and client it was set
  up with ("A node recorded as solv" below).

`erpc --json r --chain solana list` gives each node's `backend`. What every chain's commands share
(1Password, the SSH agent and `--ssh-key` after the verb, the two-minute firewall rollback,
`plan`, `--yes`, `--json`) is in the skill `erpc-nodes`.

## Hardware

| Node | What it needs | ERPC server |
|---|---|---|
| New node (native); `init` refuses less | Ubuntu 24.04 and no other release, systemd 255, x86-64 with AVX2 and SHA-NI, 32 threads, 480 GiB of memory as the kernel reports it, and three separate ext4 or XFS filesystems: accounts 900 GB, ledger 900 GB, snapshots 450 GB | bare metal RPC |
| Index RPC (solv only) | 32 cores or more, 768 GB of RAM (1152 GB to be stable), large high-endurance NVMe | bare metal RPC+ / RPC++ |

Check ERPC's stock (`server_stock`, kind `bare_metal`, type RPC) for what is free, and compare
threads, memory and disks with the catalogue (`server_catalog`), whatever the server type is
called. 512 GB or more and a 2.8 GHz+ clock are worth having (SLV's Solana guides). A VPS is
never enough.

## A new node (native)

The server also needs the three filesystems mounted and empty at `/mnt/erpc-solana-accounts`,
`/mnt/erpc-solana-ledger` and `/mnt/erpc-solana-snapshots` (erpc does not partition, format or
mount disks), no `solv` user and nothing under `/etc/erpc`, and a login with passwordless sudo
(`--user`, `ubuntu` by default) whose key an SSH agent holds.

erpc makes no key on this path. Before `init` the operator puts the node's identity, a Solana
JSON keypair, in a concealed 1Password field and passes its reference by id (the 26-character
vault and item ids, not names) and its public key. An RPC node has no vote account, sync key or
commission. The name is lowercase letters, digits and `-`, a letter first, 32 characters at
most; `--vault` is needed only the first time on a network; `-n testnet` works the same way.

```sh
erpc r --chain solana -n mainnet --name <name> init --host <address> \
  --ssh-key ~/.ssh/id_ed25519.pub --vault <vault id> \
  --identity-reference op://<vault-id>/<item-id>/keypair --identity-public <key> \
  --accounts-uuid <uuid> --ledger-uuid <uuid> --snapshots-uuid <uuid> \
  --rpc-allow <client ranges> --management-allow <your ranges>
erpc r --chain solana -n mainnet --name <name> deploy --ssh-key ~/.ssh/id_ed25519.pub
erpc r --chain solana -n mainnet --name <name> status --ssh-key ~/.ssh/id_ed25519.pub
```

1. `init` asks first, then checks the platform and the three filesystems (given by UUID, the
   name under `/dev/disk/by-uuid`), records the node as one item in 1Password (the reference and
   public key, no key), and prepares the server: build tools and nginx from apt, accounts that
   cannot log in, a data directory on each filesystem, four kernel settings and the clock
   service. It starts no node. The same command again resumes it.
2. `deploy` builds Agave from source on the server (4.4.0 with this erpc; `plan` shows the
   target), under its builder account and on two CPU cores. The server stops a source fetch
   after 30 minutes and a compile after four hours; erpc waits and says so each minute. If the
   command is interrupted the build goes on: run the same command again, and read it with
   `logs --component build`. A failed build is dropped with `deploy --abandon-build` before
   another can start. Then deploy applies the firewall and confirms it over a new SSH
   connection, reads the identity keypair from 1Password and sends it over SSH to the server,
   which keeps it encrypted for that machine, and starts Agave, not voting, and its gateway. A
   second `deploy` builds again and restarts the node.
3. `status` prints a JSON report and exits 5 until `rpc_ready` is true: the node on the right
   network under its identity and the pinned version, healthy, a finalized block at most 120
   seconds old, and the gateway answering. Exit 1 means erpc could not ask the node.

After `deploy`, 7211 and 7212 answer only the `--rpc-allow` ranges (nobody, when there are
none), as plain HTTP and WebSocket: TLS belongs on a gateway of the operator's in front. The SSH
port answers only the address erpc connected from and the `--management-allow` ranges, so give a
stable range and keep the provider's console at hand. Ports 8000 to 8032 are open to peers, and
Agave's own RPC ports, 8899 and 8900, are closed. erpc's table covers only these ports; every
other port on the server is left to the server's own rules.

Operating it: `logs --component node|gateway|firewall|build` (`--lines` up to 1000), `stop`,
`start`, `restart`, `update` (builds the release this erpc pins), `update-config --rpc-allow …
--management-allow …` (each replaces its list; `--clear-rpc-allow` empties it), `plan --change
deploy|update|update-config`, and `destroy`, which stops and retires the node and keeps its
data, its key on the server and the firewall; `deploy` brings it back.

A native node refuses `--type`, `--client jito`, `--version`, `--geyser-version`,
`--monitoring-allow`, `logs -f`, `--service faithful` and `destroy --purge-data`.

## A node recorded as solv

It keeps its commands. The client is `jito` or `agave`; the type is `send-tx`, `index` (account
indexes and history, with Old Faithful on 8888), `grpc` (Yellowstone gRPC on 10000) or
`index-grpc`; JSON-RPC is on 7211, WebSocket on 7212. Firedancer is not offered for RPC:
Frankendancer ends with Alpenglow, and the full Firedancer's own RPC has no sendTransaction,
history, indexes or Geyser plugins.

- `init` and `deploy` resume or repeat as before; an Index node's first deploy also fills Old
  Faithful's index cache, for up to four hours.
- `status` (health, slot, identity, Old Faithful, gRPC, firewall; exits 5 on a problem),
  `logs [--source validator|journal|faithful|firewall] [--lines N] [-f]`,
  `start|stop|restart [--service validator|faithful]`, `update [--version <tag>]
  [--geyser-version <tag>]` (builds the new release in place, then restarts; a failed build
  leaves the running client as it was), `update-config --rpc-allow … --monitoring-allow …`,
  `plan --change deploy|update|update-config`, `destroy [--purge-data]` (the 1Password item
  stays).
- Its firewall table is `erpc_solana_rpc`: 7211, 7212, 10000 and 8888 from `--rpc-allow`,
  metrics (9100 node exporter, 8999 the Geyser plugin) from `--monitoring-allow`, SSH from
  `--management-allow` and erpc's own address, and agave's ports 8000–8030 from anyone.
- `deploy`, `update`, `update-config` and `destroy` now stop at the firewall step, changing
  nothing, while `/etc/systemd/system/solv.service.d` (or the same directory of
  `faithful.service` or `of1-index-sync.service`) holds a file other than erpc's
  `50-erpc-firewall-guard.conf`. Move the operator's own drop-in out of that directory and run
  the command again.
- `erpc r --chain solana migration plan|inspect|execute|resume|status` moves a solv node to
  the native backend. `plan` reports anything but an Agave `send-tx` node without Geyser or Old
  Faithful as unsupported, and that node stays on solv; so does one whose Agave was not built
  from 4.3.2, the only mainnet origin this erpc accepts, or whose startup configuration
  `migration inspect` does not accept. `docs/solana-native.md` in erpc's repository has the
  procedure.

SLV's DoubleZero, richat and SHA-256 patch are not in erpc: SLV still does those.

## When something fails, and tuning

- A node that is behind after a restart is catching up; send traffic back only when `status`
  says it is caught up. Restart one node at a time.
- The box is tuned like a validator's (SMT off, CPU boost, IRQ pinning: skill
  `solana-validator-mainnet`), checked with `slv check boost -t rpc -n mainnet`. erpc's
  32-thread floor counts the CPUs the running kernel has online.

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a native node, `plan` shows the
release it would be built from and `status` the one it runs; `erpc --json r --chain solana list`
gives a solv node's `version`.

- https://github.com/anza-xyz/agave and https://docs.anza.xyz/operations/setup-an-rpc-node: Agave
  and Anza's RPC node guide
- https://github.com/jito-foundation/jito-solana and https://docs.jito.wtf/: Jito
- https://github.com/rpcpool/yellowstone-grpc: the Yellowstone gRPC (Geyser) plugin
- https://github.com/rpcpool/yellowstone-faithful: Old Faithful, the history archive
