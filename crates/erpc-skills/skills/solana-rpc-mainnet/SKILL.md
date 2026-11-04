---
name: solana-rpc-mainnet
description: Running a Solana mainnet RPC node of one's own with erpc r --chain solana -- standard, index, Geyser gRPC -- the hardware and ERPC bare metal it needs, the tuning it shares with validators, and when ERPC's RPC, gRPC or shreds plans fit better than a node.
---

# Solana RPC node, mainnet

First ask what the node is for. An app or a bot that only calls RPC usually does better with
ERPC's plans than with a node of its own (skill `erpc-services`): shared RPC, Unlimited RPC on a
VPS of its own, Dedicated RPC on bare metal run by ERPC, Geyser gRPC or shreds when data must be
pushed or arrive sooner. A node of their own is for full control, custom plugins or indexing.

## Hardware

| Node | CPU | RAM | Disk | ERPC server |
|---|---|---|---|---|
| RPC | 24 cores or more at 2.8 GHz+ | 512 GB or more | NVMe, accounts / ledger / snapshots apart, larger than a validator's | bare metal RPC |
| Index RPC | 32 cores or more | 768 GB, 1152 GB to be stable | large, high endurance | bare metal RPC+ / RPC++ |

Check ERPC's stock (`server_stock`, kind `bare_metal`, type RPC) for what is free, and compare RAM
and disk with the catalogue (`server_catalog`). A VPS is never enough. Source: SLV's Solana guides.

## Running it

erpc runs them on mainnet: `erpc rpc --chain solana` (`erpc r --chain solana`), the port of
`slv rpc`. The client is `jito` (default) or `agave`; the type is `send-tx`, `index` (account
indexes and history, with Old Faithful on 8888), `grpc` (Yellowstone gRPC on 10000) or
`index-grpc`. Firedancer is not offered for RPC: Frankendancer ends with Alpenglow, and the full
Firedancer's own RPC has no sendTransaction, history, indexes or Geyser plugins.
JSON-RPC is on 7211, WebSocket on 7212.

1. `erpc r --chain solana init -n mainnet --name rpc1 --host <ip> --type index --client jito
   --ssh-key <key.pub> --rpc-allow <proxy ips> --management-allow <stable ssh range>`: checks the
   server, measures Jito's regions, pins the client tag and commit (and the Yellowstone plugin
   built for that agave, and Old Faithful with its binary's SHA-256), stores the node in
   1Password and makes the `solv` user.
2. `erpc r --chain solana deploy -n mainnet --name rpc1 --ssh-key <key.pub>`: shows which free
   disks become /mnt/ledger, /mnt/accounts and /mnt/snapshot and asks, builds the client from
   source (an hour or more), makes the node's own identity (it never leaves the node), fetches a
   snapshot into an empty ledger (the freshest and fastest of the ERPC mirrors and Avorio's
   public mirror; the validator fetches one itself when none answers), starts the services and applies the firewall. An Index node's
   first deploy also fills Old Faithful's index cache, for up to four hours.
3. Operate: `status` (health, slot, identity, Old Faithful, gRPC, firewall; exits 5 on a problem),
   `logs [--source validator|journal|faithful|firewall] [--lines N] [-f]`,
   `start|stop|restart [--service validator|faithful]`, `update [--version <tag>]
   [--geyser-version <tag>]` (builds the new release in place, then restarts; a failed build
   leaves the running client as it was), `update-config --rpc-allow … --monitoring-allow …`,
   `plan --change deploy|update|update-config`, `destroy [--purge-data]` (the 1Password item
   stays).

What every chain's commands share (1Password, the SSH agent and `--ssh-key` after the verb, the
firewall and its two-minute rollback, `plan`, `--yes`, `--json`, repeating a verb) is in the skill
`erpc-nodes`. For Solana RPC the table is `erpc_solana_rpc`: 7211, 7212, 10000 and 8888 from
`--rpc-allow`, metrics (9100 node exporter, 8999 the Geyser plugin) from `--monitoring-allow`,
SSH from `--management-allow` and erpc's own address, and agave's ports 8000–8030 from anyone.
Other networks, and SLV's DoubleZero, richat and SHA-256 patch, are not in erpc: SLV still does
those.

When something fails:

- `update` builds the new release first; a failed build leaves the running client as it was.
- The first deploy of an Index node fills Old Faithful's index cache, for up to four hours: a
  long deploy there is expected.
- A node that is behind after a restart is catching up; send traffic back only when `status`
  says it is caught up.

The box is tuned like a validator's (SMT off, CPU boost, IRQ pinning: skill
`solana-validator-mainnet`), checked with `slv check boost -t rpc -n mainnet`. Restart one node
at a time, and send traffic back only once it is caught up.

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a node erpc runs, the release it
pinned is the one `init`, `update` and `status` show.

- https://github.com/anza-xyz/agave and https://docs.anza.xyz/operations/setup-an-rpc-node: Agave
  and Anza's RPC node guide
- https://github.com/jito-foundation/jito-solana and https://docs.jito.wtf/: Jito
- https://github.com/rpcpool/yellowstone-grpc: the Yellowstone gRPC (Geyser) plugin
- https://github.com/rpcpool/yellowstone-faithful: Old Faithful, the history archive
