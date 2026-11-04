---
name: sui-node
description: Running a Sui validator or full node (mainnet, testnet) -- the hardware each needs, and what erpc offers for it today.
---

# Sui node

| Node | CPU | RAM | Disk |
|---|---|---|---|
| Validator | 24 cores | 128 GB | 4 TB NVMe |
| Full node | 8 cores | 128 GB | 4 TB NVMe, 7 TB or more unpruned |

Source: docs.sui.io. Compare with ERPC's catalogue and stock (`server_catalog`, `server_stock`); the RAM and the total disk
are what rule servers out most often. Say plainly when no product meets it.

`erpc r --chain sui` implements the full-node lifecycle on mainnet and testnet;
`erpc n --chain sui` is a compatible alias. Use init, deploy, list, status, logs,
start, stop, restart, plan, update, update-config and destroy. Deploy schedules
verified snapshot bootstrap and status checks gRPC plus advancing checkpoints.
`erpc v --chain sui` manages the validator role with original protocol/network/
worker keys imported from 1Password and encrypted on the reserved host. Use
`registration --action prepare|validate|status` for external registration guidance,
key checks and public active-set observations. The account key stays external;
erpc never signs or broadcasts stake transactions. Same-host `deploy --restore-keys`
requires the original receipt and keys. Never run the same signer on two hosts.
Actual host/network acceptance remains deferred. The host needs Ubuntu 24.04 and pre-mounted storage.
See the embedded Sui template README for retention, gateway and recovery rules.

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a node erpc runs, the release it
pinned is the one `init`, `update` and `status` show.

- https://github.com/MystenLabs/sui: the node and validator source
- https://docs.sui.io/operators: Sui's operator documentation (full node and validator)
