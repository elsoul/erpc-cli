---
name: avalanche-node
description: Running an Avalanche node or validator (mainnet, Fuji) -- the hardware it needs, and what erpc and ERPC offer for it today.
---

# Avalanche node

| Node | CPU | RAM | Disk |
|---|---|---|---|
| Validator | 8 cores / 16 threads | 32 GB | 2 TB local NVMe, 3000+ IOPS |

Source: build.avax.network (high stake). Compare with ERPC's catalogue and stock (`server_catalog`, `server_stock`); say
plainly when no product meets it.

`erpc r --chain avax` manages RPC nodes; `erpc n --chain avax` is its alias.
Use `erpc v --chain avax` from init for Primary Network validator intent.
Mainnet and Fuji are implemented with offline checks; real-host and on-chain
acceptance remain deferred. Never present a successful deploy as active validation.

All twelve lifecycle verbs operate. The default reviewed release is v1.15.2;
updates require an explicit supported 1.15 patch tag and never automatically
roll back a database. Full state-sync and C-Chain archive are immutable choices.
No disk is formatted implicitly. Native API stays loopback; restricted gateways
use 9652 for RPC and 9653 for metrics, with public P2P on 9651.

Identities are sealed, pinned and backed up in 1Password. Missing established
keys cause refusal, never regeneration. `identity-backup` and `identity-restore`
cover same-host recovery only, with restore requiring a stopped service.
Cross-host migration requires a separately designed fencing workflow.

`prepare-registration` and `validate-registration --file` produce/check unsigned
review data for Core Stake. They do not sign or broadcast. Validate the actual
BLS proof, fees and UTXOs externally. Validation starts upon P-Chain acceptance,
not at a future scheduled start. Use `status --registration <file>` afterward;
an elapsed intended term is not evidence of historical registration or rewards.

The repository operator guide is `docs/avalanche.md`. For RPC access without a
node, ERPC's shared RPC covers Avalanche (skill `erpc-services`).

## Official sources

What changes faster than this skill -- releases, flags, requirements -- is in the project's own
repositories and documentation. Read them when an answer depends on the current release (an agent
that can fetch pages should), or point the operator to them. For a node erpc runs, the release it
pinned is the one `init`, `update` and `status` show.

- https://github.com/ava-labs/avalanchego: AvalancheGo, the node
- https://build.avax.network/docs/nodes: Avalanche's node and validator documentation
