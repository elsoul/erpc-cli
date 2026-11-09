---
name: bsc-node
description: Operate network-qualified BSC RPC nodes and fresh validators with fixed snapshots, immutable ownership and guarded custody.
---
# BSC nodes and validators

<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

Use `erpc r --chain bsc` with explicit mainnet or chapel. Mainnet selects Geth
1.7.8; Chapel selects 1.8.1 for Jenner. Do not equate a Chapel release notice
with mainnet activation. Exact binaries, source commits and network metadata
are in `crates/erpc-chain-bsc/networks/catalog.json`. Artifact hashes are not signatures.

Use a dedicated Ubuntu 24.04+ AMD64/ARM64 host with at least sixteen cores,
64 GB RAM and the selected snapshot's full bootstrap capacity. Mount the complete
`/var/lib/erpc-bsc` tree together. Init reserves ownership without running Geth.
Full history is recommended; `--storage pruned` is an immutable explicit choice.
All twelve lifecycle verbs are implemented for RPC and the separate validator role.

Snapshot sources are fixed official catalogs; MD5 checks detect corruption and
are not publisher signatures. Downloads are bounded and resumable. Only database
files can enter unpublished staging, which is atomically published on completion.
Never delete a running database to force a retry. Plan reports initial capacity;
capacity is rechecked before every install/start and retains a 200 GB reserve.

The peer identity is created once on the target; subsequent loss, corruption or
account changes require explicit recovery. Mining/voting/unlock are disabled in RPC mode.
HTTP/WS/metrics remain loopback-only, P2P 30311 is public, and an authenticated
external gateway is an operator-managed boundary. Keep stable management ranges.
A fresh SSH confirmation of the exact firewall run precedes long deployment.

Updates fence startup before stopping writers, preserve data and reject database
downgrades. If an owned service unit disappears, native-process identity and
quiescence must still be established. Destroy retires the owner without purging
history or key material. Resume installation with deploy at the stored target.

Status requires the owned process, matching chain/genesis, fresh head, peers and
completed sync. A successful deployment submission is not readiness evidence.
Actual nodes/keys/transactions were not used in implementation tests. Real-host
bootstrap, reboot, RPC/WS, capacity and upgrade acceptance remain deferred until
the full implementation batch is ready. Read `docs/bsc-rpc.md` for boundaries.

## Validator role

Use `erpc v --chain bsc` on a dedicated host (mainnet 128 GB RAM; Chapel 16 GB) with the external operator's
public `--operator` address at init. Its financial key never enters the node.
Deploy creates fresh consensus/BLS hot keys once, verifies a concealed 1Password
backup by readback, and starts with mining disabled. The observer only enables
mining after backup, synchronization, network and registered-key checks pass.
HTTP/WS RPC are explicitly disabled in a verified derived configuration; use
private IPC observations. Epoch membership is reported separately from node
readiness and registration.

Use `plan --change register` after synchronization and backup confirmation to
verify public PoP fields for the official staking application. All funding and
registration transactions are signed externally. Registration does not guarantee
election. Never infer an operator's financial authority from possession of a
consensus/vote key.

`update-config --restore-custody` restores only the same established owner's
acknowledged key backup and leaves it stopped. Native vote history is required
and never recreated from that backup. Reject arbitrary used-key imports and
cross-host key-only restoration. Stop/destroy revoke pending deployment and
activation before stopping; failure retains the fence. Read
`docs/bsc-validator.md` for custody, registration and live-acceptance boundaries.

## Official sources

- https://github.com/bnb-chain/bsc/releases/tag/v1.7.8
- https://github.com/bnb-chain/bsc/releases/tag/v1.8.1
- https://docs.bnbchain.org/bnb-smart-chain/developers/node_operators/full_node/
- https://github.com/bnb-chain/bsc-snapshots
