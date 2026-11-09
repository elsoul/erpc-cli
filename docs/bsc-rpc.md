<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# BNB Smart Chain RPC nodes

`erpc r --chain bsc` manages a dedicated BSC Geth node on mainnet (56) or
Chapel (97). The twelve lifecycle commands are init, deploy, list, status, logs,
start, stop, restart, plan, update, update-config and destroy. Full block history
is the default; `init --storage pruned` selects the separate official pruned
snapshot and a 600,000-block history window. Both modes verify new state locally.
Neither promises archive historical state. Validator consensus/BLS custody and
StakeHub registration are separate from this RPC backend.

Source qualification, small metadata fixtures and offline failure tests are the
current evidence. Real-host bootstrap, reboot, workload and network upgrade
acceptance remain deferred until the complete implementation batch is ready.
No production node, signing key or financial transaction was used for development.

## Qualified releases and artifact trust

Mainnet selects **1.8.2**, commit
`54afaff4da31ac9e49ba646a4f65104edac5a2f3`, required before the Jenner activation
at **2026-12-08 02:30 UTC**. Chapel retains **1.8.1**, commit
`947ba1cb1ef05d4a5f71b738113a3d8b4c16f6b7`, for its separate activation on
2026-10-29. Old mainnet 1.7.8 remains in the catalog to recognize original
installations and recovery evidence. New mainnet nodes use 1.8.2; startup and
readiness guards refuse 1.7.8 once the mainnet activation time is reached.
The registration observer also fences and drains an expired validator, preserving
its data and keys. Stops and explicit upgrades remain available. No automatic binary update or
rollback is performed. [Mainnet release](https://github.com/bnb-chain/bsc/releases/tag/v1.8.2),
[Chapel release](https://github.com/bnb-chain/bsc/releases/tag/v1.8.1).

Expiry shutdown remains available while another common node operation is
preparing its tools. The observer rechecks original ownership under the BSC
operation lock and permits only cancellation and owned drain during that
contention. Normal signing activation still requires the common lock. A failed
drain can be retried even when startup is already fenced or an update is
incomplete; its original target, data and signing history remain retained.
Repair failed storage or shutdown, then submit a fresh explicit qualified update.

Upgrade existing mainnet RPC nodes with `erpc rpc --chain bsc update --network
mainnet --name <node> --version 1.8.2 --ssh-key <operator.pub>`; use `v` for a
validator. `plan --version 1.8.2` exposes the selected target and the network
activation requirement. Preserve the existing database, P2P identity and
validator signing history. An interrupted update resumes its recorded target.

Review client-facing changes before upgrading from 1.7.x: trace output and
`reexec` handling changed, `--rpc.rangelimit` replaces the old range flag, and
RPC block overrides interpret `prevRandao` as a millisecond remainder (0–999).
These changes can apply before the fork. The generated ERPC configuration does
not use the removed opcode, transaction-reannouncement or ENR-filter fields;
its explicit cache sizing is retained. MEV is disabled by the qualified native
default and the generated configurations, so this profile does not enable the
new MEV gRPC listener. [Compatibility changes](https://github.com/bnb-chain/bsc/releases/tag/v1.8.0-alpha),
[RPC and gRPC changes](https://github.com/bnb-chain/bsc/releases/tag/v1.8.1).

Linux AMD64/ARM64 binaries and network ZIPs are selected by exact HTTPS URLs,
byte sizes and SHA-256 values. The actual asset is `geth-linux-arm64`, although
the release prose uses an underscore in its label. The v1.7.8 and v1.8.2 release bodies list
identical outdated network ZIP checksums. The actual small ZIP bytes match the
release asset API and the v1.8.1 checksum table; their genesis/config contents
are unchanged. ERPC records
those observed ZIP hashes and the exact enclosed genesis/config hashes in
[the catalog](../crates/erpc-chain-bsc/networks/catalog.json). It does not claim
the old body authenticated different bytes. No detached signature or reproducible
build verification is asserted; initial trust is the official GitHub release over
TLS. Binary payload verification occurs on the target before execution.

The full-node reference is BSC Geth. The old generic Erigon recommendation is
obsolete, and Reth-BSC's validator support remains a separately qualified question.
This backend does not substitute an Ethereum Geth binary for the BSC fork.
[Full-node guide](https://docs.bnbchain.org/bnb-smart-chain/developers/node_operators/full_node/),
[reference source](https://github.com/bnb-chain/bsc/tree/54afaff4da31ac9e49ba646a4f65104edac5a2f3).

## Host and bootstrap

Use dedicated Ubuntu 24.04+, passwordless sudo, Linux AMD64/ARM64, at least
16 CPU cores and 64 GB RAM, with local SSD/NVMe storage. These are ERPC
provisioning floors, not measured throughput guarantees. Mount the complete
`/var/lib/erpc-bsc` tree on the provisioned filesystem so staging and database
publication share a filesystem. No disk is formatted or existing unowned BSC
service, data, account or group adopted.

The initial capacity policy is twice the selected catalog's rounded compressed
size (with per-file rounding allowance), plus 200 GB. Full mainnet is roughly
15 TB and pruned roughly 4 TB; Chapel full is roughly 1.25 TB and pruned roughly
560 GB. Inspect the selected catalog and actual free space; these estimates do
not promise future chain sizes. Allocated owned database/staging/download bytes
reduce the remaining initial budget. A 200 GB free reserve always applies, and
capacity is rechecked before preparation, install/resume and every start/reboot.

Bootstrap uses the official catalog at commit
`258bc869f9fb77e68993bd6a5769832cbf842401`: mainnet snapshot
`mainnet-geth-pbss-20261009` or its pruned counterpart, Chapel
`testnet-geth-pbss-20260917` or its pruned counterpart. Source-published MD5
checks detect transfer corruption; they are **not signatures or a modern
publisher-authentication mechanism**. The exact manifest and source locations
are fixed in this CLI. Snapshot contents remain a first-party trust assumption.
[Official catalog](https://github.com/bnb-chain/bsc-snapshots/tree/258bc869f9fb77e68993bd6a5769832cbf842401),
[official storage guidance](https://github.com/bnb-chain/bsc-snapshots/blob/258bc869f9fb77e68993bd6a5769832cbf842401/usage/legacyfullnode_usage.md).

Downloads resume only their fixed bytes and must pass their checksum before
extraction. The importer accepts regular database files/directories under
`geth/chaindata`; traversal, absolute paths, links, device nodes, account keys and
other archive files are rejected. A partial staging database is never used by
Geth. Only a completed, durably recorded staging tree is atomically published.
An interrupted extraction can rebuild its unpublished staging tree using retained
verified downloads. An interrupted publication resumes without replacing data
that has already been published. Previously completed databases are never
reinitialized from a newer snapshot or automatically deleted. An altered completed
download or irrecoverably corrupt database requires explicit operator inspection.

## Private APIs and persistent identity

```sh
erpc r --chain bsc init -n chapel --name bsc-a --host <server> \
  --ssh-key <operator.pub> --vault <vault> --storage full \
  --management-allow <stable-management-cidr>
erpc r --chain bsc plan -n chapel --name bsc-a
erpc r --chain bsc deploy -n chapel --name bsc-a --ssh-key <operator.pub>
erpc r --chain bsc status -n chapel --name bsc-a --ssh-key <operator.pub>
```

Initialization reserves immutable host/network/role/platform/retention/snapshot
ownership and installs helpers without starting Geth. The node's P2P identity is
created once on the target during deployment and retained under
`/var/lib/erpc-bsc/identity/nodekey`, with a root-owned content identity record.
Interrupted first creation reuses the staged identity. Once published, a missing
or changed identity blocks startup and requires explicit recovery; it is not
silently regenerated. This is a peer key, not a validator consensus, BLS, operator
or funded wallet key.

The client runs under its dedicated unprivileged UID/GID with a root-controlled
empty account keystore. Mining, BLS voting, insecure account unlock and unprotected
transaction acceptance are disabled. HTTP 8545, WebSocket 8546 and metrics 6060
bind only to loopback. Native RPC modules are limited to eth/net/web3; CLI status
uses the private Unix socket for fixed read methods. P2P 30311 TCP/UDP is public.
Application TLS/authentication exposure is outside this backend; use an operator
managed tunnel or gateway when remote RPC access is needed.

The common firewall admits SSH only from the current controller and stored
management ranges. A short firewall operation must be confirmed through fresh
SSH before long download/install work begins. Boot and service guards require
the exact confirmed receipt. Package installation suppresses unrelated service
autostarts. Keep a stable management range to preserve later access.

## Updates, status and recovery

`update --version <version>` selects only a qualified catalog entry and refuses
rollback. `update-config --management-allow <cidr>` replaces management policy.
The controller records an installation fence before stopping the owned writer;
helpers/catalogs are published as complete revisions, not partially mixed files.
Failed installation stays fenced. Resume with deploy using the stored target;
initialization cannot rewrite helpers of an installed or retired node. With no
owner record, any managed identity, staged download, receipt or helper remnant
causes refusal; a same-owner interrupted identity publication preserves its key.

Every deployment has a fresh caller intent checked before firewall changes,
installation and start. Stop/destroy revoke that intent and persist a startup
fence before attempting shutdown, including during a failed installation. Queued
plays cannot revive the cancelled operation. A subsequent explicit deploy may
resume the retained target; a stopped installed node may explicitly start again.
An actively running remote play holds the common operation lock, so another
mutator refuses while it is running rather than racing its filesystem changes.

Stop/update/destroy verify service termination and inspect any remaining process
using the managed database argument. An orphan can be signaled only after its
UID, pinned executable and PID start time are verified; pidfds avoid PID reuse.
A foreign or unverifiable writer causes refusal rather than an unsafe kill or
false stop-success report. Data and identity stay intact when shutdown fails.

`destroy` stops/disables the owned node and records retirement. It retains its
immutable ownership, database, identity and restrictive firewall. There is no
purge or forget switch. A same-owner deploy can resume retained state. This
managed lifecycle does not prevent a privileged operator from creating copies or
running unrelated processes outside its control.

`logs --json` emits one encoded journal record per line, including its output
stream; ordinary logs retain their text format.

`status` requires the owned running process, exact chain ID and genesis hash,
completed synchronization, connected peers and a head no more than 120 seconds
old (or 120 seconds in the future). These are operational thresholds, not finality
guarantees. An unready status exits unsuccessfully; a successful deployment may
still be catching up. The later live batch must verify mainnet/Chapel sync,
RPC/WS behavior, persistence, reboot, interrupted download/install, low space and
future network-qualified upgrade compatibility.

Owner receipts and privileged code/configuration destinations require real,
root-owned ancestors without group/other write permission. Existing unsafe
directories, linked receipts, or permission drift are refused before reservation
or mutation; the CLI never repairs ownership to adopt unknown state. Helper
publication is checked against the sealed carried source before preparation
reports success. Restore the host trust boundary through explicit operator
recovery before retrying a refused operation.
Managed service and firewall boot units include their drop-in directories in
this boundary. Unknown overrides are refused; only the common managed firewall
guard is accepted. Fresh initialization never adopts pre-existing unit artifacts.

Privileged SSH control uses the reviewed complete-release loader. Service startup
checks the fixed release directory from outside the script before interpretation;
boot firewall loading enters through that checked controller. Carried deployment
commands use isolated Python from the sealed operation bundle, and common guards
and rollback timers validate their standalone helper before executing it.

A cancellation-record write failure does not skip owned shutdown. Explicit
stop/destroy still attempt the reviewed process drain and disable the node; a
shutdown failure also attempts the validated orphan-writer path. A transient
storage error is retried after drain, but the operation still reports a failure. If storage remains unavailable, durable restart prevention cannot be
claimed: repair storage/services and retry. Keys, data and ingress are retained.
