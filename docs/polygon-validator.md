<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Polygon validator operations

`erpc v --chain polygon` manages a dedicated Bor + Heimdall v2 validator host
on Mainnet or Amoy. It implements `init`, `deploy`, `list`, `status`, `logs`,
`start`, `stop`, `restart`, `update`, `update-config`, `plan` and `destroy`, plus
read-only `registration prepare/validate/status` through `--action`.
Deployment initially runs an **observer**. Signing is enabled only by an explicit
`--activate-validator` after the original observer is healthy and current
on-chain membership, public key and external owner match. The implementation is exercised with offline fixtures; real-host deployment, performance and financial acceptance remain
unverified.

Polygon admission is limited; running this software does not grant a validator
slot. Apply through the [official admission process](https://docs.polygon.technology/pos/get-started/becoming-a-validator).
Keep the staking owner's key outside the managed host and this CLI. Registration,
stake, token approval and funding are external operations. The dedicated hot
signer subsequently signs native consensus, Bor blocks and Heimdall checkpoint
transactions. The [official topology](https://docs.polygon.technology/pos/how-to/validator/validator-binaries)
uses separate sentries and a local RabbitMQ broker.

## Qualified clients and host

Bor `v2.10.3` (`a16f123d9b4f41a552a3a98d93a0340430838576`) and Heimdall v2
`v0.13.2` (`03090c94e7eaef344cd16efd6c968431c4041847`) retain the same
Mainnet/Amoy package, keyless signature and immutable genesis verification as
[the RPC/sentry guide](../crates/erpc-chain-polygon/templates/README.md).
No arbitrary client version, remote script or community snapshot is selected.

Use a dedicated Ubuntu 24.04 host with cgroup v2, 16 CPU cores, 64 GB RAM and
6 TB SSD/NVMe for Mainnet; Amoy uses 16 GB RAM and 2 TB. These are the
[Polygon recommended specifications](https://docs.polygon.technology/pos/how-to/prerequisites).
ERPC checks at least 16 available logical CPUs and usable kernel memory of
60,000,000 KiB for Mainnet / 15,000,000 KiB for Amoy. It accounts for CPU affinity
and all visible ancestor CPU/memory limits, refusing nested containers or unknown
budget observations. These are admission floors, not a benchmark or a guarantee
of exclusive CPU capacity. See [kernel cgroup semantics](https://docs.kernel.org/admin-guide/cgroup-v2.html).

Provision ext4 or XFS at `/var/lib/polygon`. An empty root-owned `lost+found`
is preserved. Original filesystem UUID, directory inode and account IDs are
reserved before ownership changes; nested mounts, including same-device bind
mounts, are refused. Kernel device numbers are checked within each observation
and are not persisted across reboots. The RPC guide's database-aware disk floors
and operating reserve also apply. Runtime resource pressure prevents preparation
or startup, while owned stop/destroy remain available.

The dedicated local broker is RabbitMQ **4.4.0**, source
`24d5157cd415ef396c8ecd40a2d08c4d7ad3da9f`, official image recipe
`4ad287295317ea1d9a577396fa28466a1bbf3430` (`4.4/ubuntu`). Its immutable
multi-platform index is
`sha256:485319d42170eab53d8a030e1cc49d95e41f5d325479fa504736db8091981eb7`.
Architecture manifests and config digests are closed in the
[broker catalog](../crates/erpc-chain-polygon/templates/scripts/broker.py).
The release API publication is 2026-10-19; the upstream calendar lists
2026-10-20. These are observed official registry digest pins, not an independent
publisher signature. [Release](https://github.com/rabbitmq/rabbitmq-server/releases/tag/v4.4.0),
[image recipe](https://github.com/docker-library/rabbitmq/blob/4ad287295317ea1d9a577396fa28466a1bbf3430/4.4/ubuntu/Dockerfile),
[support calendar](https://www.rabbitmq.com/release-information).

RabbitMQ 4.2 community support ended on 2026-07-31. The pinned Heimdall
Machinery result cache still declares transient non-exclusive queues, so this
broker permits only `deprecated_features.permit.transient_nonexcl_queues=true`.
No other deprecated feature is enabled. A broker release change requires a
reviewed catalog/migration; ERPC never changes the image tag automatically.
[Native result cache](https://github.com/0xPolygon/heimdall-v2/blob/03090c94e7eaef344cd16efd6c968431c4041847/go.mod),
[Machinery AMQP backend](https://github.com/RichardKnop/machinery/blob/0c29c70ce38d85464145df8455c3ccca5d605b59/v1/backends/amqp/amqp.go).

The broker container has ceilings of 4 CPUs and 4 GiB, no extra swap, no core
dumps, a read-only root, dropped capabilities and one original numeric runtime
account. Only its local AMQPS listener is enabled. These limits follow
[RabbitMQ's production guidance](https://www.rabbitmq.com/docs/production-checklist);
they do not reserve exclusive physical CPUs or isolate disk I/O from the native
clients. CPU/I/O contention and memory adequacy must be measured during host
acceptance. Docker must be rootful without user namespaces, use cgroup v2 and
the systemd driver; its explicit parent is `system.slice` as described by
[Docker](https://docs.docker.com/reference/cli/dockerd/). An unknown stopped Docker
installation is not implicitly started.

## Original signer and observing deployment

Create the concealed execution-only parent configuration described in the RPC
guide. Validator dependencies require a public HTTPS parent endpoint, correct
Ethereum Mainnet/Sepolia identity and normal certificate verification. Provider
URLs/headers are selected by an identifier-only 1Password reference; they never
enter public inventory, bundles or process arguments.

```sh
erpc v --chain polygon init -n amoy --name validator1 --host HOST \
  --ssh-key OPERATOR_PUBLIC_KEY --vault VAULT_ID --advertise-ip PUBLIC_IP \
  --l1-execution op://VAULT_ID/ITEM_ID/FIELD_ID --stake-owner EXTERNAL_OWNER \
  --sentry SENTRY_IP,BOR_NODE_ID,HEIMDALL_NODE_ID

erpc v --chain polygon plan -n amoy --name validator1
erpc v --chain polygon deploy -n amoy --name validator1 --ssh-key OPERATOR_PUBLIC_KEY
erpc v --chain polygon status -n amoy --name validator1 --ssh-key OPERATOR_PUBLIC_KEY
```

Provide one to eight distinct sentries, repeating `--sentry` for each. Validator
P2P permits only those numeric public IPs and fixed node IDs; discovery is
disabled. Native RPC is private, not exposed through `--rpc-allow`. Monitoring
and operator SSH ranges use `--monitoring-allow` and `--management-allow`.
The actual SSH port and controller address are preserved during firewall changes.

`init` generates a fresh dedicated signer on the controller. It first saves and
reads back a public inventory reservation with the original owner/creation/address,
then creates and reads only the selected concealed original key field in 1Password.
An ambiguous item creation never triggers a second key generation or adoption of
an arbitrary existing item. Retry the same inventory; missing original material
requires explicit recovery. The staking owner cannot equal this signer, and
no owner private key is requested.

The host has an immutable inventory/network/role/genesis contract. Unknown
existing runtime users/groups cannot be adopted. Original numeric UID/GID,
home, shell, direct NSS lookups, aliases and supplementary groups are checked
before private material is delivered. The first authenticated systemd condition
runs before encrypted credentials are materialized; native units use original
numeric recipients. A skipped or failed condition is not reported as accepted
startup. Root administration or deliberate numeric UID reuse remains outside
this protection boundary.

Deployment imports the original signer through protected stdin and stores it
as a host-bound encrypted credential. In observing mode, Heimdall receives a
separate original observer identity, Bor mining is disabled, and no checkpoint
sender runs. The funded hot identity is not given to an observer process.
Preparation and all credential prompts finish before a short firewall
transaction; a fresh SSH connection confirms its exact run/bundle before startup.

`deploy` reports asynchronous startup requested, **not validator readiness**.
Heimdall genesis replay precedes Bor synchronization. `status` distinguishes
`runtime_ready`, `observer_ready` and `validator_active`; a healthy observer has
`ready:false` and a non-success exit until explicit activation. This is expected.

## External registration and explicit activation

```sh
erpc v --chain polygon registration -n amoy --name validator1 \
  --ssh-key OPERATOR_PUBLIC_KEY --action prepare
erpc v --chain polygon registration -n amoy --name validator1 \
  --ssh-key OPERATOR_PUBLIC_KEY --action validate
```

`prepare` prints public external-owner data: chain ID, reviewed staking-manager
address, original signer/public key and current token/minimums when observed.
It never constructs, signs or submits a stake transaction. The signer public key
is the full 65-byte uncompressed value expected by the pinned
[`StakeFor` helper](https://github.com/0xPolygon/heimdall-v2/blob/03090c94e7eaef344cd16efd6c968431c4041847/helper/tx.go).
That native helper signs with its configured private key; do **not** run native
stake/approve commands on this managed hot-key host. Use an external owner wallet,
verify current admission/slot and contract bounds, and choose stake, fee and
approval amounts there. Fund only the dedicated signer's required transaction
fees separately. Missing observations are explicit unknowns, not default amounts.

`validate` requires current parent and Heimdall membership, the original public
key and the separate current NFT stake owner. An unregistered, jailed, exited,
wrong-owner or unsynchronized identity is not eligible. Neither `prepare` nor
`validate` activates the service. `registration --action status` reports the
same read-only observations without asserting eligibility through its exit code.

```sh
erpc v --chain polygon plan -n amoy --name validator1 --activate-validator
erpc v --chain polygon deploy -n amoy --name validator1 \
  --ssh-key OPERATOR_PUBLIC_KEY --activate-validator
erpc v --chain polygon status -n amoy --name validator1 --ssh-key OPERATOR_PUBLIC_KEY
```

The first transition proves the healthy original observer and both chain views
before stopping it. Durable authorization binds the original identity/history,
selected provider, release profile, helper revision and operation intent. Only
then is the desired active phase saved and the stopped native configuration
replaced. Retrying an interrupted transition retains that original observer
proof and performs a fresh parent eligibility check. A new inventory or missing
history cannot reuse the key to initialize an active replacement host. Active
phase is monotonic; stop the validator to suspend signing.

## Authenticated native dependencies and transaction boundary

Bor and Heimdall REST use private Unix sockets. A short root service verifies
native process identity, original UID/GID, cgroup, executable, arguments and the
socket inode, then publishes a root-owned public peer receipt. The unprivileged
adapter checks that receipt and connected `SO_PEERCRED` before sending bytes.
Long genesis replay is handled by repeating publication timers, not a blocking
startup hook. Listener replacement, missing process metadata or stale generation
refuses the connection.

Distinct private TLS identities authenticate the parent/Bor/REST adapter, native
Comet RPC and broker. Clients trust only their original CA. The broker and Bor
mutating dependency also require their original credentials. The native
`bor_getVoteOnHash` call can change downloader locking state, so it is not treated
as harmless public RPC. Provider and Basic-auth URLs live only in encrypted
native configuration, not argv/environment; the pinned native Go URL handling
redacts passwords in transport errors. [Bor implementation](https://github.com/0xPolygon/bor/blob/a16f123d9b4f41a552a3a98d93a0340430838576/eth/bor_api_backend.go),
[Heimdall transport](https://github.com/0xPolygon/heimdall-v2/blob/03090c94e7eaef344cd16efd6c968431c4041847/helper/bor_failover_http.go).

Only active mode permits native EIP-1559 checkpoint estimation/submission. The
adapter verifies original signer, Ethereum chain, canonical transaction/ABI,
reviewed RootChain recipient, zero transferred value and bounded gas/fees before
forwarding. The native fee cap is 500 gwei and tip cap 10 gwei. Current parent
eligibility and cancellation are rechecked; shared/exclusive operation locking
prevents a delayed send from crossing an acknowledged stop. Registration, token
approval, transfer and arbitrary recipients are not available through this
managed adapter. **The private key itself still has ordinary Ethereum signing
power** if stolen or used elsewhere; these local checks do not change that
on-chain capability. Native checkpoint behavior is in the pinned
[bridge](https://github.com/0xPolygon/heimdall-v2/tree/03090c94e7eaef344cd16efd6c968431c4041847/bridge).

## Operations and recovery

The [official Karwar release](https://github.com/0xPolygon/heimdall-v2/releases/tag/v0.13.2)
states that the fork is already active: Heimdall height 57,006,000 on Mainnet
(2026-11-03) and 50,020,000 on Amoy (2026-10-23). This catalog requires public
Heimdall `v0.13.2`; it does not select the private prereleases. Bor remains
`v2.10.3`. Both architecture packages and their Sigstore workflow/tag/source
identities were verified on 2026-11-04 without executing a chain binary. The
four upstream Mainnet/Amoy configuration files are byte-identical to the previous
catalog. Existing genesis pins are retained, not newly rehashed or replaced.
No state migration, resync or key rotation is part of this plain binary update.

Use an explicit `update` to select the qualified pair; `plan --change update`
previews that actual target. A stale inventory cannot request ordinary startup,
and an older installed helper cannot acknowledge the new startup protocol.
The public controller handoff first reserves a non-executable monotonic release
floor, so old queued preparations cannot replace it. That reservation preserves
the prior validator phase; it does not authorize a first signer before admission.
Publication failure attempts original shutdown and remains an error. The new
runtime also rejects pre-Karwar or unknown executable targets. Stop and destroy
remain available without weakening original-owner checks.

If a previous update stopped after native/public configuration publication but
before unit sealing, retry the explicit update. A retained original validator
admission permit, key/history, numeric accounts, stopped processes and source
identities are required. The controller checks both stored unit definitions and
loaded execution hooks. Missing seals or interrupted managed public configuration
can be rebuilt while fenced; an existing unit hash mismatch, unknown hook,
foreign recipient or missing original signing history cannot be repaired by
assuming ownership. This path never turns an unverified first observer into a
signer. Every successful retry still authenticates the new pair and seals its
units before activation. No private key or mutable validator state is recreated.


Use `logs --component bor|heimdall|parent|broker|all`, optionally `--follow`.
`--json` journal and completion records are compact NDJSON on stdout; human
journal output remains on stderr. `update` selects only this CLI's reviewed
native pair; per-client data-opening floors refuse downgrade or different bytes
for an equal version. `update-config` can rotate the selected parent reference,
sentries and ingress policy while preserving original custody and history.
TLS credentials renew during stopped preparation when within 30 days of expiry;
startup does not silently issue a new identity. A later broker release requires
an explicit reviewed upgrade path.

`stop` attempts owned shutdown even when the first durable fence write fails,
reports that failure and retains ingress protection. Unknown native/data writers
are never killed automatically. `destroy` stops/disables before removing ingress
and retains original identities, all databases, inventory and recovery material.
Broker stop is bound to the original container ID and creation generation;
a delayed old callback cannot stop a replacement container. Account drift or low
storage does not prevent verifiable owned shutdown. Persistent storage failure
cannot guarantee a durable reboot fence; repair storage and repeat the operation.

Retain `/etc/polygon/original-credentials.backup.json`, original public receipts,
both native histories, broker data and the original host's systemd credential
protection material. The package includes original encrypted core identities,
parent credentials and private TLS/Bor/broker dependencies. `deploy --restore-keys`
restores only ciphertexts matching retained originals; it cannot reconstruct lost
signing history or transfer host ownership. A stale backup cannot roll back a
newer valid TLS generation or parent rotation. Restore/restart a damaged observer
before requesting its first activation; those two operations are deliberately
separate. The 1Password original signer permits separately reviewed host-loss
recovery, but does not by itself authorize a fresh active host or recover the
host-bound observer/P2P credentials and histories. Never run two instances with
the same active identity.

## Acceptance limits

Offline tests cover actual CLI routing, custody/provider mocks, deployment phase
failure ordering, real template rendering and inert Ansible publication, original
account/storage authority, runtime socket/process models, fixed public signature
vectors, TLS builders, recovery, cancellation and broker generation checks.
No operational key or certificate was generated by verification and no node,
Docker broker, registration, checkpoint or financial transaction was executed.

Linux systemd credential ACL ordering, `O_PATH` socket grants, `/proc`/cgroup and
peer credentials, real native/container startup, full genesis replay, sentry
connectivity, checkpoint delivery and effective CPU/RAM/I/O must pass later host
acceptance. Native secret logging qualification is source-based plus inert
transport tests, not a full real-client journal audit. Kernel root capabilities
and deliberate administrative account replacement are not defeated by these
checks. Successful local checks do not claim those deployment results.
