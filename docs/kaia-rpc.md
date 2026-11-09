<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Kaia endpoint-node operations

`erpc r --chain kaia` manages a dedicated endpoint node (EN) on `mainnet` or
`kairos`. It implements init, deploy, list, status, logs, start, stop, restart,
plan, update, update-config and destroy. An EN serves RPC and validates the
chain; it is not an admitted consensus node. CN/PN topology, Governance Council
approval, staking and financial keys belong to a separate validator lifecycle.
The current onboarding guide still requires administrative approval and a GC ID;
a forecast for permissionless onboarding is not evidence of admission. [S1], [S2]

The managed EN profile explicitly disables the auction module. Its native
gasless transaction-pool validation remains available, but the pinned worker
executes lender transaction generation and signing only for consensus nodes.
The EN profile neither funds a node address nor supplies wallet unlocks; the
CN-only `--gasless.disable` flag is not passed to `ken`. The executable sets its
EN role internally; `--nodetype` is not registered by the pinned app and is not
passed. [S15], [S16] A future admitted CN
profile must make these optional lending modules an explicit custody choice.
[S13], [S14], [S15]

## Qualified client and host

The reviewed client is Kaia `v2.2.2`, source commit
`ac7c81f3a9759704b5ce77b42ae91851ce45a9c3`. Its official OCI index was observed as
`sha256:1037dcea32df3c634f04962b2b63a17167caa8f9cf957c5e266031a08ba07f80`.
Deployment selects the Linux AMD64 child manifest
`sha256:3d7c03285024e393848ffc001309e1cb27b3271b9c84f0d6f1548557e894f5c5`.
Tags do not select executable bytes. Registry provenance names the same source
commit; this is a publisher-registry/content-pin trust boundary, not an
independently verified release signature or a reproducible-build claim. [S3], [S4]

The official Docker guide supports Linux AMD64. Although the index also contains
an ARM64 descriptor, the pinned Dockerfile forces an AMD64 Ubuntu final image,
and the ARM64 provenance also names that AMD64 final-base material. This backend
therefore refuses ARM64 until its native image is separately qualified. The
container runs the fixed `ken` executable directly under a dedicated non-root
UID, with dropped capabilities, a read-only image filesystem and explicit data
and read-only peer-identity mounts. Docker's distribution-managed local Unix
socket is used; inherited Docker contexts cannot select another daemon. [S4], [S5]

Use dedicated Ubuntu 24.04+ with passwordless sudo, at least eight CPU cores and
64 GB RAM. The official EN guide recommends more than 4,000 GiB storage,
3,500 Mbps disk bandwidth and up to 10 Gbps network bandwidth. ERPC checks CPU
count, memory and capacity; it does not benchmark disk or network throughput.
The host's actual free space must also accommodate the selected compressed and
expanded snapshot together. Provision `/var/lib/erpc-kaia` on one filesystem;
nested bootstrap/data mounts, including same-filesystem bind mounts below the
native database, are refused. Linux mount topology and the actual native data
directories are rechecked before installation/resume and startup. Stop and
destroy do not require capacity or mount-topology validation. [S6]

A new host installs distribution Docker without starting Kaia. An interrupted
first Docker package installation may resume only while the reserved host has
no prior containers or custom daemon configuration. A pre-existing Docker
installation must have a healthy, inspectable local daemon. The backend does
not infer that an unreachable daemon means its containers are absent.

## Initialize and synchronize

```sh
erpc r --chain kaia init -n kairos --name en1 --host <address> \
  --vault <vault> --ssh-key <operator-public-key-file> --yes

erpc r --chain kaia plan -n kairos --name en1

erpc r --chain kaia deploy -n kairos --name en1 \
  --ssh-key <operator-public-key-file> --yes
```

The recommended default is `pruned`, using an exact official live-pruned
snapshot. `init --storage full` instead begins a full synchronization from the
built-in genesis. A pruned snapshot cannot provide historical state that it has
already discarded; it is not an archive. The official guide publishes only
live-pruned snapshots and directs full/archive operators to fresh synchronization
or the team. This backend does not expose an archive mode. [S7]

The carried catalog records the original snapshot name, compressed/uncompressed
sizes, published MD5, and the SHA-256 of the manifest bytes inspected on
2026-10-26. Mainnet uses `20261026010012`; Kairos uses `20261026010014`.
The publisher's SHA-256 field was null. MD5 detects transfer corruption here;
it does not provide an independent signature. Downloads use the exact official
HTTPS object host, bounded lengths, validated range responses and the fixed
checksum. No mutable `latest.txt` is consulted during deployment. [S7], [S8], [S9]

The downloader identifies itself as `erpc-cli/0.0.1`: the official object host
rejects generic Python-urllib requests with Cloudflare error 1010. Named-client
one-byte Range requests were checked against both objects and returned the exact
published total sizes. That checks the retrieval route, not the complete archive.

Extraction permits only regular database files under `klay/chaindata`; links,
devices, traversal, duplicate files and unexpected instance data are refused.
Incomplete extraction remains in an unpublished staging directory. A durable
receipt binds publication to its owner and selected snapshot, so a retry cannot
overwrite an established database. Verified downloads remain reusable. If the
pinned object disappears or its bytes change, deployment fails without silently
selecting a different source.

`plan` reports the fresh capacity estimate. The policy requires the larger of
4,001 GiB or compressed snapshot plus its declared expanded size plus 200 GB.
Allocated managed data/staging/cache reduce the remaining bootstrap budget, but
at least 200 GB free remains required. Capacity is rechecked on deploy, resume,
update and startup. Stop and destroy remain available when this floor fails.
These are conservative implementation estimates, not a synchronization-time or
performance guarantee.
The actual Docker storage filesystem separately needs 10 GiB free for an
installation/update and 2 GiB for ongoing startup. Before the first daemon start,
the default distribution Docker location is used for that preflight.

## Access and observations

P2P 32323 TCP/UDP is public. Multichannel 32324 is disabled. HTTP RPC 8551 and
WebSocket 8552 bind only to `127.0.0.1`; administrative/personal namespaces are
not exposed. Native gRPC, GraphQL and Prometheus listeners are not enabled by
this profile. Use an SSH tunnel or a separately reviewed authenticated TLS
gateway for remote RPC clients. SSH ingress includes the actual connected port
and controller address, plus explicit `--management-allow` IPv4 CIDRs. [S5], [S10]

Deployment first completes a short firewall transaction, confirms that exact
run and bundle over a fresh SSH connection, and then begins lengthy image and
snapshot work. The long run checks the confirmation receipt before other tasks.
Boot and manual startup also require the installed owner/image/identity and
confirmed ingress. No node listener starts during package installation or
snapshot extraction.

```sh
erpc r --chain kaia status -n kairos --name en1 --ssh-key <public-key-file> --json
erpc r --chain kaia logs -n kairos --name en1 --ssh-key <public-key-file> --json
```

Status checks the owned container and its loopback listener PID, EVM chain ID,
built-in genesis, peers, synchronization and a fresh head. Mainnet is chain ID
8217; Kairos is 1001. A running process or `eth_syncing: false` alone is not
reported as ready. JSON journals use compact records on stdout, followed by a
completion record; human-readable journals use stderr. [S10], [S11]

## Ownership, updates and recovery

The owner-state root and every ancestor must be real, root-owned directories
that other users cannot write. This is checked before reservation and every
lifecycle use; an existing empty writable or non-root-owned mount root is refused
without changing its ownership or permissions. A root-owned owner file alone
is insufficient because a writable parent could replace it.

Host, platform, network/genesis, storage mode and original bootstrap identity
remain bound to the inventory owner. A second reservation cannot adopt the same
remote data. The original secp256k1 peer identity is generated once, recorded
before publication and mounted read-only. An interrupted publication reuses its
staged identity; a missing or substituted established key is refused without
new entropy. Native Kaia otherwise generates a missing node key automatically,
which is why the managed profile always supplies its explicit key file. [S12]

Stop and destroy persist a startup fence and cancel queued deployment stages,
including after failed installation. Shutdown checks both systemd and the exact
owned container ID, sends only SIGTERM, and verifies that no dedicated-account
writer remains. A stopped container can be removed without `--force` or volume
removal; databases and identity stay outside its image filesystem. An ambiguous
or foreign process/container is refused. Destroy retains inventory, identity,
database and restrictive ingress; it does not erase data.

Updates select only a reviewed release, preserve the original database and
refuse downgrades or ambiguous same-version image/source replacement. A newer
CLI can authorize a bounded target through the old helper, but only its carried
qualified controller may execute that target. Original snapshot records must
remain in future catalogs for existing owners. `update-config` changes management
ranges while retaining the same ownership and database contract.

Keep protected backups of the original peer identity, owner state and complete
data tree. This RPC backend does not import consensus keys or turn a key-only
backup into validator authority. It has been checked offline only, with inert
artifacts and mocked processes. Linux/Docker/systemd behavior, real multi-TB
snapshot synchronization, reboot, peer connectivity, actual host recovery and
performance still await acceptance on a real host.

## Sources

[S1]: https://github.com/kaiachain/kaia/tree/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3 "Pinned client roles and source"
[S2]: https://docs.kaia.io/nodes/core-cell/become-a-validator/onboarding/ "Current administrative approval and GC ID procedure"
[S3]: https://github.com/kaiachain/kaia/releases/tag/v2.2.2 "Official stable release and mandatory Osaka notice"
[S4]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/Dockerfile "Fixed native executable layout and AMD64 Ubuntu final base"
[S5]: https://docs.kaia.io/nodes/endpoint-node/docker-setup/ "Official publisher image, AMD64 support and graceful native shutdown"
[S6]: https://docs.kaia.io/nodes/endpoint-node/system-requirements/ "Official endpoint-node hardware guidance"
[S7]: https://docs.kaia.io/misc/operation/chaindata-snapshot/ "Current object catalog, live-pruned semantics and extraction layout"
[S8]: https://snapshots.node.kaia.io/mainnet/pruning-chaindata/manifest.json "Mainnet observed snapshot metadata"
[S9]: https://snapshots.node.kaia.io/kairos/pruning-chaindata/manifest.json "Kairos observed snapshot metadata"
[S10]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/cmd/utils/flags.go "Reviewed network, listener, API, key and pruning flags"
[S11]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/params/config.go "Native network IDs and genesis hashes"
[S12]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/node/config.go "Native node-key fallback and deterministic BLS derivation"

[S13]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/kaiax/auction/config.go "Auction role gate and disable flag"
[S14]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/work/worker.go "Consensus-node-only transaction bundling"
[S15]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/cmd/utils/nodeflags.go "CN-only gasless disable option and common auction option"

Owner receipts, helper/configuration paths and managed unit/drop-in trees require
real root-owned ancestors without group/other write permission. Unknown overrides
or unowned artifacts require explicit operator recovery. Preparation verifies
the published helper revision and compatibility launcher against its sealed
source. SSH uses the complete-release loader; systemd validates the fixed release
directory before interpreting guard/start/stop code. Boot and SSH firewall
confirmation enter that checked controller, while the common helper owns its
load/confirmation lock. Data and the original node identity remain preserved.

A cancellation-write or service-stop failure still attempts graceful shutdown of
the freshly inspected owned container and disabling the unit. Any failure is
reported even if a later retry persists the fence. Persistent storage failure
cannot establish durable restart prevention; repair the host and retry. No
unidentified container is signaled and no forced kill is used.

[S16]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/cmd/ken/main.go "EN executable role and app flag assembly"
