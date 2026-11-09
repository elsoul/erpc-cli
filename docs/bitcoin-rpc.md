<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Bitcoin RPC nodes

`erpc r --chain bitcoin` manages one owned Bitcoin Core instance per host on
mainnet, testnet4, default signet or regtest. Bitcoin validators are **N/A**;
mining and wallet operations are outside this backend. The lifecycle has offline
verification and mock tests; **real-host deployment and synchronization acceptance
remain deferred**.

## Prepare and deploy

The controller needs 1Password, its SSH agent/public key, and GnuPG (`gpg` and
`gpgv`) installed in a standard system location. Target hosts require Ubuntu
24.04+, Linux x86-64/ARM64, passwordless sudo, two CPU cores and 4 GB RAM.
Provision writable ext4/XFS storage with an original filesystem UUID before init;
erpc never formats a disk. Empty root-owned pre-mounted ROOT/DATA directories
may contain a verified empty root-owned `lost+found`, which is preserved. Nested
or stacked mounts, foreign ownership and unknown existing native data are refused.

```sh
erpc r --chain bitcoin init -n signet --name btc-a --host <server> \
  --ssh-key <operator.pub> --vault <vault> --type full
erpc r --chain bitcoin deploy -n signet --name btc-a --ssh-key <operator.pub>
erpc r --chain bitcoin status -n signet --name btc-a --ssh-key <operator.pub>
```

The executable catalog is Core **31.1**, source commit
`9be056a8a72b624dae9623b2f7bded92c2a21c91`, with the exact authenticated x86-64/ARM64
archive digests. `--version 31.1` selects this qualified target. A future version
requires an explicit source/catalog update; arbitrary newer release flags,
prereleases and automatic latest-major selection are refused. Each pin records version, resolved source commit, target architecture and
archive SHA-256. Both carried public Guix-builder keys must authenticate the
small `SHA256SUMS` manifest. TLS or a bare checksum is insufficient. The host
repeats signature authentication, downloads the pinned archive, rehashes it, and
extracts only `bitcoind` and `bitcoin-cli` before running either binary.

The controller and host use an isolated public verification keyring. The upstream
signature bundle contains additional signers; aggregate verifier exit status is
not accepted as proof. Two distinct trusted primary fingerprints are required,
and bad/expired/revoked signature statuses are refused. See the
[trust-root provenance](../crates/erpc-chain-bitcoin/templates/gpg/SOURCES.md) and
[official release-verification guide](https://bitcoincore.org/en/download/).

## Storage and private RPC

`--type full` is the default: retain block history and enable `txindex=1`.
`--type pruned --prune-mib 10240` explicitly selects bounded block-file retention
and disables the incompatible full transaction index. The prune target excludes
chainstate overhead. Retention is immutable for an owner/datadir; a later flag
cannot restore discarded history.

Free-space floors are deployment policy, not measured chain-size
promises: full mainnet 1,500 GB, testnet4 200 GB, signet 100 GB; pruned networks
reserve the configured block target plus 100 GB; regtest reserves 10 GB. Allow
further growth and RPC workload capacity. Every prepare, deployment/resume, update
and start/reboot checks the host again. Required free space is the initial floor
minus allocated bytes in Core's network-specific blocks, chainstate and indexes,
with a minimum operating reserve of 50 GB for full public networks, 100 GB for
pruned networks, and 1 GB for regtest. This is a capacity estimate, not proof of
sync completion; an installed binary or inventory flag never skips it. Stop and
destroy remain usable under disk pressure. Initial synchronization uses Core's
normal block download. There is no snapshot import or AssumeUTXO shortcut in this
backend. A deploy can finish while block download or transaction indexing continues.

Fresh Core instances use a separately reserved non-login `erpc-bitcoin` account.
Its original numeric UID/GID, dedicated groups, home and shell are recorded before
NSS creation; units use those numeric recipients. Current name/ID lookups must
agree with the original record, and a missing established account is not recreated.
Data, indexes, peer state and its cookie
are under `/var/lib/erpc-bitcoin/data` (Core adds the test network subdirectory).
The data directory is mode 0700. Configuration is `/etc/erpc/bitcoin.conf`;
verified releases live under `/opt/erpc-bitcoin/releases`.

RPC binds **only to 127.0.0.1**, uses Core's local cookie and has wallets/REST
disabled. The daemon uses command-line `-nosettings`, so writable `settings.json`
cannot override the protected configuration. The inspection client uses only
five fixed read-only JSON-RPC methods through a host-local HTTP connection. Before
reading or sending the cookie, it proves that the accepted socket belongs to the
original native PID, UID, image, argv and cgroup. Cookies remain on the host.
The service checks its
exact owned configuration and the manager's loaded numeric account, command
arguments and absence of overrides/hooks before every explicit start and boot;
it cannot start from an absent or modified listener configuration. RPC ports are
8332 mainnet, 48332 testnet4, 38332 signet and 18443 regtest. Peer TCP ports are
8333, 48333, 38333 and 18444 respectively.

There is no public RPC firewall opening or bundled TLS gateway. For operator
queries, `status` uses the authenticated local inspection path. Any separately
operated `bitcoin-cli` must run as the recorded original numeric account over
authenticated SSH so the cookie stays on the host. An SSH tunnel alone does not authenticate Core RPC.
Application access through a separate gateway requires its own TLS, authorization,
method policy and network controls; erpc does not provision that gateway or copy
cookies to the controller. No native WebSocket, gRPC or Prometheus service is
advertised.

## Ownership, updates and recovery

Every remote mutator—including start, stop and destroy—checks the inventory owner,
network and retention against a persistent root-owned host contract before touching
a service. A failed initialization from another network leaves no authority to
stop or repurpose the original node. An unowned existing Core service/datadir is
refused rather than adopted.

```sh
erpc r --chain bitcoin plan -n signet --name btc-a --change update --version <version>
erpc r --chain bitcoin update -n signet --name btc-a --version <version> --ssh-key <operator.pub>
erpc r --chain bitcoin logs -n signet --name btc-a --ssh-key <operator.pub> --follow
```

Updates select the explicit qualified `31.1` target and refuse downgrades before
changing inventory. Independent root-owned pending and committed source receipts
also preserve the highest version, commit, archive and native image hashes before
any database-opening start. Stale inventory or an older owner file cannot erase
a higher opened-source floor. Installation saves a durable
target/fence before stopping Core. A failure cannot cause an automatic binary
rollback across a database migration, and reboot cannot start a partly installed
release. Resume with a new explicit `deploy` intent. `stop` and `destroy` remain available
while installation is incomplete; they cancel queued publication/activation and
attempt original process shutdown and boot disable even when a persistent fence
write fails. Installed helper, binaries, configuration and units are published only
under the same current intent and operation lock. A previous cancelled deployment
cannot reactivate by finishing late. Complete pending cancellation/owner writes
remain restrictive even if file fsync fails before rename. Before either mutable
staging name can be replaced, its restrictive stop/generation/retirement is
preserved in an immutable content-addressed record under `cancellation-history`,
with repeated file and directory barriers. Failed open, partial write or rename
of a subsequent authorization cannot remove this evidence. Clearing it requires
a later explicit generation to cross its committed file and directory barriers;
visible pending records continue to block old stages and startup. Power-loss
persistence still depends on successful storage barriers. Data is never deleted
to recover a failed bootstrap or update.

`update-config` reauthenticates the stored release and reapplies its fixed private
configuration/service; it does not change retention. Configuration drift is refused
before mutation and needs operator investigation. `destroy` cleanly stops/disables
the owned service and records it as retired, preserving data, binaries and ownership.
There is no purge/forget switch. A subsequent deploy of that same owner can resume
its retained data. Shutdown uses verified systemd commands or a generation-bound
`pidfd` SIGTERM to retained original native processes; unknown processes are never
killed, and SIGKILL is not used. Persistent total storage failure cannot guarantee
a durable reboot fence; shutdown is still attempted and the operation reports failure.

The twelve verbs are `init`, `deploy`, `list`, `status`, `logs`, `start`, `stop`,
`restart`, `update`, `update-config`, `plan` and `destroy`. Select the network
explicitly; production mutations also require `--chain bitcoin` on the command line.

## Explicit legacy migration

Older named-account installations do not silently gain original authority. A
known managed, authenticated 31.1 profile can be migrated using an independently
retained public historical record:

```sh
erpc r --chain bitcoin deploy -n signet --name btc-a --ssh-key <operator.pub> \
  --original-runtime-record <historical-public-record.json>
```

This invocation **only migrates and leaves the service stopped**. It never
continues into deployment. Run a separate explicit `deploy` after inspecting the
result. The closed record schema is `erpc-bitcoin-original-v1`, with exactly:

- `contract`: original `owner`, `network`, `storage`, `prune_mib` and `host_binding`.
  The binding is SHA-256 of the compact JSON array containing the domain
  `erpc-bitcoin-original-host-v1`, original SSH address, login user, port and
  pinned host-key text, in that order.
- `machine_sha256`: SHA-256 of the original stripped ASCII machine-id.
- `layout`: `root` and `data` objects each containing original `uuid` and
  `fstype`, plus the historical `root_inode` and `data_inode` integers.
  Kernel device numbers are not durable identity.
- `account`: original `name`, numeric `uid`/`gid`, absolute `home` and `shell`.
  Only the known legacy `bitcoin`/non-login profile is supported here.
- `highest_source`: original `version`, source `commit`, archive `sha256` and
  target `platform`, representing the highest source that opened the database.
- `daemon_sha256` and `client_sha256`: original executable hashes established
  from that authenticated release, not hashes inferred from current unknown files.

Use independently retained history. Do not manufacture missing evidence by
reading today's mutable NSS, mount table or installed binaries. The migration
compares all fields, original volumes/inodes, dedicated account lookups, private
DATA permissions, source marker and native bytes. Unknown history, higher opened
versions, changed UUID/inode, nested mounts or reassigned identities are retained
and refused. Migration does not create/change accounts, chown DATA, regenerate a
cookie, replace a native binary or start the node. It records the original legacy
owner and repeats persistence barriers after interrupted publication. An explicit
verified ROOT mode transition from 0700 to 0755 permits numeric-account traversal;
DATA stays private. This is not an arbitrary external Core-import mechanism.

## Health and acceptance

`status` distinguishes original account/volume authority, source-floor and owned
process/listener proof, service liveness, RPC warmup, network/genesis identity,
initial block download, header progress, retention and transaction-index readiness.
Full RPC requires a synced transaction index at the validated tip. Public networks
also require peers and a plausible recent tip timestamp; regtest deliberately skips
peer/freshness assumptions. Unready status exits unsuccessfully and includes specific
problems in JSON. These checks do not claim that every RPC query or external gateway
has been exercised.

Offline evidence covers original UID/GID and UUID/inode qualification, real
file/fsync interruption and cancellation, proc/socket-shaped proof with inert
images, actual carried stdin framing/entrypoints, stopped migration retries,
and the actual signed 31.1 manifest with both public trust roots,
corrupted manifest/signature/archive rejection, clean verifier environments, mocked
ownership failures, wrong-network initialization followed by attempted mutations,
interrupted bootstrap/update recovery, immutable inventory and index-aware health.
No native node binary, operational key, production NSS mutation or real systemd
service was executed for these tests. Modeled process/mount/NSS checks do not
substitute for the deferred Linux kernel/systemd acceptance batch. The later live
batch must cover sync, RPC/index behavior, restart/reboot, update recovery and
firewall/gateway behavior on selected authorized hosts.
