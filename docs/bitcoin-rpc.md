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
Provision the data filesystem before init; erpc never formats a disk.

```sh
erpc r --chain bitcoin init -n signet --name btc-a --host <server> \
  --ssh-key <operator.pub> --vault <vault> --type full
erpc r --chain bitcoin deploy -n signet --name btc-a --ssh-key <operator.pub>
erpc r --chain bitcoin status -n signet --name btc-a --ssh-key <operator.pub>
```

The reviewed default is Core 31.1. `init --version <stable-version>` selects a
specific newer release; automatic latest-major selection and prereleases are not
used. Each pin records version, resolved source commit, target architecture and
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

Core runs as the non-login `bitcoin` user. Data, indexes, peer state and its cookie
are under `/var/lib/erpc-bitcoin/data` (Core adds the test network subdirectory).
The data directory is mode 0700. Configuration is `/etc/erpc/bitcoin.conf`;
verified releases live under `/opt/erpc-bitcoin/releases`.

RPC binds **only to 127.0.0.1**, uses Core's local cookie and has wallets/REST
disabled. The daemon uses command-line `-nosettings`, so writable `settings.json`
cannot override the protected configuration. The inspection client reads the
explicit config only and does not load dynamic settings. The service checks its
exact owned configuration before every boot;
it cannot start from an absent or modified listener configuration. RPC ports are
8332 mainnet, 48332 testnet4, 38332 signet and 18443 regtest. Peer TCP ports are
8333, 48333, 38333 and 18444 respectively.

There is no public RPC firewall opening or bundled TLS gateway. For operator
queries, run the installed `bitcoin-cli` as `bitcoin` over authenticated SSH so the
cookie stays on the host. An SSH tunnel alone does not authenticate Core RPC.
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

Updates require an explicit stable version and refuse downgrades before changing
inventory, then verify the same constraint on the host. Installation saves a durable
target/fence before stopping Core. A failure cannot cause an automatic binary
rollback across a database migration, and reboot cannot start a partly installed
release. Resume the same stored target with `deploy`; another target or concurrent
service mutation is refused while installation is incomplete. Data is never deleted
to recover a failed bootstrap or update.

`update-config` reauthenticates the stored release and reapplies its fixed private
configuration/service; it does not change retention. Configuration drift is refused
before mutation and needs operator investigation. `destroy` cleanly stops/disables
the owned service and records it as retired, preserving data, binaries and ownership.
There is no purge/forget switch. A subsequent deploy of that same owner can resume
its retained data.

The twelve verbs are `init`, `deploy`, `list`, `status`, `logs`, `start`, `stop`,
`restart`, `update`, `update-config`, `plan` and `destroy`. Select the network
explicitly; production mutations also require `--chain bitcoin` on the command line.

## Health and acceptance

`status` distinguishes service liveness, RPC warmup, network/genesis identity,
initial block download, header progress, retention and transaction-index readiness.
Full RPC requires a synced transaction index at the validated tip. Public networks
also require peers and a plausible recent tip timestamp; regtest deliberately skips
peer/freshness assumptions. Unready status exits unsuccessfully and includes specific
problems in JSON. These checks do not claim that every RPC query or external gateway
has been exercised.

Offline evidence covers the actual signed 31.1 manifest with both public trust roots,
corrupted manifest/signature/archive rejection, clean verifier environments, mocked
ownership failures, wrong-network initialization followed by attempted mutations,
interrupted bootstrap/update recovery, immutable inventory and index-aware health.
No node binary archive was downloaded or executed for these tests. The later live
batch must cover sync, RPC/index behavior, restart/reboot, update recovery and
firewall/gateway behavior on selected authorized hosts.
