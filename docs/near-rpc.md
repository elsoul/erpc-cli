<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# NEAR RPC followers

`erpc rpc --chain near` manages a dedicated Mainnet or Testnet follower using
nearcore. The twelve operations are `init`, `deploy`, `list`, `status`, `logs`,
`start`, `stop`, `restart`, `update`, `update-config`, `plan`, and `destroy`.
This role tracks all shards with five-epoch garbage collection. It does not
provide archive history or load a validator signing key.

## Qualified releases and host

The reviewed defaults are Mainnet **2.14.0**, source
`bc4e9e8cfb03d9e82f027883055624e18576993e`, and Testnet **2.14.0-rc.6**, source
`d37c9e9ed3412dfab319e2e56bde24fd38e62ef1`. Testnet deliberately uses its
network-specific prerelease guidance. Its observed public RPC was still rc.5
when inspected; this is not a claim that every public provider had upgraded.
See the [stable release](https://github.com/near/nearcore/releases/tag/2.14.0),
[Testnet release](https://github.com/near/nearcore/releases/tag/2.14.0-rc.6), and
[operator guide](https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/rpc/run-rpc-node.md).

Mainnet 2.14.0 is required for protocol 87/88. Voting starts on November 4 and
November 6, 2026 at 00:00 UTC respectively; the official Mainnet RPC reported
protocol 87 with a fresh head on November 4. Upgrade the original node explicitly
with `update --version 2.14.0`. The native client migrates the existing database
from version 49 through 50 to 51. Preserve the original database and credentials;
do not downgrade a database opened by the newer client. An invalid legacy
light-client row stops migration for diagnosis instead of replacing the data.
[Protocol and database transition](https://github.com/near/nearcore/releases/tag/2.14.0).

The generated profile uses peer-based state synchronization. Its pinned base
configuration has no removed `ExternalStorage` sync selection and no disabled
state-snapshot setting. Version 2.14.0 takes state snapshots every epoch. RPC
consumers should also account for the new default 100-key access-list pagination
limit and optional transaction-timeout cause fields. Testnet remains on its
separately qualified 2.14.0-rc.6 profile; Mainnet's stable tag is not substituted
for it automatically.

Only the published **linux/amd64** image is qualified. ERPC pins the official
`nearprotocol/nearcore` platform manifest digest, then checks `neard --version`
for the complete release and source commit with networking disabled. This is
publisher TLS/content pinning, not a claimed GPG signature or reproducible build.
The [release workflow](https://github.com/near/nearcore/blob/bc4e9e8cfb03d9e82f027883055624e18576993e/.github/workflows/neard_release.yml)
and [image definition](https://github.com/near/nearcore/blob/bc4e9e8cfb03d9e82f027883055624e18576993e/Dockerfile)
provide the source relationship. ERPC invokes `neard` directly, bypassing the
image's environment-based startup script.

Use Ubuntu 24.04+, passwordless sudo, 16 logical CPU cores, 32 GB RAM on Mainnet
or 16 GB on Testnet, and local NVMe storage. Initial free-space floors are 3.5 TB
and 1.4 TB respectively, with a 100 GB operating reserve as owned database
allocation grows. Provision at least 4 TB Mainnet or 2 TB Testnet to allow for
the operating system and overhead. The host verifies CMPXCHG16B, POPCNT, SSE4.1,
SSE4.2, AVX and SHA-NI on every processor before deployment. These are explicit
deployment floors based on the [official hardware guidance](https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/rpc/hardware-rpc.md),
not measured database-size promises or throughput guarantees.

## Deployment and access

```sh
erpc r --chain near init -n testnet --name near-a --host <server> \
  --ssh-key <operator.pub> --vault <network-vault> \
  --management-allow <stable-management-cidr>
erpc r --chain near plan -n testnet --name near-a
erpc r --chain near deploy -n testnet --name near-a --ssh-key <operator.pub>
erpc r --chain near status -n testnet --name near-a --ssh-key <operator.pub>
```

Peer traffic uses TCP 24567. RPC uses 3030 and a separate metrics listener uses
3032; both bind to loopback by default. Select trusted IPv4 ranges using
`--rpc-allow` or `--metrics-allow` during initialization or `update-config`.
Use `--clear-rpc-allow` and `--clear-metrics-allow` to return to loopback.
Public debug RPC, debug pages, sharded RPC forwarding and telemetry are disabled.
The native RPC listener also has metrics; clients trusted for RPC can read them.
The separate metrics listener gives monitoring clients no RPC endpoint.
[Native listener configuration](https://github.com/near/nearcore/blob/bc4e9e8cfb03d9e82f027883055624e18576993e/chain/jsonrpc/src/lib.rs).

Mainnet genesis comes from the exact nearcore source revision. Testnet uses the
official compressed genesis archive, whose compressed-byte SHA256 is pinned.
The generated official RPC configuration has its own digest. Downloads refuse
redirects, inherited HTTP proxies, wrong origins, wrong paths, oversized payloads
and digest mismatches. The decompressed genesis and final configuration are
recorded separately and checked before service startup. Existing verified source
configuration and genesis are reused for subsequent preparation. The downloaded
RPC configuration has no boot peers, so ERPC follows the official epoch-sync
procedure: query the network's fixed public RPC, verify its genesis and fresh
synced status, and intersect `network_info.active_peers` with `known_producers`.
Only bounded Ed25519 peer IDs with public numeric unicast socket addresses are
accepted. An empty qualified set refuses deployment. These observer requests
disable inherited proxies and redirects and send no credentials or transactions.
The selected peers are retained for an interrupted target, so a retry cannot
silently change its configuration. Live peers then provide epoch/state
synchronization; no deprecated community snapshot is selected.
[Native initialization](https://github.com/near/nearcore/blob/bc4e9e8cfb03d9e82f027883055624e18576993e/nearcore/src/config.rs),
[epoch synchronization](https://github.com/near/node-docs/blob/db6103b400ab056c12a5716d6cef1dca519c442b/docs/intro/epoch_sync.md).

An explicit stop or a newer preparation invalidates the earlier caller's
activation intent. A separate durable revocation marker precedes replacement
intent/target publication, so a failed write cannot leave an old queued activation
authorized. Stop and retirement attempt both independent cancellation writes
before owned shutdown. If a write or fsync fails, shutdown is still attempted and
the command reports an error; restart protection must not be assumed durable
until storage is repaired. `start` can explicitly clear a stop marker only
for a completed, verified installation; retired or interrupted installations need
a new successful deployment. Data and identity survive these failures.

Bootstrap address filtering conservatively excludes protocol/dummy/translation
prefixes explicitly, independent of Python's changing `is_global` classification.
These exclusions are based on the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) special-purpose registries.

Preparation verifies artifacts before stopping an existing node. It then writes
a durable installation fence, stops the owned service and any surviving owned
container, and installs the exact prepared configuration. Only a separate short
firewall operation, confirmed through a fresh SSH connection, authorizes
activation. The confirmation binds the caller's run and bundle, and activation
also checks the prepared policy identity. Long image/genesis downloads occur
outside the firewall rollback window.

The controller rejects writable, foreign-owned or indirect ancestors of its
state, configuration, encrypted peer credential and installed helper. State
receipts are bounded private regular files with a single link. Unknown unit
files are not adopted during initialization; managed unit drop-ins are limited
to the common firewall guard. Installed SSH and systemd entrypoints authenticate
the helper namespace before interpreting the controller, while carried plays
compare published helper bytes with their sealed source.

## Identity, upgrades and recovery

Initialization reserves the original numeric UID/GID, home and non-login shell
before changing NSS accounts. Unknown existing `near` users or groups are refused.
Interrupted group/user creation resumes only that durable reservation; data-home
ownership uses its numeric IDs. Startup, preparation, key staging and readiness
verify the original IDs, home/shell, aliases, primary-group ownership and absence
of supplementary groups. The real data home must remain private and owned by
those IDs. Account drift prevents startup without blocking shutdown of the
already owned container.

Preserve `accounts-intent.json`, `accounts-reserved` and `accounts.json` in the
protected NEAR management directory. Missing original authority is not permission
to adopt an existing account or choose a replacement UID. Legacy ownership without
these receipts requires reviewed migration before provisioning or startup; owned
stop/retirement remains available. New ownership records use a versioned wrapper
that older carried helpers refuse, preventing an old initialization play from
bypassing the account reservation.

The first deployment invokes the native initializer with networking disabled,
without an account ID, against the already verified config and genesis. It creates
only the peer key. Plaintext exists in a private temporary directory under `/run`
while it is encrypted with the host's systemd credential key. A root-owned receipt
binds the public peer key and plaintext/ciphertext digests to the immutable host
owner, network and role. Runtime plaintext is staged only under `/run`, mounted
read-only into the unprivileged container. Core dumps are disabled in both the
service and container; no private key is an argument or environment variable.

The original peer identity is retained across upgrades and retirement. Missing
or mismatched established material is refused; initialization never silently
generates a replacement. A crash between receipt publication and ciphertext
publication resumes only when the pending ciphertext matches the original
receipt. Preserve `/etc/credstore.encrypted/near-node.key`, its identity receipt,
and the host systemd credential secret in the host's protected backup procedure.
The encrypted file alone is not a portable key backup. The separately reserved validator role and external registration workflow are
described in [NEAR validators](near-validator.md).

`update --version <version>` accepts the reviewed release for that network in the
installed CLI catalog. Other releases require a reviewed catalog update.
This CLI's `start` and `restart` require the observed installed version, source
commit and image to match that network's qualification. Status keeps historical
receipts visible but does not report an older unqualified runtime as ready.
Updating the CLI alone does not upgrade an existing service; use explicit update.
Database downgrades are refused. A failed preparation remains fenced; retry
`deploy` with the stored target. An unrelated policy/configuration cannot take over
an incomplete target. `stop` and `destroy` remain available during interruption.
`destroy` retires and disables the service while retaining data, ownership and
identity. Same-owner deployment can resume it. There is no purge or cross-host
identity-adoption switch.

For an original Mainnet 2.13.4 installation interrupted before activation,
`update --version 2.14.0` can explicitly move its pending target forward. It
retains the original genesis, access policy and peer set, and records the old
target/bootstrap and exact new target in a protected journal before replacing
either receipt. The original writer is stopped before the new configuration is
published. Retry that update after a failed first publication; once its journal
exists, `deploy` can resume the recorded forward target. Other original source
pins or changed access policies are refused. Keep the original journal, database,
peer credential and validator history; this operation never creates a new identity
or resets the database. Change access settings in a separate completed operation.

`status` requires the owned container and RPC socket, matching chain/genesis and
peer identity, the installed release/source commit, an active service, a confirmed
firewall, no validator identity, `syncing=false` and a fresh latest block. It
returns an unsuccessful exit status until these conditions hold. A successful
deployment can still be synchronizing. Status does not certify all RPC methods
or archive availability.

The implementation has offline ownership, identity, partial-publication, firewall,
shutdown, capacity, source-pin and readiness tests. Initialization, epoch/state
sync, RPC workloads, restart/reboot and recovery still await acceptance on a
real host.

After verifying ownership, `stop` and `destroy` still attempt graceful shutdown
if cancellation storage fails. They report failure rather than claiming durable
restart protection, and retain credentials, chain data and filtering. If shutdown
also fails, the error reports both failures. Repair storage and retry before
relying on cancellation across reboot. Destruction remains repeatable when the
owned service unit is already absent.
