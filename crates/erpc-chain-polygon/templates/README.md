<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Polygon RPC/sentry operations

`erpc rpc --chain polygon` (`erpc r`) manages a dedicated
Bor + Heimdall v2 full/sentry host on Mainnet or Amoy. All twelve common verbs
are implemented: `init`, `deploy`, `list`, `status`, `logs`, `start`, `stop`,
`restart`, `update`, `update-config`, `plan`, and `destroy`. Validator admission,
validator signing and financial account registration are a
[separate lifecycle](../../../docs/polygon-validator.md).
No node or real-host acceptance has been performed for this implementation.

## Reviewed native pair and bootstrap

The [network catalogs](../networks/) pin Bor `v2.10.3`
(`a16f123d9b4f41a552a3a98d93a0340430838576`, 2026-10-15) and Heimdall v2
`v0.13.2` (`03090c94e7eaef344cd16efd6c968431c4041847`, 2026-11-03) for both
networks and Linux x86-64/ARM64. Each Debian package, detached signature and
certificate has an exact byte length and SHA-256. Cosign `v3.1.4`
(`0e48502cf5ef34e2e60bbd3617aa19945712f705`, 2026-10-20) is independently
byte/hash pinned. It verifies the exact upstream `packager_deb.yml` workflow,
release tag, source commit, GitHub Actions issuer, certificate chain and
transparency evidence. The verifier bootstrap relies on the reviewed binary
SHA-256; this is distinct from an independent signature bootstrap of Cosign.

These `.sig` files use Sigstore keyless signatures, not GPG. The package is
extracted without executing Debian maintainer scripts; both native version
outputs are checked before configuration changes. Bor's ARM64 workflow omits
its embedded Git commit, so the verified workflow SHA supplies the commit
binding on that architecture. Complete upstream TOML is fetched by immutable
commit and hash, then only RPC/sentry settings are changed. Source evidence:
[Bor workflow](https://github.com/0xPolygon/bor/blob/a16f123d9b4f41a552a3a98d93a0340430838576/.github/workflows/packager_deb.yml),
[Heimdall workflow](https://github.com/0xPolygon/heimdall-v2/blob/03090c94e7eaef344cd16efd6c968431c4041847/.github/workflows/packager_deb.yml),
[Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/).

Bootstrap replays the official migrated Heimdall v2 genesis. It does not
silently select a community snapshot. The official objects were streamed and
hashed on 2026-10-26; these are **our observed hashes of official bytes**, not
upstream-published signed checksums. GCS object generation and exact length are
also checked on every download:

| Network | Immutable object generation | Bytes | Observed SHA-256 |
|---|---|---:|---|
| Mainnet | `1752157618295837` | 2358946007 | `843e785e340a408d952b7aa0d92435c94643536f426ab7c3ee188bfdc68b8699` |
| Amoy | `1750794512935656` | 35404068 | `25a5bc9e17f314b54cca597a1e795ab56db7787e2fc986172f1e560ff3bf2f98` |

The [official binary guide](https://docs.polygon.technology/pos/how-to/full-node/full-node-binaries)
links the [Mainnet object](https://storage.googleapis.com/mainnet-heimdallv2-genesis/migrated_dump-genesis.json?generation=1752157618295837)
and [Amoy object](https://storage.googleapis.com/amoy-heimdallv2-genesis/migrated_dump-genesis.json?generation=1750794512935656).
Heimdall must catch up before Bor starts. Genesis replay can take substantial
time; `deploy` reports an accepted asynchronous startup, while `status` returns
a failing exit status until both layers advance and the parent and WebSocket
checks pass. Status shows each layer independently, including when Bor has not
started yet. See [snapshot tradeoffs](https://docs.polygon.technology/pos/how-to/snapshots).

## Host and access configuration

Use dedicated Ubuntu 24.04, passwordless sudo for the operator, 16 CPU cores,
64 GB RAM and 6 TB SSD/NVMe for Mainnet; Amoy uses 16 GB RAM and 2 TB.
These recommended sizes come from the
[official prerequisites](https://docs.polygon.technology/pos/how-to/prerequisites).
The implementation's conservative capacity policy is distinct: free space plus
allocated native databases must remain at least 5.5 TB (Mainnet) / 1.5 TB
(Amoy), with at least 128 GiB / 64 GiB still free and 2 GiB free on the
OS/artifact filesystem. Genesis/cache files do not count as database allocation.
Capacity is checked during preparation, activation, manual start and reboot
startup; stop and destroy remain possible under disk pressure. Provision data
storage at `/var/lib/polygon`; nested data mounts are refused.

P2P ports 30303 TCP/UDP and 26656 TCP are public. HTTP 8545 and WebSocket 8546
require `--rpc-allow`; metrics 7071 and 26660 require `--monitoring-allow`.
Both accept explicit IPv4/IPv6 CIDRs and reject `/0`. Heimdall REST/gRPC,
Comet RPC, Bor internal gRPC and the parent transport stay on loopback. The
actual connected SSH server port and controller address are preserved in the
firewall, along with `--management-allow`. Use a separately reviewed TLS gateway
for remote client access. `--advertise-ip` is an explicit numeric public peer
address checked against the shared conservative IANA policy.

## Parent credential and first deployment

Create a concealed 1Password field containing this schema, selecting an
Ethereum Mainnet endpoint for Mainnet or Sepolia for Amoy:

```json
{"execution":{"url":"https://github.com/replace-with-your-parent-provider","headers":{"Authorization":"Bearer YOUR_TOKEN"}}}
```

The URL above is a schema placeholder. Use an identifier-only `op://` reference
to the selected field. No beacon endpoint is used. URL/header contents remain
in concealed stdin and a host-bound encrypted systemd credential; inventory,
bundles, command lines and ordinary diagnostics contain no provider secrets.
The local parent proxy allows only the read methods Heimdall uses, validates
parent chain ID/genesis, and rechecks literal/DNS destinations on connection.
Numeric loopback requires the schema's explicit `allow_loopback: true`; the
proxy's own port is always refused.

```sh
erpc r --chain polygon init -n amoy --name polygon1 --host HOST \
  --ssh-key OPERATOR_PUBLIC_KEY --vault VAULT_ID --advertise-ip PUBLIC_IP \
  --l1-execution op://VAULT_ID/ITEM_ID/FIELD_ID \
  --rpc-allow TRUSTED_CIDR

erpc r --chain polygon plan -n amoy --name polygon1
erpc r --chain polygon deploy -n amoy --name polygon1 --ssh-key OPERATOR_PUBLIC_KEY
erpc r --chain polygon status -n amoy --name polygon1 --ssh-key OPERATOR_PUBLIC_KEY
erpc r --chain polygon logs -n amoy --name polygon1 --ssh-key OPERATOR_PUBLIC_KEY --component heimdall --follow
```

`init` reserves a stable unique inventory owner before establishing the remote
immutable owner/network/role/architecture/genesis contract. A second inventory
cannot adopt the same host even with identical network settings. Initializing
installs distribution dependencies and dedicated non-login accounts; it does
not start either client. `deploy` fences and drains existing services before
authenticated preparation. Only after downloads and credential access finish
does a short firewall transaction begin. Fresh SSH confirms its exact
run/bundle receipt before asynchronous activation. Rollback, failed preparation,
reboot and superseded operations cannot start an unconfirmed listener.

## Updates, custody and recovery

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


`update` explicitly selects this CLI's reviewed pair. Each client's installed
and interrupted desired version forms a monotonic floor: an older CLI cannot
downgrade either database or reinterpret an equal version with different bytes.
`update-config` retains the reviewed pair and can change trusted ranges,
advertisement or the selected parent reference. The desired reference is saved
before an interruptible rotation. Retry `deploy` after correcting a failure;
there is no destructive automatic database migration.

The original Bor P2P key and Heimdall node/consensus identities are generated
once on the host and encrypted with systemd credentials. This RPC node has no
registered validator or financial account; Bor mining/wallet integration and
Heimdall bridge transactions are disabled. Native Heimdall uses an explicit
memory keyring backend so headless version/init/start do not require an OS
keyring. Mutable consensus signing history is retained independently of keys.

Activation saves a root-readable encrypted recovery package at
`/etc/polygon/original-credentials.backup.json`. Keep a protected backup together
with the original host's systemd credential protection material and both data
directories. `deploy --restore-keys` validates and restores only the original
host-bound ciphertexts; the retained public identity and actual mutable
consensus history must match. It never imports another validator identity or
resets a missing signing-state file. If the original host binding or consensus
history is unavailable, automatic recovery is refused and requires separately
reviewed offline recovery. A later parent-token rotation is not rolled back.

`stop` persistently fences startup before draining; `start`/`restart` verify the
same contract, installed bytes, histories, reserve and confirmed ingress.
`destroy` stops/disables before removing ingress and retains inventory,
encrypted identities, recovery material and databases. Deploying again is an
explicit owned reactivation; inventory deletion is not host ownership transfer.

Before changing keys/configuration or removing ingress, the controller checks
that managed cgroups and dedicated UIDs are quiescent. It also refuses native
executables or other processes whose arguments/open descriptors reference the
managed data directories. An unknown writer is never killed automatically;
stop it through its actual owner and retry. Native/proxy health and prerequisite
checks bind each fixed API socket to the expected service MainPID, UID, cgroup,
executable and arguments, then repeat the proof after sampling to detect
replacement. Heimdall progress remains visible while Bor is waiting to start.

Root-owned ownership, intent, stop/retirement fences, original encrypted
identity/history receipts, activation and recovery publications sync their
files and directory entries before proceeding. A storage synchronization error
aborts the operation; failed fence cancellation re-establishes the fence.
A retained stopped fence cancels every deployment phase even if invalidating
its intent failed. A new preparation durably replaces the intent and publishes
its preparation fence before draining and clearing the stop fence; explicit
start also durably invalidates pending deployment intent before clearing it.
Stop attempts both cancellation barriers and disables/drains known units even
when a storage write fails, retaining ingress and reporting failure. Persistent
storage failure cannot establish a durable reboot guarantee; repair storage
and retry the failed operation before relying on it.
`logs --json` writes compact JSON records, including completion, to stdout;
human journal output remains on stderr.

## Verification limits

Offline tests exercise the actual prepare/configuration/identity publication,
immutable helper selection, service sealing, restart fences, independent sync
progress, secret schema, owner mismatch, disk pressure and downgrade refusals.
The shared firewall suite covers delayed callbacks and superseding candidates.
Strict templates cover both networks/architectures and empty/IPv4/IPv6 ACLs.
One actual pinned Cosign verification of the official Bor amd64 package passed;
changed bytes and a wrong workflow identity were rejected. Native clients were
not executed. Linux systemd/credentials/nftables, full replay, peer connectivity,
real-host recovery and performance acceptance remain deferred by the user.

The original Bor, Heimdall and parent-proxy accounts are reserved together before
any NSS account/group changes. Existing unknown accounts/groups are refused;
interrupted creation resumes only the recorded UID/GID reservation. Startup
checks the original UID/GID, dedicated home/shell and supplementary membership,
including the running native process and proxy's actual groups. Enumeration must
agree with keyed name and numeric NSS lookup; candidate IDs exclude keyed-only
records and existing users' primary GIDs. Privilege drift cannot be repaired by silently adopting the current account. A receipt-free
legacy host needs reviewed migration before startup or update; current carried
stop/destroy retains data and considers both original and currently observed
UIDs while refusing unknown writers. A component startup guard checks only that
component's original and current UIDs, so already-running owned prerequisites can
remain active; full stop/destroy checks every original runtime UID.

Each credential-bearing service uses the original numeric `User`/`Group` and a
first, externally checked `ExecCondition`. On the supported systemd 255 this
condition runs before credential materialization; `ExecStartPre` retains the
later capacity, process and synchronization checks. Loader or condition validation refusals
exit 255, and an observed failed/skipped condition is not reported as a successful
start. Asynchronous requests report readiness as pending until `status` verifies
the services. Preparation disables existing listener units before acquisition,
so an interrupted upgrade cannot automatically boot an older credential unit.
Core dumps are disabled. Original numeric IDs must remain dedicated while
services run; stop before administrative account reassignment.

The ordering follows systemd 255's
[condition and prestart execution flags](https://github.com/systemd/systemd/blob/v255/src/core/service.c),
[recipient resolution](https://github.com/systemd/systemd/blob/v255/src/core/exec-invoke.c),
and [credential ACL setup](https://github.com/systemd/systemd/blob/v255/src/core/exec-credential.c).


Privileged helper/configuration/custody/release directories and all managed
service drop-in contents must have protected root-owned, non-symlink ancestors.
Only the exact owned helper release pointer is allowed. Native and firewall
startup use an external inline trusted bootstrap before executing the immutable
controller. Firewall loading checks ownership through that controller, then lets
the common helper own the single operation lock. It does not recursively trust
the shared directory containing the intentional release pointer. No account, key
or live node was created by the offline verification.

Use the matching current CLI after a helper-profile upgrade. Older release-pointer
loaders refuse unknown helper revisions; current stop can use its sealed carried
controller without adopting legacy accounts or replacing installed helpers.

New ownership records carry the runtime protocol version so older carried helpers,
which require the original exact contract shape, refuse mutation after this
upgrade. Current code accepts the legacy scope only for inspection and owned
shutdown; it does not turn a receipt-free legacy owner into new account authority,
even when its old NSS entries have disappeared.


Mount an empty ext4 or XFS filesystem at `/var/lib/polygon` with its normal
root-owned udev UUID entry. An empty root-owned `lost+found` is preserved;
existing recovery contents require explicit recovery before deployment. New
runtime protocol 3 records the original filesystem UUID and data-directory inode
before account provisioning. Preparation, key restoration, confirmation and
startup recheck this receipt and reject nested mounts, including binds on the
same device. Kernel device-number changes across reboot are resolved through the
original UUID. Capacity credit excludes `lost+found`.

The guard reads the host mount table using the qualified
[findmnt interface](https://github.com/util-linux/util-linux/blob/v2.39.3/misc-utils/findmnt.c).
Runtime UUID verification uses the udev link and block-device metadata without
opening the device. A host from an older runtime protocol needs reviewed storage
migration before startup or update. Owned stop/destroy remains available when a
storage receipt is missing or the original volume is unavailable; data is retained.
