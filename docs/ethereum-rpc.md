<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Ethereum RPC hosts

`erpc r --chain eth` manages a mainnet Reth/Lighthouse pair. A `full` node uses
Reth's pruned preset; `archive` retains historical state. Both use the same
original inventory item, pinned SSH connection, host identity and numeric service
accounts throughout their lifetime. The [chain reference](chains/ethereum.md)
describes the clients and their official sources.

## Prepare and deploy

```sh
erpc r --chain eth init -n mainnet --name eth1 --host 192.0.2.10 --type full --ssh-key ./operator.pub
erpc r --chain eth deploy -n mainnet --name eth1 --ssh-key ./operator.pub
erpc r --chain eth status -n mainnet --name eth1 --ssh-key ./operator.pub
```

Init refuses existing accounts or native material without original authority.
It records unused numeric identities before creating accounts and binds native
data directories through protected directory descriptors. An existing mounted
data root may contain an empty, protected `lost+found`. Nested database or
snapshot mounts, including same-device bind mounts, are refused.

Deployment records its intent before firewall preparation or release work.
Archives must match the selected release digest and signing key. Only regular
client files are extracted through protected descriptors, with explicit public
execute modes. Reth’s README and LICENSES archive members are recognized but are
not executable payloads. This follows the fixed [Reth release workflow](https://github.com/paradigmxyz/reth/blob/d763342fa185e4e90ee79dc65f6a5706168b0bcb/.github/workflows/release.yml)
and [Lighthouse release workflow](https://github.com/sigp/lighthouse/blob/a376defa30470923556d91bdeb15a802e297f31f/.github/workflows/release.yml). Binaries must
report the selected version before publication. Units name immutable release
paths and original numeric users. Their privileged Python checks authenticate
the helper directory before interpreting it. Service startup verifies original
accounts, native data bindings, binaries, unit definitions, the private engine
JWT and confirmed ingress policy.

Reth's snapshot runs as a separate, resumable service. Stop can cancel its
continuation while a deployment waits. Only the private completion receipt can
skip bootstrap; a marker writable by a native client is insufficient. Free-space
admission uses the actual original data filesystem: the remaining portion of an
initial 1,500 GB (`full`) or 3,500 GB (`archive`) allowance, with at least 200 GB of
operational headroom. These are ERPC admission policies, not fixed upstream
database-size guarantees.

The engine JWT is generated on the host and retained across retries. Its value
is not put in ERPC command arguments, inventory or run bundles. RPC operation
does not import validator signing keys or authorize financial transactions.

## Operate and recover

`list`, `plan`, `status`, `logs`, `start`, `stop`, `restart`, `update`,
`update-config` and `destroy` use the same original host binding. `--layer`
selects execution, consensus or both for service operations and logs. Stopping
execution also stops its consensus dependent. Stopping consensus leaves execution
available. A stopped layer remains fenced at reboot until explicitly started.

```sh
erpc --json r --chain eth logs -n mainnet --name eth1 --ssh-key ./operator.pub
erpc r --chain eth stop -n mainnet --name eth1 --ssh-key ./operator.pub
erpc r --chain eth plan -n mainnet --name eth1 --ssh-key ./operator.pub
```

JSON journal output consists of compact JSON records on stdout, with the original
stream identified in each record. Native startup and chain readiness are separate
observations; starting a process does not establish that it has synchronized.

A failed deployment retains its original intent. Repeat the same command to
resume a still-current request. If it was canceled, use the intent shown by
`plan` to recover explicitly:

```sh
erpc r --chain eth deploy -n mainnet --name eth1 --recover-cutover ORIGINAL_INTENT --ssh-key ./operator.pub
```

Recovery stops owned writers, archives the selected operation, and preserves
native data, JWT, release and ownership receipts. It does not start a deployment.
A subsequent explicit deploy uses a fresh intent; recovered intents cannot be
re-authorized. An update failure never automatically runs an older binary over
possibly changed native data.

`destroy` retires the host and fences startup while preserving its original
material and inventory binding. `--purge-data` and `--forget` are refused for
this retirement. An explicit deploy is required to unretire it. If cancellation
cannot be persisted, ERPC still attempts owned shutdown and returns an error;
that failure is not a guarantee of durable cancellation across reboot. Restore
writable original storage before treating the cancellation as complete.

## Stable data volume authority

The managed data root must use a UUID-bearing ext4 or XFS filesystem mounted
from its whole filesystem root; nested database mounts and subdirectory bind
mounts are refused. Fresh preparation records its filesystem UUID, filesystem
type and original directory inodes before native data can be written. A kernel
device-number change after reboot is accepted when that recorded identity is
unchanged. Device numbers are compared only within the current observation to
reject a child on another filesystem; earlier numbers in retained layout/source
receipts are historical metadata, not continuing volume identity.

The controller obtains the current kernel mount and UUID with the supported
Ubuntu util-linux `findmnt` fields and matches the returned device to an open,
no-follow directory descriptor before accepting the observation. See the
[util-linux 2.39.3 field definitions and target selection](https://github.com/util-linux/util-linux/blob/v2.39.3/misc-utils/findmnt.c).
UUIDs identify filesystems, not cryptographic ownership of a cloned disk:
operator-made clones that duplicate UUIDs and original metadata must not be
substituted for the original volume.

An existing device-only ERPC receipt cannot silently learn a UUID from the
current mount. Retain an independent original storage-provisioning record or
pre-change backup that identifies the filesystem UUID and type for
`/var/lib/ethereum`. Supply this three-field JSON, using that original record:

```json
{"uuid":"12345678-1234-1234-1234-123456789abc","type":"ext4","root":"/"}
```

The value above is an inert format example, not a usable original-volume claim.
Compare the independent record with the currently attached volume; a current
`findmnt` observation alone does not establish that it is the original disk.
If the independent identity is unavailable, restore the original evidence;
do not guess it or edit the host receipts.

```sh
erpc r --chain eth deploy -n mainnet --name eth1 --upgrade-volume-authority ./original-volume.json --ssh-key ./operator.pub
```

This explicit operation checks the original host/accounts, durably fences and
drains its writers, verifies the independent UUID and original root/child inodes,
and publishes the bound volume receipt plus current authenticated helpers.
It preserves data, JWT, layout, highest-opened source records and retirement.
It never deploys or starts clients. Complete any pending cutover recovery first,
then repeat a failed upgrade with the same original evidence. After success use
a separate explicit deploy to replace old fixed-helper units before resuming.
An interrupted old initialization with a saved root binding is supported only
while its known native children remain empty and owned by root or their original
reserved users. The upgrade preserves that intent and does not fabricate a
completed layout; repeat the original `init` afterward. An old four-field legacy
migration journal can likewise accept independent UUID evidence before numeric
account receipts were published. Its independently retained account/machine/source
proof, original data inodes, archived units and JWT are verified with all services
already inactive. A separate durable receipt binds the unchanged migration journal
to that evidence; archived original units are durably masked so they cannot
restart at reboot. No unknown unit is executed and no account is adopted. Repeat
the original `init --migrate-authority` with the same original backup files to
finish that stopped conversion before deploying.

A changed UUID/type/inode, lost volume receipt, unsupported filesystem or failed
persistence remains an automatic-start refusal. Owned stop/retirement remains callable independently
of this storage check.

## Native database source floor

Each native client's highest authorized database-opening version and source is
bound to the original data volume and child directories. Acquiring a signed
candidate or installing its units does not advance this floor. Snapshot/runtime
authorization does, before native execution, and a later startup failure does
not lower it. Older inventory cannot deploy a lower Reth or Lighthouse version;
a matching version also cannot substitute its source/archive/image. Manual and
boot startup use the same checks. Explicit cutover recovery retains these floors.
There is no implicit downgrade path over an existing database.

Restore missing original floor receipts from the original authority backup.
Do not recreate them from the currently selected inventory or binary. A legacy
host uses the explicit source evidence below. This is a managed opening policy,
not proof that a process actually opened every format after authorization, or
protection against an administrator rolling back all host backups together.

## Migrate a legacy host explicitly

Legacy installations without original numeric identity receipts are not adopted
from current NSS names. Obtain the original host's independently retained
`/etc/passwd`, `/etc/group` and `/etc/machine-id` backup records, plus the
highest previously used Reth and Lighthouse versions and full source commits
from independently retained successful deployment/upgrade records. A freshly exported
current account database is not evidence of original identity. ERPC checks record
consistency, numeric isolation and the pinned host's machine identity; it cannot
establish the age or provenance of a backup selected by the operator.

Stop the legacy Reth, Lighthouse and snapshot services using the host's existing
operational procedure. Then supply the original records from the local backup:

```sh
erpc r --chain eth init -n mainnet --name eth1 --migrate-authority \
  --original-passwd ./original/passwd \
  --original-group ./original/group \
  --original-machine-id ./original/machine-id \
  --original-client-record ./original/client-openings.json \
  --ssh-key ./operator.pub
```

The client record is a JSON object with exactly `reth` and `lighthouse` fields.
Each contains `version` (canonical stable `vMAJOR.MINOR.PATCH`) and `commit`
(the full 40-character lowercase source commit). Use the highest successful
opening recorded for each client, including an interrupted upgrade that may
have opened the database. Current inventory, the `current` symlink, or an old
single deployment record is insufficient evidence that a later version never
opened it. If that history is unknown, restore verified historical authority or
provision fresh storage instead of inventing a source floor. ERPC validates the
input shape and preserves its digest; the operator must establish its provenance.

Only the fixed native account identities, highest-version/source records and
record digests are sent to the host; unrelated account records are not copied
into its authority receipts. Historical archive/image hashes are not inferred:
the first managed opening at that source must still pass normal signed artifact
qualification, after which those hashes are pinned too.
Migration refuses active native writers, changed numeric identities and
unprotected or indirect namespaces. It retains the old unit bytes, masks their
startup, preserves the JWT and native database bytes, and records the original
data bindings. It does not execute an unknown historical unit's shutdown command
or start a client. Repeat an interrupted migration with the same original records.

After successful migration, run an explicit deploy to install guarded units for
the inventory's pinned pair. Retained native data is validated and synchronized
by the clients rather than overwritten by a new snapshot. Migration itself does
not establish chain readiness. Without sufficient original records, restore an
independently verified original backup or provision a fresh dedicated host; do
not guess the original UID/GID from a current username.
