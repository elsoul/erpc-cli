<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Arc original RPC runtime

`erpc rpc --chain arc` manages full, archive and onboarded provider nodes on
mainnet and testnet. These are follower/provider profiles, not permissioned
consensus validators. All twelve RPC verbs use the original inventory, host,
network, public node key and immutable history type. Inventory and concealed-key
handling are described in [Arc custody](arc-custody.md).

## Qualified host and source

The supported profile is Ubuntu 24.04 with systemd 255, a passwordless sudo
login, 64 GB RAM, and x86-64 or AArch64. Prepare a writable UUID-addressed ext4 or
XFS filesystem for `/var/lib/arc`; initialization does not format a disk. A fresh
root-owned, non-writable-by-others empty directory, or a directory containing only
a verified empty root-owned `lost+found`, is accepted without replacing its inode.
Unknown contents, foreign ownership, symlinks, stacked mounts and every nested
mount beneath the data root are refused. Existing original directory receipts
must continue to match their original filesystem UUID/type and inode. Kernel
device numbers are checked within each observation, not persisted as stable disk
identity: the same original volume can be renumbered after reboot/remount. Older
receipts retain their original UUID and inode; they do not authorize adopting a
new current directory merely because its device number changed. Capacity is checked again at installation and startup:
ERPC estimates 1 TB for full/provider and 2 TB for archive, less allocated
original data, with at least 100 GB remaining. These are operating estimates,
not upstream size guarantees.

The executable catalog currently admits only `v0.8.1`, commit
`ab09dbfd9553a7ad48f9c134ec5e808c36512c74`. The x86-64 archive SHA-256 is
`04127c5bb9488de743755b5089f4434c335cf349386d5d01347abfbc402d932a`; AArch64 is
`b6b4de979c457e0ff595a75b2987104f6b69d71492ca372ff35cff3648a99d69`.
These pins come from the [official release](https://github.com/circlefin/arc-node/releases/tag/v0.8.1).
A future release requires a reviewed catalog addition. The installer accepts the
three expected regular archive members, verifies the archive before and after
extraction, records each image hash and checks each native version before use.
The source floor is persisted before a native database-opening command. A lower
version, same-version artifact substitution, or missing established source
history is refused; failed updates never automatically reopen data with an older
binary. The inventory pin changes only after the expected running source and
network are observed.

## Original identity and startup

Fresh preparation durably reserves the original numeric UID/GID before creating
NSS entries. Enumerated and direct name/ID lookups must agree with the dedicated
account, home, shell and group profile. A changed account is not silently adopted.
The data root, private layer directories, machine identity and contract remain
bound to their original receipts.

Native units use the original numeric `User` and `Group`. Their first externally
authenticated `ExecCondition` validates original authority before systemd grants
the consensus credential. A pre-import or condition failure exits 255; later
prestart checks preserve lifecycle synchronization and the source floor. This
ordering follows [systemd 255 service execution](https://github.com/systemd/systemd/blob/v255/src/core/service.c)
and [credential setup](https://github.com/systemd/systemd/blob/v255/src/core/exec-invoke.c).
It does not prevent an administrator from reassigning a numeric identity after
validation. Privileged Python starts with `-I`; a complete immutable helper
profile and protected ancestors are checked outside installed code before it runs.

The original node seed is transported on stdin, checked against its reserved
public key and encrypted with systemd-creds. A private durable ciphertext receipt
precedes publication. Missing original ciphertext can be rematerialized; unknown
replacement bytes are refused. `deploy --restore-custody` explicitly stops and
fences the original runtime, rewraps only the same original key, retains prior
ciphertexts, and then continues deployment. It is not a restore-only command.
Python/subprocess memory may retain copies; complete RAM erasure is not claimed.

## Deployment and recovery

A deployment reserves an operation intent, stops original writers, prepares its
firewall in a short run, confirms through a fresh SSH connection and binds the
long run to that exact run ID and bundle digest. Old activation and completion
callbacks cannot revive a cancelled operation. Cold-boot filtering uses the
common firewall controller's own lock.

Initial snapshots run in a separate original `/var/lib/arc/bootstrap` tree.
Upstream's [manifest restore](https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/crates/snapshots/src/manifest.rs)
can clear its execution destination, so ERPC never points it at active history.
A native completion callback verifies and synchronizes the pair, then records its
original inodes before promotion. A queued service is not considered complete
merely because it has not started. Interrupted promotion retains both old receipt
and destination identity and resumes with the same pair.

Use `deploy --reset-bootstrap` to quarantine an incomplete initial bootstrap.
The original partial bytes are retained. Reset refuses active history or any pair
whose promotion began. Ordinary deployment resumes original state; it does not
replace active data with a newer snapshot.

`start`, `stop` and `restart` retain `--layer execution|consensus|both` semantics.
Execution restart also stops/restarts dependent consensus. Startup is reported as
requested until observations establish readiness. Shutdown uses authenticated
current or historical unit receipts and original process generations; missing
units do not erase an original writer. A qualified orphan receives generation-bound
SIGTERM via pidfd. Unknown writers are never killed. Cancellation persistence
failures still attempt original shutdown and boot disable, then report failure;
total storage failure cannot promise a durable fence across reboot.

`destroy` retires the original runtime while retaining data, ciphertext,
receipts and filtering. `--purge-data` and `--forget` are refused. Explicit deploy
can resume that same original host; it cannot create a second owner for retained
history.

## Explicit legacy migration

A receipt-free host is not adopted from its current username. Only the supported
previous managed unit definitions and the qualified native release can migrate:

```sh
erpc rpc --chain arc --network testnet init --name arc1 \
  --ssh-key ~/.ssh/id_ed25519.pub --migrate-authority \
  --original-passwd ./original-passwd \
  --original-group ./original-group \
  --original-machine-id ./original-machine-id \
  --original-client-record ./original-client-record.json
```

The four independent historical files identify the original dedicated account,
machine and highest previously opened native source. The client record has only
`version` and full `commit` fields. The current inventory is not a substitute for
that history. Only selected public account fields and file hashes are sent to the
host; unrelated account entries remain local. The operator is responsible for
establishing these records' provenance; file hashes do not prove their age.

Migration checks current NSS against those original IDs, exact prior unit bytes,
official archive/image hashes, original data paths and the encrypted seed's public
identity. It journals original shutdown authority before replacing units,
retains the same data inodes and key, and leaves first migration retired. Retrying
a completed migration leaves runtime unchanged. Custom units, unqualified native
versions, incomplete history or mismatched originals require existing operator
recovery; ERPC does not repair them into a trusted profile.

## Observations and verification limits

Local RPC/IPC observations require the original process's numeric credentials,
executable bytes, argv, cgroup, PID/starttime and owned socket inodes. Fixed HTTP
listeners, native source, chain ID/genesis and before/after generations are checked.
Redirects and inherited proxy settings are refused. Execution and consensus
qualification are separate; full readiness additionally includes synchronization,
header freshness, capacity and confirmed filtering. Public comparison failure
remains unknown, not healthy. The observer does not decrypt the node seed.

Offline tests exercise actual controller filesystem transitions, persistent fsync
failures, historical-unit shutdown, interrupted migration/promotion, generated
external entrypoints, proc/socket-shaped observations, real local HTTP transport,
Ansible templating/controller composition and common-firewall cold boot. Native
binaries, Linux PID1 credential delivery, real NSS/mount changes, kernel filtering,
full snapshots, live hosts and operational signing have not been exercised by
these tests; those require the deferred real-host acceptance batch.
