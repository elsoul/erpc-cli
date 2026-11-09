<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Ethereum validators

`erpc v --chain eth` manages a dedicated Reth execution node, Lighthouse beacon
node and Lighthouse validator client on Hoodi or mainnet. Code and offline tests
are available; **Hoodi and mainnet real-host acceptance are deferred**. Existing
`erpc r --chain eth` mainnet RPC nodes keep their existing configuration.

Use a separate Ubuntu 24.04+ host with the documented Ethereum hardware capacity.
The backend checks the Ethereum CPU/RAM requirements and the actual native data
filesystem. A new database needs 2,000 GB free; retained native allocations reduce
that initial synchronization allowance, while at least 200 GB operational free
space remains required before deployment and startup. Provision storage before init: it never formats a disk.
It preserves a running or installed chrony/ntpd time service, or installs
systemd-timesyncd when no supported alternative is present. It refuses an existing
`reth` or `lighthouse` RPC unit, and keeps its own services,
users and data under `/var/lib/erpc-eth-validator` and `/opt/erpc-eth-validator`.
Execution RPC, Engine API, beacon HTTP and all metrics bind to loopback; host and
provider firewalls remain the operator's responsibility. Normal peer connectivity
must be available. There is no public RPC or remote-signer option in this backend.

## Reserve and deploy

```sh
erpc v --chain eth init -n hoodi --name validator-a --host <server> \
  --fee-recipient <execution-address> --ssh-key <operator.pub> --vault <vault>
erpc v --chain eth deploy -n hoodi --name validator-a --ssh-key <operator.pub>
erpc v --chain eth status -n hoodi --name validator-a --ssh-key <operator.pub>
```

`init` pins both live GitHub release tags, resolved commits and archive SHA-256,
stores **validator** metadata separately from RPC inventory, and prepares isolated
numeric service identities and descriptor-bound directories. Unknown existing
accounts, writable namespaces and unowned data are refused. Account names alone
never establish original ownership. It refuses a cached release-list fallback. Network-qualified
floors are Reth v2.8.1 and Lighthouse v8.3.2, including the cancelled Hoodi upgrade
schedule correction. `deploy` verifies each archive's pinned digest and GPG
signature using the carried publisher key, then starts EL/BN. It never imports a
key, starts signing or submits a deposit. Reth syncs through its supporting beacon
node; Lighthouse uses the network-specific Sigma Prime checkpoint endpoint.

The original account/data receipts and highest opened native sources live outside
the native writable directories. Database opening records bind version, commit,
archive and binary identity; an older inventory or executable cannot lower them.
This is a conservative opening restriction, not a guarantee that every forward
client upgrade is database-compatible. Failed persistence prevents opening, and
stop still attempts owned shutdown before reporting the failure.

## Import a new key

Generate keys and deposit data with the official staking tools described by
[Lighthouse's validator guide](https://lighthouse-book.sigmaprime.io/mainnet_validator.html).
Keep the mnemonic and withdrawal authority offline; erpc does not accept either.
The fee recipient is a separate execution address and is not withdrawal authority.

This backend assigns **one validator key per managed host**. For a never-used key,
supply its EIP-2335 encrypted keystore, password file, and EIP-3076 v5 interchange
file containing exactly that public key, the selected network's genesis validators
root, and empty signed-block/signed-attestation arrays. `--new-key` asserts that
this key has never signed anywhere. Private input files require mode 0600 on Unix.

```sh
erpc v --chain eth keys-import -n hoodi --name validator-a \
  --keystore <encrypted-keystore.json> --password-file <password-file> \
  --slashing-history <interchange.json> --new-key --ssh-key <operator.pub>
erpc v --chain eth start -n hoodi --name validator-a --ssh-key <operator.pub>
```

Import checks the network, key and history; a key already in beacon state or
reserved by another managed record is refused. Material goes directly over pinned
SSH stdin, never into argv, subprocess environment, inventory or an Ansible run
bundle. Lighthouse validates/decrypts the key in a fresh private tmpfs staging
directory before ERPC seals the original material with host-key-backed
`systemd-creds`. Native verification output is withheld. Persistent validator
definitions reference a runtime password file; they do not contain that password.
The original encrypted keystore is root-owned, and definitions are mode 0600 for
the original VC UID because Lighthouse opens that file for both reading and
writing. A separate root-private receipt checks their original contents before
startup. The runtime password is mode 0400 for that same UID on authenticated
tmpfs. Core dumps are disabled; protect host memory, swap and operating-system
backups as part of the host's custody policy.

The four dedicated users isolate execution, beacon, signing and local Engine
transport. The transport accepts authenticated Engine requests over TLS and
connects to the original Reth auth IPC socket. Before sending bytes on each IPC
connection, it checks the kernel peer credentials and the short-lived root
process/socket proof. Beacon and Engine use separate private TLS issuers and IP
SANs. VC-to-beacon uses Lighthouse's native TLS support, which is experimental.
The official native binaries add these private certificates to their normal trust
roots; ERPC does not claim that their built-in public roots have been removed.
ERPC's own local health observations use only the corresponding private issuer.
A plain replacement listener on a released loopback port does not establish TLS
identity. These interfaces are qualified against
[Lighthouse v8.3.2 signing definitions](https://github.com/sigp/lighthouse/blob/a376defa30470923556d91bdeb15a802e297f31f/common/account_utils/src/validator_definitions.rs),
[its beacon HTTP client](https://github.com/sigp/lighthouse/blob/a376defa30470923556d91bdeb15a802e297f31f/common/eth2/src/lib.rs),
and [Reth v2.8.1 auth IPC](https://github.com/paradigmxyz/reth/blob/d763342fa185e4e90ee79dc65f6a5706168b0bcb/crates/rpc/rpc-builder/src/auth.rs).

TLS leaves last 365 days and are renewed during a stopped deployment when less
than 30 days remain. Use `deploy --renew-transport` for an explicit same-owner
renewal or recovery of missing transport ciphertext. A root observer checks
certificate lifetime and original IPC/history authority; failures fence/stop the
owned stack. Issuer private keys are not retained after leaf publication. This
transport renewal never replaces the consensus key or resets signing history.

Signing requires the exact execution chain ID and consensus genesis root, a fresh
EL/BN head, no optimistic execution, an intact slashing database, and a completed
ownership record. Every VC startup also exports the retained native database and
checks its last observed high-water bounds before granting the runtime password.
The filesystem UUID/type and original directory/DB inodes bind this history;
kernel device-number changes across reboot do not replace that identity.
Replacing the DB inode or lowering those recorded bounds is refused. ERPC does
not maintain a second journal of every native signature; Lighthouse's own durable
slashing database remains authoritative between observations. The VC additionally
uses Lighthouse doppelganger protection.
It does not automatically restart after a doppelganger or other failure.
Doppelganger protection cannot prove that no external copy of a key is running.

## Migrate and recover

```sh
erpc v --chain eth migrate -n hoodi --name validator-a --to validator-b \
  --ssh-key <operator.pub>
```

Initialize and deploy the destination first. Both hosts must be reachable with the
selected operator credential. Migration writes a persistent source fence bound to
that destination, stops/disables the old VC, verifies shutdown, exports its current
Lighthouse slashing history, and imports the encrypted key/password/history over
SSH into the destination. It leaves the destination stopped. A reboot or ordinary
`start` on the old host fails its service precondition. Repeating an interrupted
migration to the same destination is supported; choosing another destination after
fencing is refused. If writing or syncing the source fence fails, the controller
still attempts to stop and disable the owned signer and refuses to export history
or custody. Destruction likewise attempts every owned stop/disable even after a
persistence or service failure, retains all data, and returns an error. Successful
shutdown cannot guarantee reboot fencing while storage cannot persist that fence.
A retry re-syncs visible original receipts before artifact publication. Temporary
root startup processes in the owned service cgroups also prevent a successful
quiescence claim; an unproved root process is not arbitrarily signaled.

A reserved public key is immutable in the controller and inventory. Rejected
imports cannot replace an existing owner or downgrade its completed state.
An interrupted import retains its existing database and original key/history.
A malformed encrypted envelope or password can be corrected for that same public
key/history before original custody has been sealed and while native signing data
is still empty. A sealed or completed import requires the same original material. A missing slashing database is a hard failure, never an invitation to
create an empty one. `destroy` fences and disables the owned services while keeping
all key material, history, binaries, data and inventory. A destroyed signer can be
migrated while its retained source custody remains readable. Importing already-used
keys from an unmanaged or lost signer is intentionally refused: first resolve its
fencing and complete history using the
[official migration guidance](https://lighthouse-book.sigmaprime.io/validator_slashing_protection.html).

Use one active controller per network vault. Inventory version checks and the local
controller lock are not a distributed atomic lease across different computers or
vaults. The backend cannot prevent an out-of-band copy or manual direct invocation
of a signing client by a privileged operator.

## Original encrypted backup and same-host recovery

```sh
erpc v --chain eth keys-backup -n hoodi --name validator-a \
  --output <new-encrypted-backup.json> --ssh-key <operator.pub>
erpc v --chain eth keys-restore -n hoodi --name validator-a \
  --backup <original-encrypted-backup.json> --ssh-key <operator.pub>
```

The backup is the exact original host-bound ciphertext, never plaintext or a
slashing database snapshot. Output must be a new file; it is created mode 0600 on
Unix and inherits the chosen directory's ACL on Windows. Keep it in protected
operator storage. Recovery also requires the original authority receipts and the
host encryption key managed by systemd; preserve these in the original protected
host backup. An encrypted capsule alone cannot recover a lost host encryption
key. `keys-restore` stops the stack, accepts only that original ciphertext, and
preserves any retirement or migration fence. It does not start signing or restore
an old slashing DB. Missing original numeric account evidence must be restored
from the original host backup, not inferred from a new account with the same name.

## Convert an existing stock managed validator

An older managed validator without original numeric receipts requires explicit
conversion. Independently stop its execution, beacon and VC services first and
retain a verified host backup. Supply the original backup's `passwd`, `group`
and `machine-id`, plus a public JSON record of the highest native versions that
have opened its retained data:

```json
{
  "reth": {"version": "v2.8.1", "commit": "<original-40-character-commit>"},
  "lighthouse": {"version": "v8.3.2", "commit": "<original-40-character-commit>"}
}
```

The placeholders must be replaced with actual independent historical evidence;
the currently installed binary does not prove the highest previously used
version. Do not manufacture original account evidence by exporting current NSS.

```sh
erpc v --chain eth init -n hoodi --name validator-a --migrate-authority \
  --original-passwd <original-backup/passwd> \
  --original-group <original-backup/group> \
  --original-machine-id <original-backup/machine-id> \
  --original-client-record <highest-opened-clients.json> \
  --ssh-key <operator.pub>
```

Conversion checks the original inventory key, network, accounts, mounted data,
stock unit definitions and supported legacy helper. It preserves the three
original numeric users and their recorded homes, reserves only the new transport
identity, fences old management, and masks the old units. Unknown/custom signing
settings are refused and preserved for separate reconciliation. Original custody
and password-bearing definitions are retained encrypted before the known
plaintext copies are removed. The current slashing DB is retained in place; its
initial import backup is never substituted for current history.

Repeat an interrupted conversion with the same original evidence. The converted
host stays retired/stopped until a separate `deploy`. That qualified deployment
checks the original key in private tmpfs and exports the retained live slashing
DB before completing conversion of its signing definitions. That export must
also cover any known bounds in the original import record; the old record is
used only as a lower-bound check and is never reimported to reconstruct history. It leaves the signer
stopped for explicit `start`. Conversion does not prove that an out-of-band copy
of the old key is absent.

## Deposit review and operation

```sh
erpc v --chain eth deposit-review -n hoodi --name validator-a \
  --deposit-data <public-deposit-data.json> --withdrawal-address <reviewed-address> \
  --ssh-key <operator.pub>
```

This validates one initial 32 ETH deposit: network, genesis fork version, imported
public key, 01/02 execution withdrawal credentials, amount, SSZ message/data roots
and BLS signature. A synced beacon state must not already contain the key. This
check cannot establish absence of pending transaction/deposit requests outside
beacon state. Review those separately and sign/broadcast once through the official
network staking launchpad linked from Lighthouse's guide. **No erpc command signs
or broadcasts a deposit transaction.** `status` reports pending/active/exited
beacon status, balance, slashing flag, service activity and readiness separately.
An active VC process is not proof of completed duties: native doppelganger checks
and duty scheduling can still be pending. Start/restart return a non-success
observation when the resulting authenticated readiness is false or unavailable,
even if the service start itself was applied.

`list`, `plan`, `logs [--lines N] [--follow]`, `start`, `stop`, `restart`, `update`,
`update-config --fee-recipient <address>` and `destroy` complete the lifecycle.
Start/stop/restart operate the owned stack in dependency order, with up to ten
minutes allowed for signing readiness. Deployment/configuration/update stop the signer and leave it stopped for an explicit
subsequent start. Updates reject downgrades and prereleases, preserve signing
history and never automatically roll binaries back across a database migration.
After a failed update, repeat the same operation and configuration; a pending
update does not silently select a newer release on retry. `plan` shows the
original intent and target. To abandon that interrupted operation, use
`deploy --recover-cutover <original-intent>`: this stops and recovers only the
named operation, retains data/custody/history, and requires a subsequent fresh
deployment. Mainnet mutations always require explicit `--chain eth`.
`logs --json` emits one compact JSON journal record per line. An accepted but
still-pending asynchronous VC start is reported as pending with a non-success
observation outcome, rather than claiming that signing is already active.

Offline validation includes public Lighthouse deposit vectors, wrong-network and
corrupted-signature rejection, mocked secret-store ownership conflicts, and remote
helper fault injection for incomplete imports, failed source shutdown, missing
history and persistent fencing. Real sync, duty production, reboot, upgrade,
funded activation and recovery on Hoodi/mainnet remain in the deferred live test batch.
