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
The backend checks the existing Ethereum CPU/RAM requirements and 1.5 TB free for
initial provisioning. Provision storage before init: it never formats a disk.
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
users/directories. It refuses a cached release-list fallback. Network-qualified
floors are Reth v2.8.1 and Lighthouse v8.3.2, including the cancelled Hoodi upgrade
schedule correction. `deploy` verifies each archive's pinned digest and GPG
signature using the carried publisher key, then starts EL/BN. It never imports a
key, starts signing or submits a deposit. Reth syncs through its supporting beacon
node; Lighthouse uses the network-specific Sigma Prime checkpoint endpoint.

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
bundle. Lighthouse validates/decrypts the keystore on the host. Root-owned custody
metadata is 0600; VC data is restricted to its service user. Lighthouse's local
validator definitions necessarily contain the unlock password; an additional
root-only custody file supports managed migration. Protect the host and original
operator backups accordingly.

Signing requires the exact execution chain ID and consensus genesis root, a fresh
EL/BN head, no optimistic execution, an intact slashing database, and a completed
ownership record. The VC additionally uses Lighthouse doppelganger protection.
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
fencing is refused.

A reserved public key is immutable in the controller and inventory. Rejected
imports cannot replace an existing owner or downgrade its completed state.
An interrupted import retains its existing database and can only retry identical
material. A missing slashing database is a hard failure, never an invitation to
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

`list`, `plan`, `logs [--lines N] [--follow]`, `start`, `stop`, `restart`, `update`,
`update-config --fee-recipient <address>` and `destroy` complete the lifecycle.
Start/stop/restart operate the owned stack in dependency order, with up to ten
minutes allowed for signing readiness. Deployment/configuration/update stop the signer and leave it stopped for an explicit
subsequent start. Updates reject downgrades and prereleases, preserve signing
history and never automatically roll binaries back across a database migration.
After a failed update, repair/retry the stored desired pair; the maintenance fence
continues to prevent signing. Mainnet mutations always require explicit `--chain eth`.

Offline validation includes public Lighthouse deposit vectors, wrong-network and
corrupted-signature rejection, mocked secret-store ownership conflicts, and remote
helper fault injection for incomplete imports, failed source shutdown, missing
history and persistent fencing. Real sync, duty production, reboot, upgrade,
funded activation and recovery on Hoodi/mainnet remain in the deferred live test batch.
