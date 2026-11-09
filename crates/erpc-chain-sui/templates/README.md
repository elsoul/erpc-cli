<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Sui node operations

`erpc rpc --chain sui` (`erpc r`) and the compatible `erpc n --chain sui`
entry point manage one full node per dedicated Ubuntu 24.04 host. The host
needs 128 GB RAM, 16 logical CPUs and a pre-mounted NVMe volume with 3.5 TB
free at `/var/lib/sui`. Init checks memory, CPU count and free space; disk
technology and sustained throughput still need operator verification. Init
never formats disks.

Initialize with `init -n testnet --name <node> --host <host> --ssh-key <key.pub>
--fingerprint <expected fingerprint> --vault <vault ID>`. Then use `deploy`
with the same network/name and SSH identity. Mainnet writes also require an
explicit `--chain sui`. List/plan read inventory; status probes the node.

Deploy verifies the embedded network release digest and immutable genesis,
creates a persistent encrypted P2P credential, configures indexed gRPC, and
confirms the firewall over a fresh SSH connection. Every mutator checks the saved
network/role/genesis under the shared remote run lock. Boot and runtime startup
require a confirmed firewall whose live rules match its saved fingerprint; rollback
stops listeners before removing filtering. Confirmation and subsequent startup
are bound to the caller's unique deployment intent; a timeout or superseding run
cannot acknowledge a restored or unrelated policy. Rollback callbacks carry the
original intent in per-operation systemd units and discard superseded callbacks.
An older unbound pending timer must settle before helpers can be upgraded. Only after confirmation does the CLI
schedule a strict-verified formal snapshot restore. Bootstrap completion
starts the full node asynchronously. Use `logs` and `status` to distinguish
download, catch-up and readiness; deploy success is not sync success.

`--rpc-allow` admits only explicitly selected clients or TLS gateways to gRPC
port 9000; broad public ranges are refused. Terminate public HTTP/2 TLS at a
separately managed gateway. Metrics and admin are private by default. The
historical `json-rpc-address` YAML field is the upstream name for the gRPC
listener; this backend does not depend on the removed JSON-RPC service.
History is retained for 14 epochs after bootstrap, not backfilled as an archive.

`start`, `stop`, `restart`, `update-config`, `update` and `destroy` use the same
saved host contract. Update adopts only this CLI version's reviewed network
release; arbitrary tags and database downgrade are refused by original source-opening history.
An incomplete bootstrap must be finished or explicitly recovered before update.
If a database exists but the completion marker is missing, bootstrap fails closed.
After inspecting the journal, use `deploy --recover-bootstrap` to stop the services,
retain the interrupted database as `db.quarantine.<timestamp>`, and retry a strict
verified restore. Recovery requires 3.5 TB additional free space and refuses a
completed bootstrap or any prior native-node/consensus use. It never deletes the
quarantine or identities. If the original incomplete bootstrap used an older
protocol-incompatible release, first migrate its independent source history as
described below, then use `update --recover-bootstrap`. This explicitly selects
the newer qualified source while retaining the original incomplete database.
The source check, recovery and deployment run under the same operation lock.
Ordinary `update` still refuses an incomplete bootstrap. Repeated recovery after
a visible rename replays the directory barriers before any new restore.

### Testnet protocol 140 and original source history

Testnet selects `testnet-v1.83.1`, source `0e0ede4cbf48c6d7654b613f62fdca71542ace03`.
The November 4, 2026 official gRPC observation reported Testnet epoch 1273 at
protocol 140; the previous qualified 1.82.2 client supports only up to 139.
Mainnet remains `mainnet-v1.82.3` and its separately observed protocol 139.
The release archives are qualified by the official asset metadata SHA-256, not
by a claimed detached signature. See the [Testnet release](https://github.com/MystenLabs/sui/releases/tag/testnet-v1.83.1),
[protocol limit](https://github.com/MystenLabs/sui/blob/0e0ede4cbf48c6d7654b613f62fdca71542ace03/crates/sui-protocol-config/src/lib.rs),
and [compiled network pins](../src/network.rs).

Acquisition verifies the archive and the three extracted executable bytes, but
does not record a database opening. Both the native node and formal-bootstrap
units retain the qualified source in `/etc/sui/release-history` immediately
before native execution. Every opening replays file and ancestor durability
barriers under a private lock. A partial entry still reserves its named source;
an older source cannot bypass it. The exact same source can complete an
interrupted entry without erasing earlier history. This prevents managed
downgrades; it does not guarantee forward database compatibility or replace
validator consensus history. Retain this directory with the original data,
account receipts and encrypted identities.

Verified bootstrap completion and native-node opening also retain a root-owned
`native-opened.json` no-reset fence. Completion is published through an original
directory descriptor and file/ancestor durability barriers before the node is
scheduled; native opening rechecks those barriers. Any partial fence, consensus
database, or completed-bootstrap marker prevents fresh bootstrap recovery.
Deleting or losing the node-owned completion marker therefore does not authorize
resnapshotting a used validator or full node. This marker records an opening
attempt, not successful synchronization or proof that a validator signed.

Existing installations without this history cannot infer it from
`/opt/sui/current`. Before updating, prepare a bounded public JSON record from
the original retained numeric account receipt and independently retained upgrade
records, including every client that previously opened this database. Do not use
the current NSS account name or current binary alone as historical evidence.
The object has exactly these fields:

- `format`: `1`.
- `contract`: the original `network`, `role` and genesis SHA-256 from
  `/etc/sui/contract.json`.
- `service_uid` and `service_gid`: the original numeric values retained in
  `/etc/sui/original-account.json` (or its atomic contract copy).
- `highest_opened`: an object with the independently established `version`,
  `commit`, `architecture` (`x86_64` or `aarch64`) and `archive_sha256`. The source
  must be in the reviewed catalog. Include attempts that could have opened the
  database. Only an installation that has never attempted an opening may use
  `null`; the controller additionally requires an empty original data home.
- `database_state`: `never-opened`, `bootstrap-only`, `bootstrap-complete`, or `native-opened`, based
  on independent original run/upgrade records. Only the first permits a null
  highest source. `bootstrap-only` means unfinished bootstrap publication and no
  native node execution; `bootstrap-complete` means independently verified
  completed restore, and `native-opened` includes node execution attempts.
  Retained established-use evidence contradicting an incomplete claim causes refusal. Do not
  infer this state from an absent completion marker. A downloaded/selected
  current archive is qualified independently and does not prove a past opening.

If those original records or historical evidence are unavailable, retain the
host stopped and obtain them before migration. ERPC checks their consistency,
not the truth of an operator's claimed earlier upgrade history.

```sh
erpc rpc --chain sui update --network testnet --name sui1 \
  --migrate-source-history original-source-history.json --ssh-key <operator.pub> --yes
erpc rpc --chain sui update --network testnet --name sui1 --ssh-key <operator.pub> --yes
```

Use `v` in place of `rpc` for the existing validator. The first command is
**migration only**: it authenticates original scope/account, stops and verifies
quiescence, checks the retained current archive against installed executables,
and durably records the independent history. It does not change the inventory
pin, update the client, import any key or restart. Original data, consensus
history and ciphertext stay in place. Explicit completed/native-use evidence
can also repair the completion marker after checking the original real, nonempty
database directories; it does not verify or repair native database contents.
Use independently verified original records and backups, never an inferred
completion state. Failed publication is retried with the
same evidence; a higher retained claim cannot be replaced with lower evidence.
The second explicit operation selects this CLI's qualified release. An unused
original installation uses `deploy` after migration instead. Old helpers refuse
the new authority protocol; use this CLI's carried `stop`/`destroy` during
interrupted deployment. Do not remove source records to make an old CLI run.
For a verified bootstrap-only original stopped on the old Testnet protocol, the
second command is `update --recover-bootstrap` instead. It does not import or
replace validator keys; repair original custody separately if necessary.

Destroy removes service definitions, retaining inventory, genesis/role contract,
chain data, firewall and the host-bound encrypted network credential. Re-deploy
preserves the identity. A missing credential after initialization is an error;
copying an encrypted credential to another machine is not a supported migration.
No staking account or on-chain transaction is created by these commands.

Source verification used the pinned MystenLabs `NodeConfig`, `sui-tool` restore
implementation, release binary list and workflow. Linux runtime and real-network
acceptance are deferred until the implementation tracks are ready, as requested.

## Validator operations

`erpc v --chain sui` manages a dedicated validator on Mainnet or Testnet with
48 logical CPUs, 128 GB RAM and the same mounted storage requirement. It exposes
the full-node lifecycle verbs plus `registration --action prepare|validate|status`.
The role is immutable: a full-node host cannot be converted to a validator by
changing a flag. If the host contract is missing, any retained validator credentials,
metadata, identity receipt or consensus database makes init refuse the host; it
cannot silently re-establish ownership over an existing signer. The validator uses `consensus-config`, the original protocol,
network and worker identities, private unindexed gRPC, zero retained object
epochs and two checkpoint epochs. TCP 8080/8081 and UDP 8084 are peer-facing;
RPC, metrics and the admin interface remain private unless monitoring ranges
are explicitly supplied. The historical primary/worker metadata uses UDP
multiaddresses, but the pinned consensus transport opens TCP sockets.

Prepare the original three key files with the pinned official Sui tooling on
an operator-controlled machine and store each in a concealed 1Password field.
Keep the account/owner key and wallet on that machine. The official
`make-validator-info` procedure also exports an account key: that file must never
be copied to the node or included in erpc metadata. Supply only the public
`GenesisValidatorInfo` document as JSON (the official YAML reader accepts this
JSON form), including its BLS proof of possession. No private fields are allowed.
The current supported metadata profile advertises one dedicated DNS host with
ports 8080, 8081, 8082 and 8084; erpc validates it before reserving the host.

For a new, never-hosted signer, initialize with:

```sh
erpc v --chain sui init -n testnet --name sui-validator \
  --host <host> --ssh-key <login.pub> --fingerprint <expected-fingerprint> \
  --vault <vault-ID> --validator-info validator.json --keys-unhosted \
  --protocol-key op://VAULT/ITEM/protocol \
  --network-key op://VAULT/ITEM/network --worker-key op://VAULT/ITEM/worker
```

Replace the uppercase reference components with the real vault/item IDs; field
names must use letters, digits, hyphens or underscores. `--keys-unhosted` is the
operator's explicit assertion that no other host runs these identities. erpc
also refuses a new import when the public active set contains the owner or any
of the three keys. It cannot discover an offline copy of a signer; never run
these same keys on two machines. Live signer migration is unsupported.

Deploy with the same network, name and SSH identity. Credential preparation first
stops and persistently fences the validator, without applying a firewall or arming
a timer while 1Password waits for the operator. A subsequent deployment confirms
its own firewall and the complete credential receipt before clearing that fence.
erpc reads only these three
fields, sends them over SSH stdin, verifies their derived public keys with the
pinned native `sui keytool`, then encrypts them with the host's `systemd-creds`.
Plaintext key files exist only in a private temporary directory under `/run` for
this operation. Key values never enter the deployment bundle, arguments,
environment, inventory listing or error output. Services receive decrypted
credentials from systemd. A receipt binds all encrypted files to the immutable
public metadata. Re-deployment verifies an existing bundle without re-reading
1Password when healthy; no replacement keys are generated.

If an established host loses or cannot decrypt a credential, ordinary deployment
refuses to replace it. `deploy --restore-keys` stops that host under the shared
run lock and restores the original three referenced keys after checking them
against the saved metadata. It requires the original identity receipt, retains
previous ciphertext in `sui-validator.quarantine.<timestamp>`, and starts only
after a new firewall confirmation. Missing receipt/changed metadata are refused.
Do not copy a host contract or receipt to another host as a migration shortcut.
Destroy retains the encrypted credentials, receipt, metadata and chain data.

## External registration and observations

`registration --action prepare` reads inventory only and returns the public
`validator_info` object and official command arrays. Write that object to
`validator.info` on the operator's machine. The pinned official CLI uses
`--client.env`; configure and verify that environment and active owner wallet
before building any transaction. For example, on Testnet:

```sh
sui validator --client.env testnet become-candidate validator.info --serialize-unsigned-transaction
sui client --client.env testnet serialized-tx <TX_BYTES> --dry-run
```

Inspect successful simulation, then sign and broadcast using official external
tooling. Fund the candidate's pool externally after candidacy exists. Build a
separate `sui validator --client.env testnet join-committee
--serialize-unsigned-transaction`, dry-run its bytes and inspect the result before
external signing/broadcast. These are sequential transactions: an unsigned or
simulated candidate has not joined or created an on-chain pool. erpc never holds
the account key, signs these transactions, funds stake or submits them.

`registration --action validate` checks stored keys against public metadata and
observes network state. Structural metadata validation is not cryptographic
proof-of-possession verification; the official candidate simulation must accept
that proof. `registration --action status` observes the public active set and
reports whether the stored owner and keys match. It does not classify candidate,
pending or inactive pools; its output gives the official `display-metadata`
command for that inspection. `status` also reports local service/checkpoint
observations, without equating process liveness to active consensus duties.

The observer uses fixed HTTPS gRPC endpoints, checks network identity and a
recent checkpoint, and rejects epoch changes during observation. For reviewed
Mainnet protocol 139 and Testnet protocols 139/140 it reads `VotingPowerAdmissionStartEpochKey` from the validator
set's dynamic fields and computes the pinned 14-epoch phases (joining voting
power 12, then 6, then 3). On 2026-10-26 read-only observations returned Mainnet
epoch 1292/start epoch 743 and Testnet epoch 1264/start epoch 707: both were in
the 3-voting-power phase. This is not a fixed SUI amount or an admission promise;
stake, duplicate metadata and the current epoch still require the external
join transaction's successful simulation. Unknown protocol versions, missing
state or pagination beyond the bounded query return unknown rather than guessing.

## Validator source and acceptance evidence

The following source commits define the implemented formats and policy:

- [Mainnet metadata and proof format](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui-genesis-builder/src/validator_info.rs).
- [Official validator commands](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui/src/validator_commands.rs) and [client simulation command](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui/src/client_commands.rs).
- [Keytool output](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui/src/keytool.rs) and [scheme-prefixed public keys](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui-types/src/crypto.rs).
- [Mainnet admission policy](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui-framework/packages/sui-system/sources/validator_set.move) and [matching Testnet policy](https://github.com/MystenLabs/sui/blob/0e0ede4cbf48c6d7654b613f62fdca71542ace03/crates/sui-framework/packages/sui-system/sources/validator_set.move). Testnet's policy is unchanged from the earlier qualified source. The used [SystemState protobuf fields](https://github.com/MystenLabs/sui-rust-sdk/blob/8c356d65b1c324590a3fd25990c382af308ea545/crates/sui-rpc/vendored/proto/sui/rpc/v2/system_state.proto) and GetServiceInfo/GetEpoch/StateService fields retain their reviewed numbers. The actual read-only observer returned protocol 140, matching public keys and the 3-voting-power phase on November 4; that observation is not a future admission guarantee.
- [Consensus TCP transport](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/consensus/core/src/network/tonic_network.rs) and [per-epoch role selection](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui-types/src/node_role.rs).
- [Pinned gRPC schemas](https://github.com/MystenLabs/sui-rust-sdk/tree/1313d5112464ecc25d7407f42442adea08589fc5/crates/sui-rpc/vendored/proto/sui/rpc/v2): `ledger_service.proto`, `epoch.proto`, `system_state.proto`, `state_service.proto` and `bcs.proto`.

Offline fixtures mock native key derivation, encrypted credential operations,
systemd/nft and gRPC, including rejection and recovery paths. Source inspection
and public read-only observations do not replace host acceptance. Actual pinned
binary execution, systemd credential loading, snapshot bootstrap, active-epoch
transition, consensus duty, restart/update and recovery on a real Linux host are
explicitly deferred. No host, signer, stake transaction or node was created during
implementation verification.

When cancellation storage fails after ownership was verified, stop still attempts
shutdown of the managed services and reports failure. The same ordering applies
to rollback, bootstrap recovery, validator preparation and carried destroy.
Unknown or mismatched ownership never authorizes shutdown. Failed persistence
never permits subsequent filter removal, data quarantine or service-definition
removal in that operation. If shutdown also fails, both failures are reported;
no durable reboot protection is claimed under persistent storage failure.
Repair storage and retry the failed operation before relying on cancellation.

Carried destroy checks the load state of both managed units and stops only those
that exist. A host initialized before deployment, a partial unit installation,
or a repeated destroy after unit removal remains recoverable. An unknown load
state or failure to stop an existing unit aborts removal rather than reporting
success.

## Original runtime accounts and credential delivery

New hosts durably reserve a dedicated numeric Sui UID and GID before changing
NSS. The original account has a non-login shell, no supplementary groups and its
original private data directory. A fresh root-owned nonwritable volume may be
empty or contain only a verified empty, root-owned `lost+found`; initialization
preserves that recovery directory and uses the qualified open directory
descriptor to set the data root to the reserved UID/GID and mode0700. Unknown
contents, links, foreign ownership and already-established permission drift
are refused. Every startup compares enumeration and direct
name/numeric NSS lookups against the protected receipt. Missing or changed
established accounts and data-directory ownership are refused, never repaired by
silently assigning another identity.

The node unit uses those original numeric recipients and a first externally
verified `ExecCondition`. For the qualified Ubuntu 24.04/systemd 255 profile,
this condition runs before encrypted credentials are materialized; the later
prestart guard still checks the native release, scope and confirmed firewall.
Loader/condition failures exit 255, and observed skipped or failed conditions are
not accepted as successful startup. Core dumps are disabled. Stop the service
before administratively reassigning its numeric IDs; authentication cannot
prevent an administrator from changing an ID after the check.

Installed helpers live in the root-owned real `/usr/local/lib/erpc/sui`
namespace. SSH, systemd and rollback callbacks authenticate helper ancestry and
files before Python interprets them. Carried publication verifies the installed
helper bytes against the sealed source. The original root-owned configuration,
receipt, helper and service/drop-in namespaces refuse writable, redirected or
unknown state before mutation.

An existing inventory record can explicitly use `init --migrate-account` to
verify and bind its observed same-host legacy service UID/GID. The legacy format
did not record historical numeric IDs; explicit migration authorizes this
currently verified dedicated account and makes that reservation immutable. Migration requires the
protected matching network/role/genesis contract, dedicated NSS profile, private
original data root, qualified native release namespace when present, matching
validator custody hashes or a decryptable original fullnode credential, and no
remaining process under the original UID after stopping/disabling old units.
It neither generates replacement keys nor moves a signer to another host.
Migration publishes a protocol-2 contract containing the original numeric
reservation atomically, so a failed secondary receipt write cannot choose a new
account on retry. Old managed helpers reject that contract. Redeploy the reviewed
numeric-recipient units before starting the migrated node.

Stop and destroy use a sealed carried helper even if installed helpers are
missing or initialization failed. They verify scope, persist cancellation and
attempt owned stop/disable even when storage fails. Original UIDs are used to
refuse surviving writers independently of current NSS names; an unidentified
writer is never killed automatically. Failure retains data, custody and filtering
and is reported as failure. If all storage persistence fails, a successful
shutdown alone does not promise durable reboot cancellation.

Credential ordering is qualified from systemd 255's
[condition/prestart flags](https://github.com/systemd/systemd/blob/v255/src/core/service.c),
[identity setup order](https://github.com/systemd/systemd/blob/v255/src/core/exec-invoke.c)
and [credential ACL setup](https://github.com/systemd/systemd/blob/v255/src/core/exec-credential.c).
The operating-system tests remain offline; real Linux credential delivery,
NSS, mounts, native execution and recovery acceptance are deferred.
