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
release; arbitrary tags and automatic binary/database downgrade are unsupported.
An incomplete bootstrap must be finished or explicitly recovered before update.
If a database exists but the completion marker is missing, bootstrap fails closed.
After inspecting the journal, use `deploy --recover-bootstrap` to stop the services,
retain the interrupted database as `db.quarantine.<timestamp>`, and retry a strict
verified restore. Recovery requires 3.5 TB additional free space and refuses a
completed bootstrap. It never deletes the quarantine or identities.

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
protocol 139 it reads `VotingPowerAdmissionStartEpochKey` from the validator
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
- [Mainnet admission policy](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui-framework/packages/sui-system/sources/validator_set.move) and [matching Testnet policy](https://github.com/MystenLabs/sui/blob/e10772f4fafef31c46f598835fe66648caf6e005/crates/sui-framework/packages/sui-system/sources/validator_set.move).
- [Consensus TCP transport](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/consensus/core/src/network/tonic_network.rs) and [per-epoch role selection](https://github.com/MystenLabs/sui/blob/bf4073918ed33cfa0b09c500658fa116a774bcfd/crates/sui-types/src/node_role.rs).
- [Pinned gRPC schemas](https://github.com/MystenLabs/sui-rust-sdk/tree/1313d5112464ecc25d7407f42442adea08589fc5/crates/sui-rpc/vendored/proto/sui/rpc/v2): `ledger_service.proto`, `epoch.proto`, `system_state.proto`, `state_service.proto` and `bcs.proto`.

Offline fixtures mock native key derivation, encrypted credential operations,
systemd/nft and gRPC, including rejection and recovery paths. Source inspection
and public read-only observations do not replace host acceptance. Actual pinned
binary execution, systemd credential loading, snapshot bootstrap, active-epoch
transition, consensus duty, restart/update and recovery on a real Linux host are
explicitly deferred. No host, signer, stake transaction or node was created during
implementation verification.
