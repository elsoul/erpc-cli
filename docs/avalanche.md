<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Avalanche node and validator commands

`erpc rpc --chain avax` (alias `r`) manages AvalancheGo on Mainnet and Fuji.
`erpc node --chain avax` (`n`) is the same RPC lifecycle. `erpc validator
--chain avax` (`v`) records explicit Primary Network validator intent and adds
registration preparation. The code has offline coverage; live host deployment,
Fuji validation and Mainnet acceptance remain deferred. Deployment never stakes,
signs a transaction, or guarantees admission/rewards.

## Host preparation and deployment

Use Ubuntu 24.04 or 26.04, passwordless sudo, at least 16 GB RAM and 8 logical
CPUs. Mount local NVMe at `/var/lib/avalanchego` before deployment. The backend
requires at least 900 GB filesystem capacity for a full node, 13 TB for C-Chain
archive. A new/empty database also needs that much free space; an existing
database needs 100 GB free operating headroom. These are minimum guards, not RPC
throughput guarantees. Use the [official sizing guidance](chains/avalanche.md).
No disk is partitioned, formatted or mounted implicitly.

```bash
erpc r --chain avax init -n fuji --name av1 --host <host> --ssh-key <key.pub> --vault <vault>
erpc r --chain avax deploy -n fuji --name av1 --ssh-key <key.pub>
erpc r --chain avax status -n fuji --name av1 --ssh-key <key.pub>
```

For a validator use `v` from the initial `init`. Role, network, host and
`--type full|archive` are immutable after initialization; RPC/node are aliases,
not an implicit conversion into a validator. Full nodes state-sync C-Chain;
archive disables C-Chain pruning and state sync before the first database exists.
It cannot reconstruct previously pruned history.

`init` resolves an explicitly selected stable 1.15 patch release (default
v1.15.2), recording its commit and SHA-256 from GitHub. `deploy` verifies that
digest and the detached release signature against the embedded Ava Labs key,
then checks the binary's version and commit. Unsupported minor versions,
prereleases, missing verification metadata and downgrades are refused.
`update --version <tag>` installs a verified release beside the current one.
There is no automatic database rollback after a new binary has opened it.

The native API is loopback-only on 9650. Public P2P is TCP 9651. A dedicated
nginx gateway exposes selected P/X/C, Info and Health paths on 9652 only to
`--rpc-allow` IPv4 addresses/CIDRs; metrics are separately restricted on 9653
through `--monitoring-allow`. Nginx enforces the same address restrictions as
the firewall, so a firewall rollback cannot expose an unrestricted gateway.
Firewall candidates are stored per run. Fresh-SSH confirmation carries that
run ID and the SHA-256 of the bundle submitted by the CLI; the remote controller
checks the candidate digest and installed-rule fingerprint. A timed-out or
superseded operation cannot confirm an older policy. Apply, confirmation and
rollback use the same remote run lock, and queued timers are bound to their
own operation. Only a matching confirmed policy is loaded at boot.
SSH admits the controller and `--management-allow` ranges. Add stable management
ranges before your controller address changes. Administrative APIs stay disabled.

## Operations and recovery

Before any mutation, the remote network, validator intent and history contract
must match. Init checks this before inventory reservation; later operations also
refuse a record whose init did not finish. Service/identity commands recheck on
the host, and every play checks before its first mutation.

All lifecycle verbs are implemented: `init`, `deploy`, `list`, `status`, `logs`,
`start`, `stop`, `restart`, `update`, `update-config`, `plan` and `destroy`.
`plan --change deploy|update|update-config` reads inventory/host state but does
not change it. `logs --follow` streams client and gateway journals.
`update-config` changes allowlists and regenerates service configuration.

A successful deploy means the process/API started, not that bootstrap finished.
`status` checks network ID, C-Chain EVM ID, all P/X/C bootstrap responses and
node health. Validator admission comes from P-Chain current-validator responses,
never from process liveness. Uptime is the peers' observation; eventual rewards
are not certified by this command.

The staking certificate/private key and BLS key are generated only on the
first authorized deployment. A sealed digest manifest prevents silent
regeneration after a missing/changed key. Deployment pins NodeID/BLS proof and
backs up all three files into a concealed 1Password field, with readback.
Backup material passes through SSH and 1Password stdin/stdout in memory; it
never enters an Ansible bundle, command-line argument or user-facing output.

`identity-backup` refreshes that backup. `identity-restore` recovers only the
same pinned host while its service/process is stopped; it verifies every file
against the inventory's pinned digests and refuses to overwrite a different
identity. Recovery does not start the service. Cross-host migration is outside
this command because checking one host cannot fence another signer.

`destroy` stops/removes the two service units; `--purge-data` additionally
removes only the database/logs. Identity, inventory, immutable host contract and
firewall remain. A subsequent deploy reuses the same identity. An interrupted
first identity generation with incomplete files is refused rather than repaired
by silently issuing a new NodeID.

## External registration

First wait for a healthy fully bootstrapped validator-intent node, then:

```bash
erpc --json v --chain avax prepare-registration -n fuji --name av1 --ssh-key <key.pub> --stake-navax 1000000000 --end <unix-end> --rewards-address <P-fuji-address> --delegation-fee-bps 200 > registration.json
erpc v --chain avax validate-registration -n fuji --name av1 --ssh-key <key.pub> --file registration.json
erpc v --chain avax status -n fuji --name av1 --ssh-key <key.pub> --registration registration.json
```

Amounts are integer nAVAX: one AVAX is 1,000,000,000 nAVAX. Validation checks
CB58 NodeID checksum, live/pinned identity, BLS encoding and binding, network,
Bech32 rewards address, stake, fee and remaining term. The prepared record is
valid for ten minutes and reserves five minutes beyond the minimum term for
submission. It is unsigned review data, not a transaction. BLS cryptographic
proof verification, current UTXOs and transaction fees must be checked by the
external signer/P-Chain; encoding validation is not claimed to prove possession.

Follow the [official staking procedure](https://build.avax.network/docs/primary-network/validate/how-to-stake)
in Core Stake, using the same network and independently reviewing NodeID, BLS
proof, stake, end time, rewards address and fee on the signing device. Since
Durango, validation starts when P-Chain accepts the transaction; there is no
future start-time option. Mainnet minimum self-stake is 2,000 AVAX and term
48 hours; Fuji minimum is 1 AVAX and 12 hours. Maximum term is one year and
minimum delegation fee 2%. Fees are additional to self-stake.

After external submission, `status` distinguishes active, not active and
unavailable current-validator observations. `getPendingValidators` is removed
in the supported release; pending transactions must be checked in the external
wallet, and are not inferred from absence in the current set. With the prepared file it also reports
remaining intended term, or an elapsed term with historical inclusion/reward
explicitly unverified. An unsigned review file is not proof that registration
was ever accepted. Reward status still needs on-chain confirmation.

The supported validator observation is [`GetCurrentValidators` at the pinned release](https://github.com/ava-labs/avalanchego/blob/4bb5c1dc13e1b6ff4eaf49fe8674666fbb342a17/vms/platformvm/service.go).
An omitted NodeID means it is not in the current set; it says nothing about
external wallet submissions still awaiting acceptance.
