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

Use a dedicated Ubuntu 24.04 or 26.04 host, passwordless sudo, at least 16 GB RAM and 8 logical
CPUs, with the host clock synchronized by NTP. Mount local NVMe at `/var/lib/avalanchego` before deployment. The backend
requires at least 900 GB filesystem capacity for a full node, 13 TB for C-Chain
archive. The remaining initial-sync estimate is that budget minus the actual
allocated blocks in the original account's network database, with at least 100 GB
free operating headroom. A tiny interrupted database does not bypass the initial
budget; sparse apparent file sizes do not count. Nested mounts, links, changed
filesystems and foreign-owned DB entries are refused. Deployment and every
managed start repeat this check; stopping does not depend on free space. These
estimates do not guarantee future chain growth or RPC throughput. Use the [official sizing guidance](chains/avalanche.md).
No disk is partitioned, formatted or mounted implicitly. An empty root-owned
protected volume, including an empty root-owned `lost+found`, can be prepared
without changing that recovery directory. Unknown data is not adopted.

Before package installation, init durably reserves the original numeric service
UID/GID, verifies direct NSS lookups against enumeration, and creates only that
reserved account. It refuses shared groups, aliases, changed account fields and
untrusted helper/configuration ancestors. Established account ownership is checked
rather than silently repaired. Package installation cannot auto-start nginx; the
distribution default nginx unit is masked so it cannot open its default listener
at reboot. An already active or overridden nginx service is not taken over.

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
The extracted executable is hashed against its authenticated receipt before
reuse; a missing legacy receipt or changed binary requires fresh archive/signature
verification. Artifact caches are version-specific. The desired release is stored
before host work, and the host persists a monotonic release floor before native
execution, including manual unit starts. A stale inventory cannot authorize a
remote downgrade or a different archive/commit for the same version. There is no
automatic database rollback after a new binary has opened it.

Status distinguishes `native_ready` (original-process P/X/C network, bootstrap and
health) from `gateway_ready` (the managed 9652 HTTP path). Overall `ready` requires
both and the inventory-pinned NodeID. A stopped gateway, substituted listener,
changed nginx/configuration or mismatching HTTP response leaves native progress
visible but makes overall RPC readiness false. Registration preparation uses
native readiness; it does not require exposing a public RPC gateway.

The gateway check binds the original numeric account, systemd MainPID/generation
and cgroup, nginx executable inode, master command, configuration digest and both
9652/9653 listener inodes before and after its HTTP observations. Completion of a
deployment stores a root-protected receipt of the distribution nginx executable
and rendered configuration. A legacy missing receipt or subsequent package/config
change requires an explicit redeploy; status does not silently adopt it. This is
a deployment receipt, not an upstream nginx artifact signature. The master command
format follows the qualified nginx 1.24.0
[process-cycle source](https://github.com/nginx/nginx/blob/84cd7217778b8b3a2e395194b641ea14050344f1/src/os/unix/ngx_process_cycle.c#L107-L125)
and [Linux process-title source](https://github.com/nginx/nginx/blob/84cd7217778b8b3a2e395194b641ea14050344f1/src/os/unix/ngx_setproctitle.c#L79-L95).
The HTTP probe uses fixed loopback port 9652, with bounded responses and no proxy
or redirect following. It proves the on-host gateway path and configured bind;
external Internet, routing and provider-firewall reachability remain untested and
are explicitly reported separately. A loopback-only configured gateway can be
locally ready without being publicly exposed.

All five HTTP temporary paths (client body, proxy, FastCGI, SCGI and uWSGI) are
explicitly under the original account's `/run/avax-proxy` runtime directory.
Even unused upstream modules [initialize these paths](https://github.com/nginx/nginx/blob/84cd7217778b8b3a2e395194b641ea14050344f1/src/core/ngx_file.c#L597-L659). The gateway stays nonroot
with `ProtectSystem=strict` and only that runtime directory writable; initial
startup does not depend on preparing distribution-default nginx directories.

The native API is loopback-only on 9650. Public P2P is TCP 9651. A dedicated
nginx gateway exposes selected P/X/C, Info and Health paths on 9652 only to
`--rpc-allow` IPv4 addresses/CIDRs; metrics are separately restricted on 9653
through `--monitoring-allow`. Nginx enforces the same address restrictions as
the firewall, so a firewall rollback cannot expose an unrestricted gateway.
A short preparation first records the caller's deployment intent, stops the
original services, publishes checked helpers and applies the candidate. A fresh
SSH connection must confirm it before the long download/install run is submitted.
That run first checks the exact confirmation receipt and uncanceled caller intent.
Firewall candidates are stored per run. Fresh-SSH confirmation carries that
run ID and the SHA-256 of the bundle submitted by the CLI; the remote controller
checks the candidate digest and installed-rule fingerprint. A timed-out or
superseded operation cannot confirm an older policy. Apply, confirmation and
rollback use the same remote run lock, and queued timers are bound to their
own operation. Before rollback can remove a first policy, externally authenticated
startup guards and persistent revocation prevent managed services from reopening
listeners. Only a matching confirmed policy is loaded at boot. The common loader
owns the boot lock; the Avalanche caller does not acquire it a second time.
SSH admits the controller and `--management-allow` ranges. Add stable management
ranges before your controller address changes. Administrative APIs stay disabled.

## Operations and recovery

Before any mutation, the remote inventory-owner binding, network, validator intent
and history contract must match. The owner is a domain-separated digest of the
stable inventory item; the raw 1Password locator is not sent to the host. A second
inventory record cannot adopt an existing owner on the same chain and host. Init checks this before inventory reservation. Startup and private
custody use the retained numeric account, root-owned receipts and closed privileged
namespace. Service/identity commands recheck on the host, and every play checks
before its first mutation. Stop/destroy use a carried authenticated helper even
after incomplete initialization or missing installed helpers, without requiring
capacity/readiness observations. Persistence failures still attempt owned shutdown
and disable, retain data/filtering, and report an error; complete storage failure
cannot promise a durable reboot fence.

All lifecycle verbs are implemented: `init`, `deploy`, `list`, `status`, `logs`,
`start`, `stop`, `restart`, `update`, `update-config`, `plan` and `destroy`.
`plan --change deploy|update|update-config` reads inventory/host state but does
not change it. `logs --follow` streams client and gateway journals.
`update-config` changes allowlists and regenerates service configuration.

A successful deploy means the process/API started, not that bootstrap finished.
`status` first binds the fixed loopback listener to the original numeric UID/GID,
MainPID generation, cgroup, executable inode/hash and exact config/argv, then
rechecks after reading the APIs. An inactive service, foreign listener, replaced
binary or PID change yields unavailable observations. The transport does not use
ambient proxies or follow redirects. Qualified observations check network ID,
C-Chain EVM ID, all P/X/C bootstrap responses and node health. Validator admission comes from P-Chain current-validator responses,
never from process liveness. Uptime is the peers' observation; eventual rewards
are not certified by this command.

The staking certificate/private key and BLS key are generated only on the
first authorized deployment. A root-owned sealed digest receipt prevents silent
regeneration after a missing/changed key. Deployment pins NodeID/BLS proof and
backs up all three files into a concealed 1Password field, with readback.
Backup material passes through SSH and 1Password stdin/stdout in memory; it
never enters an Ansible bundle, command-line argument or user-facing output.

`identity-backup` refreshes that backup. `identity-restore` recovers only the
same pinned host. It verifies the backup against both the root-owned original
receipt and inventory, cancels activation, stops/disables the owned units and
requires all original-UID processes to be absent before restoring any private file.
Current name resolution cannot redirect restored bytes to another UID. It refuses
to overwrite a different identity and retries only exact original staging bytes. Recovery does not start the service. Cross-host migration is outside
this command because checking one host cannot fence another signer.

`destroy` stops/removes the two service units; `--purge-data` additionally
removes only the database/logs. Identity, inventory, immutable host contract and
firewall remain. A subsequent deploy reuses the same identity. An interrupted
first generation with partial identity files is refused rather than repaired by
issuing a new NodeID. A consumed guard with no key bytes can retry only after
original-UID quiescence. A complete original readonly set can be sealed after an
interrupted manifest publication while its original generation reservation remains;
it is preserved byte-for-byte.

The native client stores plaintext key files under its private original-account
data directory; backups are concealed in 1Password. Account checks do not prevent
an administrator from reassigning a numeric UID, reading/copying keys out of band,
or modifying the host after authorization.

## Inventory and backup access

Ordinary inventory listing and status selection request only `erpc_format` and
`avax_node`, within the exact Avalanche network/RPC scope. They do not request
Host items or staking backups. Identity restoration projects only the uniquely
named `CONCEALED` backup field after checking the public original record.

Existing-item edits use a different boundary. The [official CLI item-template
interface](https://www.1password.dev/cli/reference/management-commands/item#item-edit)
is used without assuming that omitted template fields will be retained. After
public scope/version/identity checks, an explicit edit reads one exact item into
a typed snapshot to preserve its optional original backup, notes and tags.
Unknown fields, attachments and sections are refused before writing. A failed
read is never interpreted as an absent backup.

Provider field values enter `SecretString` before type checks; backup material
stays in that type and is serialized directly into the zeroizing stdin document.
It does not enter the legacy untyped field model, a generic JSON value tree,
argv or provider-derived error messages. Successful edits verify public fields
and retained backup bytes by readback. Failed or ambiguous writes do not trigger
rollback, cleanup, duplicate reservation or identity regeneration. Refresh the
original record before retrying. Version checks and a local lock detect ordinary
stale writes; these checks do not claim a server-side compare-and-swap guarantee.

## Explicit legacy account migration

Old contracts recorded role/network/history but no historical UID/GID. Run init
with `--migrate-account` only for the existing pinned inventory and the same host:

```bash
erpc v --chain avax init -n fuji --name av1 --migrate-account --ssh-key <key.pub>
```

Use the original RPC or validator role. The migration verifies the dedicated
current account, private data ownership, every available identity file and the
complete legacy manifest against the inventory's pinned hashes, then stops/disables and drains
the account before atomically binding it to the new contract. This explicitly
authorizes the observed account; it does not infer an absent historical UID
record. Conflicting or unrecorded legacy keys and a missing inventory identity
cannot be adopted. Missing files can be recovered afterward with `identity-restore`
from the original pinned backup, before deployment. The original files and database stay in place, and a subsequent deploy is
required before startup. The new protocol also makes old managed scope checks
refuse the migrated contract.

Native key-path and generation behavior was checked at the pinned source:
[configuration loading](https://github.com/ava-labs/avalanchego/blob/4bb5c1dc13e1b6ff4eaf49fe8674666fbb342a17/config/config.go),
[data-directory expansion](https://github.com/ava-labs/avalanchego/blob/4bb5c1dc13e1b6ff4eaf49fe8674666fbb342a17/config/flags.go),
[TLS publication](https://github.com/ava-labs/avalanchego/blob/4bb5c1dc13e1b6ff4eaf49fe8674666fbb342a17/staking/tls.go) and
[BLS publication](https://github.com/ava-labs/avalanchego/blob/4bb5c1dc13e1b6ff4eaf49fe8674666fbb342a17/utils/crypto/bls/signer/localsigner/localsigner.go).
Explicit key-path flags would require already existing files, so initial generation
uses the native defaults rooted by the fixed `data-dir`; the unit clears ambient
environment overrides. Initial sealing waits for the native writers' final readonly
mode before syncing and recording all three files.

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
