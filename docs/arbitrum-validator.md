<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Arbitrum One assertion validators

`erpc validator --chain arbitrum` manages a dedicated Arbitrum One assertion
validator. Its inventory and host contract are separate from the RPC follower.
Nova, Sepolia and Robinhood validator admission are not implemented by this
profile. An existing follower is not silently converted into a signer.

The default deployment runs native local validation in Watchtower mode. It is
reported as observing, with `validator_ready: false`. Only an explicit
`deploy --activate-signer` requests native MakeNodes assertions, confirmations
and challenges using the original dedicated wallet. Funding, ETH-to-WETH
wrapping and ERC20 allowance transactions remain external. Native automatic
deposit and allowance increases are disabled.

This backend has offline source, custody, mock-host and rendering coverage.
Linux service/kernel/Docker execution, real 1Password and host provisioning,
financial actions and live validation acceptance remain deferred. A completed
installation is not proof of successful assertion participation or rewards.

## Prepare the original host and wallet

Use a dedicated Ubuntu 24.04 x86-64 host with systemd 255 and Python 3.12,
passwordless sudo, at least 128 GB RAM and 16 logical CPUs. ERPC provision policy
requires 6 TB of initial free data space on an identified writable ext4/XFS
filesystem. Subsequent starts require the remaining initial budget, credited
only against original managed allocation, with a 200 GB operating reserve.
These are provisioning estimates for combined execution and validation, not
protocol minima or performance guarantees. Prepare storage for
`/var/lib/erpc-nitro/data`; no disk is formatted or mounted automatically.
An empty protected root-owned volume at the state root or data path can be
prepared, preserving an empty root-owned `lost+found`. Unknown data, recovery
contents, links and foreign ownership are refused. Original root/data directory
identities are durably bound before account creation or ownership changes;
retries cannot replace them with a different empty directory. ROOT and DATA have
separate original filesystem UUID/type bindings, so a legitimate dedicated DATA
mount is supported. Persistent history uses those UUID scopes and original
inodes; kernel device numbers are compared only within a current observation,
so ordinary reboot/remount renumbering does not replace the original volume.
Nested mounts beneath DATA, extra receipt-root mounts and stacked mounts are
refused.

Provide an identifier-only `op://<vault-id>/<item-id>/<field>` reference to a
CONCEALED parent execution/beacon configuration. The field uses the shared
[upstream credential format](nitro-rpc.md#preparation-and-access). Provider URLs must be public
HTTPS destinations for this validator profile. Provider material is read through
a selected concealed field, sent on SSH stdin and stored encrypted on the host.
It does not enter the public inventory, Ansible bundle, argv or user output.

```bash
erpc v --chain arbitrum init -n mainnet --name arb1 --host <host> --ssh-key <key.pub> --vault <vault> --l1-upstreams <op-reference>
erpc v --chain arbitrum deploy -n mainnet --name arb1 --ssh-key <key.pub>
erpc v --chain arbitrum status -n mainnet --name arb1 --ssh-key <key.pub>
```

Init first checks the fresh host using carried authenticated source. The public
result is read only after the exact run completes and is bound to the run,
bundle, full helper profile and request hashes. Ansible log text is never used
as ownership evidence. Init then generates one dedicated wallet in controller
memory, durably reserves its public address and creation intent, creates its
separate concealed 1Password item and reads it back. Only afterward does host
initialization reserve original numeric accounts and data authority.

A retry uses that original public reservation and original concealed item.
Ambiguous creation never authorizes another key generation. If creation did not
leave a recoverable original item, recover the original custody record before
continuing; a different key cannot replace the reserved address. Public inventory
reads project only the two public fields and check metadata again after the
read. Original host key, SSH address/user/port, filesystem UUID, wallet, creation
intent and established concealed reference are immutable.

Init does not load the hot key onto the host or start assertion signing.
Default deployment transfers only parent credentials. Image acquisition and
interactive credential reads occur before the short firewall confirmation phase.
A fresh SSH connection confirms the exact candidate run and bundle before the
receipt-bound deployment begins. Superseded or canceled activation is refused.

## External funding and explicit activation

Wait for the observing process to establish fresh local validation. Then read
the current finalized protocol and funding requirements:

```bash
erpc --json v --chain arbitrum prepare-registration -n mainnet --name arb1 --ssh-key <key.pub>
erpc --json v --chain arbitrum validate-registration -n mainnet --name arb1 --ssh-key <key.pub>
erpc --json v --chain arbitrum registration-status -n mainnet --name arb1 --ssh-key <key.pub>
```

These operations return current public observations and unsigned external
funding/wrap/approval information. They do not sign or submit those transactions.
Independently review chain ID, original wallet, observed rollup/challenge
contracts, exact amounts and allowances in the external signing tool. Keep owner,
reward and general treasury assets separate from this dedicated participation
wallet. Revalidate after funding or protocol changes.

```bash
erpc v --chain arbitrum deploy -n mainnet --name arb1 --ssh-key <key.pub> --activate-signer
```

Before active preparation, a public carried operation verifies the original
host, NSS identities, namespaces, volumes and permitted state. Only after its
completed result and exact source hashes are authenticated does the controller
read the original 1Password backup. When host custody needs import, a separate
SSH stdin operation executes that same verified carried source, repeats the
original checks before consuming the key, and stores only root-owned encrypted
custody. The key never enters an Ansible inventory, task log or command argument.
The still-observing native service receives no wallet credential or plaintext.
A healthy original ciphertext is verified without rewriting it.

Activation requires the same original wallet, current protocol and funding
checks, healthy native validation and qualified original signing history. An
already-staked arbitrary wallet without the original managed history cannot be
adopted as a fresh validator. Desired active mode is persisted before host work;
failed activation remains a retry of that original intent. Removing the flag
does not erase an established active mode or signing history.
If first activation was interrupted before its original signing-history receipt
was established, a retry may redeploy the original non-signing observer to
restore validation. The inventory's desired active mode is retained. This
recovery cannot demote an already activated signer: the host independently
refuses an observing target once its original signing-history receipt exists.
Synchronization or unavailable original authority remains an incomplete/error
result; it is not reported as successful active operation.

The native signer operates through the bounded parent transport. The transport
qualifies the original wallet and current protocol for permitted native sends.
It is not a general transaction relay, withdrawal tool or treasury wallet.
Root systemd units receive encrypted custody, validate original accounts and
stage narrowly scoped runtime material before launching the native process.
An administrator who reassigns a UID, copies a key out of band or changes the
machine after authorization is outside these managed custody guarantees.

## Ongoing operations and recovery

All twelve lifecycle commands are connected: `init`, `deploy`, `list`, `status`,
`logs`, `start`, `stop`, `restart`, `update`, `update-config`, `plan` and `destroy`.
Use the explicit `--chain arbitrum --network mainnet` for mutations. `plan` is a
public inventory/source preview; `status` performs original runtime observations.
An unready or observing validator produces a non-success status exit. JSON logs
and completion/error records use compact stdout JSON lines.

`update --version <qualified-version>` accepts only the reviewed role-local
catalog. `update-config --l1-upstreams <op-reference>` can rotate parent provider
credentials while retaining the original wallet and history, even when the old
provider is unavailable or its encrypted credential cannot be read. Deployment
first uses a public carried authorization to cancel and drain the original
runtime and retain signing history. It then checks original accounts and volumes
before reading the concealed replacement provider field. The private import is
bound to that completed run, exact source profile, owner and cancellation
generation. It validates authenticated public HTTPS, the fixed parent chain and
Beacon identity, and the fixed protocol through read-only calls before publishing
root-encrypted credentials. It does not replace the wallet or local parent CA,
relax funding/allowance checks, or permit financial sends while stopped.

Provider import failure retains the stopped fence. A retry explicitly authorizes
a new recovery; stale private input cannot supersede a later stop. First active
preparation may need to restart the same non-signing observer after this drain,
then repeat healthy validation before creating the original signing-history
receipt. An already activated signer retains its active history throughout.
`start` and `restart` use the configured original mode and repeat host/runtime guards.

`stop` cancels activation and drains the original runtime. `destroy` retires it
while retaining original wallet, data, receipts and signing history; there is
no purge-data option. An installed-controller failure can use the authenticated
carried recovery path. Disk or persistence failures remain errors even when
emergency shutdown was attempted; total storage failure cannot promise durable
reboot fencing.

### Upgrade earlier volume receipts while stopped

Earlier assertion-validator receipts included kernel device numbers. These are
not stable disk identities across reboots. Upgrade an original managed host with
the same public inventory and the current CLI:

```bash
erpc v --chain arbitrum init -n mainnet --name arb1 --ssh-key <key.pub> --upgrade-volume-authority --original-root-volume-record ./original-root-volume.json
```

The optional record is required when the old layout does not prove that ROOT
and prepared DATA were on the same filesystem. It has exactly these public
fields; use independent historical evidence for the filesystem containing
`/var/lib/erpc-nitro` and the original ROOT directory inode, not measurements
invented from today's unqualified mount:

```json
{
  "schema": "erpc-nitro-original-root-volume-v1",
  "uuid": "<original-root-filesystem-uuid>",
  "fstype": "ext4",
  "inode": 12345
}
```

`fstype` is `ext4` or `xfs`; `inode` is the original ROOT directory's inode from
the historical receipt. The operator must establish the independent UUID
record's provenance. A file hash does not prove its age. If the old ROOT and
prepared DATA observations have the same device number, the command may bind
ROOT to the already recorded DATA UUID without that extra file, but still checks
the original inodes and current mount topology. It never infers a separate old
ROOT filesystem's UUID from the present mount.

This command reads public inventory only, fences and drains the original runtime,
checks original account/data/signing-history receipts and keeps their exact
values and hashes in a private upgrade origin. The new volume receipt is durable
before the owner format is promoted. Existing stake mode, wallet, identities,
manifest floors and native source remain unchanged. Retired state is preserved.
Unproven, replaced or incomplete original records are retained and refused; the
command does not recreate a database or a missing signing-history receipt.

The operation remains stopped and does not read a 1Password wallet secret,
generate a key, send a transaction or continue into deploy. Repeat a failed
upgrade with the same historical record. After success, use an explicit normal
`deploy` with this CLI to publish the current helper profile and re-run all normal
activation checks. Previous helpers refuse the upgraded owner format. A later
`stop` does not lift retirement; only explicit deployment may resume a retired
original. These checks are not cryptographic backups or protection against an
administrator cloning or rewriting all original evidence out of band.

If host wallet ciphertext is damaged or missing, use the original concealed
1Password item with an explicit same-host recovery deployment:

```bash
erpc v --chain arbitrum deploy -n mainnet --name arb1 --ssh-key <key.pub> --restore-custody
```

This requires the original desired active mode and matching original custody
origin. For an already activated signer, the public stage first fences and
drains the original writer and retains its history; only then can the same-key
backup be delivered. Original NSS/namespace/volume and history failures prevent
private delivery. Before first activation, root-encrypted custody can be repaired
while the healthy original observer continues without wallet credentials.
Missing original identity/history evidence is retained and refused, not inferred
from a replacement key or today's account name. The command continues through
the normal deployment and activation checks after successful restoration; it is
not a restoration-only or no-resume command.
Used-key import, cross-host migration, custody replacement, ownership transfer
and automatic financial registration are not implied by this recovery option.

See the [Arbitrum primary-source map](chains/arbitrum.md) for chain and protocol
references. The exact native source, OCI manifest/config and complete helper
profile are carried by the CLI; `plan` exposes the qualified native pins.

## Qualified native runtime

The assertion role pins [Nitro v3.12.2](https://github.com/OffchainLabs/nitro/releases/tag/v3.12.2)
at source `5f02f3f03076343061f167e81b8e82ec5518064b`. Its Linux amd64 full
image manifest is
`sha256:c908f324a08b7332d1fa031b83b071cfa2d9edd8a364c4344d7c34b665bf08e9`,
with config ID
`sha256:10de676fe40c8ff6046d9ad113db2e587877442c77df013559a342ea3a81757a`.
These are observed official registry-byte pins. They are not a publisher-signed
artifact attestation or an independent reproducible-build claim. The follower
RPC release catalog remains separate.

ERPC explicitly configures the full image's same-process authenticated validation
server using `api-auth` and `self-auth`. The upstream release also provides a
separate `-validator` image/entrypoint; that is not the runtime used here.
[Native startup](https://github.com/OffchainLabs/nitro/blob/5f02f3f03076343061f167e81b8e82ec5518064b/cmd/nitro/nitro.go)
constructs and starts the validation node on the same stack before execution and
consensus. The profile uses HashDB and chain-tip validation recordings because
[native configuration validation](https://github.com/OffchainLabs/nitro/blob/5f02f3f03076343061f167e81b8e82ec5518064b/cmd/nitro/config/config.go)
rejects PathDB when a validator is required. No archive or universal watchdog
claim follows from this choice.

Startup/readiness binds the authenticated validation listener and execution
listeners to the original native PID. Financial forwarding instead checks the
original generation receipt, original-wallet signature, canonical transaction
and fresh on-chain policy. It does not perform a new privileged process scan
for every forwarded request. Database/freezer directory identity and history
sequence floors are retained; ordinary native table-file replacement is allowed.
Missing original history after hot activation cannot trigger an automatic fresh
snapshot. This protects managed continuity, not recovery from arbitrary corruption
or a cryptographic backup of the database.

The parent transport uses a private CA and authenticated loopback HTTPS without
an insecure TLS override. The public CA and encrypted leaf/key have original
receipts; the CA private key is discarded after issuance. Status exposes expiry,
and fenced preparation renews certificates within 30 days of expiry. Interrupted
renewal retries retain the same original attempt. Expiry refuses startup and
new TLS certificate validation; it does not instantly revoke an already
established session or in-flight request. Use the normal original-owner
deployment/configuration path to renew before it expires. Provider TLS roots and the original parent-local
CA have distinct scopes.
