<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Monad native nodes

`erpc r --chain monad` manages a full RPC node; `erpc v --chain monad` reserves
validator intent separately. Both provide `init`, `deploy`, `list`, `status`,
`logs`, `start`, `stop`, `restart`, `update`, `update-config`, `plan`, and `destroy`
on explicit `mainnet` or `testnet`. Validator registration, possession proofs,
funded transaction signing and broadcast use external official tooling.

Installed SSH and systemd Python entrypoints authenticate their real root-owned
ancestors and helper files before interpretation. The first carried task checks
all privileged destinations before Ansible can create directories or change
permissions. Helper publication copies the exact sealed source with explicit
public file modes and verifies it afterwards. Managed unit/drop-in trees reject
unknown overrides, links, writable ancestors and foreign ownership. Shared
firewall boot and rollback use the externally authenticated common controller.
Native data preparation drains both original service identities and opens each
directory component relative to its parent descriptor without following links.
Only newly created or originally reserved empty staging directories receive
ownership changes; established data is verified and retained. Cached bootstrap
files remain private, and package library aliases must be one-hop local links to
protected regular libraries matching the original extraction receipt.

Original numeric native/gateway identities are durably reserved before NSS
creation; direct name/ID lookup, enumerated aliases, primary-group usage, home,
shell and group membership must agree on retries and startup. Unknown existing
users/groups are not adopted. Units and persistent device permissions bind the
original numeric UID/GID. A single protected first ExecCondition checks account
authority before systemd v255's credential-write phase; the pre-start guard is
retained. This does not prevent an administrator reassigning the original
numeric UID after authentication. A skipped condition or inactive core service
is not reported as a successful start.

Stop uses retained numeric authority and attempts both native and gateway
shutdown despite current NSS drift or cancellation-write failure. The original
account receipts are required; an older incomplete installation without them is
not silently adopted or assigned replacement identities. Preserve its data and
obtain an explicit ownership/migration review. Missing or corrupted custody does
not block an otherwise provable owned shutdown. This correction does not erase
devices, native history or retained identity material.

## Qualified release

The catalog selects the Category Labs `monad` **0.16.5 amd64** Debian package:

| Component | Qualified identity |
|---|---|
| Consensus source | `33d9d5c0314eff8c6409a810b9dbf1b6381c6b5c` |
| Execution submodule in that release | `a3b16af1ac3637a262b8b1872798bccc746e81cb` |
| Debian package SHA-256 | `0b27486fc85fefedfdb44637e1ee52a1f59e0287594562f5260fa86abf62acc8` |
| Package bytes | 739508498 |
| APT primary signing fingerprint | `D9FA4D9BB7CD9328005E26980802DFD2634AE7F0` |

On 2026-10-26, the catalog's package size/digest was qualified through the signed
APT `InRelease` and matching `Packages` bytes. The deployment checks that exact
size and SHA-256 before extracting selected native executables and libraries.
It does not run the package's maintainer scripts, automatic cleanup timers or
unrelated services. Each extracted executable/library receives an installed
receipt, which startup checks. This is artifact authentication and a recorded
source relationship; it is not a reproducible-build claim. [Package metadata],
[consensus release], [execution submodule].

Mainnet audience is independently established by Foundation announcement #6,
created 2026-10-22. Its two signatures were verified against the official active
signer fingerprints. That announcement admits all Mainnet operators to 0.16.5;
the older version shown on some network pages is not used to infer approval.
Testnet and current network configuration are qualified separately. Updates
require `update --version 0.16.5` for the version in the installed CLI catalog.
A newer release needs a reviewed catalog update; downgrade and same-version
source/package substitution are refused. [Announcement], [authorized signers],
[upgrade instructions].

## Host and physical device

Use a dedicated bare-metal Ubuntu 24.04 x86-64 server with SMT disabled, at least
16 physical CPUs and 32 GB RAM. Keep a working NTP service; validator startup
requires the kernel clock to report synchronization. Follow the official CPU frequency and network
bandwidth recommendations; offline checks do not benchmark them. The execution
partition needs a nominal 2 TB-class NVMe device (at least 1.9 TB usable), with
512-byte logical sectors. OS and consensus storage need a 500 GB-class volume.
The controller measures the actual data filesystem, allowing retained allocation
to offset initial synchronization space while preserving 50 GB headroom. Package
staging is separately checked on its own filesystem. [Hardware], [installation], [kernel profile].

Provision the raw GPT partition yourself and pass its canonical PARTUUID. ERPC
never partitions a disk, changes its sector format, truncates it or runs a device
wipe. The reservation records physical serial, partition offset/size, disk size
and sector geometry; device enumeration changes do not replace that identity.
Mounts, swap, kernel holders, non-NVMe devices, duplicate PARTUUIDs and recognized
filesystem signatures are refused. Initial edge samples must be zero. Those
samples do not prove every byte is empty: `--initialize-device` is the operator's
explicit first-write authorization for the selected blank partition.

`init` installs the private package, dedicated users, directories, permissions and
the qualified network-buffer settings. Guarded native startup reserves the
package-recommended hugepages without reducing a larger existing reservation.
It first checks the selected concealed bundle's public labels locally and the
physical selection on the host before reserving inventory. It does not import
private material to the host or initialize TrieDB. If using a separate consensus filesystem, mount it
persistently at `/var/lib/erpc-monad/data` after initialization and before deploy;
the first deployment accepts only a clean root-owned directory (0700 or0755),
with at most an empty protected `lost+found`, and creates its native
subdirectories through checked descriptors. Its filesystem UUID, ext4/XFS type,
filesystem root and directory inode are then bound to the original ownership
receipt. Kernel device numbers are checked against the current PID1 mount table
and open descriptors, but are never retained across reboots. Nested mounts
(including same-device binds) and ambiguous or unidentified volumes are refused. Once selected for deployment,
replacement filesystems and missing established history directories are refused
rather than recreated. An interrupted selection can retry only that same mount.
Services
require the configured data mount before starting. The default uses the OS and
consensus volume together, as in the official hardware layout.


Existing installations with the earlier device-number-only receipt require an
explicit stopped identity upgrade before using this controller. Supply the
**original filesystem UUID from an independent provisioning or backup record**;
this is not the raw execution partition's PARTUUID. Do not infer the original
identity from whichever filesystem is currently mounted.

```sh
erpc r --chain monad stop -n testnet --name monad-rpc-a --ssh-key OPERATOR_PUBLIC_KEY
erpc r --chain monad recover-data-filesystem -n testnet --name monad-rpc-a \
  --ssh-key OPERATOR_PUBLIC_KEY --original-uuid ORIGINAL_FILESYSTEM_UUID
erpc r --chain monad deploy -n testnet --name monad-rpc-a --ssh-key OPERATOR_PUBLIC_KEY
```

The validator role uses the same recovery command. Its sealed carried controller
works even when the installed helper predates this operation. Recovery requires
the original owner, original numeric account, durable stop and quiescent native
processes. It verifies the supplied UUID and retained inode/layout, saves the
exact original receipt plus its digest, then durably changes the storage
identity receipt. Native data, signing history, original keys and raw-device
initialization/release floors remain unchanged. An interrupted publication can
retry only the same original UUID/receipt; missing history is never recreated.
For an interrupted old initialization, recovery preserves the original pending
receipt and completes only its permitted empty directory layout under the same
reserved IDs; the result remains provisional. For an interrupted first mount
selection, it retains both the old provisional receipt and the recorded selected
mount, verifies the independently supplied UUID and selected inode, and finishes
only that unused layout. Existing `lost+found` stays untouched and must be empty.
Missing established directories, unknown files, recovered payload or a previous
native initialization marker prevent this construction recovery. Each original
receipt is kept byte-for-byte with its digest before any empty-directory handoff;
interrupted recovery resumes only the recorded inodes and original filesystem.
No native client is executed and no completed native installation is fabricated.
Retry the original `init` if it stopped before helper installation; otherwise use
normal `deploy` after recovery.

The node stays stopped. A subsequent normal `deploy` installs the qualified
current helpers and preserves the original native release rules; recovery does
not publish an older helper or select a new client version. If independent UUID
evidence or the original inode/history is missing, use separately reviewed
recovery rather than adopting the visible disk. Owned stop/destroy remain
available without the new receipt. Real mounting/reboot acceptance remains
unverified by offline tests.

The mount observer uses explicit JSON columns and `--task 1` as documented by
[util-linux findmnt](https://github.com/util-linux/util-linux/blob/v2.39.3/misc-utils/findmnt.8.adoc),
separating filesystem UUID from ephemeral `MAJ:MIN` device numbers. This is an
ERPC consensus-storage policy; it does not change the native raw TrieDB device
contract.

```sh
erpc r --chain monad init -n testnet --name monad-rpc-a \
  --host <server> --ssh-key <operator.pub> --vault <network-vault> \
  --device-partuuid <blank-nvme-partition-uuid> --public-ip <public-ipv4> \
  --secp-public-key <compressed-public-key> --bls-public-key <compressed-public-key> \
  --name-record-sequence 1 --keys-ref <concealed-native-key-reference> \
  --exclusive-identity
erpc r --chain monad deploy -n testnet --name monad-rpc-a \
  --ssh-key <operator.pub> --initialize-device
erpc r --chain monad status -n testnet --name monad-rpc-a --ssh-key <operator.pub>
```

For a validator, use `v` and supply `--beneficiary <public-reward-address>` and
`--auth-address <external-withdrawal-authority>` at init. Network, role, host,
partition, public keys, peer address/sequence and financial destinations cannot
be changed in place. Use a separate reviewed migration procedure for a different
host or consensus identity; these lifecycle commands do not authorize migration.

## Native identity and financial boundary

Keep two original native keystore files in a single concealed 1Password field.
Its JSON shape is `schema: 1`, with `secp` and `bls` members; each member contains
`public_key` and `keystore_base64` (the exact original file bytes encoded as
Base64). The key reference uses identifier-only `op://` notation. Both original
files remain the portable backup; public inventory contains no private material.

The qualified native tools accept a password argument, without a password-file
or stdin-password option. This backend therefore requires **empty native
passwords inside outer encrypted custody**. An empty-password native keystore
is secret material, not safe-to-publish ciphertext. 1Password protects the source
field; systemd host credentials encrypt the original bytes on disk. Only runtime
credentials and anonymous memory-backed descriptors expose the native files to
the corresponding unprivileged tools. Native recovery output includes private
material and is captured without forwarding it to logs. Core dumps are disabled.
The native tool's own production warning still applies; ERPC does not claim an
independent audit of its cryptography. [Native keystore], [native node options].

The SECP key identifies peer/consensus messages; BLS signs consensus certificates.
The same cryptographic SECP secret could control an EVM account if reused for
that purpose. Use dedicated, unfunded consensus keys. ERPC rejects the derived
consensus address as either reserved reward or withdrawal address; it cannot
prove the key has never been assigned authority over unrelated accounts.
`--exclusive-identity` asserts that these keys have never been hosted elsewhere. A fresh
import refuses keys appearing in official retained validator epoch sets; RPC
startup also refuses such admitted identities. The native full-node client has
no permanent non-validator switch: never externally register the RPC keys.

Import verifies the native public keys, preserves original-byte digests and
publishes a durable two-key encrypted receipt before selecting either file.
Interrupted first publication resumes only the same receipt. Missing or changed
established credentials do not generate replacement identities. On a stopped
host, `identity-restore` requires the original 1Password bytes/public keys,
retains previous encrypted generations and can reseal them under the current
systemd host credential key. An interrupted explicit restoration resumes only
its retained ciphertext. It never starts a node. Host root and a consensus
process that legitimately reads its key remain inside the custody boundary.

The signed peer-name record is derived with the reserved SECP identity and
explicit monotonic sequence. Mainnet's qualified legacy endpoint representation
and Testnet's split-port representation are handled separately. [Peer records].

## Synchronization, access and recovery

Configuration is downloaded only when its compiled byte digest matches. Initial
state uses the official remote forkpoint and matching validator epoch data, then
native state sync. These fresh bounded files are explicit trusted consensus
bootstrap inputs; a release signature does not authenticate them. An interrupted
bootstrap retains the same validated pair. Updated local checkpoints are never
replaced during ordinary reconfiguration. [Remote configuration].

Native RPC listens on loopback port 8080. The separate unprivileged gateway on
8545 requires `--rpc-allow` ranges; the default denies remote clients. Metrics
remain on native loopback 9143, with a separate 9144 gateway requiring explicit
`--monitoring-allow` ranges. SSH admits the current controller and optional
`--management-allow` ranges. P2P follows each network's qualified 8000/8001/8002
configuration. The common firewall binds confirmation to the original run and
bundle digest; services verify confirmed filtering on boot.

The default HTTP profile does not enable WebSocket/event-ring or archive
extensions. Ledger/checkpoint retention follows the qualified official cleanup
policy, including the recent-ledger-progress condition. [Cleanup source].

Stop and destroy publish cancellation before potentially failing shutdown.
The controller checks surviving processes under both dedicated native/gateway
users, even if systemd units are absent; it validates executable identity and
uses process handles for termination. A failed shutdown preserves the fence and
data. `destroy` retires services but retains the raw device, data, identities and
filtering. It neither withdraws stake nor changes epoch membership.

A failure during initial `monad-mpt --create` leaves an initialization receipt.
A repeated deploy does not run creation again. Stop the node and use
`recover-device` to validate the same partition with the native read-only MPT
operation. If it cannot validate the interrupted database, ERPC preserves it for
operator recovery; it does not silently format it. [MPT options].

## External validator registration

Once status is healthy, `prepare-registration --stake-wei <explicit-integer>
--commission <explicit-1e18-fraction>` emits the exact unsigned 165-byte native
registration payload and precompile destination. Stake and commission serialize
as decimal strings so external JSON tooling cannot round them. `validate-registration --file`
revalidates its complete ownership and amounts against this node. The reserved
external `authAddress` controls staking withdrawals. Neither it nor a funded
transaction key is imported into ERPC. [Staking API], [registration source].

Use the official staking SDK externally to produce the SECP/BLS possession
proofs, construct the funded transaction, inspect it, sign and submit. The reviewed
SDK revision is `f6e454f60e84166379ec16296d5ef6f28cf346cd`. Its library entrypoint
is `add_validator(keygen, amount_wei, auth_address, commission)`: pass both decimal
strings through exact integer conversion. Recover the native derived keys from
the original keystores and compare both resulting public keys; the IKM printed
by native recovery is not a substitute for the derived private key.

The reviewed CLI/TUI wrapper omits the commission argument, thereby selecting
zero, and its TUI displays private keys. ERPC does not invoke those wrappers.
Use an externally controlled, non-logging SDK signing process with the funded
signer on a hardware wallet. Before that wallet signs, decode the SDK's generated
calldata and require its first `bytes` argument to equal ERPC's `unsigned_payload`
exactly; also verify chain ID, destination and attached wei. [SDK calldata source],
[SDK onboarding]. ERPC
preparation is not signed calldata and does not reserve funds or guarantee
activation. Preparation refuses keys found in the official retained epoch sets;
it does not prove that a key has never been registered historically. Keep the
external receipt and validator ID for existing registrations. The native admission parameters include 100000 MON self-stake,
10000000 MON total stake and the top 200 by stake; epoch rules determine effective
membership. `registration-status --validator-id <external-result-id>` checks the
observed public keys/auth authority and current-epoch membership at one local
finalized block, using its hash for every view and including the native boundary-period snapshot selection. [Staking CLI],
[validator instructions].

Offline checks cover ownership, device metadata, interrupted creation,
original-key publication/restoration, cancellation, surviving processes,
configuration and public registration encoding. Actual native node execution,
real 1Password/SSH transfer, device initialization, full synchronization,
restart/reboot, staking admission and performance are deferred to the acceptance
batch. Offline fixtures are not evidence of completed real-host deployment.

[Package metadata]: https://pkg.category.xyz/dists/noble/InRelease
[consensus release]: https://github.com/category-labs/monad-bft/tree/33d9d5c0314eff8c6409a810b9dbf1b6381c6b5c
[execution submodule]: https://github.com/category-labs/monad/tree/a3b16af1ac3637a262b8b1872798bccc746e81cb
[Announcement]: https://github.com/monad-crypto/mf-nodeops-comms/blob/6c94e756cf64b6d5eae01e820db49d73a3571bea/announcements/mf-6/announcement.txt
[authorized signers]: https://docs.monad.xyz/node-ops/gpg-keys.json
[upgrade instructions]: https://docs.monad.xyz/node-ops/upgrade-instructions/v0.16.5
[Hardware]: https://docs.monad.xyz/node-ops/hardware-requirements
[installation]: https://docs.monad.xyz/node-ops/full-node-installation
[Native keystore]: https://github.com/category-labs/monad-bft/blob/33d9d5c0314eff8c6409a810b9dbf1b6381c6b5c/monad-keystore/src/main.rs
[native node options]: https://github.com/category-labs/monad-bft/blob/33d9d5c0314eff8c6409a810b9dbf1b6381c6b5c/monad-node/src/cli.rs
[Peer records]: https://github.com/category-labs/monad-bft/blob/33d9d5c0314eff8c6409a810b9dbf1b6381c6b5c/monad-peer-discovery/examples/sign-name-record.rs
[Remote configuration]: https://docs.monad.xyz/node-ops/full-node-installation#remote-configuration-fetching-v0121
[Cleanup source]: https://github.com/category-labs/monad-bft/blob/33d9d5c0314eff8c6409a810b9dbf1b6381c6b5c/debian/opt/monad/scripts/clear-old-artifacts.sh
[MPT options]: https://github.com/category-labs/monad/blob/a3b16af1ac3637a262b8b1872798bccc746e81cb/category/mpt/cli_tool_impl.cpp
[Staking API]: https://docs.monad.xyz/reference/staking/api
[registration source]: https://github.com/category-labs/monad/blob/a3b16af1ac3637a262b8b1872798bccc746e81cb/category/execution/monad/staking/staking_contract.cpp
[Staking CLI]: https://github.com/monad-developers/staking-sdk-cli/tree/f6e454f60e84166379ec16296d5ef6f28cf346cd
[validator instructions]: https://docs.monad.xyz/node-ops/validator-installation

[RPC block references]: https://github.com/category-labs/monad-bft/blob/33d9d5c0314eff8c6409a810b9dbf1b6381c6b5c/monad-rpc/src/types/eth_json.rs

[kernel profile]: https://github.com/category-labs/monad-bft/blob/33d9d5c0314eff8c6409a810b9dbf1b6381c6b5c/debian/etc/sysctl.d/90-monad-network-buffer.conf

[SDK calldata source]: https://github.com/monad-developers/staking-sdk-cli/blob/f6e454f60e84166379ec16296d5ef6f28cf346cd/src/staking_sdk_py/generateCalldata.py
[SDK onboarding]: https://github.com/monad-developers/staking-sdk-cli/blob/f6e454f60e84166379ec16296d5ef6f28cf346cd/docs/validator-onboarding.md
