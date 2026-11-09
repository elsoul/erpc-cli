<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# BSC validator operations

`erpc v --chain bsc` manages a dedicated BSC validator host on `mainnet` or
`chapel`. It implements init, deploy, list, status, logs, start, stop, restart,
plan, update, update-config and destroy. The [RPC guide](bsc-rpc.md) covers the
shared binary qualification, full/pruned snapshot bootstrap, capacity estimates,
firewall confirmation and database preservation. Validator ownership is separate
from RPC ownership; an existing RPC host cannot be converted by changing inventory.

This backend creates fresh consensus and BLS vote keys on the owned host. The
financial operator's key stays in its external wallet. Funding, registration,
self-delegation, commission changes, withdrawal and transaction signing/broadcast
remain in the official staking tools. The two supported entry points are
[mainnet staking](https://www.bnbchain.org/en/bnb-staking) and
[Chapel staking](https://testnet-staking.bnbchain.org/en/bnb-staking). [S1], [S2]

## Prepare and deploy

Use a dedicated Ubuntu 24.04+ AMD64/ARM64 host. The validator preflight requires
sixteen cores, 128 GB RAM on mainnet or 16 GB on Chapel, plus the selected
snapshot's calculated bootstrap capacity and operating reserve. Mainnet's official guidance also specifies NVMe,
40k IOPS, 500 MB/s disk throughput and at least 512 Mbps networking; the CLI does
not benchmark those properties. Check them before registration. An existing
synchronized clock is preserved;
otherwise a supported installed time daemon is selected before a
`systemd-timesyncd` fallback. The kernel synchronization flag must be affirmative
before signing or registration preparation. The common CPU-count preflight remains conservative for Chapel. Mount the complete
`/var/lib/erpc-bsc` tree together. [S3]

```sh
erpc v --chain bsc init --network chapel --name signer1 \
  --host <address> --operator <external-operator-public-address> \
  --vault <vault> --ssh-key <operator-public-key-file> --yes

erpc v --chain bsc plan --network chapel --name signer1

erpc v --chain bsc deploy --network chapel --name signer1 \
  --ssh-key <operator-public-key-file> --yes
```

Mainnet selects reviewed Geth 1.8.2 for the December 8 Jenner activation; Chapel
retains 1.8.1 for its separate network schedule. See [upgrade requirements](bsc-rpc.md#qualified-releases-and-artifact-trust). The exact
binary hashes, source commits and network metadata are carried in the catalog.
Full block history is recommended; `init --storage pruned` is an explicit,
immutable choice. A higher tag is not automatically a mainnet-qualified release.

Init reserves the host and external operator address without creating signing
keys. Deploy authenticates the client and initial database, creates one consensus
account and one BLS wallet, and preserves their original identities on retries.
These client commands run under the dedicated non-root account with supplementary
groups cleared; the controller verifies account quiescence before sealing files.
A root-owned credential receipt is durable before key creation; an interrupted
publication reuses the same staged material. Existing unmanaged identities,
changed keys, extra wallet keys and lost published material cause refusal.

The consensus key is an encrypted Geth keystore; the vote key uses the pinned
client's encrypted Prysm wallet. Separate random passwords are encrypted with
`systemd-creds` using the host key. Runtime passwords reach Geth through sealed,
inherited memory descriptors, never password arguments or plaintext password
files. Published key files are root-owned and read-only to the node group.
The operator address and reserved public identities cannot be replaced through
an inventory update. [S2], [S4], [S5]

Deploy writes a concealed custody backup of the signing material and original
peer identity in the selected 1Password vault, reads
that exact field back, and only then acknowledges its digest to the host.
Creation uses a JSON template on stdin. A retry finds the same owner-tagged item;
it refuses ambiguous items or differing contents. The inventory stores its
reference, not the secret value. A failed or ambiguous backup operation leaves
signing ineligible. [S6]

## Register externally and observe activation

After synchronization, prepare the public registration fields:

```sh
erpc v --chain bsc plan --change register --network chapel --name signer1 \
  --ssh-key <operator-public-key-file> --json
```

This reads the owned host, requires completed synchronization and its acknowledged
backup, and verifies the BLS proof locally. The proof binds the operator address,
vote public key and chain ID; the consensus address is separately bound to host
ownership. Use the resulting public fields in the official staking application.
A registered operator with different identities is reported as a conflict.
The command creates no transaction and moves no funds. Registration does not
guarantee election. Consult the current official form for required self-delegation
and fees. [S1], [S4], [S7]

Validator JSON-RPC HTTP/WS listeners are disabled. The official configuration's
`HTTPHost = "localhost"` is explicitly cleared in a deterministic, verified
validator configuration, together with `WSHost`; merely omitting `--http` would
leave that listener enabled. Geth unlock is permitted only with external RPC
disabled. P2P 30311 is public in the selected direct-P2P topology; metrics 6060
remain loopback-only. Private IPC supplies operational observations. [S3], [S8]

On every process start, mining begins disabled. A root observer periodically
checks the owned process, network/genesis, synchronization, peers, fresh head,
synchronized host clock,
backup acknowledgement and exact registered consensus/BLS identities. It enables
mining only when those checks succeed and the registration is not jailed. Geth's
consensus engine independently enforces election before producing blocks/votes.
This observation does not sign or submit the registration transaction. [S7], [S9]

Signing eligibility is separate from authority to stop the owned process. Private
control checks the reviewed process, kernel-reported IPC peer PID/UID/start time,
and network/genesis before using the miner API. Failed eligibility checks stop an
already running miner. If IPC control or stop confirmation fails, the observer
durably revokes startup and queued deployment, then attempts graceful shutdown of
only revalidated owned writers; a shutdown failure retains the fence.

`status` separates node readiness, registration, mining and the current epoch's
consensus/vote membership. Contract reads are pinned to the observed canonical
block hash, and the native Parlia snapshot is read at that same hash. The official
staking developer guide documents these view methods and the native contract
address. [S11] `ready`
requires the owned keys to be elected as well as operationally eligible; an
unregistered or unelected candidate is not reported as an active validator.
Missing or malformed observations are reported as unknown/unready. [S7], [S9]

```sh
erpc v --chain bsc status --network chapel --name signer1 --ssh-key <public-key-file> --json
erpc v --chain bsc logs --network chapel --name signer1 --ssh-key <public-key-file> --json
```

Journal records use compact JSON lines on stdout in JSON mode. They include the
node and registration observer journals and identify stdout/stderr streams.

## Stop, update and recover

The shared deployment intent and startup fence apply to validators too.
Stop/destroy cancel queued deployment stages and stop the observer before
quiescing the node, including after a failed installation. A delayed observer
reads the current fence and cannot revive a stopped owner. Failed shutdown
retains the fence and reports failure. Destroy preserves keys, native vote
history, database, inventory and restrictive firewall.

Updates preserve the same keys and native history, qualify the selected version,
and refuse a database downgrade. A future release can be reserved by an older
installed controller, but the carried new controller must qualify it before any
installation mutation. The complete helper revision is published atomically;
isolated Python startup checks the protected sibling directory. SSH control also
verifies the exact supported release file profile and its content digest.

For missing or damaged signing files on the same established host:

```sh
erpc v --chain bsc update-config --restore-custody --network chapel --name signer1 \
  --ssh-key <operator-public-key-file> --yes
```

Recovery stops/fences the signer, verifies the exact acknowledged backup against
its immutable owner and public identities, and preserves replaced encrypted files
for inspection. An interrupted recovery resumes its recorded publication intent.
It leaves the service stopped; use an explicit start after inspection.

The native vote journal is **not** replaced by a key backup. The qualified Geth
client uses a fsynced JSON WAL with a bounded recent-vote history. ERPC checks its
file/record shape, signer identity and stopped checkpoint; missing, truncated,
foreign or regressed history is refused. These checks do not establish a global
record of signatures made by operator-created copies. Native history and the
client's slashing rules remain necessary. [S10]

Validation follows the effective WAL view after native `START` front-truncation
recovery. Every index in the required recent 512-vote window must remain present
and contiguous; conflicting segments or discarded older copies cannot satisfy a
missing record. The checker never repairs or fills history automatically.

This first validator lane supports fresh generation and same-host key recovery.
It refuses arbitrary used-key imports and cross-host backup restoration. Moving
used keys requires a separate managed source fence and native-history transfer;
a local inventory lock or key-only backup cannot establish that authority.

## Verification scope

Offline tests use synthetic keystores and mocked client/store commands, an
upstream public BLS verification vector, strict service renders and ownership,
interruption, cancellation, backup-readback, registration and native-history
failure cases. Linux systemd/credential/memfd behavior, large snapshot
bootstrap, actual 1Password writes, reboot, network synchronization, election,
voting and mainnet operation still await acceptance on a real host.

## Sources

[S1]: https://docs.bnbchain.org/bnb-smart-chain/validator/create-val/ "Official registration, public identities and external staking applications; read 2026-10-26"
[S2]: https://docs.bnbchain.org/bnb-smart-chain/validator/manage-keys/ "Operator versus consensus/vote key roles; read 2026-10-26"
[S3]: https://docs.bnbchain.org/bnb-smart-chain/validator/run-val/ "Official hardware and validator process guidance; read 2026-10-26"
[S4]: https://github.com/bnb-chain/bsc/blob/cdb7548b5baacfdae92f9f63437d6456411665f3/cmd/geth/blsaccountcmd.go "Pinned BLS wallet creation/import/list and operator-chain-bound proof"
[S5]: https://github.com/OffchainLabs/prysm/blob/21e1f7883b88ce39d16263d1cdea70bfdaa4d359/validator/accounts/wallet_create.go "Prysm v5.3.2 imported wallet writes encrypted account material"
[S6]: https://www.1password.dev/cli/item-create "Official stdin JSON-template creation; concealed field semantics documented by 1Password"
[S7]: https://github.com/bnb-chain/bsc-genesis-contract/blob/84641812a013eda1593e058aeed4dc116c7746eb/contracts/StakeHub.sol "Pinned view ABI and proof-of-possession domain; live values are observed, not inferred from constants"
[S8]: https://github.com/bnb-chain/bsc/blob/cdb7548b5baacfdae92f9f63437d6456411665f3/cmd/utils/flags.go "HTTP/WS configuration overrides and BLS/journal flags"
[S9]: https://github.com/bnb-chain/bsc/blob/cdb7548b5baacfdae92f9f63437d6456411665f3/consensus/parlia/api.go "Native snapshot-at-hash and epoch validator observations"
[S10]: https://github.com/bnb-chain/bsc/blob/cdb7548b5baacfdae92f9f63437d6456411665f3/core/vote/vote_journal.go "Native 512-entry vote journal; dependency tidwall/wal 1.1.7 enables fsync by default"

[S11]: https://docs.bnbchain.org/bnb-smart-chain/staking/developer-guide/ "Official StakeHub address and validator information view methods; read 2026-10-26"

A cancellation-record write failure does not skip owned shutdown. Explicit
stop/destroy still attempt the reviewed process drain and disable the node and
validator timer as applicable; a shutdown failure also attempts the validated
orphan-writer path. A transient storage error is retried after drain, including
the latest known native journal checkpoint, but the operation still reports a
failure. If storage remains unavailable, durable restart prevention cannot be
claimed: repair storage/services and retry. Keys, data and ingress are retained.
