<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Optimism, Base and Soneium follower RPC

`erpc r --chain optimism|base|soneium` manages a dedicated execution/derivation
follower with a persistent peer identity. It does not operate a sequencer,
batch poster, fault-proof challenger or independent PoS validator. Base's upstream
`--mode validator` names its follower derivation mode; it does not grant staking
or sequencing authority.

The implementation is qualified through pinned source, rendering and offline
failure-injection tests. **Real-host bootstrap, provider compatibility, RPC/WS,
reboot, throughput and upgrade acceptance remain deferred** until the full
implementation batch is ready. A deployment submission is not proof of sync.

## Networks and qualified software

| Family | Networks and L2 IDs | Execution / derivation |
| --- | --- | --- |
| Optimism | mainnet 10; sepolia 11155420 | op-reth 2.6.1 / op-node 1.19.11 |
| Base | mainnet 8453; sepolia 84532 | base-reth-node / base-consensus 1.5.1 |
| Soneium | mainnet 1868; minato 1946 | op-reth 2.6.1 / op-node 1.19.11 |

OP releases resolve to `e16bffa18420c86dbab693097bc33117f74a5f7d` (op-reth)
and `43c071cbff8ad7512581561aa2d43c990544b650` (op-node). Linux AMD64 and
ARM64 OCI platform manifests are individually pinned in the
[release catalog](../crates/erpc-chain-op/src/release.rs). The host pulls that digest
and checks the resulting platform, repository digest and entrypoint/environment.
No GPG signature, attestation or reproducible-build claim is made for these images.
The initial trust is the official registry and release metadata over TLS.
[op-reth release](https://github.com/ethereum-optimism/optimism/releases/tag/op-reth/v2.6.1),
[op-node release](https://github.com/ethereum-optimism/optimism/releases/tag/op-node/v1.19.11).

Base uses its own native 1.5.1 binaries from commit
`5476069f1eb74a56bccb56fdefd4b4bb0e3cda42`. Both archives must match the
reviewed SHA-256 and a valid SHA-256-or-stronger detached signature from primary
key `5EFE7BCFCD85682711F9FC30904841FFEBD38BAD` before binary extraction.
The embedded public key comes from the pinned upstream installer; erpc does not
run that installer or accept its trust-root overrides. Mainnet Denim requires
1.5.1 by **2026-11-05 18:00 UTC**; Sepolia has already activated it.
[Base release](https://github.com/base/base/releases/tag/v1.5.1),
[pinned verification source](https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/baseup/baseup).

The OP operator guide explicitly includes Soneium, and the pinned clients contain
its mainnet and Minato chain configurations. A Soneium operator endorsement of
this exact version pair is **not documented** in the Soneium pages reviewed.
This is ERPC source qualification, not a claim of chain-operator approval or live
compatibility. The exact op-node registry submodule is
`08d6a44910d75e28a5ee1c7c047d3bdd0bbdbdd2`; source-pinned L2 anchors are
in [network.rs](../crates/erpc-chain-op/src/network.rs).
[OP guide](https://docs.optimism.io/node-operators/tutorials/node-from-docker),
[Soneium network information](https://docs.soneium.org/docs/builders/sfa),
[pinned registry](https://github.com/ethereum-optimism/superchain-registry/tree/08d6a44910d75e28a5ee1c7c047d3bdd0bbdbdd2/superchain/configs).

## Preparation and secrets

Use dedicated Ubuntu 24.04 or 26.04, passwordless sudo, at least 64 GB RAM,
16 logical CPUs, 20 GB free system space, and local SSD/NVMe capacity for the
chosen history. AMD64 must have AVX2, BMI2, FMA and MOVBE; ARM64 is also supported.
These are ERPC provisioning floors, not measured performance promises. No disk
is formatted, and existing unowned units, accounts, state or reserved listeners
are refused. One host cannot be reassigned to another family/network/history.

Place the L1 execution and beacon configuration in one uniquely labeled
**CONCEALED** 1Password field. Only that field projection is read, with a 64 KiB
value limit. Never put provider URLs or authentication in command arguments or
public inventory:

```json
{
  "execution": {"url": "<HTTPS execution endpoint>", "headers": {"Authorization": "<provider authorization>"}},
  "beacon": {"url": "<HTTPS beacon endpoint>", "headers": {"X-API-Key": "<provider authorization>"}}
}
```

Headers are optional. An explicitly selected numeric loopback HTTP endpoint can
set `allow_loopback: true` for a dedicated local L1 service. Mainnets use Ethereum
mainnet; Sepolia and Minato use Ethereum Sepolia. The shared proxy verifies both
execution and beacon genesis identities and rechecks them periodically. It denies
redirects and unsafe DNS targets, pins numeric connections with TLS hostname
verification, allows only reviewed read methods, and redacts provider error text.
Historical beacon blobs must be available for the follower's catch-up range;
current-head access alone is insufficient. Provider integrity remains a trust
assumption. [Shared transport contract](../crates/erpc-chain-rollup/README.md).

The reference is `op://<vault-id>/<item-id>/<unique-field-label>`, with identifier-only
vault/item components. The value travels over SSH stdin into an encrypted systemd
credential. A separate unprivileged proxy account receives the decrypted provider
field; execution and consensus receive only local endpoints. Engine JWT and separate execution/consensus peer identities are created only on
an initial target installation. All three are encrypted before any is published;
an atomic private owner record retains their encrypted bytes and integrity hashes.
Interrupted initial publication reuses those exact ciphertexts. After the first
installation, missing, corrupted or substituted material blocks start/reboot/update
instead of generating a replacement. Runtime plaintext must match its original
receipt; the clients receive read-only systemd credential paths (read-only tmpfs
binds for containers), avoiding their automatic missing-key behavior. No provider
value or plaintext peer key is placed in public inventory or the owner record.
The controller disables core dumps before reading credential input or creating keys.
Tests use inert deterministic payloads and mocked encryption, not real key generation.
The pinned client readers use 32-byte hexadecimal secp256k1 scalars; target generation
rejects zero and values outside the curve order.
[OP key loader](https://github.com/ethereum-optimism/optimism/blob/43c071cbff8ad7512581561aa2d43c990544b650/op-node/p2p/cli/load_config.go),
[Base consensus key loader](https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/crates/consensus/cli/src/p2p.rs),
[Base execution key option](https://github.com/base/reth/blob/7134be3b51cf9d9504f988bff3266a23085f0bd9/crates/node/core/src/args/network.rs).

```sh
erpc r --chain base init -n sepolia --name base-a --host <server> \
  --ssh-key <operator.pub> --vault <vault> --type full \
  --advertise-ip <public-peer-ipv4> --l1-upstreams <op-reference> \
  --management-allow <stable-management-cidr>
erpc r --chain base plan -n sepolia --name base-a
erpc r --chain base deploy -n sepolia --name base-a --ssh-key <operator.pub>
erpc r --chain base status -n sepolia --name base-a --ssh-key <operator.pub>
```

Use `--network minato` for Soneium's test network and `sepolia` for Optimism/Base.
Mutation commands use the repository's normal confirmation or `--yes`. Initialization
prepares the owned host without starting clients; deploy installs the reviewed pair
and queues bootstrap. The inventory's desired pair and last operation do not replace
actual remote status.

## Bootstrap, storage and history

Base uses the official small snapshot listing to choose an immutable manifest,
pins its SHA-256, validates its network/storage version, paths, output BLAKE3
records and complete component/chunk metadata, then carries that manifest to the
native downloader. The downloader resumes and verifies the selected output files.
The pinned 1.5.1 full preset retains **13,392,000 blocks**, so the catalog's older
`fullSize` estimate is not used for capacity. Initial required bytes are
`ceil((2 × selected expanded database bytes + selected compressed snapshot bytes) × 1.2)`,
with conservative minimum floors (mainnet full/archive: 4/18 TB; Sepolia: 2/6 TB).
Full selection excludes transaction senders and RocksDB indices, retains all
state/headers and the selected transaction/receipt/change-set tails; archive
includes all standard history components. Proofs are not selected.
[Capacity guidance](https://docs.base.org/specifications/node-operators/performance-tuning),
[pinned downloader](https://github.com/base/reth/blob/7134be3b51cf9d9504f988bff3266a23085f0bd9/crates/cli/commands/src/download/mod.rs),
[Base retention configuration](https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/.env.mainnet).

OP Mainnet needs its pre-Bedrock import. ERPC chooses the latest matching official
storage-v2 full/archive tar and its exact filename checksum before target download.
A retry retains the same URL/hash. Extraction runs as the node user after SHA-256
verification, accepts only database/config roots, and rejects links, devices and
path traversal. It does not import a publisher's JWT or peer identity. OP Sepolia
and both Soneium networks use execution-layer sync from their pinned chain config.
Initial OP Mainnet floors are 2 TB full / 4 TB archive; Soneium mainnet 2 TB;
other networks 1 TB full / 2 TB archive. These are ERPC floors and must be reviewed
as chains grow. [OP bootstrap guide](https://docs.optimism.io/node-operators/tutorials/node-from-docker),
[official snapshots](https://datadirs.optimism.io/).

Allocated bytes in this owner's execution and download-cache directories reduce
the remaining initial provisioning budget, with a 200 GB minimum free reserve.
This allocation-derived floor remains in force at every start/reboot/install:
bootstrap import completion does not establish chain synchronization and cannot
waive initial-sync capacity. A separate 200 GB operating reserve always applies. Quarantined recovery data does not count
as useful bootstrap allocation. Both working directories must share the provisioned
filesystem. Add storage before the reserve is exhausted.

`full` and `archive` are immutable host contracts. Full does not promise historical
state. Archive retains history supplied by the supported snapshot/client; erpc does
not add a legacy pre-Bedrock Geth endpoint or historical proof database. The selected
public API modules are `eth,net,web3`; debug/admin/Engine remain unexposed.

## Network policy and readiness

HTTP RPC **8555**, WebSocket **8556**, and metrics **9060** have independent
application and firewall ACLs. Empty lists bind their gateways to loopback.
`--rpc-allow` controls RPC/WS, `--monitoring-allow` controls `/execution` and
`/consensus` metrics, and `--management-allow` controls SSH in addition to the
current controller. Repeating a flag replaces that stored list; pass an empty
value to clear it. World-wide CIDRs are permitted only for the explicit RPC list.
TLS/authentication termination is an operator-managed gateway outside this backend.

Native execution RPC/WS 8545/8546, Engine 8551, derivation RPC 9545, metrics
6060/7300 and L1 proxy 18545/15052 remain loopback. Peer listeners are execution
30303 TCP/UDP and discovery 9200 UDP, derivation 9222 TCP and 9222 UDP (OP) or
9223 UDP (Base). Public peer advertisement requires an explicit numeric IPv4.

A short firewall operation is confirmed by a fresh SSH connection with its exact
run ID and bundle digest before any long install or credential write. Every unit
requires the common live-policy guard, and boot restores the confirmed policy.
An expired or superseded confirmation cannot approve a later operation. A separate
caller-generated deployment intent is checked before firewall preparation, provider
credential writes and installation. Stop, restart and retirement invalidate that
intent, so delayed playbooks or bootstrap completion cannot revive a canceled run.

Readiness requires the expected EL chain ID and CL rollup/L1/genesis anchor,
canonical safe/finalized EL hashes, ordered unsafe/safe/finalized heights, and
fresh L2/L1 progress. ERPC limits unsafe age to 300 seconds, safe age to 3600,
finalized age to 7200, and derivation lag to 128 L1 blocks/1800 seconds.
Structured Reth `eth_syncing` is accepted only with plausible heights and execution/
finish stage progress; equal current/highest alone is insufficient. These are
conservative operational thresholds, not protocol guarantees. The RPC gateway
waits for readiness; `status` exits unsuccessfully while readiness is false.

## Operations and recovery

All twelve verbs are implemented: init, deploy, list, status, logs, start, stop,
restart, update, update-config, plan and destroy. `erpc --json rpc logs` emits NDJSON.
`plan --change deploy|update|update-config` shows public desired settings without
reading provider values or mutating a host. `update` selects this CLI's reviewed
pair, rejects downgrades, fences startup before stopping the old pair, and never
automatically rolls a database back. `update-config` changes access/advertisement/
upstream references without implicitly changing clients.

Resume an interrupted installation with `deploy` at its stored target. Resume a
stopped/failed bootstrap with `start` or `deploy`; the immutable source is retained.
If that source has expired or an incomplete bootstrap must be replaced, explicitly
use `deploy --reset-bootstrap`. The host first fences startup and stops the exact
owner, then moves incomplete execution/cache directories into a private
`bootstrap-recovery-<timestamp>` quarantine and chooses fresh official metadata.
A crash during this move is resumable with the same flag. **Completed databases
always refuse this reset.** Nothing is deleted; consensus identity, encrypted
credentials and the previous client floor remain. Inspect retained data before
performing any separate operator-directed quarantine cleanup.

Native Base shutdown checks retained service cgroups and the process table for
both dedicated account UIDs and Base client executables. Missing or inactive units
do not establish quiescence: a surviving or uninspectable native writer blocks
success and prevents installation or bootstrap quarantine from touching its data.
The controller does not kill a process whose ownership it cannot establish.

Preserve the private `/etc/erpc/rollup-owner.json`, encrypted credentials and the
host systemd encryption secret in protected backups. Ciphertext alone is not a
portable recovery key; erpc refuses established identity loss until explicit recovery.

Destroy stops/disables the owned services and retires the host while retaining
its ownership, database, identity, encrypted credentials and restrictive firewall.
It does not free the host for another network. Missing keys, altered protected
files or a completed database needing migration require explicit operator recovery;
erpc does not invent a new identity or delete that data. Before later live acceptance,
exercise restart/reboot, interrupted install/bootstrap, wrong-scope refusal, provider
loss, RPC/WS/metrics ACLs and the documented upgrade path on test networks.
