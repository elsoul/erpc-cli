<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Arbitrum and Robinhood follower nodes

`erpc r --chain arbitrum` manages One (`mainnet`), Nova (`nova`) and Arbitrum
Sepolia (`sepolia`). `erpc r --chain robinhood` manages Robinhood mainnet and
its `testnet`. Each host has one immutable owner, chain family, network and CPU
architecture. This is a follower RPC backend: sequencer, batch poster, staker and
block-validator signing are disabled. It does not activate an assertion validator,
post a bond, create a wallet or submit a registration transaction.

The implementation is qualified through source inspection and offline tests.
**Real-host synchronization, reboot and workload acceptance remain deferred**
until the complete implementation batch is ready.

## Preparation and access

Use a dedicated Ubuntu 24.04+ host with passwordless sudo, eight CPU cores,
64 GB RAM, Linux x86-64 or ARM64 and provisioned local SSD storage. The initial
capacity policy is 6 TB for One and 2 TB for the other networks. Allocation already
occupied by this owner's data reduces the remaining bootstrap budget, with a
200 GB operating reserve. These are deployment floors, not measured chain-size
promises. Capacity is rechecked before prepare, install/resume and start/reboot;
no disks are formatted and no existing unowned data is adopted.

Create a concealed 1Password field containing this JSON shape, substituting the
actual operator-selected L1 endpoints and authentication headers:

```json
{
  "execution": {"url": "<HTTPS execution endpoint>", "headers": {"Authorization": "<provider authorization>"}},
  "beacon": {"url": "<HTTPS beacon endpoint>", "headers": {"X-API-Key": "<provider authorization>"}}
}
```

Headers are optional. Only `Authorization` and `X-API-Key` are accepted. Explicit
numeric loopback endpoints can set `allow_loopback: true` for a local L1 pair.
The value itself never belongs on the erpc command line or in public inventory.
Use an identifier-only `op://<vault-id>/<item-id>/<field>` reference, where
`field` is an exact unique concealed field label:

```sh
erpc r --chain arbitrum init -n sepolia --name arb-a --host <server> \
  --ssh-key <operator.pub> --vault <vault> --l1-upstreams <op-reference> \
  --management-allow <stable-management-cidr>
erpc r --chain arbitrum deploy -n sepolia --name arb-a --ssh-key <operator.pub>
erpc r --chain arbitrum status -n sepolia --name arb-a --ssh-key <operator.pub>
```

The credential reaches the target only over SSH stdin. The host verifies the
execution and beacon genesis identities, then uses systemd credential encryption.
The proxy has a different unprivileged account from the node container and receives
`LoadCredentialEncrypted`; its arguments contain only the L1
network. Core dumps are disabled. Provider URLs and headers stay out of service
arguments, generated bundles and journal diagnostics. The shared
[L1 transport contract](../crates/erpc-chain-rollup/README.md) specifies DNS, TLS,
redirect, method, size and error-handling boundaries. Provider responses remain
trusted data; identity checks do not make a dishonest provider truthful.

One/Nova/Robinhood mainnet require Ethereum mainnet upstreams. Arbitrum Sepolia
and Robinhood testnet require Sepolia upstreams. Historical blobs may be necessary
for catch-up; a provider's current-head beacon API alone does not guarantee old
blob availability. Nova uses AnyTrust data availability through its chain registry,
rather than treating its batches as Ethereum blob data.

HTTP RPC (8547), WebSocket RPC (8548), metrics (6070), and L1 proxy ports
(18545/15052) bind only to loopback. Firewall preparation admits SSH from the
current controller address and the stored management ranges; a fresh SSH
connection must confirm the exact operation before long deployment work starts.
Use a stable management range for later access. An application TLS/authentication
gateway is outside this backend; the CLI does not expose these APIs publicly.

## Release and network qualification

The default is Nitro **3.12.1**, source commit
`70fa99a6e711f09eedd96a907290c3df0f3bcf7d`. The official image index and each Linux
platform manifest are pinned by digest in [the release catalog](../crates/erpc-chain-nitro/src/release.rs).
Deployment pulls the content digest and verifies Docker's resulting architecture
and repository digest. Tags cannot silently select executable bytes. The release
publishes no attached binary signature/checksum artifacts; this does **not** claim
GPG verification, a build attestation or an independent reproducible image build.
The initial trust is the official release reference and registry over TLS, followed
by recorded content digests. [Release](https://github.com/OffchainLabs/nitro/releases/tag/v3.12.1).

Robinhood's latest software notice recommends 3.11.4, while its full-node example
still names 3.11.2. The upstream support matrix lists 3.12.x and 3.11.5, not those
older examples. ERPC selects supported upstream 3.12.1 because its fixed source
supports Robinhood's documented ArbOS 61 and its chain/genesis configuration
format. This is **ERPC source qualification, not a newer Robinhood endorsement
or a claim of live compatibility**. Follow chain upgrade notices before the later
live batch. [Robinhood notices](https://docs.robinhood.com/chain/notices-and-upgrades/),
[node guide](https://docs.robinhood.com/chain/run-a-full-node/),
[upstream support policy](https://docs.arbitrum.io/run-a-node/nitro-support-policy),
[ArbOS upgrade implementation](https://github.com/OffchainLabs/nitro/blob/70fa99a6e711f09eedd96a907290c3df0f3bcf7d/arbos/arbosState/arbosstate.go).

Robinhood's mainnet and testnet chain files are separately pinned by SHA-256.
Mainnet additionally requires its custom genesis, also pinned; testnet omits it.
The image's home directory is irrelevant to persistence here: explicit
`/data` and `/data/chain` arguments point to the private host volume. The pinned
image uses `user` with `/home/user`, despite the Robinhood example's `/home/nitro`
mount. [Image Dockerfile](https://github.com/OffchainLabs/nitro/blob/70fa99a6e711f09eedd96a907290c3df0f3bcf7d/Dockerfile).

Followers use PathDB with online pruning and retained transaction lookup indexes.
For One, Nova and Sepolia, pinned 3.12.1 maps `--init.latest=pruned` plus the path
scheme to the official `full-path` snapshot catalog and verifies the downloaded
checksums. This is visible in `latestSnapshotKind`; the mutable snapshot guide's
HashDB-only statement does not describe that pinned code. Robinhood initializes
from its chain configuration and network-specific genesis instead. A full follower
does not promise archive state or restored pre-Nitro execution history.
[Snapshot resolver and database checks](https://github.com/OffchainLabs/nitro/blob/70fa99a6e711f09eedd96a907290c3df0f3bcf7d/cmd/nitro/init/init.go).

Nitro remains under its upstream Business Source License 1.1 and additional use
grant. ERPC does not redistribute the image or reinterpret its production-use
conditions. [Pinned license](https://github.com/OffchainLabs/nitro/blob/70fa99a6e711f09eedd96a907290c3df0f3bcf7d/LICENSE.md).

## Operations and recovery

The twelve verbs are `init`, `deploy`, `list`, `status`, `logs`, `start`, `stop`,
`restart`, `plan`, `update`, `update-config`, and `destroy`. Always select the
network explicitly. Production mutations require an explicit `--chain` too.

With `--json`, `logs` writes each native or SSH diagnostic line as a compact
`{"journal":"..."}` record on stdout, followed by the compact completion record.
A failed stream returns the normal JSON error record instead of a success
record. Embedded line breaks are escaped, so every stdout line is independently
parseable JSON. Human-mode journal output remains on stderr.

`init` retries only an unfinished preparation. An installed, installing or retired
host must use `deploy`; initialization cannot replace a running service helper.

`update --version <version>` accepts only a release in this CLI's reviewed catalog.
A later image first requires a reviewed catalog update; there is no arbitrary
image override, automatic latest-tag inference or database downgrade. The host
saves the desired release/configuration before stopping services. An interrupted
installation stays fenced from boot and normal service actions; retry `deploy`
with the stored target. Another desired configuration cannot take that target over.
Standalone mutations refuse to compete with a running deployment/firewall operation.

`update-config --l1-upstreams <op-reference>` rotates the parent-chain credential
source after validating the new pair, then reapplies guarded services. Management
ranges can also change through `--management-allow`. Same-owner retained data stays
at `/var/lib/erpc-nitro/data`; verified metadata and encrypted credentials are under
`/etc/erpc/nitro`. Containers run without capabilities, with a read-only image and
a dedicated numeric identity; the service checks labels before stopping or adopting
a pre-existing container name.

`destroy` stops/disables services and records retirement while retaining chain data,
credentials and the immutable ownership record. There is no purge/forget switch.
A same-owner deploy can resume retained data. Partial snapshot extraction or a corrupt
database that Nitro refuses is left intact: deployment never deletes history to
manufacture a successful restart. Investigate and preserve it before choosing a
fresh host or an explicit offline recovery procedure.

A successful deploy may still be downloading or synchronizing. `status` requires
active services and owned listeners, a confirmed firewall receipt, the expected L2
chain ID, a verified matching parent, `eth_syncing` false and recent L1/L2 blocks. An unready result exits unsuccessfully. It does
not certify every RPC method, archive query, finality property or external gateway.

Offline evidence includes actual official OCI manifest bytes, wrong-network and
foreign-owner mutation failures, interrupted updates, configuration ownership,
credential preflight/encryption boundaries, persistent boot fencing, host capacity,
private service arguments and public metadata hashes. No container/node image,
production credential or transaction was executed. The live batch must separately
record all five networks' bootstrap/sync, parent blob access, RPC/WS queries, restart,
reboot, capacity behavior and failed-update recovery.

## Interrupted installation and explicit cancellation

`stop` and `destroy` remain available while installation is incomplete. They
verify the immutable owner first, persist the startup fence and cancel the
current deployment intent before draining the owned services/container. They
do not require deployment hardware/capacity checks or a healthy RPC endpoint.
An already installed compatible controller stops without uploading a new bundle.
For an older or interrupted controller installation, a short carried recovery
play checks ownership and the real root-owned helper namespace/ancestors before
publishing the current controller. Unsafe existing directories, links, file
owners or write permissions are refused without adopting them. Its final action
executes the sealed carried source, rechecks destination trust and verifies the
copied controller digest before changing owner state. Installed controller probes
use the shared isolated trusted-directory loader before executing any helper.
Ordinary initialization, retries and update preparation enforce the same
namespace checks before publication and verify both copied helpers against the
sealed controller and L1 transport source afterward.
The data, credentials and ownership record remain retained.

Every deployment authorization binds the observed cancellation generation and
one new caller intent to its reviewed target. Credential installation, firewall
preparation, image installation, completion and queued startup check that intent.
A stop between any two stages rejects the old continuation; a fresh explicit
`deploy` can resume the retained target. Explicit `start` can reopen a fully
installed stopped node, while an incomplete installation must first resume
`deploy`. An invalid or failed final guard leaves the installation fenced.

The root-owned state file atomically records both cancellation and its startup
fence. Its parent and every ancestor must also be protected from replacement;
unsafe directory ownership, permissions or symlinks are refused without adopting
them. Upgraded state uses a versioned phase that older controllers reject before
mutation, so an old queued bundle cannot erase the new cancellation fields.
Keep the current CLI for future operations on that owner. If storage prevents
fence publication, the controller still attempts owned shutdown and reports a
failure rather than claiming durable cancellation.
