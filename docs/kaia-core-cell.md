<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Kaia core-cell operations

`erpc validator --chain kaia` manages one dedicated Consensus Node (CN) or Proxy
Node (PN) per host on mainnet or Kairos. Use separate hosts for the CN and PN and
supply approved static peers before deploying the core-cell topology. You can
reserve and back up the original identity before enrolling its public URI. This role uses the
same qualified Kaia v2.2.2 AMD64 image and immutable network/genesis as
[Kaia RPC](kaia-rpc.md). The CN profile requires full retention and starts from
genesis: the official hardware guidance reserves its reduced-resource live-pruning
specification for PNs and does not recommend that specification for CNs.
PN defaults to the qualified pruned snapshot, with explicit full/genesis as an
alternative. [S9] It selects the actual `kcn` or `kpn` executable;
those programs set their native roles internally. [S1], [S2], [S3]

## Admission and financial authority

Running a CN does not grant council membership. The current official onboarding
page describes Phase 1 administrative approval by the Kaia Team and a team-assigned
GC ID. Phase 2 direct registration is described as upcoming. The manager, staking
contract administration, deposits, reward destination and withdrawals stay with
the operator's external wallets; the CLI never requests their private keys or
signs or submits those transactions. The official guide recommends a Safe manager
and describes the separate contract initialization and onboarding steps. [S4], [S5]

The native CN automatically starts its consensus engine. Its qualified-membership
checks control participation; ERPC does not claim a zero-message standby before
admission. `--gasless.disable` and `--auction.disable` disable the optional native
financial transaction generation. The PN role does not use the CN-only gasless
flag. No wallet unlock or inline private-key argument is passed. [S6], [S7], [S8]

The current portal instructions still require the Consensus Node ID to hold at
least 10 KAIA when submitting an onboarding request. A zero-balance exemption for
a CN with those optional features disabled is **not documented** there. Any
funding remains an external operator action; disabling the features is not a claim
that the portal waives its prerequisite. The dedicated consensus identity must
remain distinct from the external manager and reward addresses. [S4]

## Reserve the original identities

CN hosts require the documented 16 cores / 32 threads and 128 GB memory; PN hosts
require 8 cores / 16 threads and 64 GB. The CLI checks available logical CPUs and
reported memory. ERPC selects Ubuntu 24.04 or later on the qualified x86-64 platform,
passwordless sudo and a verified SSH host key. [S9]

```sh
erpc validator --chain kaia --network kairos init \
  --name core-cn --node-kind cn --host 192.0.2.10 --user ubuntu \
  --fingerprint '<verified SSH SHA256 fingerprint>' --ssh-key ./operator.pub \
  --vault '<network inventory vault>' --advertise-ip '<CN IPv4>' \
  --peer '<approved role-qualified CN KNI>' --peer '<approved role-qualified PN KNI>' \
  --manager-address '<external manager address>' --reward-address '<reward address>'

erpc validator --chain kaia --network kairos init \
  --name core-pn --node-kind pn --host 192.0.2.11 --user ubuntu \
  --fingerprint '<verified SSH SHA256 fingerprint>' --ssh-key ./operator.pub \
  --vault '<network inventory vault>' --advertise-ip '<PN IPv4>' \
  --peer '<approved role-qualified CN KNI>' --peer '<approved role-qualified PN KNI>'
```

The addresses above are documentation placeholders. A peer uses the explicit
`kni://<128-hex-public-key>@<IPv4>:<port>?discport=0&ntype=cn|pn` form. Numeric private
routes are allowed for an approved core-cell network. Deployment requires both
CN and PN links, rejects repeated identities/routes and refuses self-peering.
Initialization may omit peers until the new public URI has been enrolled; use
`plan` to obtain the URI and `update-config --peer ...` after receiving the approved
links. The operator supplies the real peers; ERPC does not invent a topology or interpret
a peer response as admission approval. [S10], [S19]

Initialization reserves the immutable host, network, kind and advertisement,
and durably records an unused original numeric UID/GID before creating the
non-login account. Direct and enumerated NSS identities, primary group users
and supplementary groups are checked on provisioning retries and startup;
unknown or changed accounts are not adopted or repaired. It then creates a fresh dedicated secp256k1 node identity on that host. The BLS key
uses the pinned client's derivation from that node identity. The capsule is
host-encrypted and tied to owner, network, kind and machine identity. Rust
independently derives the address, public peer key, BLS public key and proof of
possession before reserving those public identities in inventory. A CONCEALED
1Password backup must be read back byte-for-byte before deployment is allowed.
Interrupted publication reuses its original staged material; an established
missing or changed original never causes key regeneration. [S11], [S12]

`plan` reports the original public registration material and external authority
fields. It is a preparation record, not evidence that the running CN has joined
the network. Use `status` after deploying to verify the original identity against
the owned native process before using the official onboarding portal. [S4]

## Deploy and operate

```sh
erpc validator --chain kaia --network kairos deploy --name core-cn --ssh-key ./operator.pub
erpc validator --chain kaia --network kairos status --name core-cn --ssh-key ./operator.pub --json
```

Deployment first requires the confirmed original backup. It fences and drains
owned writers, authenticates the qualified image and preserves the original
bootstrap/retention contract. It applies the management firewall separately,
confirms the exact candidate over a fresh SSH connection, then starts through
ownership, image, capacity, clock and custody checks. Existing chrony/ntpd or
systemd-timesyncd is selected; the distribution timesyncd package is a fallback.
Startup requires the host's NTP synchronization report to be affirmative.

Root-owned public static-peer files are mounted read-only at both native legacy
and instance lookup locations. An empty trusted-peer list is mounted at both
locations as well. This prevents a retained legacy file from overriding the
reviewed topology. The original keys are materialized only into the managed
volatile runtime directory, mounted read-only into the container. The container
uses the dedicated UID/GID, no extra groups, no capabilities and no core dumps.
The encrypted original remains outside the container. The unit runs its
authenticated controller as root and uses no PID1 credential grant to a named
service user; root performs account checks before staging the native read-only
key files with mode `0400` and the original numeric reader UID. Other group
members do not gain read access. This does not prevent an administrator from reassigning numeric IDs
after authentication. [S13]

| Verb | Effect |
|---|---|
| `init` | Reserve the original host/kind and create and verify its concealed custody backup |
| `deploy` | Authenticate and deploy the selected native profile after backup and firewall confirmation |
| `list` | Read this role's public network inventory |
| `status` | Report node synchronization, original identity and native registration/qualification observations |
| `logs` | Read bounded or followed owned-service journal records; JSON is compact stdout lines |
| `start` | Start an installed unfenced owner after all startup checks |
| `stop` | Cancel pending activation and gracefully drain the exact owned container; retain data and custody |
| `restart` | Fence and drain before guarded startup |
| `update` | Select an explicitly reviewed image/version; refuse database downgrade |
| `update-config` | Reapply management ranges and approved peer/public registration fields through a new confirmed deployment |
| `plan` | Show the public deployment and external registration preparation record |
| `destroy` | Retire and disable the owner while preserving original data, custody and filtering |

`update-config` accepts repeated `--peer`, `--reward-address`, `--manager-address`,
`--staking-address` and `--gc-id` fields for the external configuration. A PN
cannot carry CN financial registration fields. A GC ID is an unsigned 256-bit
canonical decimal string, matching the native staking contract. Supplying it alone does not prove
registration: status compares the configured value with the registered staking
contract’s read-only `gcId()` and `nodeId()` getters at the observed block. [S14]

Status keeps node readiness separate from registration. For a CN, the command's
`ready` result additionally requires fresh owned-node observations of council
membership, native qualified membership, the expected reward/staking mapping and
the original BLS registration and matching registered GC ID. Qualified membership comes from the native
`istanbul_getValidators` result; the CLI does not substitute an estimated stake
threshold for the protocol's rules. Only fixed read-only IPC methods are used,
with Linux peer credentials tied to the original container PID and UID/GID.
The governance-capable Istanbul and admin namespaces are not exposed over HTTP.
Public chain observations use one bounded block number and verify the same
canonical hash and process generation afterward. [S15], [S16], [S17]

## Recovery and retained history

`deploy --restore-custody` restores only the verified original backup on its
original host, including a stopped incomplete or retired installation. The
custody-restoration step preserves the installation/retirement state and does not
start a service itself. The same command then continues the explicitly requested
deployment: host/configuration qualification, a new deployment authorization,
preparation, fresh firewall confirmation and normal CN/PN startup. Thus a retired
installation can resume through this explicit deploy; this is not a restore-only
command. A restoration failure prevents those later deployment steps.

The capsule must match the retained owner/network/kind, machine binding and
original plaintext receipt before shutdown. Restoration cancels activation,
drains the owner and republishes encrypted custody without changing its keys.
Every creation/recovery retry re-establishes the original receipt and ciphertext
durability before publication or export. Native data is retained. It cannot restore a lost ownership
record, adopt a used key on another host or reset a database to an earlier
snapshot. Unknown or conflicting files require operator inspection.

The pinned public operator documentation does not describe a portable,
interchangeable slashing-history journal for this backend. ERPC therefore does
not provide used-key migration or database rollback, and it does not claim global
protection against operator-created copies outside its managed lifecycle. Keep
the original native data and encrypted custody together. [S4], [S18]

Stop and retirement remain available when clock synchronization, capacity or
activation eligibility fails. A cancellation-storage or service-control error
still attempts the freshly verified owned container shutdown and disables the
unit; the operation reports failure rather than claiming durable success.
Persistent storage failure cannot guarantee reboot prevention.

Offline tests cover original custody publication/recovery, independent BLS
vectors, immutable inventory, private store read-back, actual controller failure
paths, peer/registration observations, isolated startup and copied helper
verification. Real host, Docker/systemd, synchronization, admission, funding,
consensus and recovery acceptance remain deferred to the separately authorized
batch acceptance run.

## Official sources

[S1]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/cmd/kcn/main.go "Pinned kcn role"
[S2]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/cmd/kpn/main.go "Pinned kpn role"
[S3]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/cmd/utils/nodeflags.go "Registered native app flags"
[S4]: https://docs.kaia.io/nodes/core-cell/become-a-validator/onboarding/ "Current approval, funding and onboarding procedure"
[S5]: https://docs.kaia.io/nodes/core-cell/become-a-validator/prerequisites/ "External manager and Safe authority"
[S6]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/cmd/utils/nodecmd/defaultcmd.go "Automatic native engine startup"
[S7]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/kaiax/gasless/impl/init.go "CN gasless feature initialization"
[S8]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/kaiax/auction/config.go "Auction disable option"
[S9]: https://docs.kaia.io/nodes/core-cell/system-requirements/ "CN/PN resource recommendation"
[S10]: https://docs.kaia.io/nodes/core-cell/install/before-you-install/ "Core-cell topology and node identities"
[S11]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/node/config.go "Original node/BLS identities and path resolution"
[S12]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/crypto/bls/blst/secret_key.go "Pinned BLS KeyGen derivation"
[S13]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/node/config.go "Legacy and instance peer-file lookup"
[S14]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/contracts/contracts/system_contracts/consensus/CnV3/CnStakingV3Storage.sol "Native GC ID type"
[S15]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/consensus/istanbul/backend/api.go "Native qualified and demoted validator API"
[S16]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/kaiax/randao/impl/api.go "BLS registry response"
[S17]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/node/api_admin.go "Native public node and BLS identity"
[S18]: https://docs.kaia.io/nodes/core-cell/h-a-setup/ "Published high-availability guidance inspected for history interchange"

[S19]: https://github.com/kaiachain/kaia/blob/ac7c81f3a9759704b5ce77b42ae91851ce45a9c3/networks/p2p/discover/node.go "KNI peer parsing and native connection-type query"
