<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Arc validator preparation

ERPC provides a dedicated preparation host, its twelve lifecycle commands,
original local peer-key custody, official Remote signer's read-only `PublicKey`
qualification, and unsigned governance-call preparation and validation.
**Production consensus signing is held.** `activate` refuses before accessing
1Password or a host. Institutional approval, a successful TLS/public-key check,
and on-chain membership do not remove this hold. This is not a completed active
validator backend.

The qualified preparation pin is **arc-node v0.8.1**, commit
`ab09dbfd9553a7ad48f9c134ec5e808c36512c74`. A fresh check on **2026-11-04** found
v0.8.2 at `0f0be9fad975a2fe16546323b060d7b070617936`, published November 2.
It is newer, but is not automatically admitted to this executable profile.
Its official breaking-change ledger says there is no hardfork or database
migration and v0.8.0/v0.8.1 can continue on the same networks. Qualification of
that newer release is separate from this preparation change.
[Qualified release](https://github.com/circlefin/arc-node/releases/tag/v0.8.1),
[newer release](https://github.com/circlefin/arc-node/releases/tag/v0.8.2),
[pinned compatibility statement](https://github.com/circlefin/arc-node/blob/0f0be9fad975a2fe16546323b060d7b070617936/BREAKING_CHANGES.md).

## Signing boundary

The qualified source describes `Local` as suitable for testing/non-production
and `Remote` as suitable for production. The official Remote service currently
has source release **1.7.8**, commit
`a95f05b2d8e90af0bc9e890efd9ee7bc8b51b5b0`. Its production arrangement uses Nitro
Enclaves, KMS and Secrets Manager, with a tested image distributed through the
partner channel. ERPC does not provision AWS resources, configure billing, generate an external
consensus key, or export an existing seed to that service. The operator prepares
and funds the external service independently.
[Native signing providers](https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/crates/signer/src/lib.rs),
[official signer](https://github.com/circlefin/arc-remote-signer/tree/a95f05b2d8e90af0bc9e890efd9ee7bc8b51b5b0).

A production history contract still needs qualification. In particular,
`make_proposal_parts` hashes height, round and execution payload and passes only
the resulting **32 opaque bytes** to `sign_bytes`. A gateway cannot reconstruct
those signing coordinates from that hash. The public Remote protocol accepts
bytes, and the reviewed implementation does not establish a durable
height/round anti-equivocation contract. A native WAL flush or a saved hash of
opaque requests is not a substitute. The preparation implementation contains no
home-grown signing journal and cannot enable either Local or Remote signing.
[Proposal signing](https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/crates/malachite-app/src/proposal_parts.rs),
[Remote protocol](https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/crates/remote-signer/proto/arc/signer/v1/signer.proto).

## Host and public inputs

Use a dedicated Ubuntu 24.04 host, systemd 255, x86-64 or ARM64, and at least
64 GB RAM. Pre-mount the intended writable ext4/XFS volume at
`/var/lib/erpc-arc-validator`; ERPC does not partition or format it. A protected
empty root, including an empty root-owned `lost+found`, is accepted. The original
filesystem UUID/type and directory inodes are retained; a changed kernel device
number alone is not a new volume. Nested mounts are refused. ERPC's conservative
initial space policy is 1 TB free, reduced by original allocated data, with a
100 GB operating reserve. This is an ERPC policy rather than a guarantee about
upstream snapshot sizes. See the [native operator guide](https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/docs/running-an-arc-node.md).

Provide the approved external EVM controller and fee recipient, the external
signer's canonical base64 Ed25519 **public** key, and public qualification JSON:

```json
{
  "endpoint": "https://127.0.0.1:10340/",
  "server_ca_sha256": "<64 lowercase hex characters>",
  "image_sha256": "<64 lowercase hex characters>",
  "pcr0": "<96 lowercase hex characters>",
  "pcr1": "<96 lowercase hex characters>",
  "pcr2": "<96 lowercase hex characters>",
  "pcr4": "<96 lowercase hex characters>"
}
```

Replace the endpoint with the externally prepared service's fixed HTTPS IP and
supply its exact public CA PEM. That IP must be covered by the certificate.
The original endpoint, CA digest, consensus public key, image digest and PCR
inputs are immutable. They record operator-provided evidence; ERPC does not
claim live enclave attestation. The native client supports a server CA here,
not a client-certificate identity. If the provider requires mutual TLS or another
client-authorization contract, it must be qualified separately.
[Native TLS configuration](https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/crates/remote-signer/src/client.rs).

ERPC reserves a distinct local peer identity in 1Password after checking the
host's original namespace. The public host reservation precedes private item
creation. An ambiguous create/bind result is recovered only from that original
reservation; it never authorizes key regeneration. Public listings use selected
fields and do not request private key references or concealed values.

EL and CL receive separate original numeric accounts and private data layers.
Only the CL receives the host-encrypted local peer credential, after the external
condition verifies its original account. The EL owns Engine IPC; the CL has
socket access through a dedicated group but cannot replace the containing
socket namespace. Read-only admission requests authenticate the original EL
process and Unix peer before sending bytes. No external EVM/controller key or
external consensus private key is imported into this host.

## Commands

```bash
erpc v --chain arc plan

erpc v --chain arc init --network testnet --name arc-validator-one \
  --host "$HOST" --user ubuntu --ssh-key "$LOGIN_PUBLIC_KEY" \
  --fingerprint "$HOST_FINGERPRINT" --vault "$VAULT_ID" \
  --controller "$EXTERNAL_CONTROLLER" --fee-recipient "$FEE_RECIPIENT" \
  --consensus-public-key "$EXTERNAL_SIGNER_PUBLIC_KEY" \
  --remote-signer-profile signer-public.json --signer-ca signer-ca.pem --yes

erpc v --chain arc deploy --network testnet --name arc-validator-one \
  --ssh-key "$LOGIN_PUBLIC_KEY" --yes
```

Supply approved numeric `--execution-peer` enodes and `--sentry-peer` TCP/libp2p
multiaddresses when available. `--admission-approved` records institutional
approval; it does not activate signing. With no approved peers, the observer
follows official public relays. Native follow mode uses ephemeral identities;
the reserved local peer key is retained for the explicit peer configuration.
Both native layers use the minimal storage profile, matching the initial
snapshot selection. Initial snapshots run under the EL identity; only a completed,
quiesced original pair is handed to the separate CL owner. Initial bootstrap
must not be used to replace previously active signing history.

| Operation | Result |
| --- | --- |
| `init` | Reserve public ownership and local peer custody; prepare original accounts, volume and helpers. Does not start native services. |
| `deploy` | Deliver the original peer key, authorize a fresh operation, confirm ingress over fresh SSH, install and bootstrap an observer. |
| `list` | Selected public metadata for the requested network. |
| `status`, `health` | Original process/source/storage and native private REST observations; separate observer readiness and validator readiness. |
| `logs` | Original native journals; `--json` emits one compact JSON record per line plus completion. |
| `start`, `stop`, `restart` | Operate only the original observer. Stop durably cancels queued work and attempts original shutdown even if persistence fails. |
| `update` | Select a source-qualified release, retain original data, and refuse any source below the highest opened floor. |
| `update-config` | Apply explicit peer/fee/ingress changes through a fresh deployment intent and firewall confirmation. |
| `plan` | Public preparation scope and the unresolved production signing prerequisite. |
| `destroy` | Retire original services and cancel queued work; retain data, ciphertext, receipts and filtering. |

Start/deploy reports a startup request separately from readiness. It never
reports an active validator. SSH uses the server-observed connection port;
private REST/Engine/RPC interfaces are not opened publicly. Peer ingress admits
only approved peer IPs, while metric ingress requires explicit monitoring
networks. Failed or timed-out firewall preparation cannot authorize a later
installation. Missing installed helpers can be handled by sealed carried
stop/retirement; unsafe or foreign authority still refuses rather than being
adopted. When persistent storage will not accept cancellation, ERPC attempts
shutdown and reports failure rather than promising durable reboot protection.

### Loaded policy and cancellation recovery

Before explicit enable/start and in the first native ExecCondition, ERPC checks
PID1's selected typed D-Bus properties against the retained generated unit:
numeric User/Group, supplementary groups, complete Exec command lists and flags,
credential names/sources, environment/root-namespace settings, fragment and exact
firewall drop-in paths. Unknown loaded commands, credentials or runtime overrides
are refused. A disk file alone is not proof of PID1's effective policy. The first
condition runs before systemd v255 credential setup; a later ExecStartPre check
would be too late. [systemd v255 execution ordering](https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/core/service.c),
[typed command and credential properties](https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/core/dbus-execute.c).

ERPC never invokes an unknown loaded stop hook. It still attempts graceful
signaling of only independently revalidated original image/UID/argv/cgroup/PID
identities, and reports incomplete shutdown when loaded policy cannot be proved.
Restore the original approved unit/drop-in policy and reload PID1 before retrying;
ERPC does not adopt or erase foreign overrides. Privileged administrator changes
after authorization are outside this boundary.

Lifecycle cancellation uses append-only private events, separate from consensus
signing history. Empty or partial events and restrictive atomic-writer pending
files invalidate older grants. A new explicit deployment durably archives pending
bytes before replacing them, binds its grant to the complete retained history,
and clears recovery/retirement only after original quiescence and publication.
Failed new authorization cannot revive an older continuation. A retired or
recovery-only reason retained solely in committed/pending HALT is preserved
before ordinary stop retries; stop cannot downgrade it to a restartable pause.
If its archival fails, the prior bytes remain untouched while owned shutdown is
still attempted. Keep the `events/`
directory with the other original authority receipts. `lifecycle_recovery_required`
in status identifies pending evidence requiring fresh deployment. An ordinary
completed stop can be followed by explicit start, which creates a fresh runtime
grant; old deployment continuations remain revoked. Older preparation receipts
without this history require a fresh explicit deploy before restart.

## Public signer and governance qualification

```bash
erpc v --chain arc remote-public-key --network testnet --name arc-validator-one \
  --ssh-key "$LOGIN_PUBLIC_KEY" --json

erpc v --chain arc prepare-registration --network testnet --name arc-validator-one \
  --step register --from "$EXTERNAL_REGISTERER" --json > registration.json

erpc v --chain arc validate-registration --network testnet --name arc-validator-one \
  --step register --from "$EXTERNAL_REGISTERER" --registration-file registration.json \
  --ssh-key "$LOGIN_PUBLIC_KEY" --json
```

The signer query invokes only the official empty `PublicKey` request over
server-CA TLS and compares the result with the original public identity. It never
invokes `Sign`. Governance steps are `register`, `configure-controller`
(`--registration-id`, `--voting-power-limit`), `activate`, `voting-power`
(`--voting-power`), and `remove`. These prepare exact official calldata with zero
native value; the governance `activate` step is separate from the unavailable
native `erpc v ... activate` command.

Validation recomputes the original intent, qualifies chain/genesis/fresh head
through original EL IPC, checks a requested registration ID's key where needed,
and performs read-only `eth_call` at that same block. It reports simulation,
not submission, wallet ownership, funding, deployed governance implementation,
actual registration or native signing permission. Keep all signing and submission in the external authorized
controller/registerer/owner workflow. Registry membership and positive power are
observations, not an ERPC activation authorization.
[Official manager](https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/contracts/src/validator-manager/PermissionedValidatorManager.sol),
[controller roles](https://github.com/circlefin/arc-node/blob/ab09dbfd9553a7ad48f9c134ec5e808c36512c74/contracts/src/validator-manager/roles/Controller.sol).

## Recovery and acceptance

`restore-peer-key` first stops the original scope, then rewraps the same original
1Password peer key. Original ciphertext is retained. Missing/current-host
undecryptable original ciphertext can be recovered, but substituted unrecognized
files are refused and preserved for investigation. The command does not restart.
It cannot restore, rotate or migrate an external consensus key.

`status` reports the public `bootstrap_intent` even when the native runtime is
unavailable. `reset-bootstrap --original-intent <128-bit hex>` uses that receipt,
first stops, then quarantines
only the named incomplete initial bootstrap. A completed or partially promoted
original pair is retained and resumed; an already started observer or used signer
cannot be reset. Repeat deploy uses a fresh intent. Neither destroy nor these
recovery commands delete the original databases or promote an observer into a
signer. Missing established NSS identities are not inferred from current names
or recreated automatically; retain the original receipt and resolve the original
numeric identity before retrying.

Offline verification covers public inventory/key transcripts, generated entry
commands, compiled bundle/play/controller paths, cancellation, staged promotion,
volume/namespace drift and public-fixture TLS. Real Linux/PID1/NSS, native archive
execution and synchronization, server-provided admission, operational credentials,
and external signer availability remain acceptance tests. Production signing
additionally requires the separately verified Circle history/recovery contract
and explicit qualified implementation; it remains held.
