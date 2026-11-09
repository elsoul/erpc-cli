<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Native Solana RPC and validator nodes

New `erpc rpc --chain solana` and `erpc v --chain solana` hosts use isolated
native Agave accounts. Existing Solv hosts keep their recorded backend. Selecting
`--backend native` does not migrate a Solv host; conflicting ownership is refused.
`--backend solv` resumes an existing host and cannot create a new Solv deployment.

The RPC profile is non-voting. A validator starts with a separate
**synchronization identity with voting disabled**. Registered validator identity,
vote account and withdrawal authority are reserved separately. Explicit
`deploy --activate-validator` switches a healthy synchronization host to its
original registered identity after public registration and native BLS checks.
Use the [registration commands](solana-registration.md) for public inspection
and externally signed registration preparation; registration alone does not
activate this host.

## Qualified clients and host policy

| Network | Agave release | Source commit | Build compiler |
|---|---|---|---|
| Mainnet | 4.4.0 | `9ef63128134af559561f6a91a641ec01e665c70d` | Rust 1.98.1 |
| Testnet | 4.4.0 | `9ef63128134af559561f6a91a641ec01e665c70d` | Rust 1.98.1 |

The November 4 qualification uses the [general-adoption 4.4.0 release](https://github.com/anza-xyz/agave/releases/tag/v4.4.0)
for both networks. Its fixed Cargo.lock additionally pins the upstream BLS
implementation; compiler components remain independently hash- and size-checked.
The existing generated arguments retain voting-history restoration, bounded
ports and disabled XDP. Removed experimental XDP flags and external schedulers
are not enabled. Source/compiler verification is not a native build or live
upgrade acceptance result.

Use explicit `update` for this source change; `update-config` cannot silently
replace the installed executable. A build pending under the previous catalog
must finish with its original CLI/configuration or be explicitly abandoned
before a new build. An interrupted runtime cutover requires its original
`--recover-cutover` intent. These paths retain original data and identity; a new
catalog does not rewrite an old source receipt or establish migration compatibility
for a custom Solv configuration.

ERPC builds `agave-validator` from the fixed source and lockfile rather than
assuming the CLI archive contains the validator. Compiler components, source
commit, lockfile and build environment are qualified by the carried catalog.
Fetching and compilation run under a dedicated unprivileged builder. A completed
build is a candidate, not permission to start a node. [Agave source][main-source];
[Testnet source][test-source]; [operator requirements][requirements].

The host profile requires Ubuntu 24.04, systemd 255, x86-64 with AVX2 and SHA CPU
features, synchronized time and separate management, builder, runtime and proof
identities. The RPC ingress has its own account without identity credentials.
ERPC requires at least 32 logical threads / 480 GiB usable memory for RPC,
24 threads / 300 GiB for a mainnet validator, or 24 threads / 120 GiB for a
testnet validator. These are ERPC capacity policies,
including build capacity; usable memory is not the installed DIMM label.

Provision and mount three distinct ext4 or XFS filesystems before initialization:

| Mountpoint | Minimum formatted capacity |
|---|---|
| `/mnt/erpc-solana-accounts` | 900 GB |
| `/mnt/erpc-solana-ledger` | 900 GB |
| `/mnt/erpc-solana-snapshots` | 450 GB |

Initialization binds their UUIDs and original numeric ownership. ERPC does not
format, mount or erase disks. Nested mounts, bind aliases and foreign contents
are refused. Interrupted initialization accepts only its original receipts and
data. Remaining synchronization capacity accounts for already allocated original
data; a small partial directory does not waive the initial free-space check.
Native snapshot discovery uses the qualified network's known RPC identities and
expected genesis. [Bootstrap and network guidance][setup].

## Initialize an RPC host

Prepare a dedicated Solana JSON keypair in a uniquely labelled concealed
1Password field. Pass its **identifier-only reference** and matching public key.
The private JSON travels through protected SSH stdin during deployment, not CLI
arguments or retained Ansible bundles. The management SSH account must differ
from node, builder, proof and gateway accounts.
Use an absolute path to the management public key. ERPC selects the configured
1Password/SSH agent; pass `--ssh-agent <absolute socket path>` to choose it explicitly.
A native node's `--name` starts with a lowercase letter and has at most 32
lowercase letters, digits and `-`; the host holds it to the same rule.

```sh
erpc rpc --chain solana --network testnet init \
  --name rpc-test --host 192.0.2.20 --user ubuntu \
  --fingerprint '<independently verified SSH fingerprint>' \
  --ssh-key "$HOME/.ssh/management.pub" --vault '<network inventory vault>' \
  --identity-reference 'op://<vault-id>/<item-id>/keypair' \
  --identity-public '<dedicated node public key>' \
  --accounts-uuid '<mounted accounts UUID>' \
  --ledger-uuid '<mounted ledger UUID>' \
  --snapshots-uuid '<mounted snapshots UUID>' \
  --rpc-allow 198.51.100.20/32

erpc rpc --chain solana --network testnet deploy \
  --name rpc-test --ssh-key "$HOME/.ssh/management.pub"
```

Initialization reserves ownership, installs prerequisites and prepares accounts;
it does not start Agave. It may start the distribution clock service. Deployment
resumes or builds the qualified source, confirms filtering over a **fresh SSH
connection**, stops the original runtime for cutover, imports only its original
identity, publishes units and verifies actual process/network readiness.

For a synchronization host, use `v init` with the same host/volume options,
without `--rpc-allow` (a validator takes no RPC allow list), plus
`--sync-reference`, `--sync-public`, `--vote-public`, `--withdraw-public` and
`--commission` (0 to 100). The sync key and its reference must differ from the
reserved signing identity's. When `init` stores the validator's registration,
the identity reference must name the field `keypair`, as in the example above.
Its registered signing key is not loaded by synchronization deployment. Financial
vote/withdrawal keys are not imported. Retrying a partial public reservation uses
its exact original accounts; it does not generate replacement keys. A
registration that is stored already, such as one an interrupted `init` left
without its host, is taken over as it is by the same `init` when the identity,
vote and withdrawal public keys match it; the `keypair` field rule does not
apply to that `init`. Until then, `list` shows the registration as
`[no host yet]` (`"backend": null` and no hosts with `--json`), and the other
verbs for its name say that the same `init` resumes it.

## Explicit validator activation

Complete external vote-account/BLS registration and fund the dedicated identity
using the official external tools. The identity, vote account, separate external
withdrawer and commission must match the original initialization. Supply the
registered BLS public key and confirm that this dedicated identity is not running
or being activated on another host. That confirmation is an operator assertion;
ERPC cannot discover an out-of-band copy of a key.

```sh
erpc --json v --chain solana --network testnet plan \
  --name validator-test --ssh-key "$HOME/.ssh/management.pub" \
  --activate-validator --bls-public '<registered BLS public key>' --exclusive-identity

erpc v --chain solana --network testnet deploy \
  --name validator-test --ssh-key "$HOME/.ssh/management.pub" \
  --activate-validator --bls-public '<registered BLS public key>' --exclusive-identity
```

Activation reuses the qualified installed build. It verifies a fresh finalized
vote account, current and scheduled future voting authorities, withdrawal
authority, BLS key, commission, current rent quote and positive identity balance
before stopping synchronization. A positive balance is not a voting-fee budget
guarantee. After confirmed ingress and a stopped cutover, the original identity
is imported from its original concealed reference. A separate numeric proof
account receives an encrypted credential and runs the qualified
`solana-keygen bls_pubkey` without network access. Only its bounded public output
is captured. A mismatch with the registered BLS key prevents voting-unit
installation. Original public registration, proof and key-material digest are
durably bound before startup; an interrupted attempt cannot substitute them.
Each exact proof service definition retains its original shutdown receipt.
Updating a proof service first preserves both old and candidate ownership;
an interrupted file replacement can still stop either original definition.
Startup accepts only the current activation's exact receipt and definition.

The voting runtime uses `--require-tower` and
`--process-ledger-before-services`. Both qualified clients restore their native
Tower and signed vote history before starting services. Native first-account
exceptions still apply; ERPC does not parse, reset or bypass signing history.
See the fixed [Mainnet startup source][history-main] and
[Testnet startup source][history-test].

Once activated, ordinary deployment, updates and restarts retain voting mode
and the same registered identity. They repeat current registration checks and
preserve native history. Ciphertext restoration may prepare while custody is
unavailable, but installation and startup require the same original private
material. Restored ciphertext need not be byte-identical to its earlier
encryption. Vote-account and withdrawal private keys are never imported.

Validator `status` distinguishes local `rpc_ready` from `validator_ready`.
An observing host remains `validator_ready: false` and returns a non-success
validator-status exit. Active readiness additionally requires the original
account in the public `current` set, positive active stake, current epoch
membership and a vote within 128 finalized slots. The 128-slot threshold is an
ERPC readiness policy, not a reward guarantee. Missing or stale participation
does not become readiness merely because the service is running.
[Public vote-account API][vote-status].

## RPC ingress and ongoing operations

Agave binds RPC/WebSocket to loopback 8899/8900. A dedicated keyless nginx service
exposes HTTP 7211 and WebSocket 7212 only to explicit client networks, with access
rules in both nginx and nftables. With no client rules, application ingress is
denied. Node peer traffic uses TCP/UDP 8000–8032; SSH is restricted to the
observed caller and additional management rules. TLS termination belongs at the operator's trusted external gateway;
these host ports are plaintext and should be limited to that gateway or trusted
clients. [Anza RPC guidance][rpc]; [nginx WebSocket proxying][websocket].

The distribution `nginx.service` is persistently masked before nginx installation
and checked again after package hooks and before managed gateway startup. An
already active default service or custom unit override is refused for its owner
to resolve. The independent ERPC gateway is the only nginx service this profile
starts. All five HTTP temporary paths, including unused FastCGI/uwsgi/scgi module
paths, stay inside its private writable runtime directory.

The gateway uses the distribution nginx package and records its installed package
version and executable digest. Process-title and worker behavior were checked
against nginx 1.24.0 source at `84cd7217778b8b3a2e395194b641ea14050344f1`;
this does not claim Ubuntu's patched binary is byte-identical to upstream.
Readiness requires original process generations, numeric identities, cgroups,
executable inodes, expected listeners and network/identity/freshness responses
through the gateway. Its WebSocket handshake uses a fresh nonce and masked,
bounded close exchange. [nginx processes][nginx-source]; [WebSocket protocol][ws-rfc].

| Command | Native behavior |
|---|---|
| `list` | Public native and legacy inventory, optionally filtered by `--backend`; no password/key/reference retrieval |
| `status` | RPC ingress or active validator participation observation; failed role readiness gives a failure exit |
| `logs --component node\|gateway\|firewall\|build` | Bounded owned journal; build can select an original `--build-intent` |
| `start` / `restart` | Start only an approved runtime after current authority, custody and host checks |
| `stop` | Revoke startup and attempt all owned runtime/build/ingress stops, retaining data |
| `update` | Build the current qualified catalog target while preserving original identity and volumes |
| `update-config` | Reuse the verified installed binary, confirm new access policy and restart |
| `plan --change deploy\|update\|update-config` | Read approved/pending/desired target and access differences without mutation |
| `destroy` | Retire and stop; retain original data, encrypted custody, receipts and filtering |

For example, preview and then remove every client allow rule:

```sh
erpc --json rpc --chain solana --network testnet plan \
  --name rpc-test --ssh-key "$HOME/.ssh/management.pub" \
  --change update-config --clear-rpc-allow

erpc rpc --chain solana --network testnet update-config \
  --name rpc-test --ssh-key "$HOME/.ssh/management.pub" --clear-rpc-allow
```

`--rpc-allow` and `--management-allow` replace their stored lists. Their corresponding
`--clear-rpc-allow` and `--clear-management-allow` remove the additional rules;
the observed SSH caller is still included in that deployment's management filter.
Plans are advisory snapshots; execution independently revalidates current state.
A configuration-only update refuses a changed client qualification and requires
an explicit client update first. Inventory listings do not query live hosts, so
a native node's deployed version and last runtime result are `null` in `--json`
output and `-` in the table; inspect `status` and `plan` instead of treating the
current CLI catalog as a deployment receipt.

Before an approved runtime may open native data, ERPC durably records its Agave
version, source commit, lockfile and compiler qualification against the original
numeric account, filesystem UUIDs and data-directory inodes. A build or plan does
not advance this record. Startup, deployment and updates refuse an older version
or different source/compiler qualification at the same version. Version ordering
compares major, minor and patch numbers, then prerelease identifiers; a final
release follows its prereleases. This is an ERPC opening restriction, not a claim
that every forward Agave upgrade is database-compatible.

An interrupted record write remains restrictive, including when directory sync
fails. Repair storage and retry with the same or a later qualified target.
Stop, retirement and cutover recovery retain the original opening records. Do not
delete them or reconstruct missing history from the current CLI catalog.

### Upgrade an existing native host's source authority

An existing native host created before opening records were introduced requires
an explicit stopped upgrade. Supply a local public JSON record of the **highest
Agave version that has opened its original data**, with that version's exact
source commit. Derive it from independently retained deployment history; the
currently installed executable alone cannot establish the highest prior version.
ERPC checks the record against the recorded active client but cannot discover
unrecorded historical executions. The file must contain exactly these fields:

```json
{
  "schema": 1,
  "client": "agave",
  "network": "mainnet",
  "version": "4.3.2",
  "commit": "a203300045b405f86c9c84308b2eae76af69ac3b"
}
```

The values above are an example, not evidence for a particular host. Use its
actual history and matching network. Then run:

```sh
erpc rpc --chain solana --network mainnet init \
  --name rpc-main --ssh-key "$HOME/.ssh/management.pub" \
  --upgrade-source-authority --original-client-record ./original-client.json
```

Use `v` for an existing native validator. This operation validates original
accounts, mounted data and managed units, fences and stops owned processes,
preserves custody and native data, and installs the protected opening protocol.
It does not start a node. An interruption must resume with the same exact public
record; ordinary opening stays blocked until completion. After success, run a
separate `deploy` with the qualified client. Older helpers cannot operate the
converted account receipt. This option applies only to previously managed native
hosts; it does not adopt or migrate Solv installations.

## Original Solv configuration qualification

The copy-migration stages record an approved public configuration digest before
retiring the original service. Reservation and retirement recheck that digest;
a changed retention policy or stake override requires a new reviewed plan. The
migration retains original data, copies it to three separately provisioned
filesystems, verifies original custody and promotes the same inventory item.
Completion acknowledges native ownership; it does not start a process or activate
voting. Follow it with an explicit native deployment and health observation.

Qualified data settings retain their original meaning: WAL recovery mode,
snapshot startup policy, expected shred version, initial accounts cleaning, and
ledger retention. In both fixed Agave sources, `--limit-ledger-size` counts data
shreds while `--limit-blockstore-size` counts data and coding shreds. Migration
preserves the original flag and value, including the absence of either limit.
It does not convert their numeric values. See the [mainnet parser][retention-main]
and [testnet parser][retention-test].

The managed mainnet validator's `overrides.yml` is accepted only as a bounded
`staked_map_id` mapping of distinct public keys to unsigned 64-bit integers.
Unknown fields, YAML tags, aliases, comments and custom paths are refused. The
original path and byte hash remain in the receipt; a canonical public mapping
is copied to a root-owned native configuration file and verified before startup.
This preserves the upstream [stake override semantics][stake-overrides],
including the presence of the option enabling block-production forwarding.
Original source files are retained.

The immutable plan describes the new isolated accounts, encrypted credentials,
copy destinations, private RPC gateway and fixed native port/bootstrap profile.
For the managed non-voting RPC template, it explicitly removes
`--no-wait-for-vote-to-start-leader`: the fixed client [documents that option as
a double-signing risk][leader-safety]. The native rooted-vote leader safeguard
remains enabled. A voting or synchronization configuration using that bypass is
not qualified. Filename or role alone is not evidence that a key lacks funds or
other authority. Unknown custom features remain under the existing Solv manager.

### Execute and resume an original copy migration

Use `migration inspect` first. Only the qualified managed Agave configurations
are accepted; custom Jito, Firedancer, Geyser and other unsupported features stay
under their existing manager. Retain independent original passwd, group,
machine-ID, highest-used client history and build records. The live executable's
hash or version alone cannot prove its origin. The original build record has
`schema`, `client`, `network`, `source`, `executable_sha256` and
`executable_bytes`; `source` contains the exact version, commit, Cargo.lock hash,
Rust version and Rust manifest hash. Supply separate records for client `agave`
and client `solana-keygen`, built from the same independently qualified source.
Do not substitute a current target release for the original source. Original
source, compiler and Git dependencies are retained in a separate migration
catalog when deployment targets change.

```sh
erpc rpc --chain solana --network mainnet migration execute \
  --name rpc-main --management-user operator --ssh-key "$HOME/.ssh/management.pub" \
  --original-passwd ./original-passwd --original-group ./original-group \
  --original-machine-id ./original-machine-id \
  --original-client-record ./original-client.json \
  --original-build-record ./original-agave-build.json \
  --original-keygen-record ./original-keygen-build.json \
  --target-accounts-uuid <original-approved-target-uuid> \
  --target-ledger-uuid <original-approved-target-uuid> \
  --target-snapshots-uuid <original-approved-target-uuid>
```

Use `v` for the qualified original validator. The three target UUIDs must be
distinct and must differ from every original source volume. The management login
must be separate from the original `solv` runtime account. The command previews
the normalized original settings and explicit configuration changes before
confirmation. Its stored digest is rechecked before retirement. Unqualified
platforms, original artifacts, accounts, mounts, effective commands or original
key authority refuse before reservation and retirement.

The fixed public RPC must support a complete, bounded, finalized Vote-program
account observation. A disabled or oversized response refuses; an incomplete
`getVoteAccounts` result is never substituted. The host validates the original
key's seed/public consistency and excludes the public identity from known
registered inventory keys and the reported vote-account, node, voter and
withdrawer fields. The same-source native keygen's BLS public output is also
excluded from reported BLS voter keys. These observations are repeated before
private export. This is a current snapshot qualification, not proof of all past
or future authority, every program or network, or an absence of funds.

The independently hashed keygen image is copied into sealed memory before use.
Only its public version check and fixed `bls_pubkey /proc/self/fd/...` operation
are admitted, with a closed environment and no network namespace connectivity.
The original key is passed through a separate sealed descriptor, never arguments
or an ordinary journal. The existing kernel must support the required standard
memfd seals and normal execution; noexec or unsupported configurations are
refused without changing security policy or falling back to a temporary binary.
Both pinned [mainnet signer parser][migration-signer-main] and
[testnet signer parser][migration-signer-test] preserve this explicit file path.
The [native keygen operation][migration-keygen] reads it for public derivation;
it does not generate a replacement identity.

Original host-only RPC or non-voting synchronization custody is retained in
host-bound encryption and backed up to a dedicated CONCEALED field in the
**same reserved migration inventory item** through protected SSH output.
Readback verifies the actual stored key and canonical digest before cutover.
The original voting identity remains at its existing verified 1Password
reference; migration does not export an additional voting, vote-account or
withdrawer key from the host. All original host keys, source data and history
remain in place. Provider edits preserve unrelated notes, tags and fields.
A lost response is reconciled by exact readback, never key regeneration or a
replacement item. Local locking and readback are not provider compare-and-swap.

Before copying, original units are durably masked, original login/sudo access is
retired and all original-UID processes must be drained. A persistent condition
also refuses delayed legacy managed-run plays; other active or queued runs must
finish before retirement. Unknown root processes are not killed. Copy and
promotion retain original Tower/history bytes, source floors and actual copied
inodes. Final provider promotion retains the item's ID and original legacy
snapshots and then obtains a matching durable host acknowledgment. Original
legacy inventory records remain unchanged; only those exact saved originals
are reconciled by migration recovery, without relaxing fresh-init collision
checks.

```sh
erpc rpc --chain solana --network mainnet migration status \
  --name rpc-main --ssh-key "$HOME/.ssh/management.pub"
erpc rpc --chain solana --network mainnet migration resume \
  --name rpc-main --ssh-key "$HOME/.ssh/management.pub"
```

Status reads recorded progress even before helper publication. It always reports
`ready: null` and does not imply runtime acceptance. Resume retains the original
intent, source snapshot, key and item ID. If provider promotion or final host
acknowledgment was interrupted, it reconciles that same transition. Once the
host's completion acknowledgment exists, recovery repairs only the final marker;
it does not replay copying, old custody or old source floors over newer native
history. Repair persistent storage failures before relying on reboot durability.

## Interrupted operations and original custody

Repeat an interrupted deployment with the same name and target. A failed or
superseded source build requires `deploy --abandon-build` before selecting a new
attempt. Abandonment cancels the owned build and preserves an approved runtime
unless its cutover already began. It does not start a replacement build.

If a stop or failure interrupts runtime cutover, use
`deploy --recover-cutover <original-intent>` (also accepted by `update` and
`update-config`). The original intent is shown in `plan` or the deployment
output. This is **recovery-only**: it fences and stops owned processes, archives
the original cutover and incomplete import metadata, and preserves every
ciphertext, credential receipt, installed-unit receipt, build and native data
file. It does not start or roll back a node. Repeat the same recovery after an
interruption, then run a separate deployment with a fresh intent. Old queued
continuations remain invalid; an old recovery cannot cancel a newer operation.
Recovery cannot be combined with access changes, custody restoration or build
abandonment.

`deploy --restore-custody` (also available on `update` and `update-config`) restores
only the original encrypted identity and **continues the requested deployment**.
It is not restore-only. No private key is regenerated. Retain original ledger,
Tower and vote-history data; this profile offers no history bypass or data purge.

Stops attempt owned shutdown even if cancellation persistence fails, and report
failure rather than claiming durable reboot fencing. Repair the underlying
storage and repeat the stop before relying on reboot behavior. Unknown users,
units, process generations, filesystem ownership or substituted helper releases
are refused rather than adopted or repaired automatically.

Offline tests cover emitted entrypoints, publication/retry failures, custody,
source-build sequencing, cancellation, access policies, public inventory and
modeled process/socket/RPC behavior. A testnet validator that only syncs has also
run on a real Ubuntu 24.04 host with dedicated test keys: package installation,
source compilation, systemd credential delivery, the firewall, full network
synchronization, the operating verbs and a reboot. nginx ingress, voting and
mainnet remain deferred real-host acceptance.

[main-source]: https://github.com/anza-xyz/agave/tree/9ef63128134af559561f6a91a641ec01e665c70d
[test-source]: https://github.com/anza-xyz/agave/tree/9ef63128134af559561f6a91a641ec01e665c70d
[requirements]: https://docs.anza.xyz/operations/requirements
[setup]: https://docs.anza.xyz/operations/setup-a-validator
[rpc]: https://docs.anza.xyz/operations/setup-an-rpc-node
[websocket]: https://nginx.org/en/docs/http/websocket.html
[nginx-source]: https://github.com/nginx/nginx/blob/84cd7217778b8b3a2e395194b641ea14050344f1/src/os/unix/ngx_process_cycle.c
[ws-rfc]: https://www.rfc-editor.org/rfc/rfc6455.html
[history-main]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/core/src/validator.rs
[history-test]: https://github.com/anza-xyz/agave/blob/3ad9da2c390eb7ad2630ed15afcd463e72e007a8/core/src/validator.rs
[vote-status]: https://solana.com/docs/rpc/http/getvoteaccounts

[retention-main]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/validator/src/commands/run/args/blockstore_options.rs
[retention-test]: https://github.com/anza-xyz/agave/blob/3ad9da2c390eb7ad2630ed15afcd463e72e007a8/validator/src/commands/run/args/blockstore_options.rs
[stake-overrides]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/validator/src/commands/run/execute.rs
[leader-safety]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/validator/src/commands/run/args.rs

[migration-signer-main]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/clap-v3-utils/src/input_parsers/signer.rs
[migration-signer-test]: https://github.com/anza-xyz/agave/blob/3ad9da2c390eb7ad2630ed15afcd463e72e007a8/clap-v3-utils/src/input_parsers/signer.rs
[migration-keygen]: https://github.com/anza-xyz/agave/blob/a203300045b405f86c9c84308b2eae76af69ac3b/keygen/src/keygen.rs
