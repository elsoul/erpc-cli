<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# TRON node operations

`erpc rpc` (`r`) and `erpc validator` (`v`) implement Mainnet and Nile full-node
and delegated Super Representative lifecycle. Both expose `init`, `deploy`,
`list`, `status`, `logs`, `start`, `stop`, `restart`, `update`, `update-config`,
`plan` and `destroy`. Validator `registration --action prepare|validate|status`
keeps owner signing, permission transactions, funding and broadcast in external
official tooling. Shasta is a hosted network and is not a deployment target.

The implementation has offline fixture, source and render verification. Actual
Ubuntu/JVM installation, synchronization, encrypted-credential delivery, block
production and recovery acceptance on real hosts remain deferred.

## Host and network profile

Use a dedicated Ubuntu 24.04 host with passwordless sudo and an SSH agent.
`init` pins the SSH host key, network, role, architecture, unique persisted inventory item and public SR addresses;
it never formats disks or imports an existing unmanaged database. Reserve at
least 16 CPU cores, 32 GB RAM and 4 TB SSD for a full node; an SR uses 32 cores
and 64 GB RAM. The initial preflight requires 3.5 TB free for fresh storage. Before preparation,
activation and every manual/systemd startup, the host checks at least 3.5 TB of
free plus physically allocated chain data on the same filesystem, and at least
64 GiB still free as operating headroom. Thus a partly synchronized database can
resume without requiring 3.5 TB free again. These are ERPC deployment policies,
not additional upstream sizing guarantees. Mount data storage at `/var/lib/tron`;
nested data mounts and symlinked children are refused because their usage cannot
safely be counted against that volume's free space. Low space leaves stop and
destroy available, and never triggers deletion of chain data. This does
not replace checking physical cores, sustained SSD throughput and 100 Mbps
network capacity against the [official deployment guidance][deploy].

| Network | Reviewed release | Resolved commit | Native code version |
| --- | --- | --- | --- |
| Mainnet | GreatVoyage-v4.8.2.4 | `4e8389f159d0782f1ebcd9dab2fd88388c0e6fe9` | `4.8.2.4` |
| Nile | GreatVoyage-Nile-v4.8.2.4-PQ1-build1 | `bc7752b638d9aa4da413c78645dcff1a1aa8e40a` | `4.8.2.4.PQ1_build1` |

The [Mainnet release][main-release] and [Nile release][nile-release] are separate
pins. JAR and signature SHA-256 digests come from their release-asset metadata;
the complete immutable network configuration has its own digest. Deployment
also verifies the detached signature against the bundled network public key.
Mainnet's signing subkey is `1254F859D2B1BD9F66E7107DF859BCB44A28290B`, with
primary key `07B23298AEA4E006BD9A42DE785FB96D2C7C3CA5`; Nile uses
`BBA2FC19D5F0B54AB1EE072BCA92A5501765E1EC`. The official [Mainnet verification
instructions][signature] and [Nile installation page][nile-install] establish
these trust anchors. Expired, revoked, wrong-network or unreviewed signatures
are refused. Updating these pins and certificates requires a reviewed CLI
change; deployment does not follow a moving latest-release URL.

x86_64 uses Java 8 and LevelDB; aarch64 uses Java 17 and RocksDB. ERPC selects
Ubuntu's distribution-maintained OpenJDK JDK packages, including
[OpenJDK 8 on Noble][ubuntu-java], rather than installing a mutable third-party
Java binary. The JDK compiles a small non-signing adapter against the verified
JAR with annotation processing disabled. It invokes the client's own encrypted
keystore reader; ERPC does not reimplement wallet cryptography.

The complete upstream network config is included unchanged, followed by narrow
operational overrides. Both use TRON's normal address prefix; neither a `nile`
network type nor a Mainnet config with a few fields replaced is substituted.
Nile's upstream `needSyncCheck=false` is overridden to `true` before production.
The [Mainnet config][main-config] and [Nile config][nile-config] pin the genesis
and peer settings independently.

The default bootstraps from genesis. The official [backup catalog][backups]
includes plaintext-IP snapshot downloads without an authenticated manifest;
ERPC does not import those snapshots automatically. Mainnet replay can take
weeks to months. Do not interpret a successful `deploy` as synchronization or
production readiness.

## RPC lifecycle and access

Use `erpc r --chain tron --network nile <verb>` with `--name` for a reserved
host. `init --help` lists host, fingerprint, login-key and allowlist arguments;
`plan` requires no host connection. `--rpc-allow` explicitly authorizes trusted
clients or TLS gateways, `--management-allow` adds SSH ranges, and
`--monitoring-allow` authorizes private scrapers. The current controller's SSH
address is retained during policy changes. Unrestricted API CIDRs are refused.

- TCP/UDP 18888: public peer traffic.
- TCP 8090/8091 and 50051/50061: native Fullnode/Solidity HTTP and gRPC.
- TCP 8545/8555: partial Ethereum JSON-RPC compatibility for full nodes only.
- TCP 9527: restricted Prometheus scraping. PBFT APIs, backup peers, wallet
  extension and event publishing are disabled by this profile.

SR API listeners remain accessible only locally; the SR CLI has no RPC allowlist
flag. Native APIs have no ERPC-provided public authentication or TLS termination.
Use a controlled TLS gateway for remote query clients. The [JSON-RPC catalog][jsonrpc]
describes method limitations; this profile does not promise historical Ethereum
state, debug or trace compatibility.

Every mutator verifies immutable remote ownership, including the inventory item ID, under the common `/opt/erpc`
lock. Preparation writes a persistent startup fence and drains the old service
before changing binaries, configuration or credentials. It starts no rollback
timer during downloads or 1Password prompts. A separate short phase applies the
operation-bound firewall candidate; fresh SSH confirmation binds its exact run
and bundle digest. Activation requires that receipt and the unchanged verified
artifacts. Startup and reboot check both the confirmed live policy and the
original contract; a failed, rolled-back or superseded operation cannot start
the node.

`status` requires a fresh correct-network public tip, two advancing local heads,
a bounded head gap, the pinned native code version, gRPC success and (for RPC
nodes) the expected JSON-RPC chain ID. Temporary API outages report unavailable
readiness rather than assuming success. An incomplete or failed readiness report
returns the problems-found exit code so monitors can detect it. `stop` creates a durable stop fence;
`start` verifies the existing activation and removes only that stop fence.
`update` uses this CLI's reviewed release. Host preparation compares its exact
network-specific native version, including Nile PQ/build ordering, against both
the installed release and any interrupted target before stopping or replacing
artifacts. Older versions and changed artifacts under the same version are
refused; unknown ordering requires a separately reviewed migration. The original
intent binds tag, commit, version and JAR/config digests through preparation,
manifest publication and activation. Stop/destroy retain this monotonic floor;
an older CLI cannot silently downgrade an already prepared or activated release. `destroy` drains/disables/removes the service
while retaining its ownership, database, credentials and filtering. A removed
service can be recreated with `deploy` on the same reserved host.

## Dedicated Witness custody and external registration

Create a **new, never-hosted dedicated ECDSA Witness signer** with official
external tooling. Keep the candidate account's Owner and Active authority in
external wallets. Store the original native encrypted V3 keystore and its exact
password in two **CONCEALED** 1Password fields. Pass identifier-only
`op://<vault-id>/<item-id>/<field>` references; names, inline secrets and owner
keys are refused. The [SR best practices][sr-best] and [permission guide][permissions]
explain why a production Witness signer should be separate.

1. Run validator `init` with `--owner-address`, `--witness-address`,
   `--candidate-url`, `--keystore-ref`, `--password-ref` and `--keys-unhosted`.
   This reserves public metadata; it does not read either concealed field.
2. Run `registration --action prepare`. It emits public `wallet/createwitness`
   request data and the dedicated Witness-permission requirements. Inspect the
   current network fee and use official tooling to construct, sign and broadcast
   externally. Preserve the complete existing Owner/Active permission objects
   when configuring Witness permission; ERPC never submits their replacement.
3. Before importing the key, the candidate must be registered and delegate
   **Witness permission ID 1, threshold 1, one signer of weight 1**. The signer
   must be absent from all Owner/Active keys. `deploy` checks current genesis,
   fresh state, that exclusive permission and synchronized time. A newly
   imported signer already elected in the active set is refused: provision the
   candidate before obtaining election votes. Live migration from another host
   is not an implicit deployment operation.
4. `deploy` reads only the two selected concealed fields, validates bounded
   native keystore schema/KDF settings and uses the signed client's wallet
   reader to authenticate the password and derive the reserved signing address.
   Inputs cross SSH on stdin, never public run bundles, command arguments or
   subprocess environments. Both the native keystore and its password are
   stored as systemd-encrypted credentials. The service receives its private
   credential directory and the exact password through stdin; no plaintext
   private key is written to node configuration.
5. Run `registration --action validate` to validate original custody and current
   delegation; `registration --action status` reports candidacy/election,
   dynamic fee, maintenance interval and production counters. Request votes
   externally after synchronization. `status` distinguishes healthy node state
   from `producer_eligible`; account counters do not prove that this particular
   host produced a block.

Registration fee and election interval are read from current chain parameters;
Nile does not inherit a hardcoded Mainnet six-hour interval. The top 27 elected
SRs produce blocks, as described by the [SR guide][sr-guide]. Nile's reviewed
release includes additional post-quantum functionality; this profile supports
the source-verified native ECDSA V3 keystore and dedicated single Witness key
only, and refuses unsupported key-scheme fields.

Encrypted credentials have a public receipt bound to the host contract and
original signer. Ordinary deploy/update reuses that receipt and never rotates
or regenerates keys. `deploy --restore-keys` can restore the **same original
signer on the same stopped, fenced host**, including an interrupted credential
publication. It retains older ciphertext generations. Missing ownership or an
original identity receipt requires explicit recovery outside new-node init;
ERPC will not silently adopt orphan credentials or retained consensus history.
Keep secure external backups of both original concealed fields. Systemd's
host encryption does not protect a compromised root account; see the official
[credential semantics][systemd]. No real key, host, stake or broadcast was used
for implementation acceptance.

[deploy]: https://developers.tron.network/docs/deploy-the-fullnode-or-supernode
[main-release]: https://github.com/tronprotocol/java-tron/releases/tag/GreatVoyage-v4.8.2.4
[nile-release]: https://github.com/tron-nile-testnet/nile-testnet/releases/tag/GreatVoyage-Nile-v4.8.2.4-PQ1-build1
[signature]: https://tronprotocol.github.io/documentation-en/releases/signature_verification/
[nile-install]: https://nileex.io/run/getRunPage
[ubuntu-java]: https://packages.ubuntu.com/noble/openjdk-8-jre-headless
[main-config]: https://github.com/tronprotocol/java-tron/blob/4e8389f159d0782f1ebcd9dab2fd88388c0e6fe9/framework/src/main/resources/config.conf
[nile-config]: https://github.com/tron-nile-testnet/nile-testnet/blob/bc7752b638d9aa4da413c78645dcff1a1aa8e40a/framework/src/main/resources/config-nile.conf
[backups]: https://tronprotocol.github.io/documentation-en/using_javatron/backup_restore/
[jsonrpc]: https://tronprotocol.github.io/documentation-en/api/json-rpc/
[sr-best]: https://developers.tron.network/docs/sr-best-practices
[permissions]: https://developers.tron.network/docs/advanced-configuration-for-super-representative
[sr-guide]: https://developers.tron.network/docs/super-representatives
[systemd]: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

## Process ownership and durable recovery

A missing or inactive `tron-node.service` is not proof that a writer stopped.
Before changing client/configuration or credentials, the controller checks the
service cgroup, dedicated `tron` UID, native JAR arguments and open/argument
references to `/var/lib/tron`. It also refuses occupied managed TCP/UDP ports.
Unknown processes are never killed automatically; stop them through their
actual owner before retrying. First initialization and manual/service startup
apply the same ownership boundary.

Readiness requires the managed JVM's MainPID, process generation, UID, cgroup,
executable inode, exact launch arguments and native API socket ownership to
match before and after observations. The launcher names the immutable reviewed
JAR directory directly. The public release manifest is readable by the runtime
account; credentials remain private systemd inputs. Matching responses from an
unowned loopback server cannot make a node ready. Fixed HTTP observations reject
redirects and ambient proxies; the gRPC probe ignores curlrc configuration.
Ingress uses the observed server-side SSH port, including forwarded connections.

Ownership, intents, stop/preparation fences, activation and credential receipts
sync files and directory entries before later phases run. An interrupted initial
credential import can retry only when its durable preparation marker matches,
no generation was selected, and no prior activation or native history exists.
Unused encrypted generations are retained. Once an original receipt exists,
`--restore-keys` remains the explicit recovery path; it preserves chain data.
A stopped fence rejects delayed deployment phases even if invalidating their
intent failed. Only a new durable preparation, or an explicit start that first
invalidates the old intent, may clear it. Stop attempts both cancellation
barriers and disables/drains known units even on storage failure, retaining
ingress and reporting the error. Persistent storage failure cannot establish a
durable reboot guarantee; repair storage and retry before relying on it.
Destroy retains the existing deny-by-default firewall and data.

These boundaries have offline process/cgroup/socket models, a real inert data
writer, injected sync failures and fixed-transport tests. Real Linux service,
filesystem, keystore and node acceptance remain deferred; no chain executable,
real key or financial transaction was run for this correction.

Privileged helper, firewall, release, configuration and custody destinations are
checked before provisioning changes, including every existing ancestor. Unknown
symlinks, non-root owners and group/world writable paths are refused rather than
repaired implicitly. Only the exact managed release/credential pointers are
accepted. The service's inline root bootstrap validates its helper before
executing it; validation inside a replaceable script is not its trust boundary.

A new runtime account starts from a durable reservation of unused system UID/GID
values. Account/group creation may resume only that reservation. Startup checks
the original UID/GID, dedicated home and non-login shell, primary group and NSS
supplementary membership. Unknown existing accounts/groups and privilege drift
are refused. Earlier versions did not record original UID/GID authority: such
hosts can still stop/destroy their known services and retain data, but startup
or update requires a separately reviewed migration; no implicit adoption is
performed. Stop also considers the retained UID when the current NSS entry has
changed. No real account or group was created by the offline verification.
