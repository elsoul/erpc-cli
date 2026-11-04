# Controller dependencies in the testnet validator plays

SLV runs `ansible-playbook` on the operator's machine, so its plays may read
files there, run lookups there, and delegate tasks to `localhost`. erpc runs the
same plays on the node itself (`-c local`), where "the controller" is the node.
Every line that depended on the operator's machine therefore either changes
meaning or breaks.

This table covers every such line in the plays erpc carries for a testnet
validator: the closure of `ansible/erpc-testnet-validator/{create_user,deploy}.yml`
under `crates/erpc-chain-solana/templates/`. A test in that crate fails if a new
one appears or a line marked here disappears.

There are three treatments:

- **inject**: erpc provides the value itself, as a file in the bundle or a host
  variable.
- **rewrite**: the line reads the carried copy of the same file.
- **keep**: the line means the same thing on the node.

| Play | What it read on the controller | Treatment | Now |
|---|---|---|---|
| `cmn/build_agave.yml`, `build_jito.yml`, `build_allnodes_jito.yml` | `vars_files: ~/.slv/versions.yml` (required) | inject | `{{ playbook_dir }}/../../vars/versions.yml`, which erpc writes from the validator's pinned version |
| `cmn/check_alpenglow_floor.yml` | `vars_files: ["~/.slv/versions.yml", "/dev/null"]` | inject | the same bundle file; the messages name it |
| `testnet-validator/deploy-start-validator-sh.yml` | `vars_files: ["~/.slv/versions.yml", "/dev/null"]` | inject | the same bundle file |
| `testnet-validator/deploy-start-validator-sh.yml` | `src: ~/.slv/testnet-validator/start-validator.sh.j2` when not sync-only | rewrite | always the carried `jinja/testnet-validator/start-validator.sh.j2`; sync-only already used it |
| `cmn/copy_restart_sh.yml` | `src: ~/.slv/cmn/restart.sh.j2` | rewrite | the carried `jinja/cmn/restart.sh.j2`; SLV's copy is byte for byte the same file |
| `testnet-validator/setup_solv_service.yml` | `src: ~/.slv/testnet-validator/solv.service.j2` | rewrite | the carried `jinja/testnet-validator/solv.service.j2` |
| `mainnet-validator/create-start-validator-sh.yml` | `vars_files: ["~/.slv/versions.yml", "/dev/null"]`; `src: ~/.slv/mainnet-validator/start-validator.sh.j2` when not sync-only | inject, rewrite | the bundle's `vars/versions.yml`; always the carried `jinja/mainnet-validator/start-validator.sh.j2` |
| `mainnet-validator/setup_solv_service.yml` | `src: ~/.slv/mainnet-validator/solv.service.j2` | rewrite | the carried `jinja/mainnet-validator/solv.service.j2` |
| `mainnet-validator/create_overrides.yml` | `src: ~/.slv/mainnet-validator/overrides.yml.j2`; `hostvars[…].staked_rpc_identity_account`, `staked_rpc_amount` | rewrite | the carried template; the two values read by the template from the host when set, else its defaults (SLV's staked map) |
| `mainnet-rpc/start-validator.sh.j2` (template) | SendTx RPC: `--limit-ledger-size 30000000` | fix | 50000000, the least agave 4.3 takes (`LEGACY_DEFAULT_MIN_MAX_LEDGER_SHREDS`); with 30000000 the validator exits at start, found on rpc1 on 2026-10-24 |
| `cmn/create_user.yml` | `vars_files: ~/.slv/config.pwd.yml` (the `solv` password hash) | inject | `{{ playbook_dir }}/../../vars/config.pwd.yml`. erpc reads the host's `solv` password from 1Password, hashes it in memory and writes only the hash there, and the file is removed with the run directory |
| `cmn/create_user.yml` | `lookup('env', 'HOME')` and `ansible_ssh_private_key_file` to find the operator's public key; a `delegate_to: localhost` stat of it; `lookup('file', …)` to read it | inject | the host variable `solv_authorized_key`, one OpenSSH public key line. An assert refuses anything else before any change |
| `cmn/tasks/validator_bootstrap.yml` | `delegate_to: localhost` stat and `lookup('ansible.builtin.file', …)` of `{{ playbook_dir }}/../../jinja/…` | keep | on the node, `localhost` is the node and `playbook_dir` is the bundle, so this still checks the carried startup templates |
| `cmn/copy_restart_sh.yml`, `cmn/assert_unstaked_identity.yml`, `testnet-validator/deploy-start-validator-sh.yml`, `testnet-validator/start_solv.yml` | `hostvars[inventory_hostname].…` | keep | the host's own variables, from the bundle's inventory; erpc passes the inventory hostname the host has in 1Password |
| `cmn/check_alpenglow_floor.yml`, `cmn/build_*.yml` | `lookup('ansible.builtin.vars', …)` | keep | reads variables, not files |

## The mainnet RPC node plays

The same treatments, for the closure of `ansible/erpc-mainnet-rpc/*.yml`
(SLV's `mainnet-rpc/init.yml` and what it imports):

| Play | What it read on the controller | Treatment | Now |
|---|---|---|---|
| `mainnet-rpc/copy_keys.yml` | `~/.slv/keys/<identity>.json`, a `delegate_to: localhost` stat of it, and the file copied to the node | not carried | the node makes its own identity (`erpc-mainnet-rpc/identity.yml`): an RPC node's identity has no stake, so it never needs to leave the node. Its public key is read back into the node's item |
| `mainnet-rpc/create-start-validator-sh.yml` | `vars_files: ["~/.slv/versions.yml", "/dev/null"]`; `src: ~/.slv/mainnet-rpc/start-validator.sh.j2` | inject, rewrite | the bundle's `vars/versions.yml`; the carried `jinja/mainnet-rpc/start-validator.sh.j2` |
| `mainnet-rpc/setup-solv-service.yml` | `src: ~/.slv/mainnet-rpc/solv.service.j2` | rewrite | the carried `jinja/mainnet-rpc/solv.service.j2` |
| `mainnet-rpc/geyser_build.yml` | `vars_files: ~/.slv/versions.yml`; `~/.slv/mainnet-rpc/geyser.json.j2` | inject, rewrite | the bundle's `vars/versions.yml` (`geyser_version`, and `geyser_commit`, which the build now checks the tag still points at); the carried `geyser.json.j2` |
| `mainnet-rpc/install_of1_service.yml` | `src: ~/.slv/mainnet-rpc/generate_configs.sh.j2` | rewrite | the carried `generate_configs.sh.j2`. The service is started, not restarted, so a re-run of deploy leaves a running Old Faithful as it is |
| `mainnet-rpc/install_of1.yml` | nothing; it downloaded `faithful-cli` at `of1_version`, default `v0.7.14`, with no check | inject | `of1_version` and `of1_sha256` from the node's pins: erpc reads the SHA-256 of `faithful-cli_linux_amd64` from GitHub's asset digest at `init`, and `get_url` checks it. No default |
| `cmn/wget_snapshot.yml` | nothing; it pinged `solana-snapshot-${region}.erpc.global` for a list of region names | replaced | not carried: `erpc-mainnet-rpc/snapshot.yml` asks the ERPC mirrors and Avorio's public mirror for their newest archives and takes the freshest and fastest. A mirror that answered ping but not HTTPS held the old play for hours. The deploy fetches a snapshot only into an empty ledger |
| `cmn/of1_index_cache_sync.yml` | `src: files/of1-index-sync.sh`, `files/start-faithful.sh` | keep | the play's own `files/`, carried beside it |

What erpc puts in an RPC node's bundle: `vars/versions.yml` with the
`mainnet_rpcs` section (`erpc_chain_solana::rpc::versions_yml`), the
inventory with the variables SLV's `slv rpc init` wrote (`validator_type`,
`rpc_type`, `port_rpc`, `dynamic_port_range`, `region`) plus erpc's
(`erpc_geyser`, `erpc_faithful`, `of1_version`, `of1_sha256`, the firewall's
lists, `erpc_disks`), `vars/config.pwd.yml` for `create_user` only, and
`files/free-disks.sh`.

## Startup flags brought up to the running recipe

SLV's testnet startup templates (`start-validator.sh.j2`,
`start-validator-agave.sh.j2`, `start-validator-jito.sh.j2`) were behind the
testnet validator ERPC runs. They now write what it runs, checked against
agave v4.4.0-beta.1's own argument definitions:

| Flag | SLV wrote | Now |
|---|---|---|
| `--expected-shred-version` | only when set for a sync-only node, else 57087 | always; 4457, which every testnet node reported on 2026-10-23, unless `expected_shred_version` is set |
| ledger size | `--limit-ledger-size 200000000`, deprecated in agave 4.3.0 | `--limit-blockstore-size 400000000` (`limit_blockstore_size`); the floor is above 4.3.0 |
| snapshots | in the ledger directory | `--snapshots /mnt/snapshot`, the disk `mount_disks.yml` prepares |
| `--only-known-rpc` | in the agave and jito templates only | in all three |
| RPC | bound to all addresses, published in gossip (the agave and jito templates bound `0.0.0.0` explicitly) | `--rpc-bind-address 127.0.0.1 --private-rpc` |
| `--no-port-check` | set | dropped; agave hides it |
| `--commission-bps` | 1000 from SLV's inventory | 0 (`erpc_chain_solana::vars`) |

The identity stays SLV's layout: `--identity /home/solv/identity.json`, a link
`setup_unstaked_identity.yml` points at an unstaked key made on the node, and
`assert_unstaked_identity.yml` refuses a link to the staked one.

## Disks

SLV's `mount_disks.yml` takes the unmounted NVMe disks of 800 GB or more that
have no partition, largest first, as `/mnt/ledger`, `/mnt/accounts`,
`/mnt/snapshot` and `/mnt`. A disk that came with an empty partition (the
London test server's second disk had one 512 MB partition, all zeros, left by
the provider's installer) was skipped, and the ledger stayed on the root disk.

- **Which disks are free** is one script, `erpc_ssh::FREE_DISKS_SCRIPT`. A
  disk is free when it is not mounted, nothing holds it, and it has either no
  partition table and no signature, or only partitions that have no
  filesystem, RAID or LVM signature, are not held, are not in `/etc/fstab`
  and are not a UEFI boot entry.
- `erpc v deploy` runs it on the node, shows which disk becomes which
  directory and which partition tables are removed, and passes the operator's
  answer as the host variable `erpc_disks` (`[{name, wipe}]`).
- `mount_disks.yml` uses `erpc_disks` instead of its own listing. Before it
  removes a partition table (`wipefs --all`), it runs the same script from the
  bundle's `files/free-disks.sh` and stops if the disk is no longer free.
- `tasks/format_and_mount.yml`: when the directory a new disk is mounted on
  holds data (a node deployed before), solv stops and the data is copied onto
  the disk first, then removed from the root disk; the deploy starts solv at
  its end. `/mnt` itself is left as SLV has it. The mount point is given to
  `solv`.

## What erpc puts in a bundle

| File or variable | From |
|---|---|
| `vars/versions.yml` | the validator's pin (S4c), from `erpc_chain_solana::versions::versions_yml`: `<network>_validators.version_<client>` without the `v` (`allnodes_jito` for allnodes-jito), and `commit_<client>`, the commit the tag pointed at when it was pinned. `build_agave.yml`, `build_jito.yml` and `build_allnodes_jito.yml` check out the tag and stop before building unless it is still that commit; the full Firedancer's `erpc-validator-firedancer/setup.yml` does the same |
| `vars/config.pwd.yml` | `encrypted_password`: the SHA-512 crypt hash of the host's `solv` password. The password is generated at `erpc v init` and kept in the host's 1Password item; the hash is made in memory for each run. It is needed for `create_user` only |
| `inventory.yml`, the host's variables | the validator and host items (S4), plus `solv_authorized_key`, and for a deploy `erpc_disks` |
| `files/free-disks.sh` | `erpc_ssh::FREE_DISKS_SCRIPT`, the free-disk rule the deploy checks again before wiping |

## Who runs the plays on the node

`create_user` runs as the first SSH user (usually `ubuntu`), with `become`. Every
later play runs as `solv`. `create_user` gives `solv` sudo without a password, so
`become` needs no password. That matches SLV, which switched its inventory's
`ansible_user` to `solv` after `create_user`.


## RPC firewall operation receipts

Ethereum, Arc and Solana RPC bundles carry one shared Python controller from
`erpc-ops`. A fresh SSH confirmation supplies the run ID and submitted bundle
SHA-256 and must match the pending policy and live nftables fingerprint. Timers
are bound to individual operations and share the remote run lock with confirmation.
The short preparation finishes and is confirmed before building, snapshots or long
startup checks begin. The deployment's first play requires that exact confirmed
receipt, so another controller cannot substitute a newer policy between phases.
Rollback persistently revokes startup authorization before stopping unfiltered
services; a queued manual start and a reboot must both respect that fence.

The Solana `solv` and optional Faithful units now require the RPC firewall unit
and verify live filtering before starting. Firewall application precedes public
listeners; boot recovery restores a confirmed policy, while a first deployment
without a confirmed or live policy cannot start. If rollback cannot restore an
older policy, it stops and disables the affected services before removing the
table. These changes explain the corresponding vendored-file digest updates.


Before any new policy is applied, root-owned systemd drop-ins add the startup
guard to every managed listener (including existing and optional services), and
the service manager reloads them. This also protects Solana update/config paths
that do not rewrite the original unit. Filter removal refuses missing or changed
guard overrides. Destroy first installs these guards, revokes startup and strictly
stops the services; a failed stop preserves filtering. Guard drop-ins remain after
teardown so cached or queued starts cannot bypass the fence before unit removal
and daemon reload complete. A later reviewed deployment reuses them.
