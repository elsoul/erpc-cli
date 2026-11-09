# Provenance

The files under this directory come from SLV, ELSOUL LABO B.V.'s Solana
validator toolkit, licensed Apache-2.0 like erpc.

- Repository: https://github.com/ValidatorsDAO/slv
- Commit: `8d6a5f0` (2026-10-20)
- Template version: `template/2026.10.19.1053`

## Vendored files

Copied unchanged unless the change column says otherwise; why each change
was made is in `docs/porting/ansible-controller-deps.md`. A test in
`src/lib.rs` checks every file against the digest here, so a file cannot
change without this table changing in the same commit.

| File | SHA-256 | Change |
|---|---|---|
| `ansible/cmn/add_solv.yml` | `4e0c4fdbc6531bbc31750d1b2326b62afdcb1024bad65179df6da95907384879` | unchanged |
| `ansible/cmn/assert_unstaked_identity.yml` | `5684747ef5e7873049c546ea7bb2976cbd6ebb4afa58645acb20701c10cc9d7e` | unchanged |
| `ansible/cmn/assert_validator_bootstrap.yml` | `90be4cdf3c8396e85c1d460d19309d9a2ebf99b82d3c980d682f64fc322f4575` | unchanged |
| `ansible/cmn/build_agave.yml` | `fb0139f9de59576cf10bf59534360ea757b255376cbc4e6d29669348bb4f8fe0` | S2: versions from the bundle's `vars/versions.yml`; S4c: stops before building unless the tag still points at the pinned commit |
| `ansible/cmn/build_allnodes_jito.yml` | `89c87b868790f7b720b278231ed6e7e2cf9399695a342e6e3f6ca349630970ca` | S2: versions from the bundle's `vars/versions.yml`; S4c: stops before building unless the tag still points at the pinned commit |
| `ansible/cmn/build_jito.yml` | `11e0008990df4fa91a8c77488d4aa44e24cf1aff6983649f780602c6829040cd` | S2: versions from the bundle's `vars/versions.yml`; S4c: stops before building unless the tag still points at the pinned commit |
| `ansible/cmn/build_solana.yml` | `634fee22f0cb9f1e55c441534d592594d6c41261291ea8d3727f20bb5d50a61b` | unchanged |
| `ansible/cmn/check_alpenglow_floor.yml` | `34660f99aa50e65209faa116ae1c357e8ec056b72d63c4fdb7a234d83d91e1c4` | S2: versions from the bundle's `vars/versions.yml` (and the messages say so) |
| `ansible/cmn/copy_restart_sh.yml` | `118750d0c40255177ba8a7c3dfc245b98537565100e4c3f65566ed1ba622a317` | S2: the template from the carried `jinja/cmn/`, not `~/.slv/cmn/` |
| `ansible/cmn/create_user.yml` | `d98adfcaeb632449a80f67b47e489d792d1260c2c96738c5b739961d5dc815d8` | S2: the password hash from the bundle's `vars/config.pwd.yml`; the key to authorize from `solv_authorized_key`, checked, instead of a file on the operator's machine |
| `ansible/cmn/disable_swap.yml` | `e6600b79ffdef6cc7e1a877ffb7b9c5ed769f476822faaed2f9c69e53c2d3637` | unchanged |
| `ansible/cmn/files/of1-index-sync.sh` | `a8ed574fa21eae01888ede1fc757d069d269b9e0465706159ffede91d33a4093` | unchanged |
| `ansible/cmn/files/start-faithful.sh` | `a0d12352e330993af64128cc38cda366cd49d6ed41a7756b7f8fa7268b920a1c` | unchanged |
| `ansible/cmn/fix_permissions.yml` | `d514530de07b0af9ba44ac6dbbb579cee9c501d5c51dac19a640a64f4c6028f7` | unchanged |
| `ansible/cmn/install_package.yml` | `4402d2e1f1d46985311843869e7c0506526cfb5a5dee48c96e6d2ec326b70006` | unchanged |
| `ansible/cmn/install_rust.yml` | `54e83254f35c7654f243b54a5906ada1f13a584efcd06a341aa76012bde24ad5` | unchanged |
| `ansible/cmn/mount_disks.yml` | `3cf74ce5fdffd8599541a81d3540f0a53553e639a16114aa1a7d9f349f57b2c3` | erpc: the disks come from `erpc_disks`, which erpc lists with the operator; a disk with only empty partitions is checked again with the bundle's `files/free-disks.sh` and its partition table removed |
| `ansible/cmn/of1_index_cache_sync.yml` | `629cf78d50cc5e2b109aae60fa49a3a1f7d45e0079335ec9d4076cd3fc09abae` | unchanged |
| `ansible/cmn/optimize_system.yml` | `036d239256ec27d74dc0347cafbc2ac602efc63cbef3731c76245dada265850f` | unchanged |
| `ansible/cmn/setup_logrotate.yml` | `8c20fc54dc66251900b0d7ae3e305f602f760d1669104f922bf0d312e94aa51f` | unchanged |
| `ansible/cmn/setup_node_exporter.yml` | `e95fb4a9fb22a65b079912f775b734ee6ac986d1af301cc9d9dd103f677f3ab1` | unchanged |
| `ansible/cmn/setup_norestart.yml` | `008c7082e6aef10cf89f9a875c805a48a7f256a493bdcbbb80d57c5dd5f05d9c` | unchanged |
| `ansible/cmn/setup_unstaked_identity.yml` | `2f9bc07bb8a7f55548c98a7b559f64c34541cb09913901233660790d62ea44b9` | unchanged |
| `ansible/cmn/stop_richat.yml` | `8cb11c29348c73d6cb5413096bf46e6b579e0729b0baa32fdb518e3f73adbe58` | unchanged |
| `ansible/cmn/tasks/format_and_mount.yml` | `2769c74901ce52b9dc172bb54ea4eadc4bcd4579b3608448630e75e469e0fd0c` | erpc: before a disk is mounted over a directory that holds data, solv stops and the data moves onto the disk; the mount point is given to solv |
| `ansible/cmn/tasks/validator_bootstrap.yml` | `18301567f903fb589dcbc3a841e4b916ca7f5a87535971e8c33e1139e067ebce` | unchanged |
| `ansible/mainnet-rpc/add_solv.yml` | `4e0c4fdbc6531bbc31750d1b2326b62afdcb1024bad65179df6da95907384879` | unchanged |
| `ansible/mainnet-rpc/create-start-validator-sh.yml` | `6178e7b2424aead9b7a9517226c0e6af2381ddc35394e991e1e3230b779d898e` | R4: versions from the bundle's `vars/versions.yml`; the startup template from the carried `jinja/mainnet-rpc/` |
| `ansible/mainnet-rpc/geyser_build.yml` | `7f4961286a3d182bf87e2b23c82530d38837a35d463cf24ac0e4cc1a6c269512` | R4: versions from the bundle's `vars/versions.yml`; `geyser.json` from the carried `jinja/mainnet-rpc/`; stops before building unless the tag still points at the pinned commit |
| `ansible/mainnet-rpc/install_of1.yml` | `5057d135b56db9c3208f9582be5d579d17c448683a87f8c721ee566c6b26c9ae` | R4: the release and the SHA-256 of its binary from the node's pins, checked on download; no default version |
| `ansible/mainnet-rpc/install_of1_service.yml` | `5b7c1554b55d65db7341bc603fa2da6ed12e8efcbe9eaa6fed65a3ee08a3f37e` | R4: carried config generator and idempotent start; RPC startup requires the operation-bound firewall service and a matching live-rule guard; root Python guards use isolated startup |
| `ansible/mainnet-rpc/setup-solv-service.yml` | `8dc433e981348e3f831b0aa9528b97a5488eb85d08ea72a6d9708f936ee9d49e` | R4: the unit from the carried `jinja/mainnet-rpc/`, not `~/.slv/` |
| `ansible/mainnet-rpc/start_solv.yml` | `36bcd583105e9ae410b43158f5796a9c3d7e597f27746d3abb34e5af099b4ff2` | unchanged |
| `ansible/mainnet-validator/create-start-validator-sh.yml` | `b3f96448caca7bb67194eee7a3585947849627047095e73b6cee09ac8ac66998` | erpc: versions from the bundle's `vars/versions.yml`; the startup template always from the carried `jinja/` |
| `ansible/mainnet-validator/create_overrides.yml` | `cb9743ddf63515d6c2dcee848a88d750790028091a804e0ee2ffa603f1b3b62d` | erpc: the template from the carried `jinja/mainnet-validator/`; the staked map's identity and amount from the host when set, else the template's defaults |
| `ansible/mainnet-validator/setup_solv_service.yml` | `a6e100ab1238a6b4cac56124007cec19070abb6beae8865d54b3beec41230efe` | erpc: the template from the carried `jinja/mainnet-validator/`, not `~/.slv/` |
| `ansible/mainnet-validator/start_solv.yml` | `cd20934cf504201438ba77f8a78138e377f81f14249e81d3c3a9c4825fdf347d` | unchanged |
| `ansible/testnet-validator/deploy-start-validator-sh.yml` | `fbcb82e921807eba304ab094c21ddac0a10e0dd65305465caa3e39c2a4ee2681` | S2: versions from the bundle's `vars/versions.yml`; the startup template always from the carried `jinja/` |
| `ansible/testnet-validator/setup_solv_service.yml` | `a0977025f3934d15517391268fadc6f0ea7eee18976f12ebebb19b2285179c1f` | S2: the template from the carried `jinja/testnet-validator/`, not `~/.slv/` |
| `ansible/testnet-validator/start_solv.yml` | `6802709ad2c33a7720cc15dd4389ae559cafbf8f8bdf119e504e0c07367ca508` | unchanged |
| `jinja/cmn/restart.sh.j2` | `52c6f09d74537f0720da613d8713e6670928e1ee7d6f4f588b4d2c5f44fefb63` | unchanged |
| `jinja/mainnet-rpc/generate_configs.sh.j2` | `149ffb2d31c82820707ec0742fb6bbd36edd9e797eaa64c8ba587620bf09c157` | unchanged |
| `jinja/mainnet-rpc/geyser.json.j2` | `858714c30dc172c410c04d848be693e6ca8c228c93c355cbec8032705316ae0f` | unchanged |
| `jinja/mainnet-rpc/solv.service.j2` | `edbd590357c4b64ef431e59b795e67c67832f8ed2ad5077686bb50f5d25d5988` | RPC startup requires the operation-bound firewall service and a matching live-rule guard; root Python guards use isolated startup |
| `jinja/mainnet-rpc/start-validator.sh.j2` | `1b79272464b866674d92a324c322df67dfa542fdce91787b839de1c49559fca1` | erpc: SendTx RPC keeps `--limit-ledger-size 50000000`, agave 4.3's minimum; SLV's 30000000 is refused at start |
| `jinja/mainnet-validator/overrides.yml.j2` | `1801ea151d5739af9503c0af6e4b9c98ae3c22198f3b6bcb39c5d56fd61b101c` | unchanged |
| `jinja/mainnet-validator/solv.service.j2` | `e412807646f0e5e48372e8c54503bedb46064cc30ee6defd445471bb31c0da9b` | unchanged |
| `jinja/mainnet-validator/start-validator.sh.j2` | `ed3ee36d06b7b82a549116ef771e75d7278c1c7df2c3119a514dd2a0cfadd367` | unchanged |
| `jinja/testnet-validator/solv.service.j2` | `ed0e62e40c6bd9abce73587ab1fbc2f348bd7bedfc49664e7547a003ee049b2d` | unchanged |
| `jinja/testnet-validator/start-validator-agave.sh.j2` | `3593cc7bc6b33c5430182d8a7e953af7bb026514fb04b6ea793d7435749cd9bb` | recipe: the flags of the testnet validator ERPC runs (2026-10-23); see the porting table |
| `jinja/testnet-validator/start-validator-jito.sh.j2` | `43cdba58908f17b35a7f879b5cbf36985e1c294b5aa51d059eb95666014f07ee` | recipe: the flags of the testnet validator ERPC runs (2026-10-23); see the porting table |
| `jinja/testnet-validator/start-validator.sh.j2` | `b2461a572bc18d547764f4d9df6f2f13a6236600322b5a79050d85aa3bf96285` | recipe: the flags of the testnet validator ERPC runs (2026-10-23); see the porting table |

## Written for erpc

| File | What it is |
|---|---|
| `ansible/erpc-testnet-validator/deploy.yml` | SLV's `testnet-validator/init.yml` with its Firedancer plays (Frankendancer) replaced by erpc's full Firedancer, and imports rewritten for its directory |
| `ansible/erpc-mainnet-validator/deploy.yml` | SLV's `mainnet-validator/init.yml` with imports rewritten for its directory, the full Firedancer from erpc's plays, and the snapshot from `erpc-mainnet-rpc/snapshot.yml` into an empty ledger |
| `ansible/erpc-validator-firedancer/setup.yml`, `start.yml`, `files/erpc-keypair.py`, `jinja/erpc-validator-firedancer/*` | the full Firedancer validator (v26.x) for both networks: built at the pinned commit, an unstaked identity made with openssl (the host has no Solana CLI), its TOML over Firedancer's cluster defaults with Alpenglow on, and `firedancer.service` |
| `ansible/erpc-testnet-validator/create_user.yml` | runs SLV's `cmn/create_user.yml` |
| `ansible/erpc-mainnet-rpc/deploy.yml` | SLV's `mainnet-rpc/init.yml` with the imports rewritten for its directory, the identity made on the node, no Firedancer, the snapshot only into an empty ledger (`snapshot.yml`), no richat, and the firewall last |
| `ansible/erpc-mainnet-rpc/identity.yml` | the node's own RPC identity (`solana-keygen`), and `identity.json` linked to it; a host whose `identity.json` is anything else is refused |
| `ansible/erpc-mainnet-rpc/update.yml` | the newly pinned client (and Yellowstone plugin) built with SLV's plays, the startup written again, the service restarted |
| `ansible/erpc-mainnet-rpc/config.yml` | the startup script written again, the service restarted only when it changed, then the firewall |
| `ansible/erpc-mainnet-rpc/snapshot.yml`, `files/erpc-snapshot-fetch.sh` | the snapshot an empty node starts from, in place of SLV's `cmn/wget_snapshot.yml`: the ERPC mirrors and Avorio's public mirror asked for their newest archives, the fresh ones timed, the fastest taken (aria2c over many connections where ranges are served) |
| `ansible/erpc-mainnet-rpc/destroy.yml` | stops the services and removes their units and the firewall; the chain data only when asked |
| `ansible/erpc-mainnet-rpc/firewall.yml`, `tasks/firewall.yml` | the node's nftables table, applied under a rollback timer that erpc disarms from a fresh SSH connection, as the Arc node's is |
| `jinja/erpc-mainnet-rpc/*` | the table, its boot unit, and the rollback and confirm helpers |

## Left out

- `ansible/testnet-validator/init.yml` and `ansible/mainnet-rpc/init.yml`,
  replaced by erpc's own entry plays.
- SLV's Firedancer plays and templates (Frankendancer): not for RPC nodes,
  which run agave or jito, and not for validators, which run the full
  Firedancer from erpc's own plays.
- Plays that copy plaintext keys (`copy_keys.yml`, `cmn/copy_rpc_keys.yml`):
  erpc keeps validator identities in 1Password, and an RPC node makes its own.
- richat (`geyser_richat_build.yml`, `install_richat.yml`,
  `cmn/check_richat_release.yml`): it has no release for agave 4.3 or later,
  the mainnet floor.
- `cmn/update_ubuntu.yml`: it rewrites the apt sources to a mirror chosen by
  region and runs a dist-upgrade; the validator's deploy leaves it out too.
- DoubleZero and the SHA-256 patch (`patch_sha256.yml`).
