<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The release gate refuses a tag
whose version has no entry below.

## [Unreleased]

## [0.1.0-rc.3] - 2026-11-10

### Added

- `erpc rpc call` sends JSON-RPC to shared Solana and Ethereum mainnet
  endpoints or an operator-provided URL. The x402 option quotes and signs a
  Base EURC payment after terminal confirmation.
- `erpc webhook` manages local subscriptions and delivers matching
  WebSocket notifications to HTTP callbacks. `erpc completions` generates
  shell completion scripts.
- The unversioned installer URLs prefer the latest stable release and select
  the most recently published prerelease when no stable release exists.
  Versioned installer URLs keep selecting the requested tag.

- The `solana/pumpfun` template trades pump.fun graduations as well as
  pools made by hand. It reads a graduation's `create_pool` where it
  happens, inside pump.fun's `migrate_v2` and with accounts from address
  lookup tables; buys and sells with WSOL on either side of the pool and
  with tokens on Token-2022; and buys a graduation from its `create_pool`
  without RPC reads or a simulation first. `graduated_only` keeps it to
  graduations.
- With `SHREDS_ENDPOINT` set, the template reads `migrate_v2` from the
  Shreds stream, and `buy_on_shreds` (off by default) buys from there. A
  transaction in the stream has not run, so a migration is bought only
  when its curve, pool and vaults are the addresses its mint gives them
  and the accounts read are owned by the programs that write them.
  `GET /api/timing` gives p50 and p90 of how long a migration showed in
  Shreds before Geyser processed it and before its slot was confirmed, how
  long a buy took from the pool's first sighting to its send, and how many
  slots late each buy landed. `priority_fee_micro_lamports` and
  `compute_unit_limit` set a buy's priority fee, which the take-profit
  counts as cost.
- `POST /api/bans/trace` in the template bans the wallet that first funded
  each banned creator, and the other wallets that funder sent SOL to
  lately. Wallets with a long history, funders that paid many wallets and
  the bot's own wallet are left alone.
- `erpc worker run --grpc --shreds --ip <IPV4>` gives a run on this machine
  hourly gRPC and Shreds lines that admit its public IPv4. An active line
  that already admits it is taken up; otherwise a new line is bought after
  its price is asked. When the run ends, Ctrl-C included, erpc asks to end
  each line; `--keep-lines` keeps them. Ctrl-C while a line is being bought
  waits for the purchase to be on record, then ends that line with the
  rest.
- `erpc worker api` sends one request to the app's API on its server, over
  SSH, with `API_TOKEN` read here and never shown; `erpc worker trades`
  shows the app's trade history or the profit per trade.
- `erpc ai` runs the `erpc worker` verbs that only look without asking:
  `check`, `list`, `status`, `logs` (not followed), `releases`,
  `key show`, `key balance`, `secret list`, `firewall list` and
  `backup status`. Every other verb is shown and asked as before.
- `erpc worker key send` moves SOL out of the trading wallet to one address
  after a yes: the key is read behind the same gate as a run, and the
  transfer is signed in memory and sent through the app's own RPC. It is
  followed by its own signature until it lands or its blockhash is past,
  and is said to be unsent only when the RPC node refused it before
  sending it on. The address is taken only in its canonical base58 and
  shown as decoded.
- `run.requires` in `erpc.toml` takes a set of settings of which one is
  enough, such as `["ERPC_API_KEY", "SOLANA_RPC_ENDPOINT"]`. The pumpfun
  template asks for its RPC that way, so `erpc worker check` no longer
  calls an app ready that cannot start. Such a set is an array inside
  `missing` in `secret list --json`, beside the names of single
  settings, and in `manifest.run.requires` in `check --json`.
- `erpc rpc` on six more chains, which makes all 18: Polygon PoS (Bor and
  Heimdall v2), BNB Chain (Geth, with full or pruned history), Kaia (an
  endpoint node), Monad, Hyperliquid (a non-validator node) and NEAR (a
  nearcore follower). Each has the same twelve verbs and a guide that
  `docs/nodes.md` links.
- `erpc validator` on eight more chains: Polygon PoS, BNB Chain, Kaia (a
  consensus node or a proxy node), Monad, Hyperliquid, NEAR, Arbitrum One and
  Robinhood Chain. Deposits, staking and registration are signed outside
  erpc; `registration` on Polygon, NEAR and Robinhood Chain prepares and
  checks them. `erpc validator --chain hyperliquid aqa` runs the separate
  AQA publisher. On Arc, `erpc validator` prepares a validator host and runs
  it as an observer; it does not sign.
- Solana on the native backend, for validators and RPC nodes on mainnet and
  testnet: Agave built from source on the server and run under accounts of
  its own. A validator has every verb now (`logs`, `start`, `stop`,
  `restart`, `update`, `update-config`, `plan` and `destroy` were not
  implemented), syncs under a separate identity and starts voting with
  `deploy --activate-validator`. `erpc v registration` reads the vote account
  and prepares what an external wallet signs. `docs/solana-native.md` is the
  guide.
- Live acceptance on real hosts is still under way for most of these chains:
  `docs/chains/README.md` says where each one stands.

### Changed

- `erpc worker stop`, `status` and `delete` say which hourly server and
  lines keep charging and how to end them; `status` carries them in its
  JSON. `deploy` checks the cross-build tools and the SSH key before a VPS
  is bought, and names every missing piece at once; `check` says the same
  of the tools, looking for them on `PATH` without running anything in
  the app's directory.
- Before `stop`, `restart`, `rollback` and `delete`, an app with a wallet
  is warned that its positions wait while it is down; a redeploy says so
  as it restarts the app.
- The pumpfun template keeps whether trading is on in Redis and takes it
  up again at start, so a restart does not leave it idle on paid lines.
- `erpc worker firewall` says, after a change, that the SSH allow list
  outlives the address it was made from, and that a port opened for the
  app answers only if the app binds beyond loopback.
- `erpc worker init` builds its "Next" steps from the manifest. A missing
  line setting points at `--grpc` or `--shreds` instead of `secret put`.
- A line that is becoming active shows a spinner, as does 1Password while
  erpc waits on its app. On Linux without a Secret Service the keychain is
  refused where the store is chosen, with the ways out.
- The `erpc login` store picker and vault question speak en, ja, zh and
  ru.
- CI renders the `solana/pumpfun` template as `erpc worker init` does and
  runs its clippy and tests. The templates are not workspace members, and
  nothing compiled them before.
- **Coming from 0.1.0-rc.2: new Solana nodes use the native backend.**
  `erpc v init` and `erpc r --chain solana init` for a name whose server is
  not in the inventory no longer set up a `solv` node, and `--backend solv`
  is refused for it. The server must be Ubuntu 24.04 with systemd 255, AVX2
  and SHA-NI, at least 24 threads and 300 GiB of memory for a mainnet
  validator or 120 GiB for a testnet validator (32 and 480 GiB for an RPC
  node on either), with three filesystems
  already mounted, which erpc does not partition, format or mount for a new
  node. You make the keys and keep them in 1Password before `init`, which
  takes new flags for them; erpc generates none. There is no choice of
  client, release or RPC type, and making or importing keys and
  `erpc v vote-account` are refused. `docs/solana-native.md` has the
  preparation. A node whose server 0.1.0-rc.2 recorded keeps the commands it
  was set up with, and `erpc v migration` or
  `erpc r --chain solana migration` moves a qualified one to the native
  backend.
- **Coming from 0.1.0-rc.2: nodes it deployed on six other chains.** This
  version looks on the server for helpers and ownership records that a
  0.1.0-rc.2 deploy did not write, so `deploy`, `update`, `start` and
  `restart` fail on such a node until it has been migrated once, and so does
  `status` except on TRON and Bitcoin. Until then erpc cannot stop an
  Ethereum or Arc node either: the Ethereum entries below start by stopping
  the services on the server, and Arc's migration stops them itself. A
  migration leaves the node stopped; the guide named beside each has the
  records of the original server it asks for and the `deploy` or `update`
  that follows.
  - Ethereum RPC: stop Reth and Lighthouse on the server, then
    `erpc r --chain eth init --migrate-authority` with `--original-passwd`,
    `--original-group`, `--original-machine-id` and
    `--original-client-record` (`docs/ethereum-rpc.md`).
  - Ethereum validator: stop its three services, then the same flags on
    `erpc v --chain eth init` (`docs/ethereum-validator.md`).
  - Arc RPC: the same flags on `erpc r --chain arc init`
    (`docs/arc-runtime.md`).
  - Avalanche: `init --migrate-account` (`docs/avalanche.md`).
  - Sui: `init --migrate-account` and `update --migrate-source-history`
    (`crates/erpc-chain-sui/templates/README.md`).
  - Bitcoin: `erpc r --chain bitcoin deploy --original-runtime-record`
    (`docs/bitcoin-rpc.md`).
  - TRON has no migration. This version can stop or destroy a TRON node that
    0.1.0-rc.2 deployed, keeping its data, but cannot start or update it.
- **Coming from 0.1.0-rc.2: what erpc needs on a server.** Every file erpc
  uploads, for a node and for `erpc worker`, is now written on the server by
  a Python program run through `sudo`. The server needs `/usr/bin/python3`
  and `sudo` that asks for no password: check a server of your own before
  `erpc worker deploy --host`. `/opt` must be a real directory owned by root
  that its group and others cannot write, and so must `/opt/erpc` and the
  `runs` and `uploads` directories in it where they exist; none of them may
  be a symbolic link. For a node, the filesystem that holds `/opt/erpc` must
  also keep POSIX ACLs, as ext4 and XFS do by default. To keep `/opt/erpc` on
  another volume, mount the volume there instead of linking it, and keep the
  volume's top directory owned by root and not writable by its group or
  others. Ubuntu ships that Python and such an `/opt`.
- **Coming from 0.1.0-rc.2: your own systemd drop-ins.** The firewall step
  refuses to run while `/etc/systemd/system/<unit>.d/` of a service it
  protects holds any file but erpc's `50-erpc-firewall-guard.conf`, such as
  an `override.conf` made by `systemctl edit`. It changes nothing, and on
  every node whose firewall erpc manages, the command that applies or removes
  the firewall stops there: on a solv Solana RPC node, `deploy`, `update`,
  `update-config` and `destroy`, for `solv.service`, `faithful.service` and
  `of1-index-sync.service`. Move your drop-in out of that directory and run
  the command again.
- **Coming from 0.1.0-rc.2: `erpc v keys` and `erpc v vote-account` on
  mainnet need `--chain solana` on the command line,** as every other command
  that changes a mainnet node does: a chain taken from `ERPC_CHAIN` or
  `default_chain` is refused. `keys` can write a validator's vote account key
  and withdraw authority to 1Password, even without its flags when one is
  missing.
- `erpc v list` and `erpc r --chain solana list` show each node's backend,
  list a validator registered without a host as `[no host yet]`
  (`"backend": null` in `--json`), whose other commands say that the init
  that registered it resumes it, and, when there is no node, point to
  `init --help` and `docs/solana-native.md`.

### Fixed

- Apple Silicon worker-agent CI and release builds use the supported
  `macos-15` runner. GitHub rejected the former `macos-14` image before
  executing a job.

## [0.1.0-rc.2] - 2026-11-05

Everything erpc does beyond signing in, developed since 0.1.0-rc.1 and
brought into this repository as one change. The commands exist and pass
their offline checks; acceptance on real hosts is still under way for most
chains, and each chain's guide in `docs/chains/` says where it stands.

### Added

- `erpc validator` (`v`), `erpc rpc` (`r`) and `erpc node` (`n`): RPC nodes
  on 12 chains (Solana, Ethereum, Base, Optimism, Soneium, Arbitrum,
  Robinhood Chain, Avalanche, Bitcoin, Sui, TRON, Arc) and validators on
  five (Solana, Ethereum, Avalanche, Sui, TRON), with the same verbs:
  `init`, `deploy`, `status`, `logs`, `start`, `stop`, `restart`, `update`,
  `update-config`, `plan` and `destroy`. Solana validators have only `init`,
  `deploy` and `status` of these so far, plus `list`, `keys` and `vote-account`. Six
  more chains (Polygon, BNB Chain, Kaia, Monad, Hyperliquid, NEAR) are
  researched in `docs/chains/` and answer "not implemented yet". Live
  acceptance on real hosts is still under way for most chains. Every deploy
  logs in over SSH with a key from the 1Password SSH agent or `SSH_AUTH_SOCK`
  and pins the host key. What it sets up on the host differs by chain, and
  `docs/nodes.md` lists the differences: Solana nodes run as a login user with
  passwordless sudo, Solana builds its clients at a pinned commit and fetches
  some tools without a checksum, and Solana validators, Ethereum validators and
  Bitcoin nodes get no firewall from erpc. Node and validator records
  live in 1Password, not on the operator's disk. Which keys are in 1Password and which stay on the host differs by chain.
  `docs/nodes.md` has that table, the clients, networks and guides.
- `erpc rpc --chain solana`: Solana mainnet RPC nodes, the port of `slv rpc`,
  with agave or jito and SLV's four RPC types
  (SendTx, Index with Old Faithful, Geyser gRPC, Index + gRPC). The client
  and plugin versions are pinned in its 1Password item;
  the node makes its own identity; an nftables table admits RPC from the
  operator's proxies only and rolls itself back unless erpc reconnects.
- `erpc validator --chain solana`: testnet and mainnet validators with
  agave, jito or Firedancer; the identity made in memory and kept in
  1Password; vote account and withdraw authority keys made or imported;
  `erpc v list` from the 1Password inventory.
- `erpc ai`: the assistant, in a full-screen console. It reads the signed-in
  account (credit balance and history, card subscriptions, RPC usage and the
  AI plan) through read-only tools that pass on only the fields they name;
  knows what ERPC sells and what is free now (the server catalogue, servers
  in stock by region, the prices of RPC, Unlimited and dedicated RPC, gRPC,
  shreds and bundle plans, the services the account runs, each region's
  health, and which server each chain's nodes need); can run commands on
  your computer when you allow it, every command until the conversation
  ends if you say so; opens the ERPC dashboard for monthly and yearly plans,
  and shows the link instead over SSH, without a display, from a script or
  with `--json`; suggests the message you are likely to send next (Tab
  takes it); and speaks English, Japanese, Simplified Chinese and Russian,
  as does the rest of erpc (`erpc config set language`).
- `erpc resume` and `erpc memory` (`list`, `forget`, `clear`): saved
  conversations, and what the assistant remembers between them
  (`~/.erpc/conversations/`, `~/.erpc/memory.json`).
- `erpc ai` skills by subject, named by chain, role and network
  (`solana-validator-mainnet`, `solana-validator-testnet`,
  `solana-rpc-mainnet`, `ethereum-node`, `avalanche-node`, `sui-node`,
  `erpc-account`, `erpc-services`, and more), each a `SKILL.md` the
  assistant reads when a question needs it. The mainnet validator skill
  covers hardware, clients, BLS, node tuning and safe restarts.
- `erpc skills list` and `erpc skills install [--agent claude]`: the skills
  written to `~/.erpc/skills/<name>/SKILL.md`, and to Claude Code's skills
  directory when asked. A file changed since erpc wrote it, or a skill erpc
  did not write, is left as it is. The installer runs `erpc skills install`
  after putting the binary in place.
- `erpc worker` (`w`): your own app as a tuned Rust binary on an ERPC VPS or
  bare metal. `init` picks a template (an HFT scaffold, a pump.fun bot) and
  `check` reads the manifest back; `key new`, `import`, `show` and `balance`
  keep the trading key straight in 1Password; `secret put` and `list` keep
  API tokens there; `run` builds and runs the app here, `build` builds it
  for the server, `bench` measures it; `deploy` (with `--new-vps`, `--grpc`,
  `--shreds`; prices asked first) puts it on a server under a supervising
  agent that holds the keys, and `releases` and `rollback` move between
  deploys; `status`, `logs`, `start`, `stop`, `restart`, `list` and
  `delete` manage it; `firewall` manages the server's nftables rules and
  `backup` its backups. `build` and `deploy` keep cargo's output in
  `target/erpc-build.log` and show only the warning count or the
  diagnostics. The erpc binary embeds the worker agents it installs (static
  musl, `x86_64` and `aarch64` Linux); `erpc version` prints their SHA-256.
  `[services]` in `erpc.toml` puts Redis and PostgreSQL on the server.
- `erpc storage` (`st`) and `erpc backup`: ERPC Global Storage plans
  (`buy`, `resize`, `usage`, `plan`), files `put`, `get`, `list`, `delete`
  and `sync` with an account key that encrypts them before they leave the
  machine (`key`, `keys`; `docs/storage-encryption.md` has the format), and
  machine backups with a pinned restic (`init`, `run`, `snapshots`,
  `restore`, `check`, `prune`, `schedule`, `status`, `password`;
  `docs/backup.md` sets out who holds which key).
- `erpc wallet create` and `show`: one Base wallet per person, made by erpc
  with its key kept only in 1Password, that buys ERPC Credit with EURC
  through x402 (an EIP-712 `TransferWithAuthorization` signed in memory).
- `erpc signup` and `erpc config` (`get`, `set`, `path`, `init`): the
  sign-up page, and the public settings in `~/.erpc/config.toml`.
- On Linux, sessions kept without a desktop: the kernel keyring where no
  Secret Service answers, and 1Password through an `op signin` session where
  there is no 1Password app.
- `erpc --json <command>` works for every command, and a failure reads the
  same everywhere: an `error:` line and a `hint:` line, or one JSON object, with the exit codes
  in `docs/errors.md`.
- A scheduled workflow (`jito-regions`) checks the Jito region table erpc
  carries against Jito's documentation once a week and opens an issue when
  they differ.

### Changed

- The 1Password session item is titled with the machine's own name, read
  from the operating system, instead of `$HOSTNAME`, which shells do not
  export: every machine was `unknown-host`. A session kept in 1Password
  before this needs `erpc login` once; the old `… @unknown-host` item can
  then be deleted.
- The crates `erpc-chain-arc`, `erpc-chain-avax`, `erpc-chain-bitcoin`,
  `erpc-chain-eth`, `erpc-chain-nitro`, `erpc-chain-op`,
  `erpc-chain-rollup`, `erpc-chain-sui`, `erpc-chain-tron`, `erpc-worker`
  and `erpc-worker-agent` join the workspace (26 crates in all).
- `scripts/reserve-crates.sh` reserves the workspace crates missing from
  crates.io with placeholder 0.0.1 packages (a name, a licence, a
  description and an empty library; nothing of the tree), after checking
  that every crate already there is owned as `erpc` is. The 0.0.1-only rule
  stands: a real version comes from the release pipeline alone.
- The endpoint gate learns `NODE_HOSTS`, the hosts a node reaches from the
  playbooks and templates erpc carries, accepted in those trees only, and
  `ADDRESS_ECHO_HOSTS`, the services `erpc ai` may ask for the operator's
  public address. `docs/public-hosts.md` lists both.

### Fixed

- The `solana/pumpfun` template trades on PumpSwap again: its
  `ultima-swap-pumpfun` dependency moves to `dbbe5f6`, which passes the
  buyback fee recipient (and `pool-v2` on pools with a coin creator) that
  `buy` and `sell` now require. Every trade had failed in simulation with
  `BuybackFeeRecipientMissing` (6058).
- `erpc ai` no longer garbles a character that arrives split between two
  network chunks.

## [0.1.0-rc.1] - 2026-11-02

First release through the release pipeline, as a prerelease: binaries for
five targets, the `install.erpc.global` installers, a GitHub Release with a
minisign-signed manifest, and the crates published by Trusted Publishing.
Apart from the entries below, the code is that of 0.0.1.

### Added

- The release signing key (minisign, key ID `A84D7BB71B974545`) in
  `crates/erpc-release/pubkey.txt`, replacing the placeholder.

### Fixed

- The `aarch64-unknown-linux-musl` release build links: the vendored libdbus
  is compiled without outline atomics (`.cargo/config.toml`).
- The rebuild comparison runs on the runner images cargo-dist builds on, with
  the same C compiler. In 0.0.1 it rebuilt on a different image with
  cargo-zigbuild. `docs/verify-release.md` states what the comparison does
  and does not show.
- `scripts/reserve-crates.sh` publishes in dependency order, paces new crates
  to the crates.io rate limit and refuses any version but 0.0.1.

## [0.0.1] - 2026-11-02

Published to crates.io by hand from commit `964b507` to reserve the crate
names. There is no GitHub Release, no binary and no signature for this
version.

### Added

- Cargo workspace (`erpc` binary and 14 library crates), pinned toolchain,
  `cargo-deny` / `cargo-audit` policy, REUSE compliance, security policy,
  contribution and governance documents.
- `erpc version [--json]`.
- `erpc login`, `logout`, `whoami` and `doctor`: sign in to an ERPC account
  through the OAuth device authorization grant, keep the session in the
  1Password desktop app, a 1Password service account, the OS keychain or a
  file, and report where it is and why.
- On Linux, sessions kept without a desktop: the kernel keyring where no
  Secret Service answers, and 1Password through an `op signin` session where
  there is no 1Password app.
- `erpc ai` reads the signed-in account: credit balance and history, card
  subscriptions, RPC usage and the AI plan, through read-only tools that
  pass on only the fields they name.
- `erpc ai` knows what ERPC sells and what is free now: the server
  catalogue (VPS, Super VPS, Premium VPS, bare metal by type), servers in
  stock by region, the prices of RPC, Unlimited and dedicated RPC, gRPC,
  shreds and bundle plans, the services the account runs, and each region's
  health; and which server each chain's nodes need.
- `erpc ai` skills by subject, named by chain, role and network
  (`solana-validator-mainnet`, `solana-validator-testnet`,
  `solana-rpc-mainnet`, `ethereum-node`, `avalanche-node`, `sui-node`,
  `erpc-account`, `erpc-services`), each a `SKILL.md` the assistant reads
  when a question needs it. The mainnet validator skill covers hardware,
  clients, BLS, node tuning and safe restarts.
- `erpc skills list` and `erpc skills install [--agent claude]`: the skills
  written to `~/.erpc/skills/<name>/SKILL.md`, and to Claude Code's skills
  directory when asked. A file changed since erpc wrote it, or a skill erpc
  did not write, is left as it is. The installer runs `erpc skills install`
  after putting the binary in place.
- `erpc-secret`: the key-use gate and the `op://` reference parser.
- `erpc-api`: the account lookup against `user-api`.
- CI (fmt, clippy, tests on Linux/macOS/Windows, deny, audit, reuse, gitleaks,
  public-host check, endpoint allowlist, zizmor, `dist plan`).
- cargo-dist release pipeline with GitHub Attestations, CycloneDX SBOM,
  `cargo-auditable`, release gate, independent rebuild comparison for Linux,
  minisign-signed release manifest and crates.io Trusted Publishing. Release
  artifacts are published on GitHub Releases only. Prerelease tags run the
  full release workflow and are published to crates.io as semver
  prereleases.
- `install.erpc.global` Cloudflare Worker serving the installers.
- `docs/verify-release.md`: verify signatures against a key saved once from
  `main`, not against `pubkey.txt` at the tag being checked.

[Unreleased]: https://github.com/elsoul/erpc-cli/compare/v0.1.0-rc.3...HEAD
[0.1.0-rc.3]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.1
[0.0.1]: https://github.com/elsoul/erpc-cli/tree/964b507d0276254aeec4451cfbdecc8effd83724
