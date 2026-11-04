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

## [0.1.0-rc.2] - 2026-11-04

Everything erpc does beyond signing in, developed since 0.1.0-rc.1 and
brought into this repository as one change. The commands exist and pass
their offline checks; acceptance on real hosts is still under way for most
chains, and each chain's guide in `docs/chains/` says where it stands.

### Added

- `erpc validator` (`v`), `erpc rpc` (`r`) and `erpc node` (`n`): RPC nodes
  on 12 chains (Solana, Ethereum, Base, Optimism, Soneium, Arbitrum,
  Robinhood Chain, Avalanche, Bitcoin, Sui, TRON, Arc) and validators on
  five (Solana, Ethereum, Avalanche, Sui, TRON), with the same verbs on
  every implemented chain: `init`, `deploy`, `status`, `logs`, `start`,
  `stop`, `restart`, `update`, `update-config`, `plan` and `destroy`. Six
  more chains (Polygon, BNB Chain, Kaia, Monad, Hyperliquid, NEAR) are
  researched in `docs/chains/` and answer "not implemented yet". Live
  acceptance on real hosts is still under way for most chains. Every deploy
  logs in over SSH with a key from the 1Password SSH agent or `SSH_AUTH_SOCK`
  and pins the host key. What it sets up on the host differs by chain, and
  `docs/nodes.md` lists the differences: Solana nodes run as a login user with
  passwordless sudo, Solana also fetches some tools without a checksum, and
  Solana validators, Ethereum validators and Bitcoin nodes get no firewall
  from erpc. Node and validator records,
  identities and keys live in 1Password; nothing is written to the operator's
  disk. `docs/nodes.md` has the clients, networks and guides.
- `erpc rpc --chain solana`: Solana mainnet RPC nodes, the port of `slv rpc`,
  with agave, jito or Firedancer (Frankendancer) and SLV's four RPC types
  (SendTx, Index with Old Faithful, Geyser gRPC, Index + gRPC). Every
  release the node builds or downloads is pinned in its 1Password item;
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
- `erpc --json <command>` works for every command, and a failure reads the same everywhere: an
  `error:` line and a `hint:` line, or one JSON object, with the exit codes
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

[Unreleased]: https://github.com/elsoul/erpc-cli/compare/v0.1.0-rc.2...HEAD
[0.1.0-rc.2]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.1
[0.0.1]: https://github.com/elsoul/erpc-cli/tree/964b507d0276254aeec4451cfbdecc8effd83724
