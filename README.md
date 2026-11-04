<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

<div align="center">

# erpc

**Run validators, RPC nodes and your own apps on 18 chains, with no keys on your servers.**

One command line for your nodes, your apps and your [ERPC](https://erpc.global) account,
and an assistant that runs it for you when you ask.

[Install](#install) · [Nodes](#validators-and-rpc-nodes-on-18-chains) · [erpc ai](#erpc-ai-just-ask) · [erpc worker](#erpc-worker-your-app-as-a-tuned-rust-binary) · [Free or with an account](#free-to-start)

</div>

https://github.com/user-attachments/assets/939cf35a-dc72-4a36-bf63-fa055a01c4dc

## No keys on your servers

A server that holds no secret has nothing to steal and nothing to lose.
erpc keeps every key in **1Password** (or your operating system's keychain)
and hands a server only what it needs, when it needs it.

- **Validators.** The staked identity, the vote account key and the withdraw
  authority are kept in 1Password. A new validator syncs under a throwaway
  identity, and the withdraw authority never goes to a server at all.
- **Trading bots and Web3 apps.** An `erpc worker` app gets its wallet key on
  a pipe when it starts. The worker holds it in memory only, locked and
  undumpable; there is no `wallet.json`, no `.env`, no copy on disk. After a
  reboot the app stays locked until you send the key again.
- **Secrets.** API tokens and RPC keys are stored as `op://…` references.
  The values reach the server over standard input, never on a command line.
- **Your team.** The node inventory lives in 1Password too. Share the vault
  and everyone on the team manages the same nodes from their own machine,
  with 1Password deciding who can do what.

Because nothing on the server is precious, you can rebuild any server and
deploy again in minutes.

## Install

**macOS and Linux**

```bash
curl -fsSL https://install.erpc.global | sh
```

**Windows** (PowerShell)

```powershell
irm https://install.erpc.global/ps1 | iex
```

The installer puts `erpc` in `~/.erpc/bin` and writes the assistant's skills
to `~/.erpc/skills`. Builds are published for Linux (x86_64, arm64), macOS
(Intel, Apple silicon) and Windows (x86_64). Running a mainnet validator? Use the
[high-assurance path](docs/verify-release.md), which checks the signed manifest
before anything runs.

<details>
<summary>Build from source</summary>

```bash
git clone https://github.com/elsoul/erpc-cli
cd erpc-cli
cargo build --release
./target/release/erpc --help
```

</details>

## Validators and RPC nodes on 18 chains

<table>
<tr>
<td align="center" width="96"><a href="docs/chains/solana.md"><img src="docs/assets/chains/solana.png" width="48" alt="Solana"></a><br><sub>Solana</sub></td>
<td align="center" width="96"><a href="docs/chains/ethereum.md"><img src="docs/assets/chains/ethereum.png" width="48" alt="Ethereum"></a><br><sub>Ethereum</sub></td>
<td align="center" width="96"><a href="docs/chains/base.md"><img src="docs/assets/chains/base.png" width="48" alt="Base"></a><br><sub>Base</sub></td>
<td align="center" width="96"><a href="docs/chains/avalanche.md"><img src="docs/assets/chains/avalanche.png" width="48" alt="Avalanche"></a><br><sub>Avalanche</sub></td>
<td align="center" width="96"><a href="docs/chains/bitcoin.md"><img src="docs/assets/chains/bitcoin.png" width="48" alt="Bitcoin"></a><br><sub>Bitcoin</sub></td>
<td align="center" width="96"><a href="docs/chains/polygon.md"><img src="docs/assets/chains/polygon.png" width="48" alt="Polygon"></a><br><sub>Polygon</sub></td>
</tr>
<tr>
<td align="center"><a href="docs/chains/bsc.md"><img src="docs/assets/chains/bnb-chain.png" width="48" alt="BNB Chain"></a><br><sub>BNB Chain</sub></td>
<td align="center"><a href="docs/chains/kaia.md"><img src="docs/assets/chains/kaia.png" width="48" alt="Kaia"></a><br><sub>Kaia</sub></td>
<td align="center"><a href="docs/chains/arbitrum.md"><img src="docs/assets/chains/arbitrum.png" width="48" alt="Arbitrum"></a><br><sub>Arbitrum</sub></td>
<td align="center"><a href="docs/chains/optimism.md"><img src="docs/assets/chains/optimism.png" width="48" alt="Optimism"></a><br><sub>Optimism</sub></td>
<td align="center"><a href="docs/chains/hyperliquid.md"><img src="docs/assets/chains/hyperliquid.png" width="48" alt="Hyperliquid"></a><br><sub>Hyperliquid</sub></td>
<td align="center"><a href="docs/chains/monad.md"><img src="docs/assets/chains/monad.png" width="48" alt="Monad"></a><br><sub>Monad</sub></td>
</tr>
<tr>
<td align="center"><a href="docs/chains/tron.md"><img src="docs/assets/chains/tron.png" width="48" alt="TRON"></a><br><sub>TRON</sub></td>
<td align="center"><a href="docs/chains/sui.md"><img src="docs/assets/chains/sui.png" width="48" alt="Sui"></a><br><sub>Sui</sub></td>
<td align="center"><a href="docs/chains/near.md"><img src="docs/assets/chains/near.png" width="48" alt="NEAR"></a><br><sub>NEAR</sub></td>
<td align="center"><a href="docs/chains/arc.md"><img src="docs/assets/chains/arc.png" width="48" alt="Arc"></a><br><sub>Arc</sub></td>
<td align="center"><a href="docs/chains/robinhood.md"><img src="docs/assets/chains/robinhood.png" width="48" alt="Robinhood Chain"></a><br><sub>Robinhood</sub></td>
<td align="center"><a href="docs/chains/soneium.md"><img src="docs/assets/chains/soneium.png" width="48" alt="Soneium"></a><br><sub>Soneium</sub></td>
</tr>
</table>

Two commands take a bare server to a running node. Every chain uses the same verbs.

```bash
erpc rpc init --chain ethereum        # check the server, pin the client release, store the node in 1Password
erpc rpc deploy --chain ethereum      # install, fetch a snapshot, apply the firewall, start

erpc validator init --chain solana -n testnet
erpc validator deploy --chain solana -n testnet
erpc validator status                 # health, slot, identity and firewall
```

| | Chains |
|---|---|
| **RPC node** (`erpc rpc`) | all 18 |
| **Validator** (`erpc validator`) | Solana, Ethereum, Avalanche, Sui, TRON, Polygon, BNB Chain, Kaia, Monad, Hyperliquid, NEAR, Arbitrum One |

Every deploy logs in over SSH with your key from the 1Password SSH agent, pins
the host key, runs the client as its own user that cannot log in, checks each
release against a pinned checksum, and applies an nftables firewall that
rolls itself back unless a fresh connection still gets in. You cannot lock
yourself out.

`init`, `deploy`, `status`, `logs`, `start`, `stop`, `restart`, `update`,
`update-config`, `plan` and `destroy` work the same on every chain.
[Running nodes](docs/nodes.md) has the clients, networks and guides for each
chain, and the [chain source map](docs/chains/README.md) where each one stands.

## `erpc ai`: just ask

```text
› I want to run a Solana testnet validator
```

`erpc ai` opens a conversation with the ERPC assistant. Say what you want in
your own words; it knows every chain above and every erpc command, and runs
them for you.

- **It asks before it acts.** Anything that spends money or changes a server
  is shown first, with the cursor on **Stop**. Choices are picked with the
  arrow keys.
- **It runs erpc, not improvised scripts.** The assistant drives the same
  commands you would type, so the settings that matter (pinned releases,
  checksums, the firewall, where keys live) are enforced by erpc's code every
  time, not left to what a model writes.
- **It sets up the server too.** It can start an hourly VPS, wait for it,
  install your SSH key, turn off password logins and allow SSH only from your
  address.
- **It remembers you.** Your hosts, chains and preferences carry over from one
  conversation to the next, and `erpc resume` picks up an old one.

`erpc skills install --agent claude` gives the same knowledge to Claude Code
or another agent. What the assistant can see, and what it never sees, is in
[the assistant guide](docs/ai.md) and [SECURITY.md](SECURITY.md#what-the-assistant-reads).

## `erpc worker`: your app as a tuned Rust binary

```bash
erpc worker init                      # pick a template: HFT, pump.fun bot, ...
erpc worker key new                   # the trading key, straight into 1Password
erpc worker run                       # build and run it here first
erpc worker deploy --new-vps --grpc   # a new hourly VPS and gRPC line, prices asked first
```

`erpc worker` makes an app from a template, runs it on your machine, compiles
it to a native Rust binary for Linux and deploys it to a latest-generation ERPC
VPS (or a server of your own). No Docker: the binary runs under a hardened
systemd unit with the whole machine to itself. You can also build one by
talking to `erpc ai`.

- **Locked down on the first deploy.** The firewall lets SSH in only from the
  address you deploy from. If your address changes, add every fixed address
  your admins use:

  ```bash
  erpc worker firewall allow --to ssh 203.0.113.10 198.51.100.7
  ```

- **Lost access?** Rebuild the server from the
  [dashboard](https://dashboard.erpc.global) and deploy again. Nothing secret
  was on it, so nothing is lost.
- **App state** is backed up daily to ERPC Global Storage, encrypted on the
  server: `erpc worker backup on`.

Everything about an app is in `erpc.toml`, which holds no secret and can be
committed. [docs/worker.md](docs/worker.md) has the full guide.

## Storage and backups

```bash
erpc storage buy 5        # an ERPC Global Storage plan
erpc backup init          # back this machine up with restic, on a schedule if you like
```

Files are encrypted on your machine before they leave it, and each machine
gets an append-only key that cannot delete its own backups.
See [storage encryption](docs/storage-encryption.md) and [backups](docs/backup.md).

## Free to start

`erpc validator` and `erpc rpc` are free and need no account. Install and go.

An account at [dashboard.erpc.global](https://dashboard.erpc.global) unlocks the rest:

| Command | No account | With an account |
|---|:---:|:---:|
| `erpc validator`, `erpc rpc` | ✅ | ✅ |
| `erpc ai` | | ✅ |
| `erpc worker` | | ✅ |
| `erpc storage`, `erpc backup` | | ✅ |

```bash
erpc signup     # opens the sign-up page
erpc login      # signs this machine in; the session goes to the keychain or 1Password
erpc whoami
```

## All commands

Run any command group without a verb (`erpc validator`, `erpc worker`) to
list its verbs. Every command takes `--json` for machine-readable output.

| Command | What it does |
|---|---|
| `validator` (`v`), `rpc` (`r`), `node` (`n`) | [Validators and RPC nodes](docs/nodes.md) |
| `ai`, `resume`, `memory`, `skills` | [The assistant](docs/ai.md), its saved conversations, memory and skills |
| `worker` (`w`) | [Your own apps](docs/worker.md) on a server |
| `storage` (`st`), `backup` | [ERPC Global Storage](docs/storage-encryption.md) and [machine backups](docs/backup.md) |
| `wallet` | The Base wallet that buys ERPC Credit with EURC ([details](docs/ai.md#wallet-erpc-wallet)) |
| `signup`, `login`, `logout`, `whoami` | Your ERPC account |
| `doctor` | Report how this machine stores your session |
| `config` | Read and change `~/.erpc/config.toml` (public settings only) |
| `version` | Version, build and component information |

<details>
<summary>Errors and exit codes</summary>

A failure reads the same everywhere: an `error:` line saying what went
wrong, and a `hint:` line saying what to do next when there is one. With
`--json` it is one object on standard output,
`{"error": {"code", "exit", "message", "hint"}}`.

| Exit | Code | Meaning |
|---|---|---|
| 0 | | it worked |
| 1 | `failed` | it could not do what was asked |
| 2 | `usage` | the command line was not usable |
| 3 | `needs_terminal` | a person must answer; pass `--yes` or run it in a terminal |
| 4 | `not_signed_in` | run `erpc login` |
| 5 | `problems_found` | a check (`status`, `doctor`) found problems; its report says which |
| 6 | `declined` | you said no; nothing was changed |
| 7 | `network` | ERPC or another service could not be reached |

The rules for these, and for writing a message, are in
[docs/errors.md](docs/errors.md).

</details>

<details>
<summary>Files erpc keeps</summary>

| Path | What it holds |
|---|---|
| `~/.erpc/config.toml` | Public settings (`erpc config`) |
| `~/.erpc/state/` | The session and locks (`erpc doctor` says how the session is stored) |
| `~/.erpc/conversations/` | Saved conversations |
| `~/.erpc/memory.json` | What the assistant remembers |
| `~/.erpc/vps_hosts.json` | Host keys of VPSs the assistant logged in to |
| `~/.erpc/skills/` | Skills written by `erpc skills install` |
| `~/.erpc/storage-key` | The storage encryption key, when `erpc login` keeps the session in a file |
| `~/.erpc/backup.env` | This machine's backup credentials (0600) |
| `~/.erpc/bin/restic-0.19.1` | The pinned restic `erpc backup` installs |

</details>

<details>
<summary>Repository layout</summary>

| Path | Purpose |
|---|---|
| `crates/erpc` | The binary: commands, the terminal UI, the node flows |
| `crates/erpc-core`, `erpc-auth`, `erpc-api`, `erpc-secret` | Shared types, sign-in, the ERPC API client, 1Password |
| `crates/erpc-ssh`, `erpc-ops`, `erpc-chain*` | SSH, server operations, and each chain's specifics |
| `crates/erpc-ai`, `erpc-skills` | The assistant and its skills |
| `crates/erpc-worker`, `erpc-worker-agent` | `erpc worker`, its app templates, and the agent that holds keys on the server |
| `crates/erpc-mcp-server` | An MCP server for AI agents (placeholder) |
| `crates/erpc-wallet`, `erpc-x402` | The EURC wallet and buying credit with it |
| `crates/erpc-release` | Release manifests and verification |
| `installer/` | Cloudflare Worker for `install.erpc.global` |
| `scripts/` | Hygiene and release helpers |
| `docs/` | Guides, release verification, compliance, public hosts, incident response |

</details>

## Status

Pre-release (`v0.1.0-rc`). The commands above exist and pass their offline
checks; acceptance on real hosts is still under way for most chains, and each
chain's guide says where it stands. erpc is the Rust successor of
[SLV](https://github.com/ValidatorsDAO/slv).

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) and
[`GOVERNANCE.md`](GOVERNANCE.md). Every URL in this repository must name a
host declared in `crates/erpc-core/src/endpoints.rs`, as
[`docs/public-hosts.md`](docs/public-hosts.md) explains.
`lefthook install` sets up the pre-commit checks for this, along with
clippy, the tests and a secret scan. The checks only help: review is what
enforces these rules. If a secret ever lands in the repository, follow
[`docs/secret-exposure-response.md`](docs/secret-exposure-response.md) and
rotate it before rewriting any history.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Chain logos come
from [web3icons](https://github.com/0xa3k5/web3icons) (MIT); each is a
trademark of its own project.
