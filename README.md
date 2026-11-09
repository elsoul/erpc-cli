<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

<div align="center">

# erpc

**Run validators, RPC nodes and your own apps on 18 chains, with 1Password-backed access and key management.**

One command line for your nodes, your apps and your [ERPC](https://erpc.global) account,
and an assistant that runs it for you when you ask.

[Install](#install) · [Nodes](#validators-and-rpc-nodes) · [erpc ai](#erpc-ai-just-ask) · [erpc worker](#erpc-worker-your-app-as-a-tuned-rust-binary) · [Free or with an account](#free-to-start)

</div>

## Where your keys are

erpc uses **1Password** for node inventory and managed signing-key backups,
and supports the operating system's keychain for operator credentials.
A node process needs its runtime secrets, so what stays on a server depends
on the chain: [Running nodes](docs/nodes.md#where-keys-are-kept) has the table.

- **Solana validators.** Original identities are retained in 1Password. A new
  native validator syncs under a separate non-voting identity; voting needs
  explicit registration and history checks. The withdrawal authority is not
  imported into the node. Other chains have their own custody and admission
  rules in the [node guides](docs/nodes.md).
- **Trading bots and Web3 apps.** An `erpc worker` app gets its wallet key on
  a pipe when it starts. The worker holds it in memory only, locked and
  undumpable; there is no `wallet.json`, no `.env`, no copy on disk. After a
  reboot the app stays locked until you send the key again.
- **Secrets.** API tokens and RPC keys are stored as `op://…` or `keychain:…`
  references.
  The values reach the server over standard input, never on a command line.
- **Your team.** The node inventory lives in 1Password too. Share the vault
  and everyone on the team manages the same nodes from their own machine,
  with 1Password deciding who can do what.
- **Keys that stay on a server.** Many nodes hold a key on the host. An Ethereum
  validator's keystores and unlock password live on it, and a Solana node on the
  solv backend keeps a throwaway identity in plain text. Those hosts need backups
  of their own.

Node recovery must preserve the original identity and signing history.
Follow the chain's recovery procedure before replacing a server or restoring
its data; a key backup alone does not establish safe validator recovery.

## Install

**macOS and Linux**

```bash
curl -fsSL https://install.erpc.global/v0.1.0-rc.2 | sh
```

**Windows** (PowerShell)

```powershell
irm https://install.erpc.global/v0.1.0-rc.2/ps1 | iex
```

These name a version because every release so far is a pre-release, and the
unversioned `install.erpc.global` serves only the latest stable one.

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

## Validators and RPC nodes

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

`init` prepares a server and `deploy` installs and starts the node; every chain
uses the same verbs. An Ethereum RPC node starts from a bare Ubuntu server
(24.04 or later):

```bash
# check the server, pin the client releases, store the node in 1Password
erpc rpc --chain ethereum -n mainnet --name eth1 init --host <address> --vault <vault id> --ssh-key ~/.ssh/id_ed25519.pub
# install, fetch a snapshot, apply the firewall, start
erpc rpc --chain ethereum -n mainnet --name eth1 deploy --ssh-key ~/.ssh/id_ed25519.pub
# both layers, sync and head
erpc rpc --chain ethereum -n mainnet --name eth1 status --ssh-key ~/.ssh/id_ed25519.pub
```

Some chains need more in place first, and each chain's guide says what. A new
Solana validator or RPC node needs three filesystems mounted and its keys
already in 1Password: see [native Solana nodes](docs/solana-native.md). A
Solana node whose server an earlier erpc recorded keeps the commands it was
set up with.

| | Chains |
|---|---|
| **RPC node** (`erpc rpc`) | all 18 |
| **Validator** (`erpc validator`) | Solana, Ethereum, Avalanche, Sui, TRON, Polygon, BNB Chain, Kaia, Monad, Hyperliquid, NEAR, Arbitrum One, Robinhood Chain |

Every deploy logs in over SSH with your key, from the 1Password SSH agent or
`SSH_AUTH_SOCK`, and pins the host key. Most chains run the client as its own
user that cannot log in, check each release against a pinned checksum, and
apply an nftables firewall that uses a timed rollback and requires a fresh
management connection to confirm access. Not all of them do: a new Solana node
is built on the server from a pinned source commit; a Solana node recorded on
the earlier solv backend runs as a login user with passwordless sudo and
fetches some tools without a checksum; and solv Solana validators, Ethereum
validators and Bitcoin nodes get no firewall from erpc.
[Running nodes](docs/nodes.md) has the details. Retain an independent way to
reach the host during network changes.

`init`, `deploy`, `status`, `logs`, `start`, `stop`, `restart`, `update`,
`update-config`, `plan` and `destroy` work the same on every chain, except
that a Solana validator on the solv backend has only `init`, `deploy` and
`status` of them, besides `list`, `keys`, `vote-account`, `registration` and
`migration`. Live acceptance on real hosts is still under way for most chains.
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
  arrow keys. You can allow every command for one conversation, behind a second
  question, and then nothing is asked until it ends.
- **It prefers erpc to improvised scripts.** The assistant drives the same
  commands you would type, and can run other commands and scripts only as you
  allow them. What erpc enforces on a chain is enforced by its
  code every time, not left to what a model writes. What that covers differs by
  chain: [the node guide](docs/nodes.md) lists it.
- **It sets up the server too.** It can start an hourly VPS, wait for it,
  install your SSH key, turn off password logins and allow SSH only from your
  address.
- **It remembers you.** Your hosts, chains and preferences carry over from one
  conversation to the next, and `erpc resume` picks up an old one.

`erpc skills install --agent claude` gives the same knowledge to Claude Code
or another agent. What the assistant can see, and what it never sees, is in
[the assistant guide](docs/ai.md) and [SECURITY.md](SECURITY.md#what-the-assistant-reads).

## RPC calls and webhooks

Use your signed-in ERPC account to call Solana or Ethereum mainnet. The CLI
selects the shared endpoint from the method, or you can select the network.

```sh
erpc login
erpc rpc call getSlot
erpc --json rpc call eth_getBlockByNumber '["latest", false]' --network ethereum-mainnet
erpc rpc call eth_call --params-file params.json
printf '%s' '["finalized", false]' | erpc rpc call eth_getBlockByNumber -
erpc rpc call getHealth --endpoint-url http://127.0.0.1:8899
```

For pay-per-call access without an account, request an x402 quote. To pay,
run the command without `--quote` at a terminal. The CLI shows the amount,
asks for confirmation and signs the quoted Base EURC payment with the wallet
configured by `erpc wallet create`. Keep EURC on Base in that wallet.

```sh
erpc rpc call getSlot --network solana-mainnet --x402 --quote
erpc rpc call eth_blockNumber --x402
```

A local webhook subscribes to the RPC WebSocket and POSTs events to your URL.
Start a receiver, create the subscription, then run the **ID returned by create**
in a terminal or under your process supervisor.

```sh
erpc webhook create --name slots --network solana-mainnet \
  --url http://127.0.0.1:8080/events --method slotSubscribe
erpc webhook create --name heads --network ethereum-mainnet \
  --url http://127.0.0.1:8080/events --method eth_subscribe --params '["newHeads"]'
erpc webhook list
erpc webhook run 1
```

For wallet activity on Solana, use `--template solana-wallet --wallet ADDRESS`
in place of `--method`. For Ethereum contract logs, use
`--template evm-contract-events --address CONTRACT`.

Each POST contains `webhook_id`, `network` and the original JSON-RPC
`notification`. Return HTTP 2xx to accept it. Delivery starts at the current
live subscription. A disconnect or failed callback ends the runner with a
nonzero status. Restarting subscribes to new events. Use `--once` to test a
single delivery or `--endpoint-url` on `run` to supply your own WebSocket RPC.

`webhook show ID`, `list` and `enabled-count` inspect local configuration.
`pause ID` disables delivery, `activate ID` enables a later `run`, and
`delete ID` removes the definition. Pass `--yes` for these changes in scripts.
Generate shell completions with `erpc completions zsh` (also bash, fish,
powershell and elvish).

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

- **Lost access?** If the server may have been taken over, first run
  `erpc worker backup off` to revoke its backup access key, and move funds off its
  trading key and replace its secrets. `off` does not undo what the server already
  read: [the worker guide](docs/worker.md) has the limits. Then rebuild it from the
  [dashboard](https://dashboard.erpc.global) and deploy again. If the rebuild
  changed its SSH host key, erpc refuses it until you update the pinned key. A
  deploy brings back the code, not the app's state, which only a backup can restore.
- **App state** can be backed up daily to ERPC Global Storage, encrypted on the
  server, once you run `erpc worker backup on`. Redis and PostgreSQL data are not
  covered.

Everything about an app is in `erpc.toml`, which holds no secret and can be
committed. [docs/worker.md](docs/worker.md) has the full guide.

## Storage and backups

```bash
erpc storage buy 5        # an ERPC Global Storage plan
erpc backup init          # back this machine up with restic, on a schedule if you like
```

Files are encrypted on your machine before they leave it, and each machine
gets an append-only key that cannot delete its own backups. The machine where you
ran `erpc backup init` also holds the keys that can.
See [storage encryption](docs/storage-encryption.md) and [backups](docs/backup.md).

## Free to start

Validator and RPC node lifecycle commands are free and need no account. Install and go.

An account at [dashboard.erpc.global](https://dashboard.erpc.global) unlocks the rest:

| Command | No account | With an account |
|---|:---:|:---:|
| Validator and RPC node lifecycle | ✅ | ✅ |
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
list its verbs. `erpc --json <command>` gives machine-readable output. On node
commands the flag has to go before the command.

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
| `~/.erpc/backup-password`, `~/.erpc/backup-admin-key` | The backup master password and `read_write` key, when `erpc login` keeps the session in a file |
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

Pre-release (`v0.1.0-rc.2`). The commands above exist and pass their offline
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
