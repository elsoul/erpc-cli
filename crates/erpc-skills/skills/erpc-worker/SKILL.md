---
name: erpc-worker
description: Running the user's own app on a server with `erpc worker` (`erpc w`): making it from a template (the pump.fun trading bot), keys and secrets in 1Password or the keychain, deploying it to an ERPC VPS with gRPC, Shreds or Unlimited RPC lines, running, firewalling and removing it, what it costs per hour and how to stop paying, trade history in Redis, backups, its API from here, getting the SOL out.
---

# Worker apps on the user's server

`erpc worker` runs an app of the user's own on a server, wrangler-style: `erpc.toml` at the app's
root describes it, and the commands build, deploy and run it. The full guide is `docs/worker.md`
in the erpc repository.

## What to know before acting

- **The key never touches a disk.** An app's trading key lives in 1Password or the OS keychain,
  and reaches the server's agent on a pipe, in memory only. Never suggest a `wallet.json`, a
  `.env` file, or pasting a key into a command line. `erpc worker key new` makes one,
  `erpc worker key import <FILE> --wipe` takes an existing file in and removes it.
- **Secrets** go through `erpc worker secret put <NAME>`, which asks for the value without
  showing it, or reads it from a pipe. `[secrets]` in erpc.toml holds only references. In a
  shell that is not a terminal the hidden prompt cannot be shown: it reads standard input and
  moves on, so the user runs it in a real terminal.
- **After a reboot** the worker is **locked** on purpose: `erpc worker start` sends the key
  again. Do not treat locked as broken.
- **Money:** `--new-vps`, `--grpc`, `--shreds` and `--unlimited` (on `deploy`, and `--grpc`,
  `--shreds` on `run`) start hourly products. erpc
  shows each price and asks; `-y` never answers that question. Start one only when the user
  asked for it, and say what it costs per hour and that `erpc worker delete --release-server`
  ends it all.
- **1Password approvals:** reading a secret or using an SSH key in 1Password may show an
  approval prompt in the 1Password app. "authorization timeout" means nobody allowed it.

## From erpc ai: run it, or hand it over

`run_command` runs erpc with no terminal attached and stops a command after five minutes, so
some steps are yours and some are the user's. Name the app in every command (`erpc worker
check <app>`): `run_command` cannot change directory.

- **Run yourself**, without asking: `check`, `list`, `status`, `logs -n <N>`, `releases`,
  `key show`, `key balance`, `secret list`, `firewall list`, `backup status`. Also `init
  --template <id> --name <name> --yes`, `key new`, `firewall allow/deny`, `stop`, `backup
  on/off`, which ask the user through erpc's own prompts or need none.
- **Hand over**, with the exact line for the user to type in their terminal, then read the
  result with `status`/`logs`:
  - `erpc worker secret put <NAME>`: the hidden prompt needs a terminal. Never pipe a secret
    into it from `run_command`, and never ask the user to paste a secret into the chat.
  - For an app with a `[wallet]`: `run`, `deploy`, `start`, `restart`, `rollback`. The key
    gate needs a person at a terminal; from `run_command` it refuses with "no terminal is
    attached".
  - Anything that buys or ends an hourly product (`--new-vps`, `--grpc`, `--shreds`,
    `--unlimited`, `delete --release-server`): the price prompt needs the user's yes.
  - `logs -f`, `build`, `backup now`, a first `deploy`: longer than five minutes.

## Getting an app running

One order, the same in `erpc worker init`'s Next box, `docs/worker.md` and the template's
README. Ask first, one question at a time (`ask_choice`): do they use the 1Password desktop app
(else the keychain: see **Without 1Password**)? a server already (`--vps <ID>` from
`my_services`, `--host <ADDRESS>`), or a new hourly one? SOL they can afford to lose?

```bash
erpc login                             # once per machine; 1Password or the keychain
erpc worker init                       # arrow keys: HFT, Stablecoin (soon), pumpfun-bot; --template hft skips it
erpc worker key new                    # the trading key; prints the public key to fund
erpc worker secret put API_TOKEN       # the bot's own API token: 16+ random characters
erpc worker secret put ERPC_API_KEY    # the account's RPC key (dashboard), or SOLANA_RPC_ENDPOINT in [vars]
erpc worker check                      # what is missing, every problem at once
erpc worker run --grpc --ip <IPV4>     # here, with an hourly gRPC line that lets this machine in
erpc worker deploy --new-vps --grpc    # a new hourly VPS and gRPC line, prices asked
```

- `API_TOKEN` is any 16 or more random characters; `openssl rand -hex 24` makes one.
- A setting a line provides (`GRPC_ENDPOINT`, `SHREDS_ENDPOINT`, `SOLANA_SEND_RPC_ENDPOINT`)
  is not a secret: `--grpc`/`--shreds`/`--unlimited` set it. The RPC for reads is one of
  `ERPC_API_KEY` or `SOLANA_RPC_ENDPOINT`; `check` names the set when neither is there.
- Before the first `deploy` from a Mac: `rustup target add x86_64-unknown-linux-gnu`, `zig`,
  `cargo-zigbuild`, and an SSH key; `deploy` says which is missing.

- The server: `[env.<name>]` in erpc.toml, else `--vps <ID>` (an ERPC VPS of the account),
  `--new-vps` (cheapest, nearest region; `--region`, `--plan`), or `--host <ADDRESS>` (a server
  of their own, with `--user`, `--port`, `--fingerprint`).
- Lines: `--grpc` sets `GRPC_ENDPOINT`, `--shreds` sets `SHREDS_ENDPOINT`, `--unlimited` sets
  `SOLANA_SEND_RPC_ENDPOINT` (the app sends through the Unlimited RPC and reads elsewhere). They
  admit the server's address and take no token. An Unlimited RPC takes up to 45 minutes to be
  ready.
- `--env <NAME>` deploys another environment (staging, prod) of the same app.
- **On this machine first:** `erpc worker run --grpc --shreds --ip <IPV4>` gives a local run
  lines that admit this machine's public IPv4 (`curl -4 -s https://api.ipify.org` shows it; erpc
  does not look it up). An active line that admits it already is taken up, else a new hourly
  one is bought after its price is asked. The endpoints reach the app's environment only, not
  erpc.toml. When the run ends, Ctrl-C included, erpc asks to end each hourly line;
  `--keep-lines` keeps them, still charged, for the next run with the same `--ip`. Say that
  numbers measured here include this machine's distance to the line.

## The pumpfun-bot template

The bot buys new PumpSwap pools and sells them at a profit target, a timeout or a liquidity
collapse. Its README has every setting; the trade settings are read and changed on its API
(`GET` / `PUT /api/config`, with the `API_TOKEN` bearer).

- **Two kinds of pool.** Graduations, made by pump.fun's program when a token's bonding curve
  completes, and pools made by hand by calling PumpSwap directly. Most pools opened only to be
  pulled seconds after the bots buy are the second kind. `graduated_only: true` buys
  graduations only; suggest it to a user who keeps losing to pulled liquidity.
- **Speed.** A graduation is bought from its `create_pool` instruction, with no RPC read first
  and no simulation, so a buy that lands and fails pays its fee. Pools made by hand are still read
  from the RPC first.
- **Zero-block buys.** With a Shreds line (`SHREDS_ENDPOINT`, `deploy --shreds`), every
  graduation is seen before any node has run it and timed: `GET /api/timing` gives p50/p90 of
  Shreds → Geyser processed → confirmed, and each buy's `slots_late` (0 = the pool's own slot).
  `buy_on_shreds: true` buys from the Shreds stream. To measure from this machine before paying
  for a server: `erpc worker run --shreds --grpc --ip <IPV4>`, then `GET /api/timing` (the
  numbers include this machine's distance). Tune one change at a time, as the README's
  steps go: measure with it off (`via: geyser` gives the `slots_late` to beat), turn it
  on alone, then raise the priority fee in small steps, then try `--unlimited`; back off
  when buys fail more than they land. Have the user read `/api/timing` before
  turning it on, and say plainly: a buy sent that early can land before the pool exists and fail,
  paying its fee; nothing guarantees the same slot; `priority_fee_micro_lamports` (with
  `compute_unit_limit`, default 200000) and a send RPC close to the leader (`--unlimited`) are
  what move it, and the priority fee is counted in the buy's cost for the take-profit. The
  timing is kept in memory only.
- **Bans.** A creator who opens more than `creator_max_pools` pools within
  `creator_window_secs`, or pulls liquidity, is banned, kept in Redis. A graduation's creator is
  the token's deployer. `banned_creators` adds addresses by hand. A ban is a map lookup, so a
  long list costs the trading path nothing.
- **Deepening the bans.** `POST /api/bans/trace?limit=10` bans, for each banned creator not traced
  before, the wallet that first sent it SOL and the other wallets that funder sent SOL to lately;
  each run also traces what the last one banned. Wallets with 1000+ transactions (exchanges,
  services), funders paying 50+ wallets, and the bot's own wallet are never banned. It reads
  about 200 transactions per creator from the read RPC: suggest it now and then, not in a loop.
- **The cycle.** After a deploy the bot idles until `POST /api/trade/start` (`erpc worker api
  /api/trade/start -X POST`); it then buys a pool, sells it at the target, the timeout or a
  liquidity collapse, closes the token account, and with `AUTO_LOOP=false` stops there until
  started again. `?mode=sell_only` sells what is held and buys nothing. `PUT /api/config`
  changes last for the running process only: put lasting ones in erpc.toml and redeploy.
- **Before stop, restart or rollback** erpc warns that positions wait while the app is down; a
  redeploy says so only as it restarts the app, after its yes. So before any of them, wind down
  first: `erpc worker api /api/trade/start?mode=sell_only -X POST`,
  then `erpc worker api /api/trade/status` until `active_positions` is 0.
- **The way out for the SOL:** `erpc worker key send --to <PUBKEY> --sol <AMOUNT>` (or `--all`
  for everything but the fee) moves SOL out of the trading wallet after the user's yes; it
  reads the key behind the same gate as a run, so it cannot be run from erpc ai. It says
  "nothing was sent" only when the RPC refused the transfer; when the RPC gave no answer it
  follows the transfer by its signature until it lands or its blockhash is past, and when it
  ends with "may have gone out", the user looks that signature up before sending again: a
  second send is a second transfer. Tokens still held are sold by the bot (`sell_only`), not
  by erpc.
- To check how a trade went, read the wallet's transactions on-chain: the bot's own history is
  `erpc worker trades` (`--profit`), which needs Redis on the server.

## Faster, step by step

The lines are steps, and a user takes the next one when the numbers say the one before is
no longer what holds the bot back. Find the step the user is on from erpc.toml (`[env.<name>].lines`)
or the settings their run has, say what the next one costs per hour, and move one step at a time.

| Step | Line | What changes | Suggest the next when |
|---|---|---|---|
| 1 | gRPC (`--grpc`) | Pools seen at processed, bought with a simulation; `graduated_only` for a user losing to pulled liquidity | `/api/timing` shows buys landing a slot or more after the pool, once the price has moved |
| 2 | Shreds (`--shreds`) | Graduations seen before any node ran them; `buy_on_shreds` buys from there | `shred_to_processed_ms` is short but `slots_late` stays above 0: the bot is not slow, the send route is |
| 3 | Unlimited RPC (`--unlimited`) | Sending through an RPC of their own in the server's region; `erpc worker bench` shows the gain | Still late at a priority fee they will pay: bandwidth at the leader, not distance, is the limit |
| 4 | SWQoS | A stake-backed connection with the priority bandwidth leaders give stake | erpc does not start it. Say so, and that step 3 is the top of what erpc starts; promise nothing about it |

- A user who finds zero-block buys hard (buys failing, `slots_late` not moving with the fee)
  is at the 2 → 3 line: name the Unlimited RPC, and what `/api/timing` showed that says so.
- Suggest a step down when buys fail more than they land or the fee eats the profit; each
  step is charged by the hour, and `erpc worker delete --release-server` ends them all.
- Numbers measured on this machine (`erpc worker run --ip`) include its distance to the lines:
  the decision is made on the server that will trade.

## Redis and PostgreSQL on the server

An app that needs a local database says so in erpc.toml, and every deploy installs (once, from
Ubuntu's packages) and starts it before the app:

```toml
[services]
redis    = true    # the app gets REDIS_URL = redis://127.0.0.1:6379/
postgres = true    # the app gets DATABASE_URL over the local socket, no password
```

- **Which:** Redis for short-term memory (a cache, a ban list, recent trades: fast, cheap to
  lose); PostgreSQL for long-term memory (records and history to keep and query). Suggest the
  one the user's use calls for; both only when both are needed.
- To add one to a running app: set it in `[services]`, then `erpc worker deploy`. Nothing else
  is installed by hand, and neither listens beyond the server.
- Their data is not in `erpc worker backup`: for the pumpfun bot that backup holds an empty
  state directory, since its history and bans live in Redis. `backup on` says so.
- The pumpfun template reads Redis only (`REDIS_URL`); `postgres = true` gives it a
  `DATABASE_URL` it never opens. Suggest PostgreSQL for an app that reads it. A local
  `erpc worker run` has no Redis unless `REDIS_URL` is set in `[vars]`: history and bans then
  last for that run only.
- Reading the history from this machine: `erpc worker trades` (`--profit`), or any route with
  `erpc worker api <PATH>`; the token is read here, never shown, and the API stays on loopback.

## Day to day

| The user wants | Command |
|---|---|
| Is it running, which release | `erpc worker status` (also names the hourly server and lines on record) |
| What am I paying for right now | `credit_balance` (its `hourlyResources`, with the price per hour) or `my_services`; `erpc worker status` for what this app's environment holds |
| End one line, keep the bot | `end_hourly_product` on that line, then `erpc worker deploy --forget-line <ID>` so the record follows |
| Its log | `erpc worker logs -n 200`, `erpc worker logs -f` |
| Start, stop, restart | `erpc worker start`, `erpc worker stop`, `erpc worker restart` (`stop` ends no hourly product, and says so) |
| Drop the key from the server's memory | `erpc worker stop --lock` |
| Go back a release | `erpc worker releases`, then `erpc worker rollback` or `erpc worker rollback --to <RELEASE>` |
| Who may reach the server | `erpc worker firewall list` |
| Open the API to an address | `erpc worker firewall allow --to app <ADDRESSES>` |
| Remove an address | `erpc worker firewall deny --to ssh <ADDRESSES>` |
| Put the firewall back as erpc.toml says | `erpc worker firewall sync` |
| Compare RPC latency from the server | `erpc worker bench` (the erpc-rpc-bench skill) |
| Back its state up every day | `erpc worker backup on --at 03:00` (needs a storage plan) |
| Is it backed up, how did the last run go | `erpc worker backup status` |
| Back up now | `erpc worker backup now` |
| Stop backing up | `erpc worker backup off` (the snapshots stay) |
| Remove it, and end what it pays for | `erpc worker delete --release-server` |
| Their apps on this machine | `erpc worker list` |
| What erpc.toml describes and lacks | `erpc worker check` |
| The wallet's SOL | `erpc worker key balance`; `erpc worker key send --to <PUBKEY> --sol <N>` moves it out |
| Forget a server that is gone | `erpc worker delete --forget`; a line ended elsewhere: `--forget-line <ID>` on deploy or delete |

- The firewall drops every inbound connection but SSH from the allow list and the app's
  `run.port` from `firewall.app_allow`. An API that should be reached needs both
  `firewall.app_allow` and `API_BIND = "0.0.0.0"` in `[vars]`. Each firewall change rolls itself
  back within 120 s unless a fresh connection gets in, so a mistaken change cannot lock the user
  out. The list outlives the address it was made from: a changed home address does lock them
  out, and the way back in is ERPC support for an ERPC server, or the provider's console for a
  server of their own (`--host`), so have them keep a second address they can reach the server
  from in `firewall.ssh_allow` (an office, a VPN exit).
- SSH allows single addresses only; networks go to `--to app`.
- A failed deploy rolls back to the previous release by itself; `erpc worker logs` says why.
- A backup holds the app's state, `/var/lib/private/erpc-worker-<id>`, not its releases, copied
  while the worker runs (a database may need its own dump). It is set up from this machine: the
  server gets its own append-only key and restic key, never the session or the admin key, so it
  cannot delete snapshots. But the account has one repository: a server taken over can read
  every machine's snapshots, keeps the repository's key after `off`, can add snapshots under
  another machine's name, and can fill the account's storage. Tell the user this before `on`; revoking its access key (`off`) cuts
  it off.
- Snapshots are named for the worker and its server, erpc-worker-<id>-<tag> (`on` prints it). Restore from this machine,
  after `erpc backup init` there, with `erpc backup restore latest --from-host
  erpc-worker-<id>-<tag> --path /var/lib/private/erpc-worker-<id> --target <dir>` (the
  erpc-storage skill). `off` revokes the keys first, even when the server cannot be
  reached; `erpc worker delete` revokes them once it goes ahead, so for a server taken over or
  unreachable, run `off` first. When `off` exits non-zero, it lists what is left, and `erpc storage
  keys revoke <n>` removes an access key by hand. `on` records the keys' numbers in
  `[env.<name>.backup]`: commit erpc.toml's change (an inventory environment keeps it in its
  1Password item). The snapshots stay; `erpc backup prune
  --host erpc-worker-<id>-<tag>` thins out old ones.

## Without 1Password

`erpc login` offers the stores this machine has; without the 1Password desktop app it keeps the
session in the OS keychain, and `key new` and `secret put` then use the keychain too
(`--store keychain` says so outright). What that means, said before the first command:

- The key exists on this one machine only, in its keychain; there is no copy and no sync, and
  another machine cannot read it (`keychain:` references are refused there). A lost or wiped
  machine means the wallet is gone: keep little in it, or use 1Password.
- Linux needs a desktop keyring (a Secret Service: GNOME Keyring, KWallet) in a logged-in
  session. A headless server, WSL or an SSH login has none, and erpc refuses to keep the key
  there; the way out is 1Password through `op` (`erpc login --store 1password-desktop` or a
  service account), not a file.
- `--store file` for the session leaves a secret on disk; never suggest it for a key.

## Another machine, 1Password inventory

An environment with `inventory = { vault = "<vault-id>" }` keeps its server facts in a 1Password
item instead of erpc.toml: any machine signed in to the vault, with the app's repository, can
run every command. A new environment becomes one when `erpc login` keeps the session in
1Password; `erpc worker deploy --vault <VAULT_ID>` chooses a vault, `--inline` keeps erpc.toml.
`erpc worker list` also shows worker items in the login vault that no app here names. In such an
app, keys in the keychain cannot be read elsewhere: suggest 1Password for them.

## When something fails

- "cannot start without <SETTING>": `erpc worker secret put <SETTING>`, a `[vars]` entry, or the
  line flag that sets it.
- "your key was added but does not get in": 1Password did not sign; unlock it, allow the
  request, run the same command again.
- "release … failed …; the server went back to …": the previous release still runs; read the
  log.
- "locked": `erpc worker start`. A reboot locks the worker on purpose, and nobody is told: the
  hourly server and lines keep charging while it sits locked, so after a reboot the user runs
  `erpc worker start` or `erpc worker delete --release-server`.
- "Is my bot still trading?": `erpc worker status` (the agent's state and what is charged),
  `erpc worker api /api/trade/status` (`running`, `active_positions`), `erpc worker logs -n 50`.
  With Redis on the server the bot comes back trading as it was after a restart; without it,
  every start comes up with trading off until `POST /api/trade/start`.
- A line that did not become active is on record: deploying again waits for it,
  `erpc worker delete --release-server` ends it.
- "changed in 1Password since this command read it": another machine deployed; run it again.
