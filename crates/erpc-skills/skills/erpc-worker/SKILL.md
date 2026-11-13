---
name: erpc-worker
description: Running the user's app on a server with `erpc worker` (`erpc w`): making it from a template (HelloWorld, pump.fun bot), keys and secrets (1Password, keychain, keystore), deploying it to an ERPC VPS with gRPC, Shreds or Unlimited RPC lines, running, firewalling and removing it, what it costs per hour and how to stop paying, trade history in Redis, backups, its API from here, getting the SOL out.
---

# Worker apps on the user's server

`erpc worker` runs an app of the user's own on a server, wrangler-style: `erpc.toml` at the app's
root describes it, and the commands build, deploy and run it. The full guide is `docs/worker.md`
in the erpc repository.

## What to know before acting

- **The key never touches the server's disk, and no disk unencrypted.** An app's trading key
  lives in 1Password or the OS keychain, or, on a machine with neither (see **Without
  1Password**), in erpc's keystore: a file on the user's machine, encrypted under their
  passphrase. It reaches the server's agent on a pipe, in memory only. Never suggest a
  `wallet.json`, a `.env` file, or pasting a key into a command line. `erpc worker key new`
  makes one, `erpc worker key import <FILE> --wipe` takes an existing file in and removes it.
- **Secrets** go through `erpc worker secret put <NAME>`, which asks for the value without
  showing it, or reads it from a pipe. `[secrets]` in erpc.toml holds only references. In a
  shell that is not a terminal the hidden prompt cannot be shown: it reads standard input and
  moves on, so the user runs it in a real terminal. With `--generate` (a token of the app's
  own, which erpc makes) or `--from-account` (the account's RPC API key) it asks for no value
  and shows none.
- **After a reboot** the worker is **locked** on purpose: `erpc worker start` sends the key
  again. Do not treat locked as broken. An agent that failed or was killed (out of memory,
  say) is started again by systemd and is locked the same way.
- **Money:** `--new-vps`, `--grpc`, `--shreds` and `--unlimited` (on `deploy`, and `--grpc`,
  `--shreds` on `run`) start hourly products. erpc shows each price and asks at a terminal;
  on `deploy`, `--yes` answers it (the price is still printed), since an hourly product is
  paid from prepaid ERPC Credit and refused when the credit does not cover it. Start one only
  when the user asked for it, and say what it costs per hour and that `erpc worker delete
  --release-server` ends it all. Ending is always the user's to say, at a terminal.
- **1Password approvals:** reading a secret or using an SSH key in 1Password may show an
  approval prompt in the 1Password app. "authorization timeout" means nobody allowed it.

## From erpc ai: run it, or hand it over

`run_command` runs erpc with no terminal attached and stops a command that runs too long, so
some steps are yours and some are the user's. A command that only looks (the first list
below) is stopped after 30 seconds, and any other, which runs once the user has agreed to
it, after five minutes. `erpc worker deploy`, `erpc worker build` and `erpc worker run
--check` have 90 minutes instead, when you give them as `argv`, as they are: inside a
`shell` script they keep the five minutes, so never run them there, nor in the background.
Name the app in every command (`erpc worker check <app>`): `run_command` cannot change
directory.

- **Run yourself**, without asking: `check`, `list`, `status`, `logs -n <N>`, `releases`,
  `key show`, `key balance`, `secret list`, `firewall list`, `backup status`. Also `init
  --template <id> --name <name> --yes`, `key new`, `firewall allow/deny`, `stop`, `backup
  on/off`, which ask the user through erpc's own prompts or need none. And `build`, which
  buys nothing and has the 90 minutes: one that was stopped all the same is run again, and
  cargo carries on from what it has compiled. And `erpc worker secret put <NAME>
  --generate` and `erpc worker secret put <NAME> --from-account`, which ask for no value:
  erpc makes it, or reads the account's RPC API key, and shows it to nobody. They need the
  store open (the keystore unlocked, or 1Password answering); for the keystore see the
  hand-over below.
- **Hand over**, with the exact line for the user to type in their terminal, then read the
  result with `status`/`logs`:
  - `erpc worker secret put <NAME>` for a value the user has to give (neither `--generate`
    nor `--from-account`): the hidden prompt needs a terminal. Never pipe a secret into it
    from `run_command`, and never ask the user to paste a secret into the chat.
  - `erpc worker secret unlock`, and the first `key new` or `secret put` on a machine that
    uses the keystore: the keystore's passphrase is typed at a terminal, by the user. Never
    ask for it in the chat, and never look for a way to pass it to erpc: there is none.
    "the keystore is locked" from a command you ran means the user runs
    `erpc worker secret unlock`, then you run the command again.
  - For an app with a `[wallet]`: `run`, `deploy`, `start`, `restart`, `rollback`. The key
    gate needs a person at a terminal; from `run_command` it refuses with "no terminal is
    attached". What you can do for such an app is everything but the key: once `erpc worker
    build <app>` has finished, `erpc worker deploy <app> --new-vps --grpc --yes --prepare`
    gets the server, the firewall, the lines and a release in place and starts, stops and
    restarts nothing: an app that runs there runs on, under the agent it had, even when a
    newer agent was installed (the command says so). Then hand over one line, `erpc worker
    deploy <app>`, which hands the key over and starts the app: it builds and installs a
    release of its own, from the cached build, and starts that one.
  - Anything that ends an hourly product (`delete --release-server`, `run`'s lines when it
    ends): the user's yes at a terminal. `run --grpc`/`--shreds` has no `--yes`: its price
    prompt needs the terminal too.
  - `logs -f`, `backup now`: longer than five minutes.
- **Build before you buy:** before a deploy that starts something, run `erpc worker build
  <app>` and wait until it has finished. A deploy buys the server first and builds after:
  a build that fails then leaves a VPS charged by the hour with nothing on it. With the
  build done, the deploy's own build is cached and short. Give the deploy as `argv`, as it
  is, so that it has its 90 minutes: inside a script it is stopped after five, with the
  server bought. A deploy that was stopped all the same has its server on record: the same
  command again takes it up.
- **Starting hourly products yourself:** when the user asked for a server or a line, and the
  build is done, run the deploy with the flags that name them and `--yes` (`erpc worker
  deploy <app> --new-vps --yes`, `--vps <ID>`, `--grpc`, …). Say first what each costs per
  hour (`hourly_catalog`) and what the credit is; read the price lines the command prints
  back to the user after. Without `--yes` the command refuses from `run_command` and says
  so. Never add `--yes` to a start the user did not ask for. `--yes` also answers the first
  login to a server erpc has not made key-only yet (a new one, or `--vps <ID>`): its key
  goes in and password logins go off.
- **A start with no outcome:** when a deploy says a start "may or may not have gone
  through", that the purchase "is still being made", or that the answer "says nothing
  about the earlier one", its request stays on record. Run the same command again, with
  the same flags (shortly, when it is still being made): it sends the same request and
  makes no other. Do not change the flags, do not try another region, and do not start
  it another way (`start_hourly_product`): each could buy a second.
- **A purchase erpc cannot put on record:** when a deploy says user-api "has a purchase
  under this request and does not give it to this command", or "did not say which" it
  started, run nothing again: the server or line may well have been started already.
  Show the user what the account runs (`my_services`, `credit_balance`) and the hint the
  command printed. A server is taken up with `erpc worker deploy <app> --vps <ID>`; a
  line that is not on record is ended (`end_hourly_product`, the user's yes). Removing
  the request from erpc.toml afterwards is the user's to do, and to decide.

## The first app: HelloWorld

A user who has never deployed anything, or who wants to see erpc worker work before any money or
key is involved, starts here. `erpc worker init --template helloworld --name <name> --yes` makes
a small HTTP API in Rust that needs no key, no secret and no data line; `init` with no
`--template` and nobody to ask makes it too.

```bash
erpc worker init --template helloworld   # makes ./hello-world
erpc worker run hello-world              # builds and runs it here: http://127.0.0.1:3000/
erpc worker deploy hello-world           # a VPS of the account, or a new hourly one, price asked
erpc worker api / --dir hello-world      # the answer from the server, over SSH
erpc worker delete hello-world --release-server   # removes it and ends the hourly server
```

- It has no `[wallet]`, so the key gate does not apply: you can run `run --check`, `status`,
  `logs` and `api` for it yourself, and the whole deploy too: after `erpc worker build
  <app>`, `erpc worker deploy <app> --new-vps --yes` (or `--vps <ID> --yes`) buys the
  server, logs in to it and starts the app with nobody at a terminal, printing the price it
  accepted. It takes about two minutes.
- `erpc worker api <PATH>` sends no token for an app with no `API_TOKEN` in `[secrets]`.
- Suggest it as the first step to a beginner who asks for a bot: the bot is deployed with the
  same commands, plus its key, its settings and its lines.

## A public API: the WAF

An app the public calls goes behind a WAF: `[waf]` with `port = 8080` in erpc.toml, then
`erpc worker deploy`. The server then runs an HTTP proxy on that port which refuses scanner
probes, an address over its request rate (429, and a ban once it keeps being refused),
oversized and malformed requests and ones too slow to arrive, and forwards the rest to the
app on loopback; `firewall.app_allow` opens the WAF's port, never the app's.

- Nobody is let in until the user says who: `erpc worker firewall allow --to app <ADDRESS>
  --dir <app>`, or `0.0.0.0/0` for everyone, which erpc accepts only behind a WAF. Opening an
  API to everyone is the user's decision: ask before you run it.
- `erpc worker check <app>` says what the WAF will do; `status` and `firewall list` show what
  it counted and blocked, `logs --waf -n <N>` each request it refused. You can run those.
- After a change to `[waf]`, the server still runs the rules of the last deploy, and `status`
  says so. `firewall allow --to app` then lets nobody new in: it fails, with the change kept
  in erpc.toml, and names `erpc worker deploy`, which puts the new rules in place and opens
  the port after. Closing the port (`firewall deny` of every address) works at once. The same
  holds while the WAF is still a process of an agent from before the one installed (after a
  `deploy --prepare` with a newer erpc, say), or was started before its config or its unit on
  the server last changed (one was written there and no deploy has restarted the WAF since):
  `status` says so, and a deploy restarts it.
- Say what it is not: plain HTTP/1.1 (no TLS, no HTTP/2, no WebSocket), no look inside
  bodies, no authentication; bans and counts are forgotten when it restarts. It holds each
  address to a request rate and a number of connections, and holds 1024 connections in all:
  it is no shield against a flood from many addresses, or one that fills the server's link.
  The keys and their defaults are in `docs/worker.md`, "The WAF".

## An app the user already has

A user with a bot or service that runs today (under systemd, Docker, another language) does
not start from a template: `erpc worker import` in its directory writes the `erpc.toml` it
describes, and changes nothing else in the app.

- A Cargo package: `erpc worker import` (add `--bin <NAME>` when it builds several binaries,
  `--name` to name the app otherwise). Anything else: the user builds the Linux binary their
  own way, then `erpc worker import --binary <PATH> --port <PORT> --health /healthz`; erpc
  ships that binary as it is and refuses one a server cannot run, which `erpc worker check`
  says before a deploy buys a server.
- You can run `import` yourself: it reads the directory, runs nothing in it, and writes one
  new file, `erpc.toml` (it refuses when anything is at that path), besides adding the app
  to erpc's own list. It copies values from `.env.example` and its like; from `.env` it
  takes names, and a port number under a port's name, nothing else (an example that is a
  link is not read at all, and one that is one file with another name gives names only).
  It copies none it takes for a secret, by the setting's name or by a credential in the
  value. Those are named in its
  output with `erpc worker secret put <NAME> --dir <app>` for the user to type, and in
  `erpc.toml` as comments; a key file, by its whole path, with
  `erpc worker key import <FILE> --wipe --dir <app>`. Use the steps as printed.
- Relay what `import` warns of: a file it would not read (a link out of the directory, an
  example that is a link, a pipe, one over 1 MiB), a quote that never closes, lines it left
  out because they name no setting (it says how many, never what they hold; the app is
  deployed without them), a port it did not use, a key file to rename. Tell the user to read
  `erpc.toml` before committing it: a secret in a shape erpc does not know is copied as
  written. `erpc worker check` warns under `[vars]` of the shapes that are seldom anything
  else; it does not warn of a long part of a URL's path (an RPC URL with its key there) nor
  of words shaped like a recovery phrase, both of which `import` holds back.
- Tell the user what a server changes for an app not written for one: settings arrive as
  environment variables (no `.env` there); the app's own directory is read-only, so it
  writes under `ERPC_WORKER_STATE_DIR`; a trading key arrives as 64 bytes on the file
  descriptor `ERPC_WORKER_KEY_FD` names, not as a file; Docker is not used.
- Then the same commands as any app: `check`, `run` (a Cargo app), `deploy`.

## Getting an app running

One order, the same in `erpc worker init`'s Next box, `docs/worker.md` and the template's
README. Ask first, one question at a time (`ask_choice`): do they use the 1Password desktop app
(else the keychain: see **Without 1Password**)? a server already (`--vps <ID>` from
`my_services`, `--host <ADDRESS>`), or a new hourly one? SOL they can afford to lose?

```bash
erpc login                             # once per machine; the session in 1Password or the keychain
erpc worker init                       # arrow keys: HelloWorld, HFT, Stablecoin (soon), pumpfun-bot; --template hft skips it
erpc worker key new                    # the trading key; prints the public key to fund
erpc worker secret put API_TOKEN --generate          # the bot's own API token, made and shown to nobody
erpc worker secret put ERPC_API_KEY --from-account   # the account's RPC key, read from the account; or SOLANA_RPC_ENDPOINT in [vars]
erpc worker check                      # what is missing, every problem at once
erpc worker run --grpc --ip <IPV4>     # here, with an hourly gRPC line that lets this machine in
erpc worker deploy --new-vps --grpc    # a new hourly VPS and gRPC line, prices asked
```

- `API_TOKEN` is any 16 or more random characters: `--generate` makes 64 and shows them to
  nobody. `--from-account` reads the signed-in account's RPC API key. Neither asks for
  anything, so you can run both yourself when the store is open (the keystore unlocked, or
  1Password answering); only a secret the user has to supply is handed over to type.
- `--from-account` tries the account's keys from this machine and keeps the first the shared
  RPC takes; what it prints says whether that is the account's primary key or another
  (`account_key` in `--json`). `the shared RPC takes none of the account's API keys from this
  machine` means each was answered 401 or 403 here: ended, no plan, or limited to other
  addresses (a key limited to the server's address works there and not here). Nothing was
  kept. Tell the user, and have them run `erpc worker secret put ERPC_API_KEY` themselves to
  type the key they mean. `the shared RPC could not be asked about the account's API keys
  just now` means it took none and gave no answer about one, or an answer that is not about
  the key (a rate limit, a failure of its own): nothing was kept either, so run the same
  command again.
- A setting a line provides (`GRPC_ENDPOINT`, `SHREDS_ENDPOINT`, `SOLANA_SEND_RPC_ENDPOINT`)
  is not a secret: `--grpc`/`--shreds`/`--unlimited` set it. The RPC for reads is one of
  `ERPC_API_KEY` or `SOLANA_RPC_ENDPOINT`; `check` names the set when neither is there.
- Before the first `deploy`: an SSH key, and from a Mac or Windows the cross-build (`rustup
  target add x86_64-unknown-linux-gnu`, `zig`, `cargo-zigbuild`). A Linux x86-64 machine needs
  only cargo: without those tools the app is built with its own toolchain. `check` and
  `deploy` say what is missing.

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
session in the OS keychain. `key new` and `secret put` then keep the key and the secrets on
this machine: in the OS keychain where it lasts past a reboot (macOS, Windows, a Linux desktop
session with GNOME Keyring or KWallet), else in **erpc's keystore** (`--store keychain` and
`--store keystore` say which outright). What that means, said before the first command:

- Either way the key exists on this one machine only; there is no copy and no sync, and another
  machine cannot read it (a command that needs a `keychain:` or `keystore:` reference fails
  there). A lost or wiped machine means the wallet is gone: keep little in it, or use
  1Password (`erpc login --store 1password-desktop`; a service account works for secrets, not
  for the trading key).
- **The keystore** is where it goes on a headless Linux server, WSL or an SSH login, which
  have no desktop keyring: files under `~/.erpc/keystore`, each value encrypted under a key
  that only the user's passphrase opens. The first `key new` or `secret put` there explains
  it and has the user choose the passphrase (12 characters or more, typed twice, at a
  terminal). Tell the user, in these words or their own: back the `~/.erpc/keystore`
  directory up and remember the passphrase, because erpc can recover neither and without both
  the wallet is gone; anyone who has the files and the passphrase has the key; a weak
  passphrase protects a stolen file only weakly.
- After the passphrase is typed once on Linux, the keystore stays unlocked (in the kernel
  keyring) until the machine restarts, the keyring goes unused for its idle expiry (three days
  by default), or `erpc worker secret lock`. While it is unlocked, programs running as the
  user can read it. `erpc worker secret unlock` unlocks it ahead of a command run without a
  terminal. The key `[wallet]` names is still read only for a person at a terminal, unlocked
  or not, and a key kept in the keystore does not open as a secret.
- The trading key is named by `[wallet]` alone. Never add a `[secrets]` line that names the
  wallet's reference or a `keychain:`/`keystore:` account ending in `.wallet`: erpc refuses the
  whole `erpc.toml` (`erpc worker check` says which line). A setting cannot be called `WALLET`
  in the keychain or the keystore; pick another name.
- `--store file` for the session leaves a secret on disk unencrypted; never suggest it for a
  key, and never suggest writing a key to a file of the user's own.

## Another machine, 1Password inventory

An environment with `inventory = { vault = "<vault-id>" }` keeps its server facts in a 1Password
item instead of erpc.toml: any machine signed in to the vault, with the app's repository, can
run every command. A new environment becomes one when `erpc login` keeps the session in
1Password; `erpc worker deploy --vault <VAULT_ID>` chooses a vault, `--inline` keeps erpc.toml.
`erpc worker list` also shows worker items in the login vault that no app here names. In such an
app, keys in the keychain or the keystore cannot be read elsewhere: suggest 1Password for them.

## When something fails

- "cannot start without <SETTING>": `erpc worker secret put <SETTING>`, a `[vars]` entry, or the
  line flag that sets it. The hint names the command, with `--generate` or `--from-account`
  where the app's template has the setting made or read from the account: run that one.
- "your key was added but does not get in": 1Password did not sign; unlock it, allow the
  request, run the same command again.
- "release … failed …; the server went back to …": the previous release still runs; read the
  log.
- "the keystore is locked, and nobody is at a terminal": the user runs
  `erpc worker secret unlock` in their terminal; then run the command again. Not the same as a
  locked worker, below.
- "nothing is kept under keystore:… on this machine": the value was kept in another machine's
  keystore. A secret is put again here (`erpc worker secret put <NAME> --replace`); the key
  needs that machine's whole `~/.erpc/keystore` directory and its passphrase, or 1Password.
- "locked": `erpc worker start`. A reboot locks the worker on purpose, and so does an agent
  that systemd started again after it failed or was killed. Nobody is told: the hourly server
  and lines keep charging while it sits locked, so the user then runs `erpc worker start` or
  `erpc worker delete --release-server`. A package run on the server does not restart a
  worker (deploy tells `needrestart` to leave worker units alone, and says so when it could
  not).
- "port … is taken": another worker on the server that is kept running has the same
  health-check port, or another program listens on it. Give the app a port of its own in
  erpc.toml (`port` and the health URL under `[run]`, and the `[vars]` setting the app reads
  its port from), then deploy again.
- "Is my bot still trading?": `erpc worker status` (the agent's state and what is charged),
  `erpc worker api /api/trade/status` (`running`, `active_positions`), `erpc worker logs -n 50`.
  With Redis on the server the bot comes back trading as it was after a restart; without it,
  every start comes up with trading off until `POST /api/trade/start`.
- A line that did not become active is on record: deploying again waits for it,
  `erpc worker delete --release-server` ends it.
- "changed in 1Password since this command read it": another machine deployed; run it again.
