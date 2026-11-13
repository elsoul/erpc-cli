# PumpSwap auto-trader (erpc worker template `solana/pumpfun`)

> ## ⚠️ Read this first
>
> This is a **reference implementation** of Solana transaction reads and
> writes and Geyser gRPC streaming, provided **as-is, for education and
> experiment**, under Apache-2.0 with no warranty.
>
> - **Once trading starts you can lose everything in the wallet.** PumpSwap
>   pools are volatile, liquidity collapses, RPCs fail. Fund only what you
>   can afford to lose.
> - **The trading key never touches a file unencrypted, and no file on the
>   server.** It lives in 1Password or your OS keychain, or, on a machine
>   with neither, in erpc's keystore: a file on your machine, encrypted
>   under a passphrase you choose and must not lose. `erpc worker` hands it
>   to the app on a pipe when the app starts. There is no `wallet.json`.
>   Treat the wallet as a hot wallet all the same: the machine running the
>   bot holds the key in memory.

The bot watches PumpSwap (the pump.fun AMM) over Geyser gRPC, and for each
new pool runs the whole trade: **buy → sell → close the token account**.

- New pools detected from the Geyser stream as they are created, of two
  kinds: **graduations**, the pools pump.fun's program makes when a token's
  bonding curve completes, and **pools made by hand**, opened by calling
  PumpSwap directly. Pools between WSOL and a token are traded, WSOL on
  either side (`graduated_only` leaves the second kind out).
- A graduation is bought from what its `create_pool` instruction says: the
  pool, its opening reserves and the token's program are all in it, so
  nothing is read from the RPC before the buy goes out, and it is sent
  without waiting for the pool to be confirmed.
- With a Shreds line, graduations are seen before any node has run them,
  timed against Geyser and confirmation (`GET /api/timing`), and bought
  from there when `buy_on_shreds` is set: see **Zero-block buys**.
- Status changes and notifications only after on-chain confirmation.
- Forced exit after a timeout, or at once when pool liquidity collapses.
- What is left after a sell is sold again only when the sell is sure to
  bring in more than its fee; otherwise it is burned and its account closed,
  and the rent comes back once that close lands. A close that does not go
  through is tried again.
- Discord notifications with P&L, trade history in Redis (both optional).
- A REST API with OpenAPI docs at `/docs`.

## Run it

```bash
erpc worker key new                    # the trading key; prints the public key to fund
erpc worker secret put API_TOKEN --generate          # the bot's API token, made for you and shown to nobody
erpc worker secret put ERPC_API_KEY --from-account   # the account's RPC key, read from your account, or SOLANA_RPC_ENDPOINT in [vars]
erpc worker check                      # what erpc.toml describes, and what is missing
erpc worker run --grpc --ip <IPV4>     # build and run here, with an hourly gRPC line letting this machine in
erpc worker deploy --new-vps --grpc    # build for Linux, run it on a new hourly VPS with a gRPC line
```

The same order `erpc worker init` prints. `GRPC_ENDPOINT` is not a secret:
`--grpc` provides it, here or on the server. A deploy cross-builds for
Linux, so the machine needs `rustup target add x86_64-unknown-linux-gnu`,
`zig`, `cargo-zigbuild` and an SSH key first; `erpc worker check` says which
is missing. `erpc worker stop` stops the bot and ends no hourly product;
`erpc worker status` names what the environment is charged for. Before
leaving the bot alone on a server, set `WEBHOOK_URL` (a Discord webhook, as a
secret): it is the only channel an unattended bot has, and `AUTO_LOOP` to
`"true"`, or it stops after one cycle.

`deploy --grpc` starts an hourly ERPC gRPC line that lets in the server's
address (its price is shown first), and the app gets its endpoint as
`GRPC_ENDPOINT`. ERPC lines admit by address and take no token. A later
deploy takes the same line up again, and `erpc worker delete
--release-server` ends it with the server.

`deploy --unlimited` does the same for an ERPC Unlimited RPC in the
server's region, and the app sends its transactions through it
(`SOLANA_SEND_RPC_ENDPOINT`). Reads stay on `SOLANA_RPC_ENDPOINT` or the
shared RPC, since Unlimited does not serve `getProgramAccounts` or
`getTokenAccountsByOwner`. It takes up to 45 minutes to be ready.
`erpc worker bench` compares the two from the server.

To run it here instead, give this machine lines of its own, or set
`GRPC_ENDPOINT` (and `X_TOKEN`, when that gRPC takes a token) yourself:

```bash
erpc worker run --grpc --shreds --ip "$(curl -4 -s https://api.ipify.org)"
                                # hourly lines that let in this machine's address
erpc worker run                 # build and run here, the key handed over on a pipe
erpc worker run --check         # start, wait until healthy, stop
```

`--grpc` and `--shreds` take up an active line that already lets in
`--ip`, or start a new hourly one after showing its price. The app gets
`GRPC_ENDPOINT` and `SHREDS_ENDPOINT` for this run only. When the run ends,
Ctrl-C included, erpc asks to end each hourly line; `--keep-lines` keeps
them, still charged, for the next run with the same `--ip`. Timings
measured here include this machine's distance to the lines.

`erpc worker check` lists the settings the app needs (`run.requires` in
`erpc.toml`): `GRPC_ENDPOINT` and `API_TOKEN`, and an RPC. Plain
settings go in `[vars]`. Secrets are kept by `erpc worker secret put` in
1Password, the OS keychain or erpc's encrypted keystore, and `[secrets]`
holds only their references (`op://<vault-id>/<item-id>/<field>`,
`keychain:<service>/<account>` or `keystore:<service>/<account>`).
There is no `.env` file. `erpc worker run` gives the app only these settings,
not your shell's environment.

Fund the wallet's public key with SOL before starting trading. The minimum is
about 0.013 SOL: 0.0001 to buy, 0.004 of token-account rent, 0.01 for fees.

## Settings

| Variable | Required | Default | What it is |
|---|---|---|---|
| `GRPC_ENDPOINT` | yes | — | Geyser gRPC endpoint |
| `SHREDS_ENDPOINT` | | — | Shreds stream endpoint; `deploy --shreds` sets it. Without it pools are seen in Geyser only |
| `X_TOKEN` | | — | gRPC auth token, for a gRPC that takes one (a secret); ERPC lines do not |
| `API_TOKEN` | yes | — | Bearer token every API request carries, 16+ characters (a secret) |
| `API_PORT` | | `3000` | API port; keep `run.health` in `erpc.toml` in step |
| `API_BIND` | | `127.0.0.1` | API address. Open it wider only together with `firewall.app_allow` |
| `SOLANA_RPC_ENDPOINT` | one of the two | — | RPC for reads |
| `ERPC_API_KEY` | one of the two | — | Builds the read RPC URL on edge.erpc.global when `SOLANA_RPC_ENDPOINT` is unset (a secret) |
| `SOLANA_SEND_RPC_ENDPOINT` | | the read RPC | RPC for sending transactions; `deploy --unlimited` sets it |
| `ERPC_SEND_API_KEY` | | — | Builds the send RPC URL when `SOLANA_SEND_RPC_ENDPOINT` is unset (a secret) |
| `WEBHOOK_URL` | | — | Discord webhook for notifications (a secret: the URL carries its token) |
| `EXPLORER_URL` | | — | `https://` base of a block explorer; notifications link transactions and accounts to `<base>/tx/…` and `<base>/account/…`. Without it they show the signature or address |
| `REDIS_URL` | | — | Redis for trade history, e.g. `redis://127.0.0.1:6379` |
| `CONFIG_PATH` | | `config.jsonc` | Geyser filter |
| `AUTO_LOOP` | | `false` | Keep trading after each cycle. When false the bot stops after one buy/sell cycle so you can review it |
| `TRADE_APP_LANG` | | `en` | Notification language: `en`, `ja`, `zh`, `ru`, `vi` |

The bot refuses to start without an RPC setting: a rate-limited public RPC
loses trades. URLs are logged without their query string or password, so an
API key in an RPC URL does not end up in the server's journal.

`erpc worker` sets two more itself: `ERPC_WORKER_KEY_FD`, the descriptor the
key arrives on (0, standard input, when erpc starts the app), and
`ERPC_WORKER_PUBKEY`, the public key `erpc.toml` expects,
which the app checks the key against. Started without a key the app runs
watch-only and refuses to trade.

## Trade configuration (`/api/config`)

`GET /api/config` reads it, `PUT /api/config` changes some of it.

| Field | Default | What it is |
|---|---|---|
| `buy_amount_lamports` | `100000` (0.0001 SOL) | Spent per buy |
| `sell_multiplier` | `1.1` | Take profit at buy price × this, plus the trade's transaction fees |
| `slippage_bps` | `500` (5%) | Slippage tolerance, at most 5000 |
| `max_positions` | `1` | Positions open or being bought at once |
| `min_pool_sol_lamports` | `1000000000` (1 SOL) | Smallest pool liquidity that triggers a buy; above `exit_pool_sol_lamports` |
| `sell_timeout_secs` | `300` | Forced exit after this long |
| `exit_pool_sol_lamports` | `1000000` (0.001 SOL) | Exit when pool SOL falls to this |
| `auto_loop` | `false` | As `AUTO_LOOP` |
| `warmup_secs` | `300` | No pool is bought this long after the bot starts, while it learns which creators open pool after pool |
| `creator_window_secs` | `600` | A creator opening more than `creator_max_pools` pools within this many seconds is banned |
| `creator_max_pools` | `2` | See `creator_window_secs` |
| `banned_creators` | `[]` | Creators banned from the start, by address; a `PUT` replaces the list and bans each one at once |
| `graduated_only` | `false` | Buy graduations only, no pools made by hand |
| `buy_on_shreds` | `false` | Buy a graduation when its migration shows in the Shreds stream, before it has run (needs `SHREDS_ENDPOINT`) |
| `priority_fee_micro_lamports` | `0` | Compute unit price of a buy: a priority fee. 0 pays none |
| `compute_unit_limit` | `200000` | Compute units a buy asks for when it pays a priority fee, 1 to 1400000 |

**Creators who pull liquidity are banned.** Some creators open pool after
pool to draw bots in and pull the liquidity seconds after a buy. The
creator of a graduation is the token's deployer (the pool's coin creator);
of a pool made by hand, the wallet that made it. A creator
is banned, and their pools skipped, once they open more than
`creator_max_pools` pools within `creator_window_secs`, or once a PumpSwap
`withdraw` takes liquidity out of a pool they created. The log says who was
banned and why. With `REDIS_URL` set, bans are kept in the Redis hash
`pumpfun:banned_creators` and read back at start; without it they last as
long as the bot runs.

**Following their money.** A wallet opened to pull pools is cheap to
replace, and usually replaced from the same purse.
`POST /api/bans/trace` takes banned creators not traced before, finds the
wallet that first sent each one SOL, and bans that funder and every other
wallet it sent SOL to lately. Run it now and then: each run also traces
the wallets the last one banned, a step further back.

```bash
curl -s -X POST "http://127.0.0.1:3000/api/bans/trace?limit=10" -H "Authorization: Bearer $API_TOKEN"
```

- It answers with the creators traced, the wallets banned and why, the
  creators it could not trace and why, and how many are left.
- A wallet with 1000 transactions or more is never blamed (no throwaway
  creator has that many, and a funder with that many is an exchange or a
  service), nor a funder that sent SOL to more than 50 wallets lately, nor
  the bot's own wallet.
- It reads about 200 transactions per creator from the read RPC, a few at a
  time, so a run takes a while; `limit` is 10 by default, 100 at most.
  Creators the RPC failed on are tried again next run.
- Traced creators are kept in the Redis set `pumpfun:traced_creators`. A ban
  only stops the bot buying pools that wallet creates, and checking one is a
  map lookup: a long ban list costs the trading path nothing.

```bash
curl -X PUT http://127.0.0.1:3000/api/config \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"buy_amount_lamports": 1000000, "sell_multiplier": 2.0, "sell_timeout_secs": 120}'
```

A change that would trade badly is refused with 400 and the reason, and
nothing changes: a `sell_multiplier` below 1, slippage above 50%, no
positions, or a `min_pool_sol_lamports` at or below `exit_pool_sol_lamports`
(a pool would be sold as soon as it was bought), or a priority fee
(`priority_fee_micro_lamports` × `compute_unit_limit` / 1,000,000 lamports)
above `buy_amount_lamports`. The priority fee is counted in what a buy cost,
so the take-profit covers it.

## Faster, step by step

Each ERPC line the bot can take is a step up, and the numbers say when the
step before is no longer what holds the bot back. `erpc worker deploy`
starts a line for the server and `erpc worker run --ip` for this machine,
each billed by the hour, its price shown and asked first.

| Step | Line | The bot then | Read | Take the next step when |
|---|---|---|---|---|
| 1 | Geyser gRPC, `--grpc` | Sees every pool at processed and buys it with a simulation first; `graduated_only` keeps it to graduations | `/api/trades/profit`; each buy's `slots_late` in `/api/timing` | Buys land a slot or more after the pool, once its price has moved |
| 2 | Shreds, `--shreds` | Sees a graduation before any node has run it; `buy_on_shreds` buys from there, with no read and no simulation | `shred_to_processed_ms`; `slots_late` for `via: shreds`; buys that landed and failed | `shred_to_processed_ms` is short and `slots_late` stays above 0: the bot is not what is slow, the send route is |
| 3 | Unlimited RPC, `--unlimited` | Sends through an RPC of its own in the server's region (up to 45 minutes to be ready; `erpc worker bench` compares it) | The same, and `bench` | Still late at a priority fee you will pay: the limit is bandwidth at the leader, not distance |
| 4 | SWQoS (erpc does not start it) | Sends over a stake-backed connection, which leaders give most of their bandwidth to | `slots_late`; buys that failed | The top step |

- One step at a time, `/api/timing` read before and after each; within
  step 2, **Zero-block buys** below gives the order.
- Step down when buys fail more than they land, or the fee eats the profit:
  a failed buy pays its fee for nothing, and a step costs by the hour.
- Measured from this machine (`erpc worker run --ip`) every number includes
  this machine's distance to the lines: decide on the server that will trade.
- erpc does not start SWQoS: step 3 is the top of what it starts.

## Zero-block buys

A graduation's pool is created by pump.fun's `migrate_v2`. Seen in Geyser,
the migration has already run on the node serving the stream, and a buy
sent then lands a slot or more after the pool's. The Shreds stream carries
the migration as the leader sends it out, before anyone has run it.

With `SHREDS_ENDPOINT` set, every migration in the Shreds stream is timed:
when it showed there, when Geyser showed it processed, and when its slot was
confirmed, and how far into its slot each came. `GET /api/timing` gives
each measure's p50, p90, min and max over the last 1000, and for each buy
how long it took from first sight to sending and how many slots after the
pool's it landed (0 is the pool's own slot):

```bash
curl -s http://127.0.0.1:3000/api/timing -H "Authorization: Bearer $API_TOKEN"
```

With `buy_on_shreds: true` a graduation is bought from the Shreds stream:
the bonding curve, its token account and pump.fun's Global are read at
processed in one request, the pool the migration will create is made from
them, and the buy goes out at once, without a simulation. The same pool
seen in Geyser after is not bought again.

A transaction in the Shreds stream has not run yet, and anyone can send a
`migrate_v2` that names accounts of their own. So the bot buys only when
the curve, its token account, the pool, its creator, its LP mint and its
two vaults are the addresses the mint itself gives them, and when the
curve read from the chain is owned by pump.fun's program and its token
account by the mint's token program. Any other `migrate_v2` is left to
Geyser, which shows a pool only once it exists.

What to know before turning it on:

- **The numbers decide, not the bot.** Sending is never delayed to aim at
  a slot. Read `/api/timing` first: when `shred_to_processed_ms` is short
  and `slots_late` stays above 0, the buy is not what is slow, and a
  priority fee or a faster send route is what is left.
- **A buy can land before the pool exists, and fail, paying its fee.**
  Landing in the pool's slot needs the leader to place the buy after the
  migration: a priority fee (`priority_fee_micro_lamports`) and a send RPC
  close to the leader (`deploy --unlimited`) help, and nothing guarantees it.
- **A migration that is seen is not a migration that ran.** The checks
  above keep the bot to real, completed curves; they cannot say that the
  `migrate_v2` it saw will succeed. When that one fails, the buy sent after
  it fails too and pays its fee and priority fee.
- **A pool whose buy from the Shreds stream failed is not bought after.**
  Either way above, the pool counts as considered from the moment its buy
  was sent: seen again in Geyser once it exists, or opened by a later
  migration, it is skipped until the bot restarts or has considered 50,000
  pools (the pools it has considered are kept in memory, and the list
  starts over when it is full).
- **Fewer slots late is not more profit.** Every bot aiming at the same
  pool pays for the same slot.
- The measures are kept in memory: a restart starts over. Under Alpenglow
  the same shreds carry the same transactions; confirmation comes much
  sooner, so the confirmed measures shrink.

Tuning it, one change at a time, on the server that will trade (numbers
measured elsewhere include that machine's distance to the lines):

1. **Measure with `buy_on_shreds` off.** Let a few dozen graduations go by.
   `shred_to_processed_ms` says how far ahead the Shreds stream is; the
   buys (`via: geyser`) give a `slots_late` to beat.
2. **Turn on `buy_on_shreds`**, nothing else. Compare `slots_late` for
   `via: shreds` with step 1, and read the wallet's transactions for buys
   that landed and failed: those landed before the pool.
3. **Still late?** Raise `priority_fee_micro_lamports` in small steps,
   reading `/api/timing` after each. Every buy then pays
   `priority_fee_micro_lamports` × `compute_unit_limit` / 1,000,000 lamports
   more, and the take-profit target rises with it.
4. **Still late at a fee you will pay?** The send route is what is left:
   `deploy --unlimited`, then measure again.
5. **Failing more than landing?** Lower the fee or turn `buy_on_shreds`
   off again: every failed buy pays its fee for nothing.

```bash
curl -X PUT http://127.0.0.1:3000/api/config \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"buy_on_shreds": true, "priority_fee_micro_lamports": 10000}'
```

## What it does not pay fees for

Every trade pays Solana's base fee three times (buy, sell, close: 0.000015
SOL), which is 15% of the default 0.0001 SOL buy. The bot avoids paying it
for nothing:

- **Take profit covers the fees.** The target is buy × `sell_multiplier`
  plus those three fees and the fee of every sell of the position that
  landed and failed, and what has to reach it is what the sell is sure
  to bring in: the sell is exact-out, so it brings in exactly the tokens'
  value less the slippage allowance. When the take-profit sell, a sell of
  what it leaves, and the close each go through the first time, the trade
  ends at least buy × (`sell_multiplier` − 1) up, for any setting the
  config accepts. Each of them that lands and fails pays one more fee that
  the target does not cover, up to the give-up limits below. The sell also
  passes PumpSwap's per-wallet volume account as writable; if PumpSwap
  charges rent to create it on a wallet's first sell (not verified), that
  one-time rent is not covered either. What the sell leaves is sold only
  when that sell brings in more than its own fee. At the defaults (1.1x,
  5%) the price has to rise about 32% before the bot takes profit.
- **Every transaction asks to be simulated first** (preflight, at processed
  commitment), but the buy of a graduation. An RPC that runs the simulation
  refuses one that would fail, and it costs nothing. Whether a given send
  endpoint runs it is up to that endpoint; check yours before relying on
  it. A graduation's buy goes out as soon as the pool is seen, before the
  send RPC may have it, where a simulation would refuse it: it is sent
  without one, and one that lands and fails (another bot moved the price
  past the slippage allowance first) pays its fee.
- **Nothing new is signed while an earlier sell can still land.** A sell is
  recorded before it is sent. One that is not confirmed in time, or whose
  send returned an error other than a refused simulation, is settled first:
  landed, failed, or never seen with its blockhash past. Only then is
  another signed. What the wallet holds is read from the chain before every
  sell, so a sell that landed late is drained, not sold twice. A read that
  comes back lower does not by itself let a position be sold below its
  target: a position drains only after a sell of it landed. A buy whose
  amount could not be read is recorded from its estimate and read again
  before any decision.
- **A failed sell is retried after a wait** that doubles each time, up to a
  minute. Each position has its own monitor, which keeps watching while a
  sell runs, so a retry, a forced exit or the rest of a partial sell does
  not wait for someone else to trade on the pool.
- **A position is given up after 5 sells in a row that landed and failed**,
  each paying its fee, **or after 20 failures of any kind**, those that cost
  nothing included (an RPC error, a refused simulation, a sell that expired
  unseen, a close that did not go through). Each counts once, when it is
  settled. With the waits, that is a quarter of an hour of trying or more: a
  sell left pending is waited for until its blockhash is past, a minute or
  more each time. A given-up position's tokens stay in the wallet, a
  notification is sent, and **buying pauses** until trading is started again
  (`POST /api/trade/start`); with `AUTO_LOOP=false` the cycle ends.
  `/api/trade/status` shows the pause as `sell_only`.
- **One sell at a time per position.** The monitor and every swap on the
  pool check at once; only one of them sells.
- **No pool is bought twice**, a token still held is not bought again
  through another pool, and buys under way count against `max_positions`.
- **A token that its holders can be stopped from selling is not bought:**
  one with a freeze authority, or a Token-2022 extension other than
  metadata and groups (a transfer fee, a transfer hook, a permanent
  delegate, pausing, a default frozen state, and so on). A graduated token
  is not read for this: pump.fun's program minted it, with no freeze
  authority and metadata only. That it did is taken from a `create_pool`
  pump.fun's program itself called (Geyser), or, before the migration has
  run (`buy_on_shreds`), from the bonding curve pump.fun's program holds at
  the mint's own address. Mayhem-mode pools are not bought.
- **A sell sure to bring in no more than its fee is not sent:** the tokens
  are burned and the account closed, which brings the rent back. The close
  is sent either way, so a sell costs one fee more than the burn. A pool
  with nothing left on one side is treated the same way.
- **A close is tried until the account is gone, up to the give-up limits.**
  Until then the position stays open and watched, and a close that does not
  go through is retried after a wait, like a failed sell, under the same
  selling rules as any other position; the rent comes back when one lands. A
  close burns exactly the amount it was decided for (none after a full
  sell); when the account holds anything else, it is decided again. An
  account the RPC cannot find is taken for closed only after one of the
  bot's closes went out, since an RPC a slot behind cannot find an account a
  buy just made. Before tokens are burned as worthless, the pool's reserves
  are read again.
- **A buy is watched until it lands, fails, or its blockhash is past**
  (three minutes at most), holding its slot meanwhile, so a buy that lands
  late is tracked rather than left. A send error is watched the same way,
  unless the RPC refused the buy on its simulation. When the RPC cannot
  say, tokens in the wallet still mean it landed.

`POST /api/trade/start?mode=sell_only` sells the open positions and buys
nothing; starting again without it buys again.

## API

Every request carries `Authorization: Bearer <API_TOKEN>`, except `/healthz`
and the docs page. Docs: `http://127.0.0.1:3000/docs`.

| Method | Path | What it does |
|---|---|---|
| `GET` | `/healthz` | `ok` once the app is up (no token) |
| `GET` / `PUT` | `/api/config` | Read / change the trade configuration |
| `POST` | `/api/trade/start` | Start trading (`?mode=sell_only` to only sell) |
| `POST` | `/api/trade/stop` | Stop trading |
| `GET` | `/api/trade/status` | Running state, positions, balance |
| `GET` | `/api/logs` | Trade logs (`?limit=100&offset=0`) |
| `GET` | `/api/trades/history` | Trade history from Redis |
| `GET` | `/api/trades/{id}` | One trade |
| `GET` | `/api/trades/profit` | Buy→sell P&L |
| `GET` | `/api/wallet` | Public key and SOL balance |
| `PUT` | `/api/watch-address` | The AMM program to watch |
| `POST` | `/api/grpc/start` / `/api/grpc/stop` | Start / stop the gRPC stream |
| `GET` | `/api/timing` | How early migrations are seen and how late buys land (see **Zero-block buys**) |
| `POST` | `/api/bans/trace` | Ban the funders of banned creators (`?limit=10`) |

From this machine, with the app on its server: `erpc worker api /api/trade/status`
(`-X POST`, `-d '{...}'` for a change) and `erpc worker trades [--profit]`;
the token is read here and never shown.

## Positions after a restart

Whether trading was on is kept in Redis (`pumpfun:trading`), so a crash
restart or a reboot followed by `erpc worker start` comes back trading, or
in sell-only mode, as it was; without Redis every start comes up with
trading off. On start the bot looks at the wallet's token holdings and takes
up the positions it finds again, so a restart does not strand a position. Only a
token with a WSOL/token PumpSwap pool is taken up (WSOL on either side),
the deepest such pool, and not one that its holders can be stopped from
selling. Any such token in
the wallet is taken up, bought by the bot or not, and is sold, or burned
when it is worth no more than a sell's fee: keep only the bot's trades in
its wallet. Its buy price is not known, so what it would sell for at start
is the baseline. Nothing is sold until trading is started; then it takes
profit from that baseline, or is sold at the timeout, which counts from the
start of the app.

## Where this comes from

Ported from `trade-app` in ValidatorsDAO/solana-stream (Apache-2.0). See
`NOTICE` for what was changed.
