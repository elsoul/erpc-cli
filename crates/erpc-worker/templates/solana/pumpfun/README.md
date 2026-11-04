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
> - **The trading key never touches a file.** It lives in 1Password or your
>   OS keychain, and `erpc worker` hands it to the app on a pipe when the app
>   starts. There is no `wallet.json`. Treat the wallet as a hot wallet all
>   the same: the machine running the bot holds the key in memory.

The bot watches PumpSwap (the pump.fun AMM) over Geyser gRPC, and for each
new pool runs the whole trade: **buy → sell → close the token account**.

- New pools detected from the Geyser stream as they are created. Only pools
  with WSOL as the base and the new token as the quote are traded.
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
erpc worker check               # what erpc.toml describes, and what is missing
erpc worker key new             # make the trading key; prints its public key
erpc worker secret put API_TOKEN  # asks for the value without showing it
erpc worker deploy --grpc       # build for Linux, run it on your server, with
                                # an hourly ERPC gRPC line for it
```

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

To run it here instead, set `GRPC_ENDPOINT` (and `X_TOKEN`, when that gRPC
takes a token) for this machine:

```bash
erpc worker run                 # build and run here, the key handed over on a pipe
erpc worker run --check         # start, wait until healthy, stop
```

`erpc worker check` lists the settings the app needs (`run.requires` in
`erpc.toml`): `GRPC_ENDPOINT` and `API_TOKEN`, and an RPC. Plain
settings go in `[vars]`. Secrets are kept by `erpc worker secret put` in
1Password or the OS keychain, and `[secrets]` holds only their references
(`op://<vault-id>/<item-id>/<field>` or `keychain:<service>/<account>`).
There is no `.env` file. `erpc worker run` gives the app only these settings,
not your shell's environment.

Fund the wallet's public key with SOL before starting trading. The minimum is
about 0.013 SOL: 0.0001 to buy, 0.004 of token-account rent, 0.01 for fees.

## Settings

| Variable | Required | Default | What it is |
|---|---|---|---|
| `GRPC_ENDPOINT` | yes | — | Geyser gRPC endpoint |
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

**Creators who pull liquidity are banned.** Some creators open pool after
pool to draw bots in and pull the liquidity seconds after a buy. A creator
is banned, and their pools skipped, once they open more than
`creator_max_pools` pools within `creator_window_secs`, or once a PumpSwap
`withdraw` takes liquidity out of a pool they created. The log says who was
banned and why. With `REDIS_URL` set, bans are kept in the Redis hash
`pumpfun:banned_creators` and read back at start; without it they last as
long as the bot runs.

```bash
curl -X PUT http://127.0.0.1:3000/api/config \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"buy_amount_lamports": 1000000, "sell_multiplier": 2.0, "sell_timeout_secs": 120}'
```

A change that would trade badly is refused with 400 and the reason, and
nothing changes: a `sell_multiplier` below 1, slippage above 50%, no
positions, or a `min_pool_sol_lamports` at or below `exit_pool_sol_lamports`
(a pool would be sold as soon as it was bought).

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
  commitment). An RPC that runs the simulation refuses one that would fail,
  and it costs nothing. Whether a given send endpoint runs it is up to that
  endpoint; check yours before relying on it.
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
  delegate, pausing, a default frozen state, and so on).
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

## Positions after a restart

On start the bot looks at the wallet's token holdings and takes up the
positions it finds again, so a restart does not strand a position. Only a
token with a WSOL/token PumpSwap pool is taken up, the deepest such pool,
and not one that its holders can be stopped from selling. Any such token in
the wallet is taken up, bought by the bot or not, and is sold, or burned
when it is worth no more than a sell's fee: keep only the bot's trades in
its wallet. Its buy price is not known, so what it would sell for at start
is the baseline. Nothing is sold until trading is started; then it takes
profit from that baseline, or is sold at the timeout, which counts from the
start of the app.

## Where this comes from

Ported from `trade-app` in ValidatorsDAO/solana-stream (Apache-2.0). See
`NOTICE` for what was changed.
