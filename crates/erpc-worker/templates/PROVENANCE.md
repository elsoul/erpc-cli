# Provenance

The `solana/hello` template was written for erpc worker and has no
upstream: a small HTTP API on axum, to start an app from. Its lock holds
only versions the pumpfun lock below already pins.

The `solana/pumpfun` template comes from `trade-app` in solana-stream,
ELSOUL LABO B.V.'s Solana streaming SDK and examples, licensed Apache-2.0
like erpc.

- Repository: https://github.com/ValidatorsDAO/solana-stream
- Directory: `temp-release/trade-app`
- Commit: `32dabe7c42697ac3951023b3aa90fda282fb243a` (2026-11-06), on
  `solana-stream-sdk` 4.0.0; first vendored from
  `ea0c3a476b455a9db16a20aa0e82a006df300758` (2026-10-21), on 3.0.0
- Its git dependency `ultima-swap-pumpfun`, from
  https://github.com/ValidatorsDAO/ultima (Apache-2.0), is pinned there as
  here to `dbbe5f6e595369d12b8c30a58fc05a01126f4519`.

Not carried over: `.env.sample` (settings come from `erpc.toml`, and there
is no `.env`).

## Vendored files

Copied unchanged unless the change column says otherwise; the change column
says why. A test in
`src/template.rs` checks every file against the digest here, so a file
cannot change, appear or go without this table changing in the same commit.

| File | SHA-256 | Change |
|---|---|---|
| `solana/hello/.gitignore` | `135c3692dfcacf8d030a5d557b8ac18e604828c6181b6f59ae0433f63cd8467d` | written for erpc worker: build output, and key and .env patterns in case one is copied in |
| `solana/hello/Cargo.lock.tmpl` | `51cc14b74410ade90d8e2d871a9cdb005eeb9c4386b3c7f224a341d5bd2bab3a` | the resolved lock, with the app's name filled in; every version is one the pumpfun lock already pins |
| `solana/hello/Cargo.toml.tmpl` | `9e031bef8578fcb565a2ad7f5d742337a3cd1f62f01591f532ea88738901e1b8` | written for erpc worker: axum with HTTP/1 and JSON only, serde, tokio |
| `solana/hello/README.md` | `b24aabc9790bd3305f68f7f6a8a33d7c17bbcfc72096115c1b7e9f0d45c66731` | written for erpc worker: run it here, deploy it, call it, open it, make it yours |
| `solana/hello/erpc.toml.tmpl` | `f3a1189da1a930ee64e20a6ae766c35ae0857a8bcf2d7010d0749c5283ac0be7` | written for erpc worker: a health check and a port, three plain settings, no key and no secret; a `[waf]` to uncomment |
| `solana/hello/src/main.rs` | `0dd2ca817bed3d93531595e734ebc3a1e78ac758a40838a70446b3870f69de86` | written for erpc worker: GET /, GET /hello/{name}, GET /healthz; stops on Ctrl-C or SIGTERM |
| `solana/pumpfun/.gitignore` | `cc74ac6900a9c6ba306f2db9bc1aedfe1c5e33b730249858604e5135fd3c03e6` | key file patterns kept and explained |
| `solana/pumpfun/Cargo.lock.tmpl` | `21c5727883b0b2ad317494ce9a85449bb112a20fe30fbad3e275e8bdcbf93fc5` | new: the resolved lock, with the app's name filled in; dashmap, hex, thiserror, solana-hash and solana-pubkey gone |
| `solana/pumpfun/Cargo.toml.tmpl` | `f902d2dc6300461e50865c8d1bcbed9f316b93ffff34c205390e350723e237ee` | named after the app; dotenvy and tower-http dropped, zeroize and libc added; reqwest on rustls, not OpenSSL; dashmap, hex, thiserror, solana-hash and solana-pubkey dropped as unused |
| `solana/pumpfun/NOTICE` | `8b8bf33f60b427502a0f2de858fb3f3691e2ac5138bb0d9452c45d1b8dc74ddb` | new: what this port changed; the latency monitor's removal |
| `solana/pumpfun/README.md` | `0b1b2826495a3b108cd0f880a95f0df8c8af8a2063a6d0a070448214e92ac584` | rewritten for erpc worker: no wallet.json or .env, every API request needs API_TOKEN; what the bot does not pay fees for, and the new defaults and limits; creators who pull liquidity banned; graduations and pools made by hand, graduated_only, graduation buys without a simulation; zero-block buys from the Shreds stream, GET /api/timing, the priority fee; banned creators' funding traced; running here with its own lines, tuning zero-block buys step by step; the steps up from gRPC to Shreds, Unlimited RPC and SWQoS (which erpc does not start); one quickstart, the same as init's Next box; what a deploy needs first, what stop and status say about charges; trading resumes after a restart, erpc worker api/trades, WEBHOOK_URL; what a migration seen in the Shreds stream is checked for before it is bought, and that one seen can still fail; that a pool whose buy from the Shreds stream failed is skipped from then on, until a restart or 50,000 pools considered; the keystore named beside 1Password and the keychain as where the key and the secrets are kept, and `keystore:` among the reference forms |
| `solana/pumpfun/config.jsonc` | `704c0b74d5ebbf28f89be9dd6db20bb1d199abe1fc7763339b065ec0d64d19dc` | a slot subscription, for the timing of migrations |
| `solana/pumpfun/erpc.toml.tmpl` | `815476b01704076533783467e371502073844a350069bdf6840ba2e5608886ad` | new: the app's erpc.toml; [services] redis; the RPC as a set of settings in run.requires; AUTO_LOOP and WEBHOOK_URL explained; `keystore:` references, and the key said to be in no file unencrypted |
| `solana/pumpfun/src/amm.rs` | `b02a399629c2c0416fea52e423206894ec7c9b7d62d8964378cd9d96f7aefb01` | new: PumpSwap pools read as mainnet lays them out (coin_creator before is_mayhem_mode), create_pool parsed for graduations and pools made by hand, and buys and sells built for WSOL on either side with each mint's token program; migrate_v2 read before it runs, the pool it will create made from the curve, its token account and pump.fun's Global; wrapping and unwrapping SOL, burning and closing token accounts, in one place; a migration that has not run is read only when its curve, token account, pool, pool creator, LP mint and vaults are the addresses its mint gives them, and its curve and token account only from the programs that own them |
| `solana/pumpfun/src/api.rs` | `58ef07d5afa3b36e42a2b2ed7f0ef1d0a0094251e11ccdb80f06a8bbf4474c17` | API_TOKEN required and compared in constant time; no CORS layer; /healthz; PUT /api/config refuses settings that would trade badly; sell_only kept as state and in the status; the creator-ban settings in PUT /api/config; graduated_only in PUT /api/config; GET /api/timing; buy_on_shreds and the priority fee in PUT /api/config; POST /api/bans/trace; PUT /api/config lays the patch over the configuration through serde instead of a line per field; the trading intent is kept in Redis on start and stop; clippy clean (no unused Redis count, the history read flattened); `axum::http` imported under another name, so the endpoint gate does not read `http::` as a URL |
| `solana/pumpfun/src/bin/notify_test.rs` | `f9735b8fc8076ebf35d2baa03d88360a3c871c671caa004f017e8e4def93160c` | no dotenvy; the included modules may have functions it does not use |
| `solana/pumpfun/src/creators.rs` | `b9b67198808b3586948227f58fe5a2184833137fa55214a7deef4efac8462ac5` | new: creators banned for opening pool after pool or pulling liquidity; a pool seen twice counted once; banned creators traced or not; is_banned kept for the tests only |
| `solana/pumpfun/src/engine.rs` | `af78760fea906425930914a5651e968b6bc9f046971d2da69a40d854c95d0706` | the shared keypair instead of a copy of its secret bytes per trade; no fees paid for nothing: fees in the take-profit (failed sells' included), a close retried until the account is gone and burning only what was decided, a token bought through one pool at a time, a buy settled before its slot is released, simulation before sending, sell retries limited, one seller per position, a pool and a held token bought once, tokens that can be frozen or blocked not bought, sells not worth their fee replaced by a burn, WSOL/token pools only, unconfirmed buys tracked, a monitor that watches while a sell runs, a give-up pausing buys, a sell that may still land settled before another is signed, the balance read from the chain before every sell and each sell decided in one place (plan_sell), a lower read never draining a position, restored positions sold only once trading starts and only from the deepest pool of a sellable token; pools with WSOL on either side bought, sold and restored, swaps built by amm.rs; a graduation bought from its create_pool without reads first or a simulation; the balance and blockhash read together; a priority fee on buys, counted in their cost; each buy timed from its pool's sighting to its send, and its landing slot recorded; WSOL, burn and close instructions from amm, logs from TradeLog's constructors, positions from Position::opened, notifications through webhook::notify; no latency monitor; where a graduation is known to be pump.fun's, said at market_of; clippy clean (is_multiple_of, the deprecated raw getProgramAccounts allowed on purpose, the restore's argument count allowed) |
| `solana/pumpfun/src/handlers/mod.rs` | `5edc4bcbb1c332e9abf9fc76594f2d63892ed9d5ff8040196eadfa6de273ee22` | unchanged |
| `solana/pumpfun/src/handlers/processor.rs` | `67f22ed838972ff9807e64d64d5b221166961e78c308058d8b0c71009b46117f` | pools of banned creators skipped, no buys during the warm-up, withdraws ban the pool's creator; inner instructions and lookup-table accounts read, so graduations are seen; create_pool parsed by amm.rs, its creator the third account or the coin creator; reserves by the position's side; slot progress and processed migrations timed, lookup tables read ahead for the Shreds stream, a pool's sighting passed to its buy; no map of transactions for the latency monitor |
| `solana/pumpfun/src/i18n.rs` | `7146ab2945f8683589e42f8f5f3ddc0a6b852a80ff2f9fb6adc8db562a07543e` | explorer links from EXPLORER_URL, plain signatures without it; trading resumed after a restart |
| `solana/pumpfun/src/main.rs` | `070458ad72d13a6ab3be471130b11be66e988b1295893d46655b80124e77a529` | no dotenvy; harden, then the key from erpc; API on API_BIND (loopback by default); URLs logged without credentials; banned creators read from Redis and the config at start; mod amm; the Shreds stream when SHREDS_ENDPOINT is set; mod shreds and timing; traced creators read from Redis at start; mod trace; the latency monitor and its map are gone, and the Shreds stream takes its place among the tasks the app ends with; saved bans are taken up by AppState; trading resumes as it was when Redis kept it |
| `solana/pumpfun/src/runtime/mod.rs` | `f88a6a537ac51cd52978c66a455ec967f56297c2c7e2fc6438727037e835e85f` | unchanged |
| `solana/pumpfun/src/runtime/runner.rs` | `8be2377d0a88457c1bf0877856fa7151b1695e42d7b1d4934fba22f8c53ef964` | its test's server URL names the loopback address it binds, so the endpoint gate reads a loopback host |
| `solana/pumpfun/src/runtime/settings.rs` | `a67f1157636468cedb5d5a83ed68784644b850253eee644aca0e2229d8fd9d72` | no .env.erpc; API_BIND; API_TOKEN required; no public RPC fallback; for_log; SHREDS_ENDPOINT |
| `solana/pumpfun/src/runtime/subscription.rs` | `7b42cf80daaeee0ed89223ddeb50fe5e502e505d3cda25954ec01a8b7bbaa0e4` | unchanged |
| `solana/pumpfun/src/shreds.rs` | `f2fda5d5087b32cfa455a709b2cb3702037ce91582395252ce146824a3d00669` | new: pump.fun migrations read from the Shreds stream, their lookup tables resolved, timed, and bought with buy_on_shreds; a migration whose accounts are not its mint's own is left to Geyser, and the accounts read are checked with their owners; lookup-table keys read with as_chunks |
| `solana/pumpfun/src/state.rs` | `9c205842d3a4981fe2d2dc9931e3d4313065efbeb26d08a7a7f8caf463200eca` | the wallet is one shared Arc<Keypair>; buy slots, sell claims, sell failures with backoff, configuration checks; warm-up and creator-ban settings, the creator watch; a position's side; graduated_only; buy_on_shreds, priority_fee_micro_lamports, compute_unit_limit; timing and lookup tables in the state; TradeLog and Position constructors, record() keeps a log in Redis too, take_up_saved() reads the bans Redis kept; the trading intent kept in Redis and taken up at start; clippy clean |
| `solana/pumpfun/src/timing.rs` | `be2feee8e6c8028f9f994397da32dbe778696ba60807733954cc3f72c20061bd` | new: how early graduations are seen and how many slots late buys land, for GET /api/timing |
| `solana/pumpfun/src/trace.rs` | `2f7af4b6c811e9390761dd739d4cdaa03b020dea1e4cb4f407b06a2eafceba7d` | new: the funders of banned creators, and the other wallets they funded, banned by POST /api/bans/trace; a failed transaction's transfers are not counted |
| `solana/pumpfun/src/utils/config.rs` | `8f52a384e2b86791ae9bea33caa4d625d69a5683147f5e1bef58a7acfcede5db` | unchanged |
| `solana/pumpfun/src/utils/fallback.rs` | `f97821f45a0e372cac4e9adb2176c21a952f436afb64ab02739c2dce1ebea961` | unchanged |
| `solana/pumpfun/src/utils/mod.rs` | `91490773c0cf82d64653acb36438cee2226b5e21417f513038f44036107b1d13` | blocktime removed |
| `solana/pumpfun/src/wallet.rs` | `56ffe7b854535c6793fa78f6f37bea7b56b289822c30499621a797a64e05d13b` | rewritten: the key arrives on ERPC_WORKER_KEY_FD, is checked against ERPC_WORKER_PUBKEY and shared; no wallet.json, no vanity grinder; the process is made undumpable |
| `solana/pumpfun/src/webhook.rs` | `8208b4a33827c0147c83ec7dea4adba1e1b45fb83e67fe1417e71ae99ad846eb` | a failed request is logged without the webhook URL; notify() tells Discord off the caller's path when a webhook is set |
