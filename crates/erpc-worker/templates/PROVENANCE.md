# Provenance

The `solana/pumpfun` template comes from `trade-app` in solana-stream,
ELSOUL LABO B.V.'s Solana streaming SDK and examples, licensed Apache-2.0
like erpc.

- Repository: https://github.com/ValidatorsDAO/solana-stream
- Directory: `temp-release/trade-app`
- Commit: `ea0c3a476b455a9db16a20aa0e82a006df300758` (2026-10-21)
- Its git dependency `ultima-swap-pumpfun`, from
  https://github.com/ValidatorsDAO/ultima (Apache-2.0), is pinned to
  `dbbe5f6e595369d12b8c30a58fc05a01126f4519`.

Not carried over: `.env.sample` (settings come from `erpc.toml`, and there
is no `.env`).

## Vendored files

Copied unchanged unless the change column says otherwise; the change column
says why. A test in
`src/template.rs` checks every file against the digest here, so a file
cannot change, appear or go without this table changing in the same commit.

| File | SHA-256 | Change |
|---|---|---|
| `solana/pumpfun/.gitignore` | `cc74ac6900a9c6ba306f2db9bc1aedfe1c5e33b730249858604e5135fd3c03e6` | key file patterns kept and explained |
| `solana/pumpfun/Cargo.lock.tmpl` | `317117df376284f2a459cc57bc666de2ba621ad86065eb9f318703852e4d4234` | new: the resolved lock, with the app's name filled in |
| `solana/pumpfun/Cargo.toml.tmpl` | `3760e2bf26338b98fb3290f5afcd3c9ccbab10ff42d9d55e4e9c59cd437df2fd` | named after the app; dotenv and tower-http dropped, zeroize and libc added; reqwest on rustls, not OpenSSL; the ultima git dependency pinned to a commit |
| `solana/pumpfun/NOTICE` | `e153814d2fff8df7d729c0ed2bc8db4f3022622bad6851cd9328e95db05087a9` | new: what this port changed |
| `solana/pumpfun/README.md` | `7a2a2c3511cdaec92d64d3832c034d9d2b599be897018edb21184ba87cfeaba4` | rewritten for erpc worker: no wallet.json or .env, every API request needs API_TOKEN; what the bot does not pay fees for, and the new defaults and limits; creators who pull liquidity banned |
| `solana/pumpfun/config.jsonc` | `97cec66c15c669e16b99da44c4dd3ace5dd4a96ea9f7d170393281f593865048` | unchanged |
| `solana/pumpfun/erpc.toml.tmpl` | `7812d599393a9672cc9a730ff81e3dcafcedd77feda9e4abb9a044311cd187cf` | new: the app's erpc.toml; [services] redis |
| `solana/pumpfun/src/api.rs` | `ed5da16cec76c1eeb0473d06d74fd4d6d4ed8d7ed285f87dee838a31173207e8` | API_TOKEN required and compared in constant time; no CORS layer; /healthz; PUT /api/config refuses settings that would trade badly; sell_only kept as state and in the status; the creator-ban settings in PUT /api/config; `axum::http` imported under another name, so the endpoint gate does not read `http::` as a URL |
| `solana/pumpfun/src/bin/notify_test.rs` | `96f63411cb420d194abce95745fa64a33830280364b124262662685c5902fa6f` | no dotenv |
| `solana/pumpfun/src/creators.rs` | `4f3d91b7eee40667fb06b7aedb8acc56a9b6435e46668f62e43ae0d8b89dd824` | new: creators banned for opening pool after pool or pulling liquidity |
| `solana/pumpfun/src/engine.rs` | `310c3105f72f60a04112c8da5900be266d0b7d29c5a17b84042608e0f3cfcef4` | the shared keypair instead of a copy of its secret bytes per trade; no fees paid for nothing: fees in the take-profit (failed sells' included), a close retried until the account is gone and burning only what was decided, a token bought through one pool at a time, a buy settled before its slot is released, simulation before sending, sell retries limited, one seller per position, a pool and a held token bought once, tokens that can be frozen or blocked not bought, sells not worth their fee replaced by a burn, WSOL/token pools only, unconfirmed buys tracked, a monitor that watches while a sell runs, a give-up pausing buys, a sell that may still land settled before another is signed, the balance read from the chain before every sell and each sell decided in one place (plan_sell), a lower read never draining a position, restored positions sold only once trading starts and only from the deepest pool of a sellable token |
| `solana/pumpfun/src/handlers/mod.rs` | `5edc4bcbb1c332e9abf9fc76594f2d63892ed9d5ff8040196eadfa6de273ee22` | unchanged |
| `solana/pumpfun/src/handlers/processor.rs` | `30de7a878eab66358713f9c785d17b3db5fb9b4d488bd9f75649d8827a5a1d6b` | pools of banned creators skipped, no buys during the warm-up, withdraws ban the pool's creator |
| `solana/pumpfun/src/i18n.rs` | `e00b04e5fa5d2c6891dcb82d1c8f16e1c3c6f5829c027bb10fc4e9b1092c383e` | explorer links from EXPLORER_URL, plain signatures without it |
| `solana/pumpfun/src/main.rs` | `38d0e8b5efe0720b4ad815d64b3674dbaf379cfc0b2a2433fcb51f4f29066c70` | no dotenv; harden, then the key from erpc; API on API_BIND (loopback by default); URLs logged without credentials; banned creators read from Redis and the config at start |
| `solana/pumpfun/src/runtime/mod.rs` | `f88a6a537ac51cd52978c66a455ec967f56297c2c7e2fc6438727037e835e85f` | unchanged |
| `solana/pumpfun/src/runtime/runner.rs` | `a217d33ca80814236a9b90e00ab897c5954bd841267d1a0d66f133a7b4d3c1ea` | unchanged |
| `solana/pumpfun/src/runtime/settings.rs` | `7eea293b24341649006870b91e192e6e647407f0bcea6fdca7d3cde5dda15ee2` | no .env.erpc; API_BIND; API_TOKEN required; no public RPC fallback; for_log |
| `solana/pumpfun/src/runtime/subscription.rs` | `7b42cf80daaeee0ed89223ddeb50fe5e502e505d3cda25954ec01a8b7bbaa0e4` | unchanged |
| `solana/pumpfun/src/state.rs` | `a32bda97db7db9fb1220cf972ac7215eb2af445e7d9b11a33e0ba9bcbd4b97fd` | the wallet is one shared Arc<Keypair>; buy slots, sell claims, sell failures with backoff, configuration checks; warm-up and creator-ban settings, the creator watch |
| `solana/pumpfun/src/utils/blocktime.rs` | `790786abc653ee0efc0f74cfbdc4d82d15257b5c1cc5ade7924644e0cd761799` | unchanged |
| `solana/pumpfun/src/utils/config.rs` | `8f52a384e2b86791ae9bea33caa4d625d69a5683147f5e1bef58a7acfcede5db` | unchanged |
| `solana/pumpfun/src/utils/fallback.rs` | `f97821f45a0e372cac4e9adb2176c21a952f436afb64ab02739c2dce1ebea961` | unchanged |
| `solana/pumpfun/src/utils/mod.rs` | `fedc6076b88317ed13104865b082fbcd27eb63c62a7b4640145b6668fed37fbb` | unchanged |
| `solana/pumpfun/src/wallet.rs` | `56ffe7b854535c6793fa78f6f37bea7b56b289822c30499621a797a64e05d13b` | rewritten: the key arrives on ERPC_WORKER_KEY_FD, is checked against ERPC_WORKER_PUBKEY and shared; no wallet.json, no vanity grinder; the process is made undumpable |
| `solana/pumpfun/src/webhook.rs` | `5392d3577972ec46ddf56b625af698dd04088c757c627c9bb7f8e00abddd0c24` | a failed request is logged without the webhook URL |
