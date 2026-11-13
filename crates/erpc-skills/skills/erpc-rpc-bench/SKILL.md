---
name: erpc-rpc-bench
description: Measuring and comparing RPC latency from the user's own server with `erpc worker bench` -- ERPC's shared RPC, an Unlimited RPC in the same region, and RPCs the user has from other providers -- and showing the result as a clear table with what it means for the app.
---

# RPC latency from the server: `erpc worker bench`

What an app on a server waits for is the time from that server to its RPC, not from the
user's laptop. `erpc worker bench` measures it where the app runs: the erpc worker agent on the
server sends the same JSON-RPC call to each endpoint, round after round, and erpc prints the
spread of the times.

## When to use it

- The user asks whether an Unlimited RPC would be faster for their app, how fast their RPC is
  from their server, or how an RPC they have from another provider compares.
- After `erpc worker deploy --unlimited`, to show what it bought.
- When an app is slow to send transactions, before blaming the app.

It needs a worker deployed to a server (`erpc worker deploy`): the environment's server is where
the calls are made from. Without one, say so; a measurement from the user's own machine says
little about a server in a data centre.

## Running it

```bash
erpc worker bench                          # getSlot, 100 calls each, shared vs Unlimited
erpc worker bench --rounds 300             # more calls, steadier tails
erpc worker bench --interval 150           # 150 ms between rounds, for a rate-limited plan
erpc worker bench --method getLatestBlockhash
erpc worker bench --url other=op://<vault-id>/<item-id>/url   # another provider's RPC
erpc worker bench --url other=-            # type its URL, not shown
erpc worker bench --env prod --json        # for reading the numbers programmatically
```

- **Endpoints compared:**
  - `shared` is ERPC's shared RPC (`edge.erpc.global`), which routes to the nearest ERPC region.
    It uses the app's `ERPC_API_KEY` secret when erpc.toml has one, else the account's API key:
    the first of the account's keys the shared RPC takes when erpc tries them from this
    machine, or, when it takes none, the first it does not refuse either (no answer, a rate
    limit, a failure of its own). Refused with all of them here, erpc measures with the
    account's primary key all the same and says so under the table
    (`"shared_key_refused_here": true` with `--json`): a key limited to the server's address
    is refused here and works there. Pass that line on.
  - `unlimited` is the environment's Unlimited RPC, when `erpc worker deploy --unlimited` started
    one.
  - `--url NAME=...` adds any other endpoint, up to six in all: an RPC the user has from another
    provider, their own node. Most such URLs carry a key, so prefer `NAME=op://…` or
    `NAME=keychain:…` (where the URL is kept) or `NAME=-` (typed, not shown) to a URL typed on the
    command line, which stays in shell history. Do not suggest `erpc worker secret put` for it:
    that hands the value to the app as well.
  - `--no-shared` leaves the shared RPC out, for comparing other endpoints only.
- **Methods:** `getSlot` (the default), `getBlockHeight`, `getLatestBlockhash`, `getHealth`. These
  are reads every Solana RPC serves, the Unlimited RPC included. `getSlot` also shows freshness.
- **How it measures:** two warm-up calls per endpoint are not counted, so a TLS handshake is not
  taken for latency. The order rotates each round, so no endpoint is always the warmer one. Each
  endpoint keeps one connection, as an app does.
- **Keys:** they reach the server on standard input, never on a command line or in a file. The
  table names each endpoint by scheme, host and port only. Never repeat a key, or a URL that
  holds one, back to the user.

## Showing the result

Show the table erpc prints as a Markdown table, with the fastest endpoint first, then say in
one or two sentences what it means. For example (the numbers here are made up):

| Endpoint | p50 | p90 | p99 | Failed | Slots behind |
|---|---|---|---|---|---|
| unlimited (same region) | 0.62 ms | 0.80 ms | 1.4 ms | 0/100 | 0.00 |
| shared | 3.10 ms | 4.20 ms | 9.8 ms | 0/100 | 0.35 |

- **p50** is the typical call; **p90** and **p99** are the slow ones that decide whether a trade
  lands. A low median with a long tail is not a fast RPC.
- **Failed** above 0 needs its own line: erpc prints the first error. A failed endpoint is not
  merely slow.
  - `HTTP 429` is the endpoint's plan refusing calls past its rate. The calls go back to back
    unless `--interval` spaces them: run again with `--interval 150` (or more) before comparing.
  - `HTTP 401` from the shared RPC means the key is refused: the account has no active shared RPC
    plan, or the key is wrong.
- **Slots behind** (for `getSlot`) is how far, on average, an endpoint's answer was behind the
  freshest answer of the same round. Above about 1 means it lags, whatever its latency.
- Say where it was measured from: the server and its region, which erpc's first line gives.
- The numbers are this moment's. A single run on a quiet minute is not a guarantee; suggest
  `--rounds 300` or a second run before a decision that costs money.

## What to recommend

- **An Unlimited RPC in the server's region** is a dedicated endpoint next to the server. It
  serves a short list of methods, including `sendTransaction`, `simulateTransaction`,
  `getLatestBlockhash`, `getSignatureStatuses`, `getAccountInfo`, `getMultipleAccounts`,
  `getBalance` and `getSlot`. It does not serve `getProgramAccounts` or `getTokenAccountsByOwner`.
  - So `erpc worker deploy --unlimited` points the app's sending at it
    (`SOLANA_SEND_RPC_ENDPOINT`) and leaves its reads on the shared RPC.
  - It is billed by the hour from ERPC Credit until `erpc worker delete --release-server` ends it.
    erpc shows the price before starting it: asked at a terminal, said and started under
    `--yes`.
  - Getting it ready takes time: a server is set up for it, up to 45 minutes.
- **The shared RPC** is enough when the app is not racing anyone, or when the difference is a
  millisecond or two against a strategy measured in seconds.
- Do not start an Unlimited RPC, or anything that costs money, only to measure it. The user
  decides after seeing the price: `erpc worker deploy --unlimited` asks at the price at a
  terminal, and with `--yes` starts it without asking, so add `--yes` only once the user has
  said yes to the price.
- Unlimited RPC endpoints are plain HTTP (no TLS) and admit only the addresses on their
  whitelist, which erpc sets to the server's address. Say so if the user asks about encryption.
