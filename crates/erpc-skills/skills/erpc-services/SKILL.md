---
name: erpc-services
description: What ERPC sells and which to recommend -- shared RPC, Unlimited RPC, Dedicated RPC, Geyser gRPC, Shreds, bundles, SWQoS, VPS, Super VPS, Premium VPS and bare metal -- with their prices, the stock by region, hourly billing from ERPC Credit, and what erpc can start for the user.
---

# ERPC services: what to recommend, and where to get it

What ERPC sells, so a request for infrastructure gets a concrete answer. Answer from the account
and catalogue, never from memory, with the date when it matters:

- ERPC's servers with their specs and prices (`server_catalog`), what is free in each region now
  (`server_stock`), the price of every other plan (`plan_prices`), what the user already runs
  (`my_services`), and how each region is doing (`service_health`).
- The names in parentheses are `erpc ai`'s tools. An agent without them (Claude Code reading
  this skill) cannot see the account or the stock: say so, and suggest asking `erpc ai`.

Products are billed monthly or hourly. Hourly ones are paid from ERPC Credit: one starts when the
card authorisation (€5) is done and the credit covers an hour of everything already running
plus the new one, and it stops being charged when it is ended. ERPC Credit is bought by card or
in EURC. Do what the user asks with a tool when one does it; when none does, say plainly that
erpc cannot do it yet. Price page: https://erpc.global/en/price/.

## Monthly and yearly by card

- erpc cannot buy a monthly or yearly subscription itself and has no payment link of its own:
  they are bought in the ERPC dashboard. When the user wants one, or a payment link for one,
  call `open_dashboard`: it opens the dashboard's home in their browser. Tell them to pick the
  product there, choose monthly or yearly, and pay by card; the subscription starts once the
  payment is done. When `opened` is false, give them the `url` to open instead. An account
  without the card authorisation sees no products there until it is done: the dashboard asks
  for it first.
- Say the price first (`plan_prices`), and the yearly one when they ask about a year: it is
  paid at once, 12 times the monthly price less 30 percent.

## Hourly or monthly: which costs less

- A month is about 730 hours. Hourly for a whole month costs its price per hour times 730;
  compare that with the monthly price before saying either is cheaper. Hourly costs less only
  when it runs fewer hours than the monthly price divided by the price per hour.
- Example, with prices that change (use the tools' figures): gRPC Standard at €0.34 an hour is
  about €248 for a month running all the time, more than €198 a month; hourly is cheaper only
  below about 580 hours (24 days) a month.
- Hourly suits a trial, a short job or something that runs part of the time; a service that
  runs all month is cheaper monthly, and cheaper still yearly.

## Starting and ending hourly products

- What can be started hourly, its price per hour and the fields its start takes
  (`hourly_catalog`; give the family for the products' names).
- Start one only when the user asked for it (`start_hourly_product`, with the family and the
  fields: the productId from the catalogue, the region and the rest as the user chose them).
  When the plan or region is not settled, let the user pick it with `ask_choice` (the plans and
  regions with stock as options, each with its price or what is free). Once it is, call the
  start straight away, without asking "shall I start it?": erpc then shows the person the
  product, the price per hour, the credit and how long it lasts, and starts it only on their
  yes; a no is final for that request.
- What the result means: `done` true is started (`provisioningPending` true: assigned, ready
  shortly). A VPS can be logged in to a few minutes after: say it was started and that you are
  waiting, then call `wait_until_ready`, which waits up to five minutes. Not ready, or stopped on
  the way: something went wrong; say so and that ERPC support can look into it, and do not start
  another.
- Refusals carry user-api's message and code: the card authorisation is missing
  (`PAYMENT_AUTH_REQUIRED`), the credit does not cover it, or there is no stock in that region.
  Say which and what fixes it (buy credit, another region); never retry on your own.
- End one only when the user asked (`end_hourly_product`, with productType and userProductId
  from the credit balance's `hourlyResources`). It stops and stops being charged, and cannot be
  undone; when the balance says it cannot be ended now, say why.

## Logging in to a VPS

- A VPS comes with a password login. Once it is ready, log in for the user with `secure_vps`:
  erpc logs in once with ERPC's password (it never reaches you), puts the user's own SSH key in
  place, checks the key gets in, and turns password logins off for good. Then tell them how to
  log in: `ssh <user>@<ip>`, with their key. Also when the user asks how to log in to a VPS
  erpc has not set up yet. These tools take the VPS's `userVpsId`: from the start's result, or
  from `my_services`.
- Never give, ask for or repeat a password. If the user has no SSH key, tell them to make one
  (`ssh-keygen -t ed25519`) or point erpc at theirs (`erpc config set ssh_key <path.pub>`).
- After that, recommend allowing SSH from their address only (`restrict_ssh`), with
  `ask_choice`; set it up only when they agree or ask. Say that if their address changes (home
  and mobile networks often do), they cannot log in until it is allowed again. More addresses go
  in `extraAddresses`; `open: true` takes the list away.
- None of this runs without a person at the terminal: `erpc ai -m` in a script or with
  `--json` refuses, and says so.

## Buying ERPC Credit with EURC

- `top_up_credit` buys credit with EURC on Base from the user's own wallet; ERPC pays the gas.
  The amount is in Credits (1 to 10,000; 1 Credit = €0.01) and VAT is added to the EURC total.
  Call it only when the user asked to buy credit, with the amount they named.
- erpc shows the person the credits, subtotal, VAT and EURC total, their wallet and ERPC's
  treasury, and signs only on their yes. It signs nothing but a EURC transfer on Base to that
  treasury for the quoted amount.
- No wallet set up yet: call `create_credit_wallet`. The user keeps one wallet, never more:
  it uses the ERPC wallet already in 1Password (made before, on any machine; found by the
  tag erpc gives it, the first one made if there are several), and makes a new one
  only when there is none, with the key kept only in 1Password (the vault `erpc login` uses,
  or the one the user names). It asks the person first and gives back the address; the user
  then sends EURC on Base to it (no ETH needed). At a terminal the same is `erpc wallet create
  [--vault <id or name>]` (`--no-ai` keeps erpc ai from asking to pay from it), and `erpc
  wallet show` shows the address. A wallet the user already has elsewhere can be pointed at
  instead: `erpc config set credit_wallet op://<vault-id>/<item-id>/<field>`, `erpc config set
  credit_wallet_address 0x…`, and `erpc config set credit_wallet_ai on`.
  Never ask for, show or handle a private key.
- The result says whether the credit was granted (`done`); a refusal names why (no card
  authorisation, an address or country user-api will not invoice, not enough EURC). The user
  can also buy credit by card.

## Getting data from a chain (no server of their own)

- Shared RPC (`plan_prices` family `erpc_plan`): Solana RPC over HTTP and WebSocket in many
  regions; Ethereum and Avalanche too. Plans free, developer, business and pro, each a monthly
  allowance of RPC credits (`rpc_usage` shows what is used). Calls carry the account's API
  key. https://erpc.global/en/rpc/
- Unlimited RPC (`unlimited_rpc`): an endpoint of their own on a dedicated VPS, HTTP/WS without TLS
  for speed, no credit allowance, reached from IPs they whitelist. Standard and Pro.
- Dedicated RPC (`dedicated_rpc`): a Solana RPC node on its own bare metal, run by ERPC.
- Geyser gRPC, shared (`grpc`): pushed streams of accounts, transactions, slots and blocks, from
  a whitelisted IP. Standard: 10 streams per IP; Premium: 50. https://erpc.global/en/grpc/
- Geyser gRPC, dedicated (`dedicated_grpc`): Geyser on a bare metal server of their own.
- Shreds (`shreds`): Solana shreds, before a block is assembled, a step ahead of gRPC; shared,
  from a whitelisted IP. Direct / dedicated shreds run on a VPS or bare metal of their own. Epic
  Shreds Direct is closed to new orders. https://erpc.global/en/shreds/
- Bundles (`bundle`): an RPC plan with shared shreds and gRPC together.
- SWQoS: a stake-backed connection that gives transactions priority bandwidth.
  https://erpc.global/en/staked-connection/
- Enterprise and custom needs: https://erpc.global/en/enterprise/

## Servers

- VPS (`server_catalog` kind `vps`): EPYC, 1 to 8 vCPU, for bots, gateways and monitoring.
- Super VPS (`super_vps`): 5.7 GHz cores, 4 to 16, for latency-sensitive bots.
- Premium VPS (`premium_vps`): 5.7 GHz Ryzen on the same network as the Solana shreds sources.
- Bare metal (`bare_metal`), by type: APP for apps, bots and testnet validators; MV for Solana
  mainnet validators; RPC for Solana RPC nodes; UT for 48 cores and more; LG for large.
- A year paid at once is 12 times the monthly price, less 30 percent.
- Recommend only what `server_stock` shows free in the region asked for; when there is none, say
  so and name the regions that have it.
- What a node needs (CPU, RAM, disk) is in the skill for that chain and role: read it, then
  compare with the specs `server_catalog` gives, RAM and disk above all, and say plainly when no
  product meets them. A VPS is never enough for a Solana mainnet validator or RPC node.

## Common requests

- "I want an RPC node." Ask which they mean, or answer both: RPC access for an app or bot needs
  no node (shared RPC, or Unlimited / Dedicated RPC for more), with gRPC or shreds when they need
  data streamed or sooner; running their own node needs bare metal RPC, from `server_stock`
  (skill `solana-rpc-mainnet`).
- "I want a VPS." Ask what it is for and where; show the tier that fits and its stock there.
- "I want to run a validator." Testnet first is the usual path. Check `server_stock` for bare
  metal APP (testnet) or MV (mainnet) in the region they want; then the skill for that chain and
  network.
- "What do I have?" `my_services`. Passwords and API keys are secrets: never ask for them or
  repeat them.
