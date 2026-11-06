<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Worker apps: `erpc worker`

`erpc worker` (alias `erpc w`) runs an app of your own on a server, the way
wrangler runs a Worker. It makes the app from a template, runs it on your
machine, builds it for Linux, and deploys it to an ERPC VPS, a new hourly one,
or a server of your own. Everything about the app is in `erpc.toml` at its
root, which holds no secret and can be committed.

The first template is `solana/pumpfun`, a pump.fun (PumpSwap) trading bot
ported from ValidatorsDAO/solana-stream. `--chain solana` is the default, and
other chains get templates of their own.

## The trading key never touches a disk

An app with a wallet gets its key on a pipe when it starts, from 1Password or
the OS keychain. No `wallet.json`, no `.env`, no copy on the server.

- **Where it is kept:** `erpc worker key new` makes the key in 1Password (when
  `erpc login` keeps the session there) or the keychain. `erpc.toml` records
  the reference and the public key.
- **On the server:** the erpc worker agent holds the key in memory only. It
  makes itself undumpable and locks its memory. It hands the key to the app on
  a file descriptor, and the app wipes it after reading.
- **Getting the SOL out:** `erpc worker key send --to <ADDRESS> --sol <N>`
  (or `--all`, everything but the fee) signs one transfer in memory, after
  your yes at a terminal, and sends it through the app's own RPC. It is
  followed by its own signature until it lands or its blockhash is past;
  when erpc ends without knowing, look that signature up before sending
  again, since a second send is a second transfer.
- **After a reboot,** the worker comes back **locked**: the app does not run
  until `erpc worker start` sends the key again. There is no encrypted copy on
  disk to fall back to.
- **Secrets** (API tokens, RPC keys) are kept the same way but reach the app as
  environment variables, not on a pipe. `erpc worker secret put <NAME>` keeps the value in 1Password or the
  keychain, and `[secrets]` holds only `op://…` or `keychain:…` references.

## Without 1Password

1Password is optional. `erpc login` offers the stores this machine has; with
no 1Password desktop app it keeps the session in the OS keychain, and
`erpc worker key new` and `secret put` then use the keychain too (`--store
keychain` says so outright, `--store 1password --vault <id>` the other way).
What that means, before the first command:

- The key exists on this one machine only, in its keychain. There is no copy
  and no sync, and another machine cannot read a `keychain:` reference. A
  lost or wiped machine means the wallet is gone: keep little in it, or use
  1Password, which every machine signed in to the vault can read.
- Linux needs a desktop keyring (a Secret Service: GNOME Keyring, KWallet) in
  a logged-in session. A headless server, WSL or an SSH login has none, and
  erpc refuses to keep a key there, since the kernel keyring forgets it at a
  reboot; the way out is 1Password through `op`, not a file.
- With 1Password, every read may show an approval prompt in the app. erpc
  shows a spinner while it waits; "did not allow it in time" means nobody
  allowed it, "not signed in" means the app's CLI integration is off.

## From nothing to a running app

`erpc worker init` asks one thing: what to make, picked with the arrow keys.

- **HFT** and **pumpfun-bot** are both made from the pumpfun template for
  now; each will have its own.
- **Stablecoin** is coming soon.
- The app is named after the choice (`hft-bot`, `pumpfun-bot`). When a
  directory of that name is there already, a person picking gets -2, -3
  and so on; a script (`--yes`, `--json`, no terminal) gets an error, as
  before, rather than another app.
- `--template hft` (or `pumpfun-bot`, or a template id) skips the picker,
  and `--name` names the app.

```bash
erpc login                             # once per machine: the session in 1Password or the keychain
erpc worker init                       # pick with the arrow keys; makes ./<name> with erpc.toml
cd <name>
erpc worker key new                    # the trading key, kept where the session is; prints the public key to fund
erpc worker secret put API_TOKEN       # the bot's own API token: any 16+ random characters (openssl rand -hex 24)
erpc worker secret put ERPC_API_KEY    # the account's RPC key from the dashboard (or SOLANA_RPC_ENDPOINT in [vars])
erpc worker check                      # what erpc.toml describes, and what is missing
erpc worker run --grpc --ip <IPV4>     # build and run here, with an hourly gRPC line letting this machine in
erpc worker run --check --grpc --ip <IPV4>   # the same, stopped once healthy
erpc worker deploy --new-vps --grpc    # a new hourly VPS and gRPC line, prices asked first
```

Before the first `deploy` from this machine: the Rust target for the server
(`rustup target add x86_64-unknown-linux-gnu`), `zig` (`brew install zig` on
macOS) and `cargo-zigbuild` (`cargo install cargo-zigbuild --locked`) for the
cross-build, and an SSH key (`ssh-keygen -t ed25519`, or `erpc config set
ssh_key <path>.pub`). `erpc worker check` lists what is missing, and `deploy`
refuses before it buys anything when something is.

`init` prints this order for the app it made, with a `secret put` for each
setting the template needs and the line flags for the settings a line
provides. A setting a line provides (`GRPC_ENDPOINT`, `SHREDS_ENDPOINT`,
`SOLANA_SEND_RPC_ENDPOINT`) is never a secret: `--grpc`, `--shreds` and
`--unlimited` set it. `run.requires` may hold a set of settings of which one
is enough, as the pumpfun template does for its RPC: `["ERPC_API_KEY",
"SOLANA_RPC_ENDPOINT"]`; `check` names the set when neither is set, and the
first of the set is the one `init` suggests.

`deploy` finds the server in this order:

1. the one `[env.<name>]` names;
2. `--vps <id>`, an ERPC VPS of the account;
3. `--new-vps`, the cheapest hourly VPS in the region nearest this machine (by
   its time zone; `--region` and `--plan` choose otherwise);
4. `--host <address>`, a server of your own: Ubuntu or Debian with systemd
   and nftables, reached as root or a user with passwordless sudo; the
   worker's firewall then drops every inbound connection to that server but
   SSH and the app's port, so a server that serves anything else is not the
   one to use;
5. otherwise, at a terminal, a list of the account's running VPSs, with "start
   a new one" at the end.

Anything that costs money is shown with its hourly price, the balance, and how
long the credit lasts, and starts only after a yes. `-y` skips the other
questions but never that one.

## What a deploy does

`erpc worker build` runs the cross-build alone, without deploying, and
leaves the release in `target/`: the way to see a build fail before a server
is bought.

1. Checks `erpc.toml`, every setting the app needs, and that this machine may
   read the key.
2. Builds the app for the server with `cargo zigbuild` (glibc 2.31 and up),
   and records the release's digests in `release.json`.
3. Picks the server and pins its SSH host key. A new ERPC VPS is made key-only
   first: your key goes in and password logins go off.
4. Installs the agent (the one this erpc carries, for the server's machine;
   `erpc version` shows its SHA-256) and the worker's hardened systemd unit
   (`erpc-worker-<app>-<env>`).
5. Sets the firewall:
   - SSH only from `firewall.ssh_allow` and the address the deploy comes from;
   - every other inbound connection dropped, except `run.port` from
     `firewall.app_allow`.

   Each change runs under a 120-second rollback timer and is kept only once
   a fresh connection gets in, so a mistaken change cannot lock you out. The
   list itself outlives the address it was made from: a home address that
   changes does, and the way back in is then ERPC support for an ERPC
   server, or its provider's console for a server of your own (`--host`).
   So keep a second address you can reach the server from in
   `firewall.ssh_allow` (an office, a VPN exit) before trusting a home one.
6. Starts the data lines asked for (`--grpc`, `--shreds`, `--unlimited`), or
   takes up the ones already on record.
7. Uploads the release, checks its digests, and installs it beside the
   earlier ones (`/opt/erpc/workers/<id>/releases/`).
8. Hands the key and the secrets to the agent.
9. Activates the release and waits for its health check. A release that does
   not come up healthy is rolled back to the one before.

What is bought goes on record at once:
- **A new VPS:** as soon as user-api names it, before it is ready. A deploy
  that stops after that leaves it on record. The next `erpc worker deploy`
  takes it up instead of buying another, and
  `erpc worker delete --release-server` ends it. Its price was the question
  asked; a deploy asks no second "Go ahead?" after it.
- **The server's facts:** host, pinned key and allow list are written right
  after the firewall (step 5), so a deploy that fails later can still be
  reached by `logs`, `status` and the next deploy.

## Data lines: gRPC, Shreds, Unlimited RPC

ERPC's hourly lines admit the server by its address and take no token. erpc
starts them for the server and gives the app their endpoints:

| Flag | Line | The app gets |
|---|---|---|
| `--grpc` | Geyser gRPC | `GRPC_ENDPOINT` |
| `--shreds` | Shreds (Shredstream gRPC) | `SHREDS_ENDPOINT` |
| `--unlimited` | Unlimited RPC in the server's region | `SOLANA_SEND_RPC_ENDPOINT` |

- **Plans:** each line is the cheapest of its family unless `--grpc-plan`,
  `--shreds-plan` or `--unlimited-plan` names one.
- **On record:** a line goes into `[env.<name>].lines` the moment user-api
  names it, its endpoint filled in later. A line whose endpoint is not known
  yet sets nothing the app gets.
  - Whether it still exists is decided by what the account is charged for
    (the credit snapshot); user-api's status list says whether it is set up.
  - The next deploy takes it up once both show it. While only one does (it
    is being set up, or the snapshot, cached for up to a minute, is behind),
    deploy refuses rather than buy another.
  - A line neither shows leaves the record, and deploy buys one after
    asking: but only one that was seen with its endpoint before. A line
    just started that neither shows yet is waited for, and a line not
    billed by the hour is never dropped.
  - A line ended outside erpc that deploy keeps waiting for:
    `--forget-line <id>`, on deploy or on delete, takes it off the record.
- **Ending:** `erpc worker delete --release-server` ends each line, then the
  server.
  - A line is dropped from the record without ending only by the same rule
    deploy goes by: seen with its endpoint before, and neither listed nor
    charged for. A line just started is ended, and stays on record if that
    fails.
  - A line it cannot end does not stop the server being ended; what was not
    ended stays on record and is named (running the command again carries
    on).
  - A line not billed by the hour is never ended by erpc: it is named, to
    end in the dashboard.
- **Unlimited RPC:**
  - It runs on a dedicated server, which takes up to 45 minutes to set up.
    erpc lets the worker's address in, and keeps waiting through that.
  - It serves `sendTransaction` and a short list of reads, not
    `getProgramAccounts` or `getTokenAccountsByOwner`. So the app sends
    through it and reads where it did.
  - Its endpoint is plain HTTP (no TLS) and admits only the whitelisted
    address.

### Lines for a run on this machine

`erpc worker run` takes `--grpc` and `--shreds` too, for trying the app here
against real data before it goes to a server:

```bash
erpc worker run --grpc --shreds --ip "$(curl -4 -s https://api.ipify.org)"
```

- **The address:** the lines admit this machine's public IPv4 address,
  given with `--ip`. erpc does not look it up itself. A home address that
  changes needs the run started again, and lets in nothing new until then.
- **Taken up or bought:** an active line of the account's that admits
  that address already is taken up. Otherwise a new hourly one is started,
  after its price is shown and asked about; `-y` never answers that, and
  `--grpc-plan` / `--shreds-plan` choose the plan.
- **What the app gets:** `GRPC_ENDPOINT` and `SHREDS_ENDPOINT` in its
  environment, for this run only. Nothing goes into erpc.toml.
- **Ending:** when the run ends (the app stops, `--check` is done, or
  Ctrl-C) each hourly line is ended, after asking. Ctrl-C while a line is
  being bought waits for the purchase to be on record, then ends that line
  with the rest. `--keep-lines` keeps them, still charged; the next run
  with the same `--ip` takes them up. A line not billed by the hour is left
  as it is. Ended any other way (the terminal closed, a second Ctrl-C), the
  lines stay and are charged: the next run takes them up, the dashboard
  ends them.
- **The numbers:** what an app measures here includes the distance from
  this machine to the line, so it is slower than the same app on a server
  near it.

## How fast is each RPC from the server: `erpc worker bench`

```bash
erpc worker bench                                  # getSlot: shared RPC vs the Unlimited RPC
erpc worker bench --rounds 300 --interval 150      # for a plan that limits calls per second
erpc worker bench --url other=op://<vault-id>/<item-id>/url   # another provider's RPC
```

- **Where it runs:** the agent on the server times each call, so the numbers
  are what the app gets.
- **Endpoints:** ERPC's shared RPC (with the account's key, or the app's
  `ERPC_API_KEY` secret), the environment's Unlimited RPC, and each `--url`.
  `--no-shared` leaves the shared RPC out. A `--url` value may be the URL
  itself, `op://…` or `keychain:…` (where a URL with a key in it is kept), or
  `-` (read from standard input, or asked for unseen).
- **What it prints:**
  - p50, p90, p99, min and max;
  - failures, with the first reason;
  - how many slots each answer was behind the freshest in the same round.
- **Keys** reach the server on standard input only. The table shows scheme,
  host and port.
- **Measured on 2026-10-29** from a VPS in Amsterdam: the Unlimited RPC in the
  same region answered getSlot in 1.1–1.3 ms at the median (p99 about 1.5 ms).
  The shared RPC took about 27 ms (p99 about 100 ms).

## Running it

Reading the app's API from this machine, with the API still on the server's
loopback: `erpc worker api <PATH>` (`-X POST`, `-d '{...}'` for a change) and
`erpc worker trades [--profit]`. The `API_TOKEN` is read here from `[secrets]`
and reaches `curl` on the server on its standard input, as part of its
configuration: it is on no command line and in no journal.

| Command | What it does |
|---|---|
| `erpc worker status` | Locked or running, which release, since when |
| `erpc worker logs -n 200`, `logs -f` | The app's and the agent's log |
| `erpc worker start` | Runs the app, sending the key when the worker is locked |
| `erpc worker stop`, `stop --lock` | Stops it; `--lock` also drops the key from memory |
| `erpc worker restart` | Stops and starts it again |
| `erpc worker releases` | The releases kept on the server (`deploy.keep_releases`) |
| `erpc worker rollback`, `rollback --to <release>` | Goes back to the previous release, or the one named |
| `erpc worker firewall list` | Who may reach the server: erpc.toml beside the server's table |
| `erpc worker firewall allow --to ssh\|app <addresses>` | Lets addresses in, and applies it |
| `erpc worker firewall deny --to ssh\|app <addresses>` | Stops letting them in |
| `erpc worker firewall sync` | Makes the server's firewall what erpc.toml says again |
| `erpc worker delete`, `delete --release-server` | Removes the worker; `--release-server` also ends its lines and its hourly server. A plain delete refuses a VPS bought and never reached (it would forget it while charged), and one of a reached hourly VPS takes it off the record while it is still charged, which it warns of. What could not be removed or ended stays on record. `--forget` leaves a server that can no longer be reached unreached; `--forget-line <id>` takes off the record a line ended outside erpc |
| `erpc worker list` | The apps on this machine and where each is deployed; `--prune` takes those whose erpc.toml is gone off the list |
| `erpc worker backup on [--at 03:00]`, `off`, `status`, `now` | Backs the app's state up every day to ERPC Global Storage (below) |

Every command takes `--env <name>` (default `default`) to choose the
environment, and `--json`. Run from anywhere, a command finds its app by the
name erpc knows it by: `erpc worker run hft-bot`, `erpc worker status
hft-bot`. `--dir` takes the app's directory, or its name too (a directory of
that name, when there is one, wins); `secret put`, `secret rm`, `key import`,
`firewall allow` and `firewall deny`, whose own arguments come first, take the
app by `--dir` only.

At a terminal, results and failures are drawn with a mark on each line (✅
done, ⚠️ to heed, 💡 a hint, 👉 the commands to run next) and progress with
›. Anywhere else (a pipe, a file, a script) the plain lines are as they were,
and `--json` is unchanged, with these exceptions:

- `init`'s next steps name the app (`erpc worker check hft-bot`, and `cd`
  relative to where it was run) when that name finds it, in the text and in
  JSON's `next`.
- `key new` on an app that has a wallet already says so and exits 0. Its
  JSON says `"already": true`, and the JSON of a key made or imported says
  `"already": false`.
- Since `--dir` takes a name too, a `--dir` that is neither a path here nor
  a name erpc knows fails as `erpc knows no app named …` rather than as
  `there is no erpc.toml in … or above it`.

## Backing up the app's state: `erpc worker backup`

`erpc worker backup on` backs the worker's state up every day, at `--at` in
the server's time and within 30 minutes after, to ERPC Global Storage,
encrypted by restic. A storage plan is needed (`erpc storage buy 5`).

- **What is backed up:** `/var/lib/private/erpc-worker-<id>`, the app's
  state, where systemd keeps it for the worker's dynamic user. The
  releases are not: a deploy puts them back.
- **Set up from this machine:**
  - this machine makes the server's own `append_only` access key, labelled
    `erpc worker <tag> <id>`, and its own restic key, named
    `erpc-worker-<id>-<tag>`, with the account's backup secrets (`erpc
    backup` keeps them; the first `on` makes them when there are none, and
    says to keep a copy of the password). The tag, eight hex digits from
    the server's host key and the id, keeps apart workers of one id in two
    apps or on two servers;
  - the server gets restic 0.19.1, checked against the digest erpc pins,
    and the two keys, root-only in `/etc/erpc/backup/<id>.env`;
  - the server never holds the erpc session, the account's admin key or its
    master password, so it cannot delete snapshots.
- **What a server taken over can do:** the account has one backup
  repository, and every restic key opens it. Whoever takes the server over
  can read every machine's snapshots in the account, this machine's
  included; keeps the repository's key, which restic never changes, after
  `off`; can add snapshots under another machine's name, so check what
  `restore latest` picks after one; and can fill the account's storage,
  which stops every machine's backups. Revoking its access key is what cuts
  it off: `off` does so first, whether or not the server answers; `erpc
  worker delete` does so once it goes ahead, which for a server that cannot
  be reached takes `--forget` or `--release-server`. `on` says this before
  it asks.
- **Consistency:** restic copies the files as they are while the worker
  runs. A database the worker writes may need its own dump to restore
  consistent.
- **The run:** a systemd timer, `erpc-backup-<id>.timer`, runs restic as
  root, which may read the state and write only its cache, at the lowest CPU
  and I/O priority. A run missed while the server was off runs when it is
  back.
- **Restore,** from this machine, after `erpc backup init` on it (`on`
  prints the name):

  ```bash
  erpc backup restore latest --from-host erpc-worker-<id>-<tag> --path /var/lib/private/erpc-worker-<id> --target ./restored
  ```

- **`off`** revokes the server's access key and removes its restic key
  first, whether or not the server answers, then stops the timer and removes
  the units and the credentials from the server. `on` keeps the keys'
  numbers in `[env.<name>.backup]` (ids, not secrets; in the 1Password item
  for an inventory environment), so `off` and `delete` revoke those, and any
  other labelled for the worker on this server. When an access key or the
  server's credentials are left, `off` says what and exits non-zero; `erpc
  storage keys list` shows the access keys and `erpc storage keys revoke
  <n>` revokes one by hand. The snapshots stay; `erpc backup prune --host
  erpc-worker-<id>-<tag>` thins out old ones.
  `erpc worker delete` revokes the keys and stops the backup on the server
  too; an access key it cannot revoke keeps the environment on record, and
  the delete fails, to be run again. A key counts as revoked once the list
  of keys read after no longer shows it, or, when that list cannot be read,
  once user-api says it revoked it. If user-api keeps refusing a key
  the dashboard no longer shows, remove `[env.<name>.backup]` (or the item's
  `backup` field) by hand. A second `on` revokes the keys the
  first one made before it makes new ones; if it then fails, it says the
  worker is not backed up until `on` goes through. Removing the restic key needs
  the account's backup admin key and password on this machine (`erpc backup
  init`); without them it is left and said, which holds nothing up, since
  the server without its access key cannot reach the repository.

## Several workers, several machines

- **Several workers on one server:** each runs as its own unit
  (`<app>-<env>`), with its own releases and state. They share the server's
  firewall table, and each opens only its own port.
- **Several environments of one app:** `[env.staging]`, `[env.prod]` and so
  on, each with its own server and lines.
- **Another machine:** an environment can keep its server facts in 1Password
  instead of `erpc.toml`, with `inventory = { vault = "<vault-id>" }`.
  - **What the item holds:** one item per environment, tagged
    `erpc/worker/<app>/<env>`. It has the server, its pinned host key, the
    allow lists, the lines, and the release now running with when and from
    where it was deployed.
  - **Taking over:** any machine signed in to that vault, with the app's
    repository, can run every command.
  - **Which environments:** a new one is an inventory environment when
    `erpc login` keeps the session in 1Password. `deploy --vault <vault-id>`
    names another vault, and `deploy --inline` keeps the facts in `erpc.toml`.
  - **Writes:** each one checks that the item has not changed since it was
    read.
  - **Delete:** archives the item.
  - **Listing:** `erpc worker list` also shows the worker items in the login
    vault that no app on this machine names.
  - **Keychain references:** in such an app, `keychain:` references are
    warned about, since another machine cannot read them.

## `erpc.toml`

```toml
name     = "pump-sniper"
chain    = "solana"
template = "solana/pumpfun@1"

[run]
files    = ["config.jsonc"]
requires = ["GRPC_ENDPOINT", "API_TOKEN"]
health   = { http = "http://127.0.0.1:3000/healthz", timeout_secs = 30 }
port     = 3000                      # what firewall.app_allow opens

[vars]                               # plain values, sent as written
API_PORT = "3000"
RUST_LOG = "info"

[secrets]                            # references only
API_TOKEN    = "op://<vault-id>/<item-id>/credential"
ERPC_API_KEY = "op://<vault-id>/<item-id>/credential"

[wallet]
source = "op://<vault-id>/<item-id>/keypair"
pubkey = "<its public key>"

[services]                           # installed and started by deploy
redis    = true                      # REDIS_URL = redis://127.0.0.1:6379/
postgres = false                     # DATABASE_URL over the local socket

[env.default]                        # written by deploy
host     = "203.0.113.10"
ssh_user = "ubuntu"
host_key = "ssh-ed25519 AAAA…"
lines    = [{ kind = "grpc", id = "<line id>", endpoint = "<the line's endpoint>", hourly = true }]

[env.default.resource]
kind   = "vps"
id     = "<VPS id>"
region = "amsterdam"
hourly = true

[env.default.firewall]
ssh_allow = ["198.51.100.7/32"]
app_allow = []

[env.prod]                           # server facts kept in 1Password instead
inventory = { vault = "<vault-id>" }
```

### `[services]`: Redis and PostgreSQL on the server

The pumpfun template reads Redis only, for its trade history and its banned
creators; `postgres = true` would give it a `DATABASE_URL` it never opens.
Their data is not in `erpc worker backup` (`backup on` says so), and a local
`erpc worker run` has no Redis unless `[vars]` sets `REDIS_URL`.

An app that needs a local Redis or PostgreSQL says so in `[services]`, and
every deploy makes sure they are installed (from Ubuntu's own packages, the
first time) and running before the app starts. The app gets their address
as a setting unless `[vars]` sets it, and `run.requires` counts it as set.

| Service | What deploy does | What the app gets |
|---|---|---|
| `redis` | `redis-server`, listening on 127.0.0.1 only | `REDIS_URL = "redis://127.0.0.1:6379/"` |
| `postgres` | `postgresql`, with a role and database named after the worker's unit (`erpc-worker-<app>-<env>`), the user systemd runs the app as | `DATABASE_URL = "postgresql:///?host=/var/run/postgresql"`: the local socket, peer authentication, no password |

Which to use: **Redis for what is kept a while** (a cache, a ban list, the
last trades: fast, and losing it costs little), **PostgreSQL for what must
last** (records, history, anything to query later). Nothing from outside the
server reaches either: the firewall drops every inbound connection but SSH
and `app_allow`. Their data lives on the server, outside the worker's state
directory, so `erpc worker backup` does not cover it.

`erpc worker check` says what the file describes, every problem at once, and
the warnings:
- a `[vars]` value that looks like a secret;
- a setting `run.requires` names that nothing sets;
- `firewall.app_allow` while the app listens on loopback only.

## When something fails

Failures use erpc's codes and exit statuses ([errors.md](errors.md)). The
ones a worker meets most:

| Message (start of it) | Why | What to do |
|---|---|---|
| `<app> cannot start without <SETTING>` | `run.requires` names a setting nothing sets | `erpc worker secret put <SETTING>`, set it in `[vars]`, or deploy with the line that sets it (`--grpc`, `--unlimited`) |
| `your key was added but does not get in` | The SSH agent did not sign: 1Password locked, or its request not allowed | Unlock 1Password, allow the request, run the same command again (it carries on) |
| `1Password could not …: authorization timeout` | 1Password asked for approval and nobody answered | Allow the request in 1Password, and run it again |
| `<NAME> is empty; nothing was kept` | `secret put` read an empty standard input: the shell is not a terminal | Run it in a terminal, or pipe the value in |
| `release <id> failed: …; the server went back to <previous>` | The new release did not pass its health check | `erpc worker logs`; the previous release still runs |
| `… is locked: the trading key has not been handed over` | The server rebooted, or `stop --lock` | `erpc worker start` |
| `could not let <ip> in to line <id>` | user-api did not take the Unlimited RPC's whitelist | Deploy again; the line is on record and is taken up |
| `<kind> line <id> did not become active in <n> minutes` | The line is still being set up | Deploy again to wait more; `delete --release-server` ends it once it is active |
| `user-api did not start it (HTTP 409): OUT_OF_STOCK` | No server of that plan free in that region | `--region <another>` |
| `… changed in 1Password since this command read it` | Another machine wrote the inventory item meanwhile | Run the command again |
| `shared: … HTTP 401` (bench) | The shared RPC refused the key: no active shared RPC plan, or a wrong key | Check the plan on the dashboard, or set `ERPC_API_KEY` |
| `shared: … HTTP 429` (bench) | The plan's rate limit | `--interval 150` or more |

## What erpc never does

- Put a key, a secret, or a URL that carries one on a command line.
- Write a trading key or an app's secret to a file. The exception on a server is
  `erpc worker backup on`, which leaves the server's own backup keys in a
  root-only file.
- Start, buy or end anything without showing its price and asking.
- Leave a server open: the firewall is in force before the app first starts.
- Reach a server whose host key does not match the pinned one.
