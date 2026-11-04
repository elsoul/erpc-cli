---
name: erpc-worker
description: Running the user's own app on a server with `erpc worker` (`erpc w`) -- making it from a template (the pump.fun trading bot), keeping its trading key and secrets in 1Password or the keychain, deploying it to an ERPC VPS or a new hourly one with gRPC, Shreds or Unlimited RPC lines, and running, rolling back, firewalling and removing it.
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
- **Money:** `--new-vps`, `--grpc`, `--shreds` and `--unlimited` start hourly products. erpc
  shows each price and asks; `-y` never answers that question. Start one only when the user
  asked for it, and say what it costs per hour and that `erpc worker delete --release-server`
  ends it all.
- **1Password approvals:** reading a secret or using an SSH key in 1Password may show an
  approval prompt in the 1Password app. "authorization timeout" means nobody allowed it.

## Getting an app running

```bash
erpc worker init                       # arrow keys: HFT, Stablecoin (soon), pumpfun-bot; --template hft skips it
erpc worker key new
erpc worker secret put API_TOKEN
erpc worker check                      # what is missing, every problem at once
erpc worker run --check                # start here, wait until healthy, stop
erpc worker deploy --new-vps --grpc    # a new hourly VPS and gRPC line, prices asked
```

- The server: `[env.<name>]` in erpc.toml, else `--vps <ID>` (an ERPC VPS of the account),
  `--new-vps` (cheapest, nearest region; `--region`, `--plan`), or `--host <ADDRESS>` (a server
  of their own, with `--user`, `--port`, `--fingerprint`).
- Lines: `--grpc` sets `GRPC_ENDPOINT`, `--shreds` sets `SHREDS_ENDPOINT`, `--unlimited` sets
  `SOLANA_SEND_RPC_ENDPOINT` (the app sends through the Unlimited RPC and reads elsewhere). They
  admit the server's address and take no token. An Unlimited RPC takes up to 45 minutes to be
  ready.
- `--env <NAME>` deploys another environment (staging, prod) of the same app.

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
- Their data is not in `erpc worker backup`.

## Day to day

| The user wants | Command |
|---|---|
| Is it running, which release | `erpc worker status` |
| Its log | `erpc worker logs -n 200`, `erpc worker logs -f` |
| Start, stop, restart | `erpc worker start`, `erpc worker stop`, `erpc worker restart` |
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

- The firewall drops every inbound connection but SSH from the allow list and the app's
  `run.port` from `firewall.app_allow`. An API that should be reached needs both
  `firewall.app_allow` and `API_BIND = "0.0.0.0"` in `[vars]`. Each firewall change rolls itself
  back within 120 s unless a fresh connection gets in, so a mistake cannot lock the user out.
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
- "locked": `erpc worker start`.
- A line that did not become active is on record: deploying again waits for it,
  `erpc worker delete --release-server` ends it.
- "changed in 1Password since this command read it": another machine deployed; run it again.
