# Hello, World! (erpc worker template `solana/hello`)

A small HTTP API in Rust, and the shortest way to see `erpc worker` work:
it needs no key, no secret and no data line. Run it here, deploy it to a
server, call it, then make it yours.

| Method | Path | What it answers |
|---|---|---|
| `GET` | `/` | `{"message":"Hello, World!","app":"<name>","version":"0.1.0"}` |
| `GET` | `/hello/{name}` | The same, greeting `{name}` |
| `GET` | `/healthz` | `ok` once the app is up |

## Run it here

```bash
erpc worker run                 # build and run on this machine
curl http://127.0.0.1:3000/     # in another terminal
```

Ctrl-C stops it. `erpc worker run --check` starts it, waits until
`/healthz` answers, and stops it again.

## Deploy it

```bash
erpc worker deploy --new-vps    # a new hourly ERPC VPS; its price is shown and asked first
erpc worker api /               # call the API on the server, from here
erpc worker status              # running or not, which release, what is charged
erpc worker logs -n 50
```

`erpc worker deploy --vps <ID>` takes a VPS the account already has, and
`--host <ADDRESS>` a server of your own. A deploy builds the app for Linux,
uploads the release, sets the firewall and starts it; a release that does
not come up healthy is rolled back to the one before. `erpc worker check`
lists what a deploy from this machine still needs (an SSH key and the
cross-build tools), with the command that installs each.

The server's firewall drops every inbound connection but SSH from your
address, so the API answers on the server's loopback only, which is where
`erpc worker api` calls it. To reach it from outside:

```bash
erpc worker firewall allow --to app <YOUR-ADDRESS>   # who may reach port 3000
# and in erpc.toml, under [vars]:  API_BIND = "0.0.0.0"
erpc worker deploy
```

When you are done, `erpc worker delete --release-server` removes the app
and ends the hourly server, so nothing keeps charging.

## Settings

| Variable | Default | What it is |
|---|---|---|
| `API_PORT` | `3000` | The port; keep `run.port` and `run.health` in `erpc.toml` in step |
| `API_BIND` | `127.0.0.1` | The address it listens on. Open it wider only together with `firewall.app_allow` |
| `GREETING` | `Hello` | The word before the name: change it in `[vars]`, deploy, and see it change |

Plain settings go in `[vars]`. A secret (an API key, a token) is kept by
`erpc worker secret put <NAME>` in 1Password, the OS keychain or erpc's
encrypted keystore, and `[secrets]` holds only its reference; the app reads
both as environment variables. There is no `.env` file.

## Make it yours

- **A route:** add a handler in `src/main.rs` and a line in `routes()`.
- **State on the server:** `[services]` in `erpc.toml` puts Redis
  (`REDIS_URL`) or PostgreSQL (`DATABASE_URL`) beside the app.
- **Chain data:** `erpc worker deploy --grpc` starts an hourly Geyser gRPC
  line for the server and gives the app its endpoint as `GRPC_ENDPOINT`;
  `--shreds` and `--unlimited` do the same for Shreds and an Unlimited RPC.
- **A trading key:** `erpc worker key new` keeps one in 1Password, the
  keychain or erpc's encrypted keystore and hands it to the app on a pipe
  when it starts. The `pumpfun-bot` template (`erpc worker init --template
  pumpfun-bot`) shows an app that uses all of these.

Everything about the app is in `erpc.toml`, which holds no secret and can
be committed.
