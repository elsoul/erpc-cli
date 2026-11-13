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

## The trading key never touches the server's disk

An app with a wallet gets its key on a pipe when it starts, from 1Password,
the OS keychain or erpc's keystore on your machine. No `wallet.json`, no
`.env`, no copy on the server. erpc writes the key to no disk unencrypted:
the one file it puts it in is the keystore's, on your machine, encrypted
under a passphrase of yours ([Without 1Password](#without-1password)).

- **Where it is kept:** `erpc worker key new` makes the key in 1Password
  (when `erpc login` keeps the session there), else in the keychain, else,
  on a machine whose keychain forgets at a reboot, in the keystore.
  `erpc.toml` records the reference and the public key.
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
  until `erpc worker start` sends the key again. There is no copy on the
  server's disk, encrypted or not, to fall back to. An agent that fails or
  is killed (out of memory, say) is started again by systemd and comes back
  locked the same way.
- **A package run does not restart a worker.** Debian's and Ubuntu's
  `needrestart` restarts services after a package run, an unattended
  security update included, and a restarted worker would come back locked.
  `deploy` tells it to leave the worker units alone
  (`/etc/needrestart/conf.d/50-erpc-worker.conf`): in its automatic mode it
  defers them, and asked at a terminal its default answer for them is no.
  - When the rule could not be written, the deploy says so and goes on:
    the worker then runs without this protection.
  - What runs keeps what it loaded. An app that is a dynamically linked
    binary, as one erpc builds is, uses an upgraded library only from its
    next start (`erpc worker restart`, a deploy). The agent is a static
    binary with no library to pick up; it is replaced by a deploy that
    installs a newer one.
  - `erpc worker delete` leaves the rule on the server, for the other
    workers there.
- **Secrets** (API tokens, RPC keys) are kept the same way but reach the app as
  environment variables, not on a pipe.
  `erpc worker secret put <NAME>` keeps the value in 1Password, the
  keychain or the keystore, and `[secrets]` holds only `op://…`,
  `keychain:…` or `keystore:…` references.

## Without 1Password

1Password is optional. `erpc login` offers the stores this machine has; with
no 1Password desktop app it keeps the session in the OS keychain.
`erpc worker key new` and `secret put` keep what they are given in the
first of these that applies, unless `--store` names one (`--store
1password --vault <id>`, `--store keychain`, `--store keystore`):

1. **1Password**, when `erpc login` keeps the session there or `--vault` is
   given.
2. **The OS keychain**, where it keeps a value past a reboot: macOS,
   Windows, and Linux with a desktop keyring (a Secret Service: GNOME
   Keyring, KWallet) in a logged-in session.
3. **erpc's keystore**, on a Linux machine with no such keyring: a headless
   server, WSL, an SSH login. The kernel keyring that holds the session
   there forgets everything at a reboot, and a key forgotten is a wallet
   lost, so the key goes into an encrypted file instead. (`--store
   keychain` on such a machine is refused, with these ways out.)

What that means, before the first command:

- In the keychain or the keystore, the key exists on this one machine only.
  There is no copy and no sync, and another machine cannot read a
  `keychain:` or `keystore:` reference. A lost or wiped machine means the
  wallet is gone: keep little in it, or use 1Password, which every machine
  signed in to the vault can read (`erpc login --store 1password-desktop`,
  through `op signin` where there is no desktop app). A 1Password service
  account can hold an app's secrets; erpc does not read a trading key with
  one.
- With 1Password, every read may show an approval prompt in the app. erpc
  shows a spinner while it waits; "did not allow it in time" means nobody
  allowed it, "not signed in" means the app's CLI integration is off.

### The keystore

The keystore is a directory of files, `~/.erpc/keystore` (`keystore` under
`ERPC_HOME` when that is set). On Unix (Linux, macOS) its directories are
made `0700` and its files `0600`; on Windows erpc sets no permissions of its
own, and they have those of the directory they are in.

- `master.json` holds a random 32-byte master key, sealed under a key that
  PBKDF2-HMAC-SHA256 (600,000 iterations, a random salt) makes from your
  passphrase.
- `entries/<service>/<account>.json` holds one value, sealed with
  ChaCha20-Poly1305 under a key of its own, derived from the master key.
  The seal covers the entry's name and its kind (`key` for a trading key,
  `secret` for anything else), so a file moved or renamed to another
  account does not open, and neither does one whose kind was rewritten, or
  one from another keystore.

The format is written out, field by field, at the top of
`crates/erpc-auth/src/store/keystore.rs`, so the files can be read without
erpc.

- **First use:** the first `key new` or `secret put` that keeps something
  there says what the keystore is and has you choose its passphrase, typed
  twice at a terminal, 12 characters or more. erpc takes the passphrase from
  that hidden prompt only: never from an argument, an environment variable
  or a pipe.
- **At the prompt,** on Linux and macOS, the terminal's echo stays off from
  the first time the passphrase is asked for until the last attempt has
  been checked. An attempt typed ahead while one is checked is not shown,
  and what was typed and not read is discarded.
- **Unlocking, on Linux:** once the passphrase has opened the keystore, the
  master key is kept in the kernel's persistent keyring, in memory, and the
  commands after it do not ask. That lasts until the machine restarts,
  until the keyring has gone unused for the time in
  `/proc/sys/kernel/keys/persistent_keyring_expiry` (three days, unless the
  system says otherwise), or until `erpc worker secret lock`, which drops
  every unlock erpc keeps for you: also that of a keystore under another
  `ERPC_HOME`, or of one whose files are gone.
  `erpc worker secret unlock` asks ahead of time, and says until when. When
  the kernel does not let erpc use the keyring (a shell started without a
  login of its own: `su` without `-`, `sudo -E`), nothing is kept, erpc
  says so, and each command asks.
- **With nobody at a terminal** (a script, `erpc ai`), a command that needs
  the keystore uses the unlock when there is one, and otherwise fails,
  naming `erpc worker secret unlock`. An unlocked keystore hands over
  secrets, not the trading key. Each entry is sealed as a key or as a
  secret; one kept as a key (by `key new` or `key import`) opens only as
  the key `[wallet]` names, which erpc reads only for a person at a
  terminal, and not as a secret, whatever line names it.
- **On macOS and Windows** (`--store keystore`) no unlock is kept: each
  command that needs the keystore asks for the passphrase, once, and so
  needs a terminal.

What it does and does not protect:

- **Back the `keystore` directory up, and remember the passphrase.** erpc
  can recover neither. Without both, what the keystore holds is gone; for a
  trading key, that is the wallet.
- Whoever has the files and the passphrase has the key. Without the
  passphrase the files are only as strong as the passphrase is: PBKDF2
  makes every guess slow, and does not make a guessable passphrase safe.
- While the keystore is unlocked, any program running as you can read the
  master key from the kernel keyring (one whose session does not hold your
  keyring can link it in) and open every entry, a key's too. erpc's own
  rules (the key `[wallet]` names only for a person at a terminal, never
  for an AI tool; a key kept in the keystore never opened as a secret) are
  what erpc does; they do not bind other programs running as you.
  `erpc worker secret lock` when you are done.
- Names are not hidden: an entry's file is named after its app and
  setting, and its size shows how long the value is.
- A changed file does not open; an older copy of the same entry put back
  in its place does.
- `erpc worker secret rm` deletes a secret's entry file along with its line
  in `erpc.toml` (unless another setting of the app names the same entry).
  It does not scrub the disk, and copies in your backups stay. A trading
  key's entry (`<app>.wallet`) is never deleted or written over by erpc:
  to replace a key, move the funds, then remove its file and `[wallet]`
  yourself.
- The keystore holds one spelling of a name. Where file names ignore case
  (macOS and Windows, unless set up otherwise) `<app>.WALLET.json` is the
  key's own file, so a setting cannot be called `WALLET`, in any case, in
  the keystore or the keychain; `--store 1password` takes the name. Where
  the directory already has two spellings of one name, erpc reads, writes
  and removes neither: remove the one that is not wanted.

## From nothing to a running app

`erpc worker init` asks one thing: what to make, picked with the arrow keys.

- **HelloWorld** is the one to start from: a small HTTP API in Rust that
  needs no key, no secret and no data line. These take it from nothing to
  a server, and the bot below is deployed the same way:

  ```bash
  erpc worker init --template helloworld   # makes ./hello-world
  erpc worker run hello-world              # here: curl http://127.0.0.1:3000/
  erpc worker deploy hello-world           # your VPS, or a new hourly one (price asked first)
  erpc worker api / --dir hello-world      # {"message":"Hello, World!",…} from the server
  ```

- **HFT** and **pumpfun-bot** are both made from the pumpfun template for
  now; each will have its own.
- **Stablecoin** is coming soon.
- The app is named after the choice (`hello-world`, `hft-bot`,
  `pumpfun-bot`). When a directory of that name is there already, a person
  picking gets -2, -3 and so on; a script (`--yes`, `--json`, no terminal)
  gets an error, as before, rather than another app.
- `--template hft` (or `helloworld`, `pumpfun-bot`, or a template id) skips
  the picker, and `--name` names the app. With nobody to ask and no
  `--template`, HelloWorld is what is made.

The rest of this section is the bot's order, with the key and the settings
a trading app needs:

```bash
erpc login                             # once per machine: the session in 1Password or the keychain
erpc worker init                       # pick with the arrow keys; makes ./<name> with erpc.toml
cd <name>
erpc worker key new                    # the trading key, in 1Password, the keychain or the keystore; prints the public key to fund
erpc worker secret put API_TOKEN --generate          # the bot's own API token, made for you and shown to nobody
erpc worker secret put ERPC_API_KEY --from-account   # the account's RPC key, read from your account (or SOLANA_RPC_ENDPOINT in [vars])
erpc worker check                      # what erpc.toml describes, and what is missing
erpc worker run --grpc --ip <IPV4>     # build and run here, with an hourly gRPC line letting this machine in
erpc worker run --check --grpc --ip <IPV4>   # the same, stopped once healthy
erpc worker deploy --new-vps --grpc    # a new hourly VPS and gRPC line, prices asked first
```

Before the first `deploy` from this machine: an SSH key (`ssh-keygen -t
ed25519`, or `erpc config set ssh_key <path>.pub`), and a way to build the
app for the server, which is Linux:

- **From a Mac or Windows:** the cross-build. The Rust target for the server
  (`rustup target add x86_64-unknown-linux-gnu`), `zig` (`brew install zig`
  on macOS) and `cargo-zigbuild` (`cargo install cargo-zigbuild --locked`).
- **From a Linux machine of the server's kind** (x86-64 for every ERPC
  server): nothing more than cargo. Without the cross-build's tools the app
  is built with this machine's own toolchain, and the binary then needs the
  glibc it was linked against, which `build` and `deploy` name. With them
  installed it is built for glibc 2.31 and up, as from a Mac.
- **An app built another way:** nothing; see **An app you already have**.

`erpc worker check` lists what is missing, and `deploy` refuses before it
buys anything when something is.

The two `secret put` lines of the bot's order ask for no value:

- **`--generate`** makes it: 32 random bytes, as 64 hexadecimal characters.
- **`--from-account`** reads the signed-in account's API keys from user-api
  and keeps the first one the shared RPC takes. An account can have several
  keys, and a key can have an end date, so the keys are tried in order, the
  primary one first, with one `getHealth` each at the shared RPC, which is
  given 8 seconds to answer for a key. A key answered with success is
  taken, and no key after it is tried. A key answered 401 or 403 is
  refused and the next is tried. Any other answer (a rate limit, a
  failure of the RPC's own, a redirect), and no answer, says nothing of
  the key, for it or against it, and the next is tried too. Only a key
  the RPC took is kept. What the command says then names it as the
  account's primary key or as one of its other keys, and `--json` has
  that as `account_key`: `primary` or `other` (null for a value typed or
  generated).

Neither value is printed, with `--json` either. The store still has to
open: the first use of the keystore, or a locked one, needs a person at a
terminal (`erpc worker secret unlock`).

The keys are tried **from this machine**, and what the shared RPC answers
here is not always what it answers the server. A key can be limited to the
addresses it is used from: one limited to the server's address is refused
here though it works there. erpc reads only the status, so a 401 or 403
from anything between this machine and the RPC reads as a refusal too.
When every key is refused, `--from-account` keeps nothing and fails with
`the shared RPC takes none of the account's API keys from this machine`:
a key kept unseen that then fails on the server would be found out only
there. Keep the key you mean by hand, typed unseen or piped in:

```bash
erpc worker secret put ERPC_API_KEY        # asks for the value, unseen
```

When the RPC took no key and could not be asked about one of them (no
answer, or one that says nothing of the key), `--from-account` keeps
nothing either, for the same reason, and fails with `the shared RPC could
not be asked about the account's API keys just now`. Run the same command
again: no value was kept, and `erpc.toml` is as it was. Both failures name
the command that keeps a key by hand for this app, with `--replace` when
the command had it.

Every command that calls the shared RPC with the account's key tries the
keys this way: `erpc worker bench` (for an app with no `ERPC_API_KEY` of
its own), `erpc rpc call` and `erpc webhook run`, as well as
`--from-account`. Each reads the account's keys from user-api and makes
one `getHealth` call for each key it tries before any call of its own: one
request more when the primary key is taken, and, with an RPC that does not
answer, a wait of up to 8 seconds for each key in turn. They part where
the RPC took no key and could not be asked about one: `--from-account`
keeps nothing, as above, while `erpc rpc call`, `erpc webhook run` and
`erpc worker bench` go on with the first key it could not be asked about,
which is not known to be a bad one, and their own call, which comes next,
tells.
The key is judged at the shared Solana RPC whatever chain is then called:
a call or a webhook for Ethereum goes to the Ethereum RPC with the key
chosen at the Solana RPC.

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
4. `--host <address>`, a server of your own: Ubuntu or Debian with systemd,
   nftables, `sudo` and Python 3 at `/usr/bin/python3`, reached as root or a
   user with passwordless sudo; the worker's firewall then drops every inbound
   connection to that server but SSH and the app's port, so a server that
   serves anything else is not the one to use;
5. otherwise, at a terminal, a list of the account's running VPSs, with "start
   a new one" at the end.

Anything that costs money is shown with its hourly price, the balance, and how
long the credit lasts. At a terminal it starts only after a yes. With `--yes`
it is said and started: an hourly product is paid from ERPC Credit, which is
bought beforehand, and user-api refuses a start the credit does not cover, so
a command line that names what to start and carries `--yes` is the yes.
Ending something is asked at a terminal whatever the flags.

### Without a person: `--yes` and `--prepare`

A script, or an agent such as `erpc ai` or Claude Code, has no terminal to
answer at. Two flags let it do the work all the same:

```bash
erpc worker deploy hello-world --new-vps --yes                     # no key: all the way, unattended
erpc worker deploy pump-sniper --new-vps --grpc --yes --prepare    # a bot: everything but its key
erpc worker deploy pump-sniper                                     # then you, at a terminal: the key, and the start
```

- **`--yes`** answers what a start asks: the price of each hourly product the
  command names (`--new-vps`, `--grpc`, `--shreds`, `--unlimited`). It also
  answers the first login to a server erpc has not made key-only yet, a new
  one or one named with `--vps <ID>`: erpc logs in once with the server's
  password, puts your key in and turns password logins off. What would have
  been asked is printed on standard error, with `--json` too. Without `--yes`
  and without a terminal, a start, or that login, is refused before anything
  is bought or changed, and the refusal says to pass it. Choosing among the
  account's servers still needs a person: name the server (`--new-vps`,
  `--vps <ID>`, `--host`).
- **`--prepare`** does everything that needs neither the trading key nor a
  secret, and starts, stops and restarts nothing: the server, its firewall,
  the lines, and a release uploaded and installed. An app that already runs
  there runs on, from the release and under the agent it had. The agent holds
  the key in memory only, so one that runs is left running even when this
  erpc carries a newer one: the new agent is installed, `--prepare` says that
  the old one still runs, and the new one takes over at the next deploy at a
  terminal, which hands the key back to it. The next `erpc worker deploy`, at
  a terminal, takes up what is on record, hands the key and the secrets over
  and starts the app. It builds and installs a release of its own and starts
  that one, not the one `--prepare` installed: a release is named after the
  time it was built. The build is cached, and the server, its firewall and
  the lines are ready, so it is short. The trading key is still read only for
  a person at a terminal: `--prepare` is how the rest gets done without one.
  For what the app keeps in erpc's keystore, `--prepare` looks that each
  entry is there and asks for no passphrase, so a locked keystore does not
  stop it; the deploy that hands the key over opens it.

## An app you already have: `erpc worker import`

An app that exists already (a bot that runs under systemd or Docker today, a
service in another language) is taken in as it is. `erpc worker import`
reads its directory and writes the `erpc.toml` it describes. Nothing else is
written in the app, nothing in it is run, and its code is not changed; erpc
adds the app to its own list (`~/.erpc/workers.toml`), as `init` does.

```bash
cd my-bot                                   # a Cargo package
erpc worker import                          # writes erpc.toml from what is there
erpc worker check                           # what it describes, and what is missing
erpc worker deploy                          # your VPS, or a new hourly one

cd my-go-service && make linux              # any other toolchain: build the Linux binary your way
erpc worker import --binary dist/service --port 8080 --health /healthz
erpc worker deploy
```

What it reads:

| In the directory | What `import` does with it |
|---|---|
| `Cargo.toml` | The app is built with `cargo build --release`, as an app made by `init` is. The app is named after the package (`--name` names it otherwise); `--bin` picks the binary when the package has several. A workspace root is refused: point it at the package. |
| `--binary <PATH>` | A Linux binary built by any toolchain, shipped as it is (`build.prebuilt`). erpc reads its header and refuses one a server cannot run: a macOS or Windows binary, a script, a shared library, a file cut short, another architecture than `build.target`, or one that is neither static nor linked against glibc with its loader at the usual path. It is a file of the app: a link under that name that leads out of the app's directory is refused. `check` warns of it, and a deploy stops on it before a server is bought. Build it again before a deploy that should carry a change. |
| `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `env.example` | Each name becomes a setting, when it can be one: a line whose text before its `=` is not capital letters, digits and `_` (starting with no digit), or is a name erpc or the server sets itself (`ERPC_WORKER_…`, `LD_…`), is left out. How many such lines a file has is said; what they hold is not, since what stands before a `=` in a file can be anything. A plain one goes into `[vars]` with the example's value. One that looks like a secret by its name (`TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `WEBHOOK` and the like), or whose value carries a credential (below), is named with the command that keeps it and its value is not copied. A quoted value is read through its closing quote, over as many lines as it runs; one of several lines, or of more than 4096 bytes, is named and not copied, since `[vars]` holds one line of that size. A quote that never closes is said, with the setting it opens at: nothing after it in that file is read. An example is read only when it is a file itself: one that is a link is not read, wherever it leads, since its values would be those of another file (the app's `.env`, say). One that is one file with another name is read as `.env` is, for its names only, and that is said: when another dotenv file of the app (`.env`, `.env.local` and the like) is a link to it, and, on Linux and macOS, when it has a second name by a hard link. |
| `.env` | Its names only (a line that names no setting is counted like an example's, and its text is neither kept nor shown), with one exception: a setting named for a port (the next row) whose value is a port from 1 to 65535 keeps that value. The rest are listed in `erpc.toml` as comments, to set there or to keep with `erpc worker secret put`. |
| `PORT`, `API_PORT` and the like; a Dockerfile's `EXPOSE` | `run.port`, unless `--port` gives it: a port from 1 to 65535. Anything else there is said and not used. `--health <PATH>` adds the health check on that port. |
| `GRPC_ENDPOINT`, `SHREDS_ENDPOINT` and the other settings a data line provides | Left out of `[vars]`: the line's flag on `deploy` sets them. |
| `wallet.json`, `id.json`, `*keypair.json` | Named, with `erpc worker key import <FILE> --wipe`, which keeps the key where erpc worker reads it and wipes the file. The step gives the file's whole path, quoted for a shell, so that it is that file from whatever directory the step is run in. A name with a character a terminal would act on is not put into a step: it is listed, to be renamed first. |
| A compose file with Redis or PostgreSQL under `services:`, by an entry's `image:` or its name | `[services]`, so that deploy puts them on the server. `REDIS_URL` or `DATABASE_URL` is then left out of `[vars]`, where it would be used in place of the address the server's own service has. |
| `Dockerfile`, the compose file itself | Not used: erpc worker runs the binary itself, under a hardened systemd unit. |

The directory may be one you cloned a minute ago, so `import` reads it with
care:

- **`erpc.toml` is made new.** When anything is at that path, a link
  included, `import` refuses: it never writes over a file or through a link.
- **It reads regular files inside the directory, up to 1 MiB each.** A link
  that leads out of the directory, a pipe, a device and a larger file are
  not read, and neither is a file that is not UTF-8. An example file that
  is a link is not read at all. Each is said.
- **No value it takes for a secret is copied.** Besides the setting's
  name, a value of up to 4096 bytes (what `[vars]` holds) is read for the
  shape of a credential. The reading is a net, not a proof. It goes by
  shapes: a secret in a shape it does not know is copied like any value,
  and a value that only looks like a secret is held. `import` holds widely
  on purpose, since every setting it holds back is named in `erpc.toml` as
  a comment and a wrong hold costs one line to move under `[vars]`; and
  `erpc.toml` is yours to read before you commit it. The kinds it looks
  for, each with an example (the rules themselves, with their edges, are
  the tests beside `credential_in` in `crates/erpc-worker/src/manifest.rs`):
  - a password or a token before a URL's host, as in
    `postgres://app:<password>@db/app`; a short user's name alone there,
    as in `ssh://git@…`, is not taken for one;
  - a parameter named for a credential, in a URL's query or in a
    connection string: `?api-key=…`, `password=…`, `accessToken=…`. A
    password's value is taken for one whatever it is, written bare, in
    quotes or in braces, whenever anything follows its `=`. It reads as
    none only when the value ends there with an empty form: after the `=`
    come at most one pair of quotes that close at once (`''` or `""`)
    and then one closing `;`, with any white space before, between and
    after them, and then nothing. In a URL's query (a
    name after `?` or `&`), an `&` where that `;` would stand is the next
    parameter, and the password is none whatever follows it. So
    `password=`, `password=;` and `password='';` at the end of a value
    are none, and so is `?password=&ssl=true`. An empty password with
    another setting after it (`Password=;Database=app`,
    `password='' dbname=app`) is held, since nothing tells which format a
    value is in and so what parts its settings. A password that is itself
    written as an empty form (a lone `;`, or `""` where a format reads
    that as two characters) is not told. Any other name's (a key's, a token's,
    a secret's) is, outside a URL's query, only when it is more than a
    short plain word or number, so that `key=value` and `token=true` are
    left alone. A name for a token to trade or a key to sort by (`inputToken`,
    `sort_key`) is not taken for one;
  - `Bearer` or `Basic` before a token; a private key's PEM header; a JSON
    Web Token;
  - a service's token by its shape, such as Stripe's `sk_live_…`, an AWS
    access key id, GitHub's `ghp_…`, Slack's `xoxb-…`, GitLab's `glpat-…`,
    Google's `AIza…`, an `sk-…` key, a Telegram bot's token, or the
    address of a Slack or Discord webhook;
  - a wallet's key as Solana tools write one: 64 bytes in base58, or a
    keypair file's 64 numbers. A transaction's signature has the first
    shape and is held with it. An address is shorter and is not. A key in
    hexadecimal is not looked for: a hash and another chain's address look
    the same;
  - words shaped like a recovery phrase: 12, 15, 18, 21 or 24 short
    lowercase words and nothing else;
  - a long part of a URL's path, where RPC providers put a key, as in
    `https://<host>/v2/<key>`. An id or a hash in a path can look the same
    and is then held too; a Solana address, a transaction's signature and
    hexadecimal after `0x` there are left alone.
- **`erpc worker check` warns of fewer kinds than `import` holds.** It
  runs before every deploy, on any app's `[vars]`, so it warns only of
  what is seldom anything but a credential: every kind above but the last
  two. Words shaped like a phrase and a long part of a path are too often
  a list or an id, and a warning for those on every run would teach to
  pass the others over. So `check` says nothing of an RPC URL whose key is
  in its path, nor of a recovery phrase, under `[vars]`: keep those with
  `erpc worker secret put`.
- **The next steps can be pasted.** Each names this app, by its directory
  when another app on erpc's list has the same name.

What an app has to know about a server, since it was not written for one:

- **Settings arrive as environment variables**, `[vars]` and `[secrets]`
  alike. An app that reads a `.env` file with a dotenv library keeps
  working: such a library does not replace what the environment already
  sets. There is no `.env` on the server.
- **Its own directory is read-only there.** Files it writes go under the
  directory `ERPC_WORKER_STATE_DIR` names (also its `HOME`), which a deploy
  keeps and `erpc worker backup` backs up.
- **A trading key arrives on a pipe, not in a file:** 64 bytes on the file
  descriptor `ERPC_WORKER_KEY_FD` names, once, when the app starts, with
  the public key it should be in `ERPC_WORKER_PUBKEY`. An app that reads a
  key file has that one read to change; the pumpfun template's
  `src/wallet.rs` shows it.
- **It is one binary and the files `run.files` lists.** Anything else it
  opens at run time has to be in that list.

## What a deploy does

`erpc worker build` runs the cross-build alone, without deploying, and
leaves the release in `target/`: the way to see a build fail before a server
is bought.

1. Checks `erpc.toml`, every setting the app needs, that this machine may
   read the key, and that it can build the app. A prebuilt binary is read
   here, before a server is picked or bought: one a server cannot run stops
   the deploy. What the app keeps in the keystore is looked for (a key
   under `[wallet]`, secrets under `[secrets]`) and the keystore opened
   now, so its passphrase is asked for before anything is built or bought.
   A `--prepare`, which reads neither the key nor a secret, neither asks
   whether this machine may read the key nor opens the keystore: it looks
   that the entries are there, and no passphrase is asked for before its
   server is bought.
2. Builds the app for the server: with `cargo zigbuild` (glibc 2.31 and
   up); with cargo alone on a Linux machine of the server's kind that has
   no cross-build tools; or not at all for a prebuilt binary, which is read
   once more, and those bytes are the ones checked, hashed and uploaded.
   The release's digests, and the glibc it needs, go into `release.json`.
3. Picks the server and pins its SSH host key. An ERPC VPS that erpc has not
   made key-only yet, a new one or one named with `--vps`, is made so first:
   after a yes (yours, or `--yes`), your key goes in and password logins go
   off.
4. Installs the agent (the one this erpc carries, for the server's machine;
   `erpc version` shows its SHA-256) and the worker's hardened systemd unit
   (`erpc-worker-<app>-<env>`), and tells `needrestart` to leave worker
   units alone; when that cannot be written, it says so and goes on. An
   agent that does not run is started, locked. One that runs is left
   running here, even when it is not the one installed: it holds the key,
   and steps 5 to 7 can still fail.
5. Sets the firewall:
   - SSH only from `firewall.ssh_allow` and the address the deploy comes from;
   - every other inbound connection dropped, except `run.port` from
     `firewall.app_allow`; for an app behind a WAF, the WAF's port in its
     place, and only where the WAF on the server already runs the rules
     `[waf]` now makes, as a process of the agent step 4 installed. Where
     no WAF runs yet the port stays closed until step 10; where one runs
     other rules, or was started by an agent from before the one
     installed, the port stays open to exactly those it was open to until
     step 10, unless the change only takes someone off, which is applied
     here, with the limit on new connections that is in force.

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
   earlier ones (`/opt/erpc/workers/<id>/releases/`). Several apps can
   share a server, each on a port of its own: a release whose health-check
   port (`run.health.http`) is that of another worker there that is kept
   running is refused here, with that worker's name, before the key or a
   secret is read. Only health-check ports are compared: an app without a
   health URL is not compared with any other, and `run.port` is not looked
   at.
8. Reads the key and the secrets, then hands them to the agent. An agent
   that step 4 left running although it is not the one installed, or its
   unit changed, is restarted only now, between the two: it comes back
   locked, and gets the key at once. So a deploy that fails before this
   leaves a running app running. `--prepare` ends before this step.
9. Activates the release and waits for its health check. A release that does
   not come up healthy is rolled back to the one before. The agent does not
   start an app while another program listens on its health-check port
   (an app without a health URL is started without that look): the deploy
   then ends at once with that reason, which `erpc worker status` and
   `erpc worker logs` show too.
10. For an app with `[waf]`: writes the WAF's config and unit, starts it
    (restarts it when either changed, or when it is still a process of an
    agent from before the one step 4 installed), waits until it listens,
    and only then makes its port what `erpc.toml` asks, wherever step 5
    left it otherwise: open to those `app_allow` lists, with the limit on
    new connections `[waf]` gives. For an app without: removes a WAF an
    earlier deploy left. `--prepare` stops before this, so it leaves a
    WAF that is there with its rules and its port as they were
    ([The WAF](#the-waf-a-public-api-behind-waf)).

What is bought goes on record at once:
- **A new VPS:** as soon as user-api names it, before it is ready. A deploy
  that stops after that leaves it on record. The next `erpc worker deploy`
  takes it up instead of buying another, and
  `erpc worker delete --release-server` ends it. Its price was the
  question, asked or answered by `--yes`; a deploy asks no second "Go
  ahead?" after it.
- **The server's facts:** host, pinned key and allow list are written right
  after the firewall (step 5), so a deploy that fails later can still be
  reached by `logs`, `status` and the next deploy.
- **A start's request:** before a start is sent, its request key goes into
  `[env.<name>.starting]` with what it was for, under `server`, `grpc`,
  `shreds` or `unlimited`:

  ```toml
  [env.default.starting]
  server = { key = "<32 hex digits>", family = "vps", product = "<product id>", region = "amsterdam" }
  grpc   = { key = "<32 hex digits>", family = "grpc", product = "<product id>", ip = "203.0.113.10" }
  ```

  The entry is what the next run sends: the same key, and never a new one
  while it is there. What erpc does with each answer follows one rule: **a
  request sent again leaves the record only when the answer is the purchase
  itself**, a 2xx that names the VPS or the line. A first request, whose
  key nobody sent before, also leaves on a refusal that is certain.

  | user-api answers | A first request | A request sent again |
  |---|---|---|
  | 2xx, with the VPS or line it made | On record; the entry goes in the same write | The same |
  | 2xx that says it started it and names nothing | The entry stays: something was started that erpc cannot put on record. Nothing is sent again | The same |
  | Nothing (a timeout, a broken connection, erpc stopped), 5xx, 408, 429 | The entry stays: run the same command again | The same |
  | 409 `PURCHASE_IN_PROGRESS` | The entry stays: the purchase is still being made; run the same command again shortly | The same |
  | 409 `IDEMPOTENCY_CONFLICT` | The entry goes: the key was made by this run, so the purchase it belongs to is not an earlier request of erpc's. Nothing is sent again by itself | The entry stays: a purchase exists under the request, which may well be the earlier request's own. Nothing is started, and nothing is sent again |
  | 409 `OUT_OF_STOCK`, `REGION_DOWN`; any other 4xx | The entry goes: nothing was made under a key never sent before | The entry stays: the answer says nothing about the first request |
  | 409 with another code, or none; 2xx that says it started nothing | The entry stays: the outcome is not known | The same |

  - **While an entry stays,** the same command sends the same request and
    makes no other, and what erpc does with the answer is in the table. The
    error says which case it was. `PURCHASE_IN_PROGRESS` is also what
    user-api answers for a purchase that was made and has since been
    closed; so when it never changes, look at what the account has.
  - **A purchase that exists and is on no record** (a request sent again
    and answered `IDEMPOTENCY_CONFLICT`, or a 2xx that names nothing): the
    server or the line may well have been started by the earlier request,
    and be charged. Look at what the account has, in the dashboard or with
    `erpc ai`.
    - A server: `erpc worker deploy --vps <ID>` takes it up; the dashboard
      ends one that is not wanted.
    - A line: a deploy cannot take up a line that is not on record. End it
      in the dashboard; the next deploy starts one.

    Then remove the entry by hand, as below. Until then the same command
    sends the same request, and erpc starts nothing on that answer.
  - **Looking, and clearing by hand:** the dashboard shows what the account
    has, and `erpc worker status` what the environment has on record. erpc
    has no flag that drops an entry: once it is sure nothing was started,
    or what was started has been taken up or ended, remove it from
    `[env.<name>.starting]` (from the item's `starting` field, for an
    inventory environment). Only then does a run make a new request.
  - **Other flags:** a command that asks for another plan, region or
    address than the entry is for sends nothing, since the earlier start
    may have gone through and this one would buy another. An entry the
    command does not ask for at all is left alone, and said.
  - `erpc worker delete` says so before it asks when it removes an
    environment that still has one.
  - **One deploy of an environment at a time.** `erpc.toml` is written
    without a lock: two deploys of the same environment started together
    each make a request of their own before the other's is on record, and
    can buy two. That is not supported.

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
  - A line neither shows leaves the record, and deploy buys one, its price
    asked or, under `--yes`, said: but only one that was seen with its
    endpoint before. A line just started that neither shows yet is waited
    for, and a line not billed by the hour is never dropped.
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
  after its price is shown and asked about, at a terminal (`run` has no
  `--yes`); `--grpc-plan` / `--shreds-plan` choose the plan. A run keeps no
  record, so a start that is not settled cannot be sent again with its
  key, and the next run makes a new one: the error says the line may have
  been started and to look at the account's lines in the dashboard. A line
  that was started is taken up by the next run once it is active.
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
- **Endpoints:** ERPC's shared RPC (with the app's `ERPC_API_KEY` secret,
  or else the account's key), the environment's Unlimited RPC, and each
  `--url`. `--no-shared` leaves the shared RPC out. A `--url` value may be
  the URL itself, `op://…`, `keychain:…` or `keystore:…` (where a URL with
  a key in it is kept; never the trading key's entry, which is refused), or
  `-` (read from standard input, or asked for unseen).
- **The account's key** is the first of the account's keys the shared RPC
  takes when erpc tries them from this machine, the primary one first;
  when it takes none, the first it could not be asked about, if there is
  one. The calls themselves are made from the server, and a key can be
  limited to the server's address. So when this machine is refused with
  every key, the bench goes on with the account's primary key and says so
  in a line under the table; with `--json`, `shared_key_refused_here` is
  `true`. If the server is refused with the key it was given, the `shared`
  row counts the calls that failed and gives the status. The account is
  read, and its keys tried, only once the command's own arguments hold: a
  `--url` that is not `NAME=URL` or names nothing the bench can call, a
  method it does not call, rounds or an interval out of range, a name
  given twice and more than six endpoints are refused before that.
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
configuration: it is on no command line and in no journal. An app with no
`API_TOKEN` in `[secrets]`, such as the HelloWorld one, is asked without.

| Command | What it does |
|---|---|
| `erpc worker status` | Locked or running, which release, since when. When signed in and user-api answers: what the environment costs by the hour, each item on record with the price the account is charged for it, and the account's credit with how long it lasts; an item that is not among the account's charges is said to be not among them, no more (the list can be a minute behind a start, and a line ended elsewhere stays on record until `--forget-line`). `--json` has the same under `hourly.charged`. Otherwise it says what is on record |
| `erpc worker status` (with `[waf]`) | Also the WAF: its port, where it forwards, since when, and what it counted; and, when the rules it runs are not the ones `erpc.toml` now makes, or it was started by an earlier agent than the one installed or before its config or its unit on the server last changed, that, with the deploy that puts them in place |
| `erpc worker logs -n 200`, `logs -f` | The app's and the agent's log. A control character in a line (an escape sequence, a carriage return) is printed as `?` |
| `erpc worker logs --waf` | The WAF's log: each request it refused, and when it started, stopped and banned an address |
| `erpc worker start` | Runs the app, sending the key when the worker is locked |
| `erpc worker stop`, `stop --lock` | Stops it; `--lock` also drops the key from memory |
| `erpc worker restart` | Stops and starts it again |
| `erpc worker releases` | The releases kept on the server (`deploy.keep_releases`) |
| `erpc worker rollback`, `rollback --to <release>` | Goes back to the previous release, or the one named. Refused, with the release in use left as it was, when that release's health-check port is now another running worker's |
| `erpc worker firewall list` | Who may reach the server: erpc.toml beside the server's table; for an app behind a WAF, the WAF, what it blocked by rule, and whether the rules it runs are `erpc.toml`'s |
| `erpc worker firewall allow --to ssh\|app <addresses>` | Lets addresses in, and applies it. `--to app` is the WAF's port for an app behind one, and only then takes everyone (`0.0.0.0/0`, `::/0`). A WAF's port is not opened wider while the WAF on the server does not run `erpc.toml`'s rules: the change is kept in `erpc.toml`, held on the server, and the command fails saying so ([The WAF](#the-waf-a-public-api-behind-waf)). Addresses that are all let in already change nothing: the command says so, names `firewall sync` for applying `erpc.toml` again, and exits 0 without asking the server |
| `erpc worker firewall deny --to ssh\|app <addresses>` | Stops letting them in. For a WAF's port it is applied at once whatever rules the WAF runs, unless `app_allow` still names someone the port is not open to yet: then it is held with that, as for `allow`. Addresses of which none is on the list change nothing, as for `allow` |
| `erpc worker firewall sync` | Makes the server's firewall what erpc.toml says again; a WAF's port is held as for `allow` |
| `erpc worker delete`, `delete --release-server` | Removes the worker; `--release-server` also ends its lines and its hourly server. A plain delete refuses a VPS bought and never reached (it would forget it while charged), and one of a reached hourly VPS takes it off the record while it is still charged, which it warns of. What could not be removed or ended stays on record. `--forget` leaves a server that can no longer be reached unreached; `--forget-line <id>` takes off the record a line ended outside erpc |
| `erpc worker import [DIR]` | Takes an app you already have: writes its `erpc.toml` (above) |
| `erpc worker list` | The apps on this machine and where each is deployed; `--prune` takes those whose erpc.toml is gone off the list |
| `erpc worker backup on [--at 03:00]`, `off`, `status`, `now` | Backs the app's state up every day to ERPC Global Storage (below) |

Every command takes `--env <name>` (default `default`) to choose the
environment, and `--json`. Run from anywhere, a command finds its app by the
name erpc knows it by: `erpc worker run hft-bot`, `erpc worker status
hft-bot`. `--dir` takes the app's directory, or its name too (a directory of
that name, when there is one, wins); `secret put`, `secret rm`, `key import`,
`firewall allow` and `firewall deny`, whose own arguments come first, take the
app by `--dir` only. `secret unlock` and `secret lock` are about this
machine's keystore, not an app: they take neither, and no `--env`.

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
- `firewall allow` and `firewall deny` with nothing to change answer
  `--json` with JSON, where they printed their text: `{"worker": …,
  "changed": false, "erpc_toml": {…}}`. `erpc_toml` has the lists
  `erpc.toml` asks for, as in `firewall list`; nothing in it says what is
  in force on the server, which is not asked. The JSON of an `allow` or a
  `deny` that changed the list says `"changed": true`, in its answer and,
  when the WAF's port was held, in the error's `details`. `firewall sync`,
  which changes no list, has no `changed`.

## The WAF: a public API behind `[waf]`

An app the public reaches, an API say, is put behind a WAF with one table
in `erpc.toml`:

```toml
[waf]
port = 8080
```

`erpc worker deploy` then runs an HTTP reverse proxy on the server, in a
systemd unit of its own (`erpc-waf-<app>-<env>`: an unprivileged dynamic
user with no key, no secret and nothing of the worker's, held to 1 GiB of
memory and to the system calls a service makes). It listens on
`waf.port`, reads each request before the app does, refuses what its rules
name, and forwards the rest to the app on `127.0.0.1:<run.port>`.

- **The app stays on loopback.** `firewall.app_allow` and
  `erpc worker firewall allow --to app` open the WAF's port, and the app's
  own port is never opened from outside. So the app needs no `API_BIND`.
- **The operator's way in goes past it.** `erpc worker api` and the health
  check reach the app on loopback, as before.
- **Who may connect is still the firewall's list**, and a WAF's port is the
  one place that list may say everyone:

  ```sh
  erpc worker firewall allow --to app 0.0.0.0/0     # and ::/0
  ```

  With nobody listed the WAF listens and nobody is let in; the deploy says
  so, with that command.
- **The port is opened once the WAF listens on it**, never before: on a
  first deploy, right after the WAF is up. A deploy whose WAF does not come
  up fails and says why, with the app still running: a port not open yet
  stays closed, and a WAF that was there before gets its config back.
- **The port is opened wider only under the rules `erpc.toml` makes.** The
  server reports its WAF's config file, every key of it; whether the WAF
  was started after its files last changed, that file and its systemd
  unit, by systemd's time for the start and the files' own for the
  change (the WAF reads its config once, when it starts, and runs under
  the unit systemd had read then); and whether the WAF is a process of
  the agent
  installed there now: the WAF is the agent's own code, and a deploy
  installs the agent this erpc carries. The rules count as `erpc.toml`'s
  only when all three hold. A server that cannot tell one of the last
  two (when its WAF was started: its systemd does not print that time to
  the microsecond; or which agent's process the WAF is) never counts:
  there a deploy is what opens the port wider, each time. The step of a
  deploy that writes those two files is not left to the two times when
  it is ended on the server before it has restarted the WAF: it leaves a
  note beside the config (`/etc/erpc/worker-waf/<id>.applying`), and
  until a deploy has restarted the WAF the WAF counts as started before
  its files last changed, whatever started it in between (systemd starts
  it again by itself when it fails, under the unit it had read). What
  the two times alone decide is a file changed there by anything else: a
  clock set back between the WAF's start and that change, or systemd
  starting the WAF again before it has read a unit changed that way,
  dates the start after a file the WAF does not run. While the
  config is not the one `[waf]` now
  makes (you changed `[waf]` and have not deployed since), or the WAF was
  started before its config or its unit last changed (the step of a
  deploy that writes them was ended on the server before it restarted
  the WAF, or one of them was changed there), or the WAF was started by
  an earlier agent
  (a newer one was
  installed by a `--prepare`, or by a deploy that stopped before its last
  step), what `app_allow` asks for is applied only if it
  lets nobody new in: when every address it lists is let in already, on
  the same port, or it lists none. So closing the port always works at once,
  and so does taking an address off a list that is otherwise in force. A
  change applied this way keeps the limit on new connections that is in
  force; the one `[waf]` now gives comes with its rules, at the deploy.
  Where the two differ, `allow`, `deny` and `sync` say that the limit in
  force was kept, and do not fail for it (under `--json`,
  `new_connections_kept` has the limit `in_force` and `erpc_toml`'s, each
  null for none; it is null when nothing was kept). Anything else is held
  whole, and the port stays open to exactly those it was open to:
  - `erpc worker firewall allow`, `deny` and `sync` say so, name the
    deploy, and fail (exit 1; under `--json` the error's `details` has
    `held`, the opening asked for, and `held_because`: `other_rules`,
    `earlier_agent` where the WAF was started by an earlier agent than
    the one installed or the server could not tell, `before_config` where
    it was started before its config or its unit last changed or the
    server could not tell when, `unreported_rules` where the server's
    agent is from before
    it reported them, or `no_waf` where no WAF runs yet). `allow` and
    `deny` have written the
    change to `erpc.toml` all the same, and the rest of the firewall is in
    force. A `deny` is held only when `app_allow` still names someone the
    port is not open to yet, an address an earlier `allow` could not let
    in: then the address denied stays let in until the deploy, or until
    the list is one the server has in force.
  - `erpc worker deploy` holds the same way at its firewall step, puts the
    new rules in place once the release runs, restarting a WAF an earlier
    agent started, or one started before its config or its unit last
    changed, even when its config is unchanged, and then makes the
    port what `erpc.toml` asks: open to those `app_allow` lists, with the
    limit on new connections `[waf]` gives. A deploy that fails in
    between, and a `--prepare`, leave the old rules with the audience and
    the limit they had.
  - `erpc worker status` and `firewall list` say when the rules on the
    server are not `erpc.toml`'s, or the WAF was started by an earlier
    agent or before its config or its unit last changed, with the deploy
    that makes
    them so; `--json` has `waf_rules`: `erpc_toml`, `other`,
    `earlier_agent`, `before_config`, `unreported` (a server whose agent
    is from before it reported its config, which agent its WAF runs and
    whether the WAF was started after its config, which is treated as
    other rules), `not_running`, `not_in_erpc_toml`, or null when the
    server has no WAF. Under `waf`, `binary` is what the server said of
    the WAF's process: `installed`, `other` or `unknown`; and `started`,
    of when it was started: `after_config` (after its config and its
    unit last changed), `before_config` (before one of them did, or a
    deploy's step that writes them was ended there and no deploy has
    restarted the WAF since) or `unknown`.

  An address counts as let in already only where it is listed as written:
  `198.51.100.7` beside `198.51.100.0/24` is a new one. The firewall's own
  limit (`new_connections`) is not among the keys compared: where the WAF
  on the server runs `erpc.toml`'s rules, a change to it alone is applied
  by `firewall sync` and by a deploy's firewall step.
- **Taking `[waf]` out** of `erpc.toml` and deploying removes the WAF from
  the server; `erpc worker delete` removes it with the worker.

Only `port` is required. Every key, with its default:

```toml
[waf]
port = 8080          # the public port, 1024 or above; the app keeps [run] port
methods = ["GET", "POST", "PUT", "DELETE"]
allow_paths = []     # every path
deny_paths = []
max_body_bytes = 1048576
max_header_bytes = 16384
rate = { per_second = 50, burst = 100 }
max_connections_per_address = 32
ban = { after = 100, window_secs = 60, for_secs = 600 }
block_probes = true
header_timeout_secs = 10
body_timeout_secs = 30
upstream_timeout_secs = 30
new_connections = { per_second = 50, burst = 100 }
```

| Key | What it does | What is refused gets |
|---|---|---|
| `methods` | The methods forwarded, in capitals (16 at most; never `CONNECT`) | 405, with `Allow` |
| `allow_paths` | The paths forwarded; none listed is every path. A pattern is one path, or everything under a prefix when it ends in `*`: `/api/*` is `/api` and all below it. Compared with the path once percent-decoded, case-sensitive | 404 |
| `deny_paths` | Paths refused, written the same way and checked first | 403 |
| `max_body_bytes` | The largest request body, 0 to 67108864 (64 MiB) | 413 |
| `max_header_bytes` | The largest request line and headers together, 1024 to 65536 | 431 |
| `rate` | Requests a second from one address (1 to 10000), and how many at once before the rate applies | 429, with `Retry-After` |
| `max_connections_per_address` | Connections one address holds at once, 1 to 1024 | the connection closed, unanswered |
| `ban` | After `after` blocked requests (1 to 1000) within `window_secs`, the address is refused for `for_secs` (up to 30 days) | its connections closed, unanswered |
| `block_probes` | Refuses what scanners ask for (`/.env`, `/.git`, `/wp-login.php` and the like): a short built-in list | 403 |
| `header_timeout_secs` | How long a client has to send a request's head, 1 to 120. Also how long a client that has stopped in the middle of a body, or stopped taking its answer, is waited for | 408 for the head; 400 for a body that stopped; the connection closed for an answer not taken |
| `body_timeout_secs` | How long a request's body may take in all, 1 to 600, not counting the time the WAF waits on the app. The time runs from the end of the head whenever the WAF could pass more of the body on to the app and has none to pass: the client has sent no more, or the WAF has not read yet what the client sent. It stands still while the app is accepting what it was passed, so a slow app does not cost its client the request. A body still coming once that time is used up is cut off, however steadily and however fast it came, and the request to the app is abandoned | 408 |
| `upstream_timeout_secs` | How long the app has to take the connection and to start answering, 1 to 600 | 504; 502 when the app is not listening |
| `new_connections` | The firewall's own limit: new TCP connections a second from one address to the WAF's port, dropped by nftables before the proxy sees them. nftables counts in a set of 65536 addresses for IPv4 and one for IPv6, an address staying in it for a minute. While a set is full, an address that is not in it is not counted, so this limit does not apply to it until the set has room again; the proxy's own limits (`rate`, `max_connections_per_address`, `ban`) still do | the packet dropped |

`rate`, `max_connections_per_address`, `ban` and `new_connections` are
turned off with `false` (`ban = false`); a key left out is its default.
`erpc worker check` says what the table will do, and what is wrong with it,
before any deploy.

What needs no key:

- A request that does not read as one unambiguous HTTP/1 request (both
  `Transfer-Encoding` and `Content-Length`, a folded header, a bare line
  feed inside a head) gets 400. So does a path that is not in normal form:
  a dot segment, an encoded slash, bad percent-encoding. A head ends with
  an empty line, CRLF CRLF: one that never gets there, a request written
  with bare line feeds throughout say, gets 408 once `header_timeout_secs`
  is up.
- A request to change protocol (`Upgrade`) gets 501.
- Every refusal counts towards the ban, a request over the rate and one
  with `Upgrade` included; that is why the default ban takes as many
  blocked requests as the burst lets through. Each refusal ends its
  connection.
- An address is an IPv4 address, or an IPv6 `/64`.
- What passes reaches the app with the same method, target and `Host`,
  and with the client's headers but for these, which are not forwarded:
  the ones that belong to the client's connection to the proxy
  (`Connection` and the headers it names, `Keep-Alive`,
  `Proxy-Authenticate`, `Proxy-Authorization`, `Proxy-Connection`, `TE`,
  `Trailer`) and `Expect`; every header whose name has an underscore
  (`X_Forwarded_For`, `Content_Length`), as nginx drops them, because some
  app servers read `_` as `-`; and the client's own `Forwarded`,
  `X-Real-IP` and `X-Forwarded-Proto`.
- The proxy says where the request came from: `X-Real-IP` is the address
  the connection came from, and that address is added to the end of
  `X-Forwarded-For`. Only the last entry of `X-Forwarded-For` is the
  proxy's word; the ones before it are whatever the client sent. It also
  sets `X-Forwarded-Proto: http`, and writes `Content-Length` as the number
  it read (`0010` reaches the app as `10`).

### Seeing what it does

| Command | Shows |
|---|---|
| `erpc worker status` | One line: the port, where it forwards, since when, and the counts since then: requests, forwarded, blocked (answered with a refusal), connections refused (closed unanswered: a banned address, an address over its connection limit, the proxy at its 1024 connections), app errors (502 and 504), addresses banned now. Forwarded, blocked and app errors add up to the requests, less the requests whose client left before it was answered, which are counted as requests only. A second line says so when the rules it runs are not the ones `erpc.toml` now makes, or when it was started by an earlier agent than the one installed, or before its config or its unit on the server last changed |
| `erpc worker firewall list` | The WAF's port and who may reach it; under the server's table, the same line, what was blocked by rule (`probe 7, rate 5, banned 3`), and the line that says the rules are not `erpc.toml`'s, or that an earlier agent started it, or that it was started before its config or its unit last changed, when that is so |
| `erpc worker logs --waf` | The WAF's journal (`-n`, `-f` as for `logs`): a line when it starts and stops, when an address is banned, when the app stops answering and answers again, and for each blocked request the rule, the status, the client's address, the method and the first 200 bytes of the target |

`--json` has the counts under `waf`. The rules are named as the counts
name them: `method`, `path` (not in normal form), `denied`, `not_allowed`,
`probe`, `rate`, `body`, `malformed`, `banned`, `connections`, `upgrade`,
`body_timeout`.
On the server the same journal is `journalctl -u erpc-waf-<app>-<env>`. A
forwarded request leaves no line, and no header or body is ever logged; a
blocked request's query is, as far as the 200 bytes reach.

What a client sends cannot write on your terminal. The WAF writes every
line of its journal as printable ASCII: a byte that is not is written as
`\xNN`, as are a quote and a backslash in a request's method and target.
`since` is shown only when it is a time, a count only when it is a number,
and a rule only when it is one of those above; the server checks them
before it reports them (it reads the WAF's counts from a file the WAF
writes, as a regular file of at most 4096 bytes), and erpc checks them
again before it prints them. And in what the server's agent answers (all
that `status`, `firewall list` and `deploy` show of the server) and in
every line of `logs`, erpc prints a control character as `?`, line breaks
and tabs aside.

### What it does not do

- **No TLS.** It speaks plain HTTP/1.1 on its port.
- **No HTTP/2:** it answers 400 to it.
- **No WebSocket**, nor any other `Upgrade`: 501.
- **No look inside bodies.** A body is measured, never read. The probe list
  looks at the path and the query only; it is short and a noise filter, not
  a guarantee. The app still checks its input.
- **No authentication.** Who may call the app is the app's to decide, and
  the firewall's list.
- **One address is one client.** Clients behind one NAT, or behind one
  proxy or CDN, share a rate and a ban; a client with many addresses has as
  many rates.
- **Bans and counts are forgotten at a restart** of the WAF: a deploy that
  changes `[waf]`, that installed a newer agent (a newer erpc carries
  one), or that finds the WAF started before its config or its unit on
  the server last changed; a package update on the server, a reboot, or
  the kernel
  ending it at its memory limit (1 GiB, more than twice what it holds at
  the largest `[waf]`), after which systemd starts it again. Where the
  server cannot tell which agent's process its WAF is, or when the WAF
  was started (its systemd does not print that time to the
  microsecond), every deploy restarts the WAF, whether or not anything
  changed, and `status` keeps its line for what could not be told. It
  remembers at most 8192 addresses and holds at most 1024 connections at
  once.
- **It listens on IPv4** (`0.0.0.0`), so an IPv6 entry in `app_allow`
  reaches nothing yet.
- **A path is compared as the bytes it decodes to.** An app that reads
  paths more loosely (ignoring case, `;` parameters, decoding twice) can be
  reached under a name `deny_paths` does not cover. `allow_paths` has no
  such gap: what is not listed is not forwarded.
- **A slow reader is not a stalled one.** A head has a time to arrive
  whole, and so has a body, less the time the WAF waits on the app. An
  answer has none to be taken in: a client that stops taking it is cut
  off, and one that keeps taking it, however slowly, is served to its end,
  on one of its address's connections.
- **A flood costs other clients part of their body's time.** The WAF
  runs on one thread. While a flood keeps it busy, the time it takes to
  come to the bytes a client has already sent counts against that
  client's `body_timeout_secs`, piece by piece, so a large upload can be
  cut off with 408 at the limit though its client sent it in time. An
  app that takes large bodies raises `body_timeout_secs` together with
  `max_body_bytes`.

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
    allow lists, the lines, a start that has no answer yet (`starting`),
    and the release now running with when and from where it was deployed.
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
  - **Keychain and keystore references:** in such an app, `keychain:` and
    `keystore:` references are warned about, since another machine cannot
    read them.

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

[secrets]                            # references only, in any of the three forms below
API_TOKEN    = "op://<vault-id>/<item-id>/credential"
ERPC_API_KEY = "op://<vault-id>/<item-id>/credential"

[wallet]
source = "op://<vault-id>/<item-id>/keypair"
pubkey = "<its public key>"

[services]                           # installed and started by deploy
redis    = true                      # REDIS_URL = redis://127.0.0.1:6379/
postgres = false                     # DATABASE_URL over the local socket

[waf]                                # an HTTP proxy in front of the app (The WAF)
port = 8080                          # what firewall.app_allow opens instead

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

### `[secrets]` and `[wallet]`: references

A secret setting and the wallet's `source` are references, never values.
`erpc worker secret put` and `key new` write them; by hand, one of:

| Reference | Where the value is |
|---|---|
| `op://<vault-id>/<item-id>/<field>` | 1Password, by vault and item id (a name can be reassigned) |
| `keychain:<service>/<account>` | The OS keychain of the machine that kept it |
| `keystore:<service>/<account>` | erpc's keystore on the machine that kept it: `entries/<service>/<account>.json` under `~/.erpc/keystore` |

erpc files what it keeps under the service `erpc-worker` and the account
`<app>.<NAME>`, or `<app>.wallet` for the key. A service and an account are
letters, digits, `.`, `_` and `-`; a keystore's do not start with `.`.
`erpc worker check` warns of a `keystore:` reference this machine's keystore
does not hold.

The trading key is named by `[wallet]` and by nothing else: it reaches the
app on a pipe and only for a person at a terminal, while a setting is read
with nobody there and handed over in the environment. So `erpc worker
check`, and every command that reads `erpc.toml`, refuses a `[secrets]`
line that names the reference `[wallet]` has, or a `keychain:` or
`keystore:` account ending in `.wallet`, in any case. In the keystore the
rule does not rest on the name: an entry kept as a key does not open as a
secret. In 1Password, and under a keychain account of another name,
nothing marks a key: an `erpc.toml` with no `[wallet]` that names such an
item under `[secrets]` has it read as a secret.

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
- a `[vars]` setting whose name looks like a secret, or whose value carries
  a credential (a URL with a password before its host, a token);
- a `build.prebuilt` binary that is not there, or that a server cannot run;
- a setting `run.requires` names that nothing sets;
- `firewall.app_allow` while the app listens on loopback only (not for an
  app behind a WAF, which should).

## When something fails

Failures use erpc's codes and exit statuses ([errors.md](errors.md)). The
ones a worker meets most:

| Message (start of it) | Why | What to do |
|---|---|---|
| `<app> cannot start without <SETTING>` | `run.requires` names a setting nothing sets | `erpc worker secret put <SETTING>`, set it in `[vars]`, or deploy with the line that sets it (`--grpc`, `--unlimited`). The hint names the command; for an app made from a template it carries `--generate` or `--from-account` where `init` named that flag for the setting |
| `your key was added but does not get in` | The SSH agent did not sign: 1Password locked, or its request not allowed | Unlock 1Password, allow the request, run the same command again (it carries on) |
| `1Password could not …: authorization timeout` | 1Password asked for approval and nobody answered | Allow the request in 1Password, and run it again |
| `<NAME> is empty; nothing was kept` | `secret put` read an empty standard input: the shell is not a terminal | Run it in a terminal, or pipe the value in |
| `the keystore is locked, and nobody is at a terminal …` | A command without a terminal needs the keystore, and no unlock is kept | `erpc worker secret unlock` at a terminal, then the command again |
| `nothing is kept under keystore:… on this machine` | The value was kept in another machine's keystore | `erpc worker secret put <NAME> --replace` here; for the key, bring that machine's whole `keystore` directory and its passphrase |
| `secrets.<NAME>: … is wallet.source, the trading key` or `… is an entry filed as a trading key` | A `[secrets]` line names the key's entry, or an account ending in `.wallet` | Remove the line: the app gets the key through `[wallet]`. A setting that only happened to be called `WALLET` is kept again under another name |
| `… cannot be told apart from …, which the keystore holds` | The keystore's directory has the name in another spelling, which is the same file where case is ignored | Remove the file that is not wanted from `entries/<service>/` |
| `release <id> failed: …; the server went back to <previous>` | The new release did not pass its health check | `erpc worker logs`; the previous release still runs |
| `… is locked: the trading key has not been handed over` | The server rebooted, the agent failed or was killed and systemd started it again, or `stop --lock` | `erpc worker start` |
| `port <n> is taken: <worker> on this server listens there`, `… another program on this server listens there` | Another worker that is kept running has the same health-check port, or another program listens on it | Give the app a port of its own in `erpc.toml` (`port` and the health URL under `[run]`, and the `[vars]` setting the app reads its port from), then deploy again |
| `release <id> runs, and its WAF did not come up: …` | The proxy did not start listening within 10 seconds. The message says what systemd calls its unit, whether anything accepts on the port, and how its journal ends: most often `Address already in use`, another program on `waf.port` | `erpc worker logs --waf`; free the port or change `waf.port`, and deploy again. The app runs meanwhile, and the WAF's port stays as the firewall step left it: closed if no WAF ran before, else open to those it was open to, under the rules from before, which the server has put back |
| `waf.<key> …` (from `check`, `deploy`) | A `[waf]` key is outside its bounds, or `waf.port` is below 1024, `run.port`'s, SSH's or the health check's | Fix `erpc.toml`; `erpc worker check` lists every problem at once |
| `<address> lets every address in, and erpc opens only a WAF's port to everyone` | `firewall allow --to app 0.0.0.0/0` for an app with no `[waf]` | Add `[waf]` and deploy, or name the addresses |
| `the WAF's port <port> was not opened to …: the WAF on the server runs rules that are not erpc.toml's …` (from `firewall allow`, `deny`, `sync`) | `[waf]` in `erpc.toml` was changed since the last deploy, and the change to `app_allow` would let someone new in under the old rules. The port stays open to those it was open to; SSH and the rest of the firewall are in force | `erpc worker deploy`: it puts the new rules in place, then opens the port |
| `the WAF's port <port> was not opened to …: the server does not say which rules its WAF runs …` | The agent on the server is from an erpc before this one, and does not report its WAF's config. The port stays as it was | `erpc worker deploy`: it installs this erpc's agent, puts `erpc.toml`'s rules in place, then opens the port |
| `the WAF's port <port> was not opened to …: the WAF on the server was started by an earlier agent …` | A newer agent was installed since the WAF started (by a `--prepare`, or by a deploy that stopped before its last step), or the server could not tell which agent's process the WAF is. The port stays as it was | `erpc worker deploy`: it restarts the WAF as the agent installed, with `erpc.toml`'s rules, then opens the port |
| `the WAF's port <port> was not opened to …: the WAF on the server was started before its config or its unit there last changed …` | The step of a deploy that writes the WAF's config and its unit was ended on the server before it restarted the WAF (it leaves a note there, and that holds until a deploy has restarted the WAF, also when systemd started it again in between), or one of the two files was changed there, so the WAF is not known to run the two files as they are; or the server could not tell when the WAF was started. The port stays as it was | `erpc worker deploy`: it restarts the WAF, with `erpc.toml`'s rules and under the unit on the server, then opens the port |
| `the WAF's port <port> was not opened to …: no WAF listens on it yet …` (from `firewall allow`, `sync`) | The app has `[waf]` and was not deployed with it yet, or its WAF is not running. The port stays closed | `erpc worker deploy` starts the WAF, then opens the port |
| `port <port> keeps the limit on new connections that is in force …` (a warning under what `firewall allow`, `deny`, `sync` say, which succeed) | The WAF on the server runs, and is not known to run `erpc.toml`'s rules (the four cases above: `[waf]` changed since the last deploy, an agent that does not report its rules, an earlier agent's WAF, a WAF started before its config or its unit last changed); `app_allow` lets nobody new in and still lists someone (the addresses the port is open to, or some of them, whether or not you changed the list); and the limit in force is not the one `new_connections` gives. The port was applied as `app_allow` has it, with the limit the server had | `erpc worker deploy`: it puts `erpc.toml`'s rules in place, then the limit `[waf]` gives |
| `WAF: the rules it runs are not erpc.toml's` (in `status`, `firewall list`) | As above: `[waf]` changed since the last deploy | `erpc worker deploy` |
| `WAF: it was started by an earlier agent than the one installed …` (in `status`, `firewall list`) | As above: a newer agent was installed since the WAF started | `erpc worker deploy` |
| `WAF: it was started before its config or its unit on the server last changed …` (in `status`, `firewall list`) | As above: the WAF is not known to run its config and its unit as they are on the server, or the server could not tell when it was started | `erpc worker deploy` |
| `WAF: <state>, and its config on the server does not read (…)` (in `status`, `firewall list`) | The agent installed on the server does not take the WAF's config file | `erpc worker deploy` writes it again. Until then the port is opened no wider, as under other rules: it stays open to those it was open to, and `firewall deny` still narrows or closes it |
| `WAF: not running (<state>)` (in `status`) | The WAF's unit ended and systemd did not bring it back, or it was stopped on the server | `erpc worker logs --waf` shows why; `erpc worker deploy` starts it again |
| `could not let <ip> in to line <id>` | user-api did not take the Unlimited RPC's whitelist | Deploy again; the line is on record and is taken up |
| `<kind> line <id> did not become active in <n> minutes` | The line is still being set up | Deploy again to wait more; `delete --release-server` ends it once it is active |
| `user-api did not start it (HTTP 409): OUT_OF_STOCK` | No server of that plan free in that region | `--region <another>` |
| `the start may or may not have gone through: …` | The request left and no answer came back, or user-api answered 5xx, 408 or 429 | Run the same command again: it sends the same request, which stays on record |
| `this purchase, or another of the account's, is still being made …` | user-api answered 409 `PURCHASE_IN_PROGRESS`: the first request is still at work, or another purchase holds the account's lock | Run the same command again shortly: it sends the same request |
| `user-api has a purchase under this request and does not give it to this command`, `user-api answered that it started this and did not say which` | A purchase exists that erpc cannot put on record; the server or line may well have been started by the earlier request | Look at the account's servers or lines (the dashboard, `erpc ai`); take a server up with `--vps <ID>`, or end what is not wanted; then remove the entry from `[env.<name>.starting]` |
| `user-api refused the request sent again … says nothing about the earlier one`, `user-api's answer does not say whether it started anything` | The answer was not about this request's key | Run the same command again later; or look at what the account has (the dashboard, `erpc worker status`) and, once nothing was started, remove the entry from `[env.<name>.starting]` |
| `an earlier start of … got no answer and is still on record, and this command asks for …` | The flags changed after a start that got no answer | Deploy with the plan and region the message names to carry on with it; or, once the dashboard shows it was never started, remove it from `[env.<name>.starting]` |
| `… changed in 1Password since this command read it` | Another machine wrote the inventory item meanwhile | Run the command again |
| `the shared RPC takes none of the account's API keys from this machine (<n> tried)` (from `secret put --from-account`, `erpc rpc call`, `erpc webhook run`) | Each of the account's keys was answered 401 or 403 when tried from this machine: the keys have ended, the account has no active shared RPC plan, or the keys are limited to other addresses, such as a server's | The dashboard shows a key's end date and the plan, and makes a new key. For a key limited to the server's address: `erpc worker secret put ERPC_API_KEY`, typed or piped in |
| `the shared RPC could not be asked about the account's API keys just now …, so nothing was kept` (from `secret put --from-account`) | The RPC took none of the account's keys, and for one at least it gave no answer in time or one that is not about the key (a rate limit, a failure of its own, a redirect). No value was kept, and `erpc.toml` is as it was | Run the same command again in a while; or keep the key you mean by hand: `erpc worker secret put ERPC_API_KEY`, typed or piped in |
| `shared: … HTTP 401` (bench) | The shared RPC refused the key: no active shared RPC plan, or a wrong key | Check the plan on the dashboard, or set `ERPC_API_KEY` |
| `shared: … HTTP 429` (bench) | The plan's rate limit | `--interval 150` or more |

## What erpc never does

- Put a key, a secret, or a URL that carries one on a command line.
- Write a trading key or an app's secret to a file, with one exception: its
  keystore on your machine, where each is encrypted under your passphrase. On
  a server, `erpc worker backup on` leaves the server's own backup keys in a
  root-only file.
- Start anything without showing its price, or end anything without asking.
  A start is asked at a terminal, and said and started under `--yes`.
- Leave a server open: the firewall is in force before the app first starts.
- Reach a server whose host key does not match the pinned one.
