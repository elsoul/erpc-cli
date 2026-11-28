<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Worker apps: `erpc worker`

`erpc worker` (alias `erpc w`) runs an app of your own on a server, the way
wrangler runs a Worker. It makes the app from a template, runs it on your
machine, builds it for Linux, and deploys it to an ERPC server, a new hourly one,
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
  `seal` for a machine's sealing key, `secret` for anything else), so a
  file moved or renamed to another account does not open, and neither does
  one whose kind was rewritten, or one from another keystore. An entry
  opens only as the kind it was kept as.

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
  erpc worker deploy hello-world           # your server, or a new hourly one (price asked first)
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
erpc worker deploy --new-server --grpc # a new hourly server and gRPC line, prices asked first
erpc worker deploy --udp               # an hourly UDP Forwarding line: raw shreds to the server's own UDP port
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

The pumpfun template needs Rust 1.98.1 or newer (`rustup update`): its
solana-stream-sdk 5.0.0 asks for it, and its `Cargo.toml` says so
(`rust-version`). An app whose `Cargo.toml` says so (or whose
workspace's does) is held to it: `deploy` names an older Rust, as the
compiler cargo builds with gives it in the app's directory (the one
`RUSTC`, else `CARGO_BUILD_RUSTC`, names when one is set, else `rustc`; a
`build.rustc` in the app's cargo configuration is not read), before it
buys anything.
`check` runs nothing in the app's directory, so it does not.

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
`SHREDS_UDP_BIND`, `SOLANA_SEND_RPC_ENDPOINT`) is never a secret: `--grpc`,
`--shreds`, `--udp` and `--unlimited` set it (`--udp` and `--unlimited` on
`deploy` only). `run.requires` may hold a set of settings of which one
is enough, as the pumpfun template does for its RPC: `["ERPC_API_KEY",
"SOLANA_RPC_ENDPOINT"]`; `check` names the set when neither is set, and the
first of the set is the one `init` suggests.

`deploy` finds the server in this order:

1. the one `[env.<name>]` names;
2. `--server <id>`, an ERPC Worker of the account by its id (`--vps <id>`,
   its name before, still works; a bare-metal server goes in with `--host`);
3. `--new-server` (before, `--new-vps`), the cheapest hourly server in the
   region nearest this machine (by its time zone; `--region` and `--plan`
   choose otherwise). For an environment `erpc.toml` has nothing for yet,
   it is started in the ERPC account, which makes the app an ERPC Worker
   there (**The first deploy** below);
4. `--host <address>`, a server of your own: Ubuntu or Debian with systemd,
   nftables, `sudo` and Python 3 at `/usr/bin/python3`, reached as root or a
   user with passwordless sudo; the worker's firewall then drops every inbound
   connection to that server but SSH, the app's port when
   `firewall.app_allow` lists someone and, with `--udp`, the UDP Forwarding
   line's port, so a server that serves anything else is not the one to use;
5. otherwise, at a terminal, a list of the account's running ERPC Workers,
   each by its id, address, region and spec (read from the product's name
   the account gives each, when it is in the known form below), with
   "start a new one" at the
   end (for an environment `erpc.toml` has nothing for yet, started in the
   ERPC account as with `--new-server`).

What `erpc worker` shows calls an ERPC server an **ERPC Worker**, followed by
its spec as the ERPC account or the product's name gives it, such as `ERPC
Worker (1 vCPU, 4 GB memory, 10 GB NVMe)`, and by its id where you need one
to name it (`ERPC Worker 100001`): in its questions, prices, status, deploy
lines and hints, in every language, never by "VPS" or the product's own
name. What neither gives is left out (a server kept in the ERPC account
has its vCPUs and memory, and no disk). A spec is read from the product's
name only when all of the name is in the known form, word by word, case
aside but for `GB` and `TB`:
- the product's own name, before the first ` - `, only of 🛰️, SLV, EPYC,
  VPS, VPS+, VPS++, VPS+++, Super, Premium, Max and Plus (a `+` there
  only within those words), as the account names its plans (`🛰️ EPYC
  VPS++ - 4 vCPU AMD EPYC4G x 16 GB DDR5 - 50 GB SSD NVMe4`);
- then parts split by ` - `: a CPU part, `<n> vCPU` (1 to 3 digits), then
  nothing, AMD, Intel, EPYC, EPYC4G, Xeon, Ryzen, AMD EPYC, AMD EPYC4G,
  AMD Ryzen or Intel Xeon, then, if given, `x <n> GB <memory>`; a memory
  part, `<n> GB <memory>`; a disk part, `<n> GB <disk>` or `<n> TB
  <disk>` (1000 GB each);
- memory words are DDR4, DDR5, RAM and ECC, disk words SSD, NVMe, NVMe3,
  NVMe4 and HDD, one kind of disk (HDD not with SSD or NVMe), no word
  twice in a part; a number is up to 9 digits with no nought first;
- each of a CPU part, memory and a disk part at most once; disk parts
  joined by ` + ` are the one disk part and give no disk, and a `+`
  between anything else gives none.

Any other name (another word, a count however written, a sign, a size too
large) gives no spec at all: the server is shown as `ERPC Worker` and its
id alone. A running server's spec is read the same way from the product's
name the account gives with it. A server of your own (`--host`) is a
server. `erpc.toml` keeps writing
the kind it records (`kind = "vps"`), and `--vps`/`--new-vps` still work.
For an environment kept in `erpc.toml`, a deploy that buys its server
asks the price with the question `erpc ai` asks before an hourly product
is started, and `delete --release-server` asks before it ends the server
with `erpc ai`'s end question; erpc says the product's name in both as the
ERPC Worker it is. The rest of those questions, and the first login's, are
`erpc ai`'s own words, which `erpc ai` keeps for itself. A reason
user-api or `erpc ai` gives for a failure is quoted as it came, and may
name a VPS.

Anything that costs money is shown with its hourly price, the balance, and how
long the credit lasts. At a terminal it starts only after a yes. With `--yes`
it is said and started: an hourly product is paid from ERPC Credit, which is
bought beforehand, and user-api refuses a start the credit does not cover, so
a command line that names what to start and carries `--yes` is the yes.
Ending something is asked at a terminal too, with one exception:
`erpc worker delete --release-server --yes` ends the app's hourly lines and
its hourly server and says each (**Without a person** below).

### Without a person: `--yes` and `--prepare`

A script, or an agent such as `erpc ai` or another coding agent, has no
terminal to answer at. Two flags let it do the work all the same:

```bash
erpc worker deploy hello-world --new-server --inline --yes         # no key: all the way, unattended, kept in erpc.toml
erpc worker deploy pump-sniper --new-server --grpc --yes --prepare # a bot: everything but its key
erpc worker deploy pump-sniper                                     # then you, at a terminal: the key, and the start
```

- **`--yes`** answers what a start asks: the price of each hourly product the
  command names (`--new-server`, `--grpc`, `--shreds`, `--udp`, `--unlimited`).
  It does not take up a UDP Forwarding line the account already has and
  that points nowhere: that is no price, and the line may be another app's,
  so the deploy stops and names it (**Data lines** below). It also
  answers the first login to a server erpc has not made key-only yet, a new
  one or one named with `--server <ID>`: erpc logs in once with the server's
  password, puts your key in and turns password logins off. What would have
  been asked is printed on standard error, with `--json` too. Without `--yes`
  and without a terminal, a start, or that login, is refused before anything
  is bought or changed, and the refusal says to pass it. Choosing among the
  account's servers still needs a person: name the server (`--new-server`,
  `--server <ID>`, `--host`). A new server for an environment `erpc.toml`
  has nothing for yet is started in the ERPC account (**The first deploy**
  below), whose first login is asked at a terminal only: without one, or
  under `--json`, that deploy is refused before anything is bought or
  written, and `--inline` keeps the environment in `erpc.toml` as before,
  where `--yes` answers the first login too. A data line asked for keeps it
  there too, as the bot's line above does.
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

What such a deploy started, `erpc worker delete <app> --release-server --yes`
ends: it removes the app, then ends each of its lines and its hourly server
without asking, and prints what each was and its price on standard error,
with `--json` too: a command line that carries `--release-server` and
`--yes` is the yes. It does not end a server another app or environment is
on, as this machine's list of apps (`erpc worker list`) and the app's own
erpc.toml have it, with the server facts of an environment kept in
1Password read from its item: it stops before anything is removed and names
them. It stops too, naming it, for an environment whose server cannot be
read (an item that does not open, an erpc.toml that is there and cannot be
read or parsed). Servers
are compared by ERPC server id, or by address as written. An app deployed
to the same server from another machine is not on that list, nor is one
whose erpc.toml is gone.
No other end is answered by `--yes`: a line a deploy offers to end after a
failed step, and `run`'s lines, are still asked at a terminal. Without
`--yes` and without a terminal, the delete is refused before anything is
removed.

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
erpc worker deploy                          # your server, or a new hourly one

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
3. Picks the server and pins its SSH host key. An ERPC server that erpc has
   not made key-only yet, a new one or one named with `--server`, is made so
   first:
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
     here, with the limit on new connections that is in force. And a UDP
     Forwarding line's port from the IPv4 addresses it sends from (below),
     whatever is done with the TCP port: the UDP port is no WAF's.

   Each change runs under a 120-second rollback timer and is kept only once
   a fresh connection gets in, so a mistaken change cannot lock you out. The
   list itself outlives the address it was made from: a home address that
   changes does, and the way back in is then ERPC support for an ERPC
   server, or its provider's console for a server of your own (`--host`).
   So keep a second address you can reach the server from in
   `firewall.ssh_allow` (an office, a VPN exit) before trusting a home one.
6. Starts the data lines asked for (`--grpc`, `--shreds`, `--udp`,
   `--unlimited`), or takes up the ones already on record. A UDP Forwarding
   line (`--udp`) is pointed at the server, and its port is opened again
   when the addresses it sends from have changed; the app gets the port as
   `SHREDS_UDP_BIND`.
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
- **A new server:** as soon as user-api names it, before it is ready. A deploy
  that stops after that leaves it on record. The next `erpc worker deploy`
  takes it up instead of buying another, and
  `erpc worker delete --release-server` ends it. Its price was the
  question, asked or answered by `--yes`; a deploy asks no second "Go
  ahead?" after it.
- **An ERPC Worker ended outside erpc** (in the dashboard, or by support):
  erpc asks the account you are signed in to. An ERPC Worker is missing
  from it when it is neither among its servers nor charged for at every
  look over a little more than a minute; one bought a moment ago can take
  that long to be listed, and is never missing. erpc.toml does not say
  which account bought it, so one missing from the account you are signed
  in to may be another account's: erpc names the account it looked at, and
  only you, at a terminal, can say it leaves the record. `--yes` does not
  answer that question; with no terminal, or under `--json`, nothing is
  done. The next deploy asks whether to take a missing ERPC Worker it
  never reached off the record and choose a server, as for a new
  environment.
  While a UDP Forwarding line billed by the hour is on the record and no
  server it reached is (such an ERPC Worker left it, one was bought and never
  reached, or `delete --release-server` ended the server but not the
  line), every deploy stops before it buys anything unless it has
  `--udp` (which points the line at the server it reaches) or
  `--forget-line <ID>` for the line: a line not asked for again keeps
  sending where it was pointed, and is charged all the same. The error
  names the line and how to point it or end it. `delete --release-server`
  takes an ERPC Worker ended outside erpc off the record without ending it;
  it asks the account only about one never reached, or one you say is not to be
  reached (`--forget`). A server that was reached is
  removed from and ended as before: erpc never takes a failure to reach
  it (its firewall, your network) for its end.
- **The server's facts:** host, pinned key and allow list are written right
  after the firewall (step 5), so a deploy that fails later can still be
  reached by `logs`, `status` and the next deploy.
- **A start's request:** before a start is sent, its request key goes into
  `[env.<name>.starting]` with what it was for, under `server`, `grpc`,
  `shreds`, `udp` or `unlimited`:

  ```toml
  [env.default.starting]
  server = { key = "<32 hex digits>", family = "vps", product = "<product id>", region = "amsterdam" }
  grpc   = { key = "<32 hex digits>", family = "grpc", product = "<product id>", ip = "203.0.113.10" }
  udp    = { key = "<32 hex digits>", family = "udp-forwarding", product = "<product id>" }
  ```

  A UDP Forwarding start names no region and no address (where the line
  sends from and to is set once it is started), so a deploy that asks for
  another `--udp-port` or `--udp-region` sends the same request again. Its
  route answers with codes of its own, read by the same rule: a held
  purchase lock is `PURCHASE_IN_PROGRESS`, `UDP_FORWARDING_CONFLICT` is a
  409 with another code, `UDP_FORWARDING_UPSTREAM_UNAVAILABLE` a 5xx.

  The entry is what the next run sends: the same key, and never a new one
  while it is there. What erpc does with each answer follows one rule: **a
  request sent again leaves the record only when the answer is the purchase
  itself**, a 2xx that names the server or the line, **or says that what
  was bought under its key has been ended** (its key is refused from then
  on).
  A first request, whose key nobody sent before, also leaves on a refusal
  that is certain.

  | user-api answers | A first request | A request sent again |
  |---|---|---|
  | 2xx, with the server or line it made | On record; the entry goes in the same write | The same |
  | 2xx that says it started it and names nothing | The entry stays: something was started that erpc cannot put on record. Nothing is sent again | The same |
  | Nothing (a timeout, a broken connection, erpc stopped), 5xx, 408, 429 | The entry stays: run the same command again | The same |
  | 409 `PURCHASE_IN_PROGRESS` | The entry stays: the purchase is still being made; run the same command again shortly | The same |
  | 409 `IDEMPOTENCY_CONFLICT` | The entry goes: the key was made by this run, so the purchase it belongs to is not an earlier request of erpc's. Nothing is sent again by itself | The entry stays: a purchase exists under the request, which may well be the earlier request's own. Nothing is started, and nothing is sent again |
  | 409 `OUT_OF_STOCK`, `REGION_DOWN`; any other 4xx | The entry goes: nothing was made under a key never sent before | The entry stays: the answer says nothing about the first request |
  | 409 "This purchase was ended while it was starting. Nothing more was granted." (gRPC and Shreds, with no code) | The entry goes: what was bought under the key has been ended, and user-api refuses the key from then on, so it is not sent again. It may have been charged by the hour from its start until it was ended, one hour at the least (for a first request, the hour paid for before it was ended), which the dashboard shows. If the entry cannot be written, the error says so, and the next run of the same command sends the key once more | The same: what the earlier request bought may have run for hours before it was ended, whatever the sentence says |
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
    - A server: `erpc worker deploy --server <ID>` takes it up; the dashboard
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
    inventory environment). Only then, or once user-api answers that what
    was bought under the key has been ended, does a run make a new
    request.
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

## Data lines: gRPC, Shreds, UDP Forwarding, Unlimited RPC

ERPC's hourly lines take no token: a gRPC, Shreds or Unlimited RPC line
admits the server by its address, and a UDP Forwarding line sends to it.
erpc starts them for the server and gives the app their endpoints:

| Flag | Line | The app gets |
|---|---|---|
| `--grpc` | Geyser gRPC | `GRPC_ENDPOINT` |
| `--shreds` | Shreds (Shredstream gRPC) | `SHREDS_ENDPOINT` |
| `--udp` | UDP Forwarding (raw shreds over UDP) | `SHREDS_UDP_BIND` (`0.0.0.0:<port>`) |
| `--unlimited` | Unlimited RPC in the server's region | `SOLANA_SEND_RPC_ENDPOINT` |

- **Plans:** each line is the cheapest of its family unless `--grpc-plan`,
  `--shreds-plan`, `--udp-plan` or `--unlimited-plan` names one.
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
- **UDP Forwarding:** the leader's raw shreds, sent over UDP from an ERPC
  node to a port of the server's own, with nothing in between. The app binds
  that port (`SHREDS_UDP_BIND`) and decodes the shreds itself.
  - **Before anything is bought,** the server and the other lines
    included, erpc checks what the UDP step would refuse: the server's
    address, which must be a public IPv4 one where it is known (a `--host`
    server, or the one on record), the port (below),
    the region where the deploy decides the server itself (`--udp-region`,
    the server on record, or a new server's `--region` or nearest region; a
    `--host` server needs `--udp-region`), the plan, and the product's list
    of the account's lines, which every later step reads too. When user-api
    does not let erpc's sign-in reach it, `deploy --udp` stops there, in
    user-api's own words, and this deploy has started nothing. Once
    the server is known (`--server`, or one picked at the terminal) the region,
    the port and the other workers' ports are checked again before any line
    is started.
  - **Plans:** Standard, €0.69 an hour, sends from one ERPC node; Premium,
    €1.39 an hour, from a mesh of nodes in its region, the first copy of
    each shred, and adds Dublin. In ERPC's own measurement (Frankfurt,
    2026-10-30) Premium was first for 98% of the shreds both carried, by a
    median of 1.78 ms ([ERPC's announcement](https://erpc.global/en/news/2026/11/03/erpc-shreds-udp-forwarding-premium-20261103/)). The cheapest the catalogue offers is taken unless
    `--udp-plan <product id>` names one; the catalogue lists Premium for the
    accounts it is on sale to. Prices are the catalogue's on 2026-11-13;
    `deploy` shows the current one before it asks.
  - **Region:** the shreds are sent from the server's ERPC region, or from
    `--udp-region`: amsterdam, frankfurt, london, ny, tokyo or singapore,
    and dublin with Premium. A `--host` server has no region on record, and
    neither plan sends from sydney, so both need `--udp-region`.
  - **Port:** `--udp-port`, else the port of the line on record, else 10001;
    1024 or above (the worker cannot bind a lower one), not the SSH port or
    `run.port`, nor a UDP port another worker on the
    server receives on. erpc opens it in the server's firewall, for IPv4
    only, to the addresses ERPC sends from, which go on record as the line's
    `sources` and are read again at each deploy, since ERPC may change them.
    An address that is not IPv4 is an error that names it.
  - **When user-api names no address:** the port stays closed, and deploy,
    `firewall sync` and `firewall list` say so. `deploy --udp
    --udp-any-source` opens it to any IPv4 address for that deploy; nothing
    on record keeps it open, so a later deploy or `firewall sync` without
    the flag closes it again. A port open to any address takes in whatever
    anyone sends it: the pumpfun template checks every shred against its
    slot's leader, and an app of your own has to do as much.
  - **Pointing it at the server:** erpc sets the line's destination to the
    server's address and port and waits up to 10 minutes for it to be
    active. Premium is charged only from then, Standard from the start; so a
    line started and not yet pointed (a deploy that stopped there) is taken
    up by the next deploy whether or not it is charged yet, and every
    deploy's summary names it and says whether it is charged. A line just
    started that user-api then does not list, or that does not become
    active, is offered to be ended at once.
  - **A line started elsewhere:** an hourly Standard line of the account
    that is pointed nowhere (a deploy that stopped before pointing it, or
    one started from the dashboard or `erpc ai` and not pointed yet) is
    offered in place of a new one, and taken up only on your yes at a
    terminal. Under `--yes` the deploy stops instead, before anything is
    bought, and names the line:
    whether it is this app's or another's is not a price `--yes` accepts.
    Take it up at a terminal, or end it if nothing uses it, and deploy
    again. While a start of this deploy's is on record no such line is
    offered: the start is sent again with its key, which finds the line it
    made.
  - **Not on this machine:** `erpc worker run` does not take `--udp`. The
    shreds go to one public IPv4 address, and a laptop behind NAT cannot
    receive them.
  - **Behind a WAF:** the UDP port is no WAF's. It is opened as the line's
    record says whatever happens to the WAF's port, and a deploy whose
    line was pointed again, or whose sources changed, applies the UDP port
    again with the WAF's port left as step 5 left it.
  - **What it costs:** `erpc worker status` lists it as `UDP Forwarding line
    <id>` with its price per hour, as Standard or Premium, beside the server
    and the other lines.
  - **From `erpc ai`:** `my_services` lists the account's UDP Forwarding
    lines (where each sends to and from), and `point_udp_line` points one at
    an address and port after your yes. That changes no firewall: for an app
    of erpc's, `deploy --udp` is the way.
  - `erpc worker delete --release-server` ends it with the other lines.
- **Unlimited RPC:**
  - It runs on a dedicated server, which takes up to 45 minutes to set up.
    erpc lets the worker's address in, and keeps waiting through that.
  - It serves `sendTransaction` and a short list of reads, not
    `getProgramAccounts` or `getTokenAccountsByOwner`. So the app sends
    through it and reads where it did.
  - Its endpoint is plain HTTP (no TLS) and admits only the whitelisted
    address.

### Lines for a run on this machine

`erpc worker run` takes `--grpc` and `--shreds` too (not `--udp`), for trying
the app here against real data before it goes to a server:

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
| `erpc worker status` | Locked or running, which release, since when. For an environment kept in `erpc.toml`, when signed in and user-api answers: what the environment costs by the hour, each item on record with the price the account is charged for it, and the account's credit with how long it lasts; an item that is not among the account's charges is said to be not among them, no more (the list can be a minute behind a start, and a line ended elsewhere stays on record until `--forget-line`). `--json` has the same under `hourly.charged`. Otherwise it says what is on record. For an environment kept in the ERPC account, it says what the account's record holds instead, with no prices (see "What changes once moved") |
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
| `erpc worker delete`, `delete --release-server` | Removes the worker; `--release-server` also ends its hourly lines and its hourly server (in an environment kept in the ERPC account, a line bought as part of a Bundle is taken off it without being ended). A plain delete refuses a server bought and never reached (it would forget it while charged), and one of a reached hourly server takes it off the record while it is still charged, which it warns of. What could not be removed or ended stays on record; an hourly server never reached (or not to be reached, with `--forget`) that is missing from the account you are signed in to is not among it (`--release-server` takes it off the record without ending it, on your yes at a terminal, naming the account; `--yes` does not answer that). `--forget` leaves a server that can no longer be reached unreached; `--forget-line <id>` takes off the record a line ended outside erpc |
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

A command given no app (no name, no `--dir`) run where there is no
`erpc.toml` in the current directory or above it asks, at a terminal, which
app: the apps erpc knows on this machine (`erpc worker list`) whose
`erpc.toml` says a name, each by that name and its directory. The command
then goes on with the app picked as if its directory had been given with
`--dir`, and the commands its hints name carry that `--dir`. Esc ends it
with nothing done. When erpc knows no app on this machine, or none it can
read, it says so, and the hint starts with `erpc worker init`; when the list
of apps (`workers.toml`) cannot be read, the error is that file's. The app is
asked for before the command checks its own options, so a value it refuses
(`erpc worker backup on --at 25:99`) is said after the pick.

The picker asks for a command that only reads, or that asks before it
buys, ends, deletes, sends or changes anything: a key typed ahead must not
choose what a command that goes ahead without asking acts on. One step is
the exception: `deploy` may start a data line an earlier run agreed to,
with no question in that run (below).

The picker asks nothing, and the command fails with `there is no erpc.toml
in … or above it` as before, for:

- any command given `--yes`;
- the commands that change something, or run the app's code, with no
  question of their own: `run` (and `run --check`), `build` (cargo runs the
  app's build scripts), `key new`, `key import`, `secret put --generate` and
  `secret put --from-account`, `secret rm`, `api` with a method other than
  GET, and `backup now`;
- any command under `--json`, with no terminal (a script, a pipe), or with
  `TERM=dumb`.

The commands that do ask are `check`, `key show`, `key balance`, `key send`
(which always asks before it sends), `secret put` with a value typed,
`secret list`, `server start`, `server end`, `deploy`, `bench`, `status`,
`logs`, `api` with GET, `trades`, `start`, `stop`, `restart`, `rollback`,
`releases`, `delete`, `move`, `firewall list`, `firewall allow`, `firewall
deny`, `firewall sync`, `backup on`, `backup off` and `backup status`, each
without `--yes`. The app is picked first. Then four of them may do
something before a question of their own, or with none in that run, all of
it free but for a data line a deploy starts as an earlier run agreed
(below):

- `server start` makes the app's and the environment's records in the ERPC
  account when they are missing (they cost nothing), before its price
  question;
- `deploy` looks at the Rust toolchain in the app's directory, unless the
  app ships a `build.prebuilt` binary (which is not built) or cargo is not
  installed: it runs `rustc` there (and `rustup`, to cross-build). Which
  `rustc` that is comes from `RUSTC` or `CARGO_BUILD_RUSTC` when one is
  set, else from `RUSTUP_TOOLCHAIN` or the app's `rust-toolchain.toml` (a
  `path` toolchain included), and rustup can install the toolchain the file
  names. A first deploy that starts a new server in the account
  (`--new-server`, or the new server picked at the terminal, for an
  environment `erpc.toml` has nothing for; or one run again after it
  stopped) also makes the app's and the environment's records in the ERPC
  account when they are missing, as `server start` does, before its price
  question; with a `--plan` whose product's name gives no size erpc reads,
  it stops there, nothing bought and nothing asked. Each data line's price
  is asked after the server's, and the lines asked are kept on this machine
  (`worker_line_starts.json`) only after those yeses. When a start this
  machine kept for it went through before, it says so instead of asking the
  price, writes `account = true` for the environment to `erpc.toml`, as the
  yes to that start agreed, and keeps the lines asked on this machine, to be
  asked when they are started. A deploy of an environment kept in the
  account whose record names a server and no deploy, with a data line asked
  or kept on this machine for it, keeps the lines asked on this machine
  before any question, and starts a line an earlier run agreed to, and
  never sent, with no question in that run while the hourly catalogue's
  price is the one agreed to: that line is charged by the hour from then,
  its price said on stderr;
- `server end`, run again after a stop, may first finish clearing the
  address of a server whose end was already said yes to, and then asks
  nothing more in that run;
- `delete --release-server` of an environment kept in the ERPC account that
  the account no longer has, when this machine trusted it under this
  sign-in (a run that stopped after deleting it, say): it may first finish
  deleting the app's record that an earlier yes agreed to delete with it,
  with the settings and secrets the account keeps for the app, then puts
  the environment away here (its table in `erpc.toml` and this machine's
  records of it), and asks nothing in that run.

At a terminal, results and failures are drawn with a mark on each line (✅
done, ⚠️ to heed, 💡 a hint, 👉 the commands to run next) and progress with
›. Three steps that can take minutes are a spinner there instead: the build
(`erpc worker build`, and a deploy's), a deploy's wait for a new server to
be ready, and its wait for a server kept in the ERPC account to be ready for
its first login. The spinner shows the step, the time taken so far, and a
short trading tip in the language erpc speaks, the next one every eight
seconds; a deploy that builds while its new server gets ready shows both
steps on one spinner. When a step ends, on success or failure, the spinner
goes and the step's › line is printed in its place (the first-login wait's
once, where it said it every round before). Under `--json`, off a
terminal, or with `TERM=dumb`, there is no spinner and these steps print
what they printed before. Anywhere else (a pipe, a file, a script) the plain
lines are as they were, and `--json` is unchanged, with these exceptions:

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
  "changed": false, "erpc_toml": {…}}`, or `"account": {…}` for an
  environment kept in the ERPC account. It has the lists `erpc.toml`, or
  the account, asks for, as in `firewall list`; nothing in it says what
  is in force on the server, which is not asked. The JSON of an `allow` or a
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
  it again by itself when it fails, under the unit it had read).
  Something at that path that cannot be removed (a directory, a file made
  immutable or append-only: only root can put one there) keeps it counted
  so after every deploy: a deploy that leaves the WAF's config and unit
  as they are restarts the WAF, which forgets its bans and counts, and
  opens the port as `erpc.toml` asks; one that would change them (you
  changed `[waf]` or `run.port`, which the WAF forwards to, or the erpc
  deploying writes the WAF's unit differently from the one that wrote it)
  cannot leave its note, so it changes nothing, opens the port no wider and
  fails; and outside a deploy the port is opened no
  wider. The deploy, `status` and `firewall list` say so with the path,
  and `allow`, `deny` and `sync` name it in their hint: remove it on the
  server as root. Then the two times decide again. What
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
    server could not tell when, `note_kept` where that is so for good, by
    a note on the server that cannot be removed, `unreported_rules` where
    the server's agent is from before
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
    `earlier_agent`, `before_config`, `note_kept` (`before_config` kept
    so by a note that cannot be removed), `unreported` (a server whose
    agent is from before it reported its config, which agent its WAF runs and
    whether the WAF was started after its config, which is treated as
    other rules), `not_running`, `not_in_erpc_toml`, or null when the
    server has no WAF. Under `waf`, `binary` is what the server said of
    the WAF's process: `installed`, `other` or `unknown`; and `started`,
    of when it was started: `after_config` (after its config and its
    unit last changed), `before_config` (before one of them did, or a
    deploy's step that writes them was ended there and no deploy has
    restarted the WAF since) or `unknown`; and `note_error`, null, or the
    path of a note that cannot be removed and why (a deploy's `--json`
    has the same under `waf`, as the server could not remove it).

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
    `erpc login` keeps the session in 1Password, unless the first deploy
    starts its server in the ERPC account (**The first deploy** below),
    which then keeps it. `deploy --vault <vault-id>` names another vault,
    and `deploy --inline` keeps the facts in `erpc.toml`; either keeps a
    new environment out of the ERPC account.
  - **Writes:** each one checks that the item has not changed since it was
    read.
  - **Delete:** archives the item.
  - **Listing:** `erpc worker list` also shows the worker items in the login
    vault that no app on this machine names.
  - **Keychain and keystore references:** in such an app, `keychain:` and
    `keystore:` references are warned about, since another machine cannot
    read them.
- **In the ERPC account:** `account = true` under `[env.<name>]` keeps the
  environment's server facts in the ERPC account instead. The account names
  the environment's servers and lines by ids of its own, never by product
  number. This is new, and
  being built a command at a time:
  - **So far:** `erpc worker status` reads such an environment from the
    account. `logs`, `start`, `stop`, `restart`, `releases` and `deploy`
    reach its server with what the account says of it, trusted as below, and
    write nothing to `erpc.toml`; the server must have an address and a host
    key in the account first (for a server `server start` or the first
    deploy started, `deploy` logs in to it once and writes them: **The
    first login** below). Only a
    server in use that the account has as
    active is reached: one gone, given back or held, and a server in use
    this machine pinned that the record no longer names (ended, or no longer
    the person's), are refused before anyone is asked, since their address
    may be someone else's now. A server in use that is suspended is said
    with every way it may come back, none as sure: paid by the hour, once
    the credit covers an hour of all the account's hourly charges; paid
    from credit by the period, once it covers its next period's charge;
    paid by card, once the unpaid invoice is paid; soon, since one left so
    can be ended. Its `hourly` is not read for it: which way brings it back
    is the account's to decide. One in another state is said with running
    the command again once it is active. Each names ERPC support and the
    server's id.
    The pinned host key stays the last check:
    a machine that does not hold it is never logged in to. `check`, and
    `list` in its plain and `--json` output, name where it is kept;
    `firewall` works on it too (below); `move` says it is moved already;
    `server start` starts a server for one whose record names no server and
    no address, and `delete --release-server` ends what it runs on (a
    line bought as part of a Bundle is only taken off it) and
    deletes its record (both below). Every other command refuses it by name
    rather than read it as an environment with no server, and a `delete
    --release-server --yes` of another environment that would end an hourly
    ERPC server counts it as one whose server is not known here, and is
    refused (without `--yes`, it is asked).
  - **Moving one there:** `erpc worker move --to account [--env <name>]`
    takes an environment kept in `erpc.toml` into the account: the app's
    record and the environment's server facts are written there, its
    server and lines are taken in by their product ids, and whether the
    app runs on the server is read from its agent. `erpc.toml` then keeps
    only `account = true`. It asks first, at a terminal; it cannot be
    undone, since the account does not give the ids back. With the
    question it says, in a note, that it is one way and what changes once
    moved, in the groups of the list below (What changes once moved), and
    points to it; `--yes` goes ahead, and says the same note on stderr as
    it starts.
    - It is written in the order that resumes. What the account has is read
      and decided on first. A server already in the slot in use is sent
      again before anything is written, as the account keeps it, so that
      the account says whether it is this one. Then the account is written,
      each step one it answers the same way when it is sent again; the
      lines, which the account names only by its own ids, are confirmed as
      they are sent. `erpc.toml` is changed after the account, and only when
      it is still as the move read it; this machine's records of what it
      trusts follow. A move stopped half way is run again.
    - It refuses, before the account is written: an environment with a
      start whose outcome is not known yet (`starting`); one with a UDP
      Forwarding line (the account does not yet give the addresses the line
      sends from, which the server's firewall lets in); one a 1Password item
      keeps (every checkout of the app reads the item, and it cannot yet tell
      them all); one whose server has no address or no host key yet (deploy it
      first: once moved, nothing could finish it); one that is backed up (its
      keys would go into the account, where deleting the environment does not
      revoke them yet: `erpc worker backup off` first); an app of that name in
      the account on another chain or with another wallet; an environment the
      account keeps with another server or more lines, or with a deploy on
      record and other facts (it is in use from another checkout); and an
      account that does not yet let this sign-in end the servers and lines of
      an environment kept there. A server the account's record holds that the
      move does not take in stops it before anything is written, gone or not:
      one in another slot, one it reads as gone, or any server when the
      environment runs on a server of your own (ERPC support, given the
      environment, can say how to go on). An environment that runs on no
      server yet is not moved either (deploy it first). An environment the
      account keeps with other server facts and nothing taken in yet (a
      move that stopped early) is brought to `erpc.toml`'s, and a record
      taken in again is brought to whether the app runs now.
    - Before `erpc.toml` is changed, the account's record is read as the
      commands that work on a moved environment read it (its server
      reached, its record carried by a deploy, its lines handed to the
      app); one they would refuse stops the move, with `erpc.toml` left as
      it was.
    - What this machine pins as trusted is its own record, with the server
      it took in: the account's answer after the move must reach the server
      the same way, or nothing is pinned and `erpc.toml` is left as it was.
      The list of who may reach the app this machine moved is recorded as
      the one put on the server, so the first deploy after does not say it
      as new, and says a change another sign-in made meanwhile.
    - A move refused for what the account's record holds says so, with
      `erpc.toml` as it was; ERPC support, given the environment, can say
      how to go on.
    - The lists of who may reach SSH and the app go into the account as
      the firewall commands write them (an IPv4-mapped address in hex).
    - A line bought as part of a Bundle stays with its Bundle: the account
      refuses to take one into an environment (`not_adoptable`, reason
      `bundle_part`), writing nothing, and the move stops there, said by
      the line's product ID, with `erpc.toml` left as it was and what was
      already written to the account staying there; ERPC support, given the
      ID, can say how to go on. Until its Bundle is on the account's
      record, one may be taken in.
    - Whatever stops the move after the account was written to is said as
      a move that stopped part way, with `erpc.toml` left as it was (a test
      cuts off each write in turn). A line the account does not have is
      said by its id: it may have been ended, or be another account's; if
      the dashboard shows it ended, `deploy --forget-line <id>` takes it off
      `erpc.toml`'s record before the move is run again. A stop before the
      first write that the account answers (a refusal, or no answer) is
      said as not moved.
  - **The first deploy:** the first `erpc worker deploy` that starts a new
    server makes the app an ERPC Worker in the account, in that one
    command. It is the way for an environment `erpc.toml` has nothing for
    yet (no `[env.<name>]`, or an empty one) when `--new-server` asks for a
    new server or the person picks "start a new one" at the terminal:
    - Before anything is written or bought: a terminal and no `--json`
      (the first login is asked there only; without one it is refused,
      saying so), `--region` one the account names (amsterdam, frankfurt,
      ny, tokyo, london, singapore or sydney), what any deploy checks on
      this machine first (the app's settings, key and secrets, the build's
      tools, the key to log in with; a setting a line asked gives counts as
      given), no more settings or secrets than the account keeps the names
      of, the sign-in, and each data line's plan, read from the hourly
      catalogue (a plan it does not offer is refused then).
    - Then the start, as `server start` makes it (below): the app's and the
      environment's records made when the account has none (free, said on
      stderr), the cheapest size the account offers, in `--region` or the
      region nearest this machine by its time zone, its price asked at the
      terminal (`--yes` says it on stderr instead). Right after its yes,
      each data line's price is asked (said under `--yes`), before anything
      is bought; a no to one buys nothing and leaves `erpc.toml` as it was.
      Then the lines asked are kept on this machine, owed, `erpc.toml` gets
      `account = true` for the environment, and only then is the start
      sent, under a key kept on this machine. A no leaves `erpc.toml` as it
      was; once a yes wrote `account = true`, it stays, whatever follows
      (another size or region declined, a line not started), and `erpc
      worker deploy` goes on from there (with `--plan` when it was asked,
      as the stop says), the lines kept here with it.
    - Then the deploy goes on as one to an environment kept there: it waits
      for the server, logs in to it once after a yes at the terminal (**The
      first login** below), asks whether to trust what the account then
      has, and deploys.
    - A run that stopped is run again: `erpc worker deploy` of an
      environment `erpc.toml` keeps in the account whose record names no
      server, no address, no line and no deploy starts one the same way, a
      start kept on this machine or open in the account first, and never a
      second server while one is open or on the record. There the prices
      (the server's, then the lines') are asked at the terminal even with
      `--yes`, unless `--new-server` is on the command line too; `--yes`
      still takes only the size `--plan` names, and offers no other. A
      line an earlier run agreed to is said, not asked again. A first deploy makes the records before it
      writes `account = true`, so an environment the account you are signed
      in to has no record of at all is another account's, or deleted: it
      is refused as before, saying so (`erpc login` with the account it was
      made in), and only `--new-server` starts a server for it in the
      account you are signed in to, its price asked as for a first deploy
      (said under `--yes`). An
      environment whose record names a server, an address, a line or a
      deploy (as one deployed to before keeps it once `server end` ended its
      server) is deployed to, or refused, as before; but one whose record
      names a server and no deploy yet (a first deploy that stopped after
      its server's start, or one `erpc worker move --to account` moved in),
      deployed with a data line's flag, or with a line kept on this machine
      for it, and nothing else for a server, starts those lines before the
      deploy, at a terminal (refused first under `--json` or with nobody
      there), once what refuses the deploy is checked (what it needs on this
      machine, the names the account keeps, a server coming in or going
      out). So the plain `erpc worker deploy` a stop names goes on with the
      lines asked.
    - A data line asked on the first deploy (`--grpc`, `--shreds`,
      `--unlimited`, each at its plan or the cheapest) is started in the
      ERPC account for the environment, once its server is logged in to:
      a gRPC or Shreds line lets the server's address in, an Unlimited RPC
      is started in the server's region; the question or note says which.
      Its price is the hourly catalogue's for the plan; the account's line
      start takes no price, and the line is charged its own. The lines
      asked are kept on this machine (`worker_line_starts.json`, beside
      erpc's config) until each is on the record. One agreed to and never
      sent is started without asking again while the catalogue's price is
      the one agreed to and the run does not name its flag again (said on
      stderr); a price changed since is asked (said under `--yes`), and so
      is a line whose flag the run names, and every other start of a line.
      A no to a line's price, there or on a first deploy, lets the line
      kept here for it go: a run again starts it only with its flag.
    - Each line start is sent under a key kept on this machine before it is
      sent, as not to be sent again, and what the account answers decides
      what becomes of it, as its contract says: started, the key goes; an
      answer that bought nothing (credit, a limit, a line not sold, another
      start of it open, the line ended while it was being started), the key
      goes, and the line stays asked, its price asked again on a run again;
      an answer that says to send it again (a start pending with a retry,
      an unavailable purchase, the account busy), or none at all, keeps the
      key, and a run again sends it again under it, with the same body, its
      price asked again, which buys no second line; any other answer (the
      start unsettled, whatever its reason, a key the account had with
      another request, a code erpc does not know) keeps the key and never
      sends it again, the stop naming the start and ERPC support. Each run
      reads the account first: a line of the kind on the record is used as
      it is; every open start is looked at, and one of a kind erpc cannot
      tell, two of the kind, one this machine did not keep to send again,
      or the one it kept for another plan or address, refuses the run,
      nothing sent. A start kept here that is not sent again (or that was
      kept for another plan or address), once the account lists no start
      of the kind open and names no such line, is let go only after a yes
      at a terminal, never under `--yes`; a line started after it is a new
      purchase, its price asked. Then the deploy waits up to three minutes
      for the line to be active with its endpoint; when it is not, it
      stops, and `erpc worker deploy` goes on from there, buying nothing
      more.
    - It goes as before, keeping the environment in `erpc.toml` (or its
      1Password item), for an environment that has anything in `erpc.toml`,
      for `--host`, `--server`, a server of the account picked at the
      terminal, `--inline` and `--vault`. It goes as before too, with a
      note on stderr saying why, for a deploy that asks for a UDP Forwarding
      line (`--udp` and its options) or `--forget-line`, which a deploy
      there does not take yet.
    - `--plan` names the hourly plan by its product id: its size is read
      from the product's name, in the known form (**ERPC Worker** above),
      by its vCPUs alone, and the account starts its own ERPC Worker of
      those vCPUs, at the account's price for that size (the price asked),
      not the plan's own price, memory or disk. A name that gives no size is refused,
      once the account's records are made (free), with the sizes the
      account starts, before anything is bought. Before the start, erpc
      reads what is free now (user-api's stock read of the standard ERPC
      Worker, every page; a box that names no type is one of it, and one of
      another type is left out: free now, not held; when that read fails,
      the size named is started all the same). When the size named has no room in
      the region, at a terminal erpc offers in its place, each with its own
      question and price: a bigger size there, fewest cores first, then the
      same size in another region, this machine's nearest and those nearest
      it first (by the distance between the regions' cities); a no, or a
      size the account does not start, goes on to the next, and when none
      is left, it stops, saying what is free.
      A start the account answers out of stock (`OUT_OF_STOCK`), though
      listed free, is offered the next the same way. Under `--yes`, only
      the size named is started, on a run again too: not free, or out of
      stock, it stops and says what is free now, nothing bought.
    - An app whose `erpc.toml` names a wallet goes the account way too: its
      record is made with the wallet's public side (`pubkey`, and where its
      key is kept, as `erpc worker move` makes it; without a `pubkey`, with
      none), and its key is handed over at the terminal, as on every deploy.
      An app of that name the account has with another wallet, or with one
      where `erpc.toml` names none, is refused before anything is made or
      bought.
  - **A server for one that has none:** `erpc worker server start [--env
    <name>] --cores <N> --region <REGION> [--yes]` buys a server, paid for
    by the hour, for an environment kept in the account whose record names
    no server and no address yet (`account = true` under its
    `[env.<name>]`). It reads the sizes the account offers the environment,
    with their prices, says the one asked for and starts it after a yes at
    a terminal; `--yes` says it on stderr instead, and with neither it is
    refused before anything is made or bought. A size not offered is
    refused with the ones that are.
    - When the account has no record of the app, or of the environment,
      they are made first, from `erpc.toml`'s name, chain and template and
      `--env`, the environment with no server and nothing else; each is
      said as it is made, and costs nothing. An app whose `erpc.toml` names
      a wallet has its record made with the wallet's public side, as the
      first deploy makes it; an app of that name in the account on another
      chain, or with another wallet, is refused.
    - The start's key is kept on this machine (`worker_starts.json`, beside
      erpc's config) before it is sent. Each run reads the account first
      (when it has the app: the environment's open starts, then its record)
      and again after the yes: a record that names a server, or a start of
      the environment still open, makes no new start, and a start kept here
      is sent again under its own key only when the account said to send it
      again (`start_pending` with `retry`, or `purchase_unavailable`) and has
      not answered otherwise since (`rate_limited` leaves that as it was).
      A new start is sent at the environment's revision read before the
      price: when the environment changed after that read, the account
      refuses it, buying nothing (`revision_conflict`), and erpc says to run
      it again. A start sent again under its key while it is still open is
      answered as before, whatever the revision.
      What the account answers to the start, and its refusal to read or
      write the app's or the environment's record, to list the starts or to
      give the price, is said in erpc's words, with its status and, when it
      gives one, its code; a refused sign-in is said as one, with the login
      hint, and an app or environment the account does not have, by its
      name.
    - The question says that `erpc worker deploy` then waits for the
      server, logs in to it once after a yes at a terminal, and deploys to
      it (**The first login** below); and how to end it from erpc: `erpc
      worker delete --release-server`, at a terminal, which deletes the
      environment's record with it (under `--yes` that delete is refused
      while the server has no address on record to tell what else may be
      on it).
  - **The first login:** `erpc worker deploy` to such an environment whose
    server in use has no host key on record, and no address on record but
    its own (one `server start` started), logs in to it before the deploy
    reaches it:
    - It is asked at a terminal only: the first login decides which host
      key the account and this machine trust, as trusting a record does.
      `--yes` is not enough, and `--json` asks nobody; either is refused
      before anything but the record is read.
    - It waits for the account to say the server is ready (in use,
      running, set up, with an address) and for its SSH to answer, reading
      the record every 15 seconds, at most 40 times (about ten minutes, more
      while SSH is slow to answer), while the account
      has the server as available, provisioning or active; one suspended or
      held for maintenance is said as such by the deploy, as before. A wait
      that runs out says to run the deploy again; it ends nothing.
    - It asks, naming the address, the host key the server offers and the
      key erpc logs in with, and that it starts nothing and has no price.
      After the yes the record is read again: a server other than the one
      asked about, another address, a server no longer ready, or a host key
      on record stops it, with nothing sent to the server.
    - It reads the server's first login from the account once: its login
      name and, while the account hands it over, its password (the account
      counts the read among its writes, and records it in its audit
      history). An answer to wait, a server the account says is gone or has
      no machine, and an answer that cannot be read stop it; so does a login
      name erpc does not use.
    - It logs in with the password once, puts the key on the server, turns
      password logins off and checks that they are off, as for an ERPC VPS
      kept in `erpc.toml`; the host key is pinned in `vps_hosts.json` as
      soon as the key gets in. A machine reached both as an ERPC VPS (`erpc
      ai`) and as a server kept in the account keeps one pin, known by its
      host key, which serves both ways. A pin at the address that holds
      another host key stops the first login before anything is sent,
      whichever way it was written, unless it is of another server the
      account names (the account's record says the address was handed
      on); the `erpc ai` login is held the same way to a pin with no VPS
      id. With no password (not handed over
      yet, removed a day after it was, or none), only an earlier attempt on
      the same machine that got as far as the key goes on, from the key.
      One erpc made key-only before, either way, is not logged in to again:
      it is asked about as such, and only recorded.
    - Then it writes the address, the host key and the login name to the
      account's record, at the revision read; a busy account is waited for,
      and a record changed under the write is read again and written again
      while it names the same server at the same address. Each way this
      stops after the login says the key is on the server already, and
      whether this run wrote the address and host key: not, or not known
      after a write that got no answer, an unreadable one, a 5xx or a
      refusal with no code.
    - This machine does not trust the record yet: the deploy then asks at
      the terminal, as for any record it has not trusted, showing all that
      the account has of the server, and goes on after a yes.
  - **What changes once moved.** The same commands, and these
    differences, group by group, as the note before the move's yes names
    them:
    - **Sign-in, trust and reach.**
      - Every command that still works on it (`status`, `logs`, `start`,
        `stop`, `restart`, `releases`, `deploy`, `firewall`, `delete
        --release-server`) needs an ERPC sign-in and the account
        reachable: signed out, or with the account down, even `stop` does
        not run.
      - The server's facts (address, host key, SSH user and port, the list
        of who may reach SSH, the app's id in the account and the server
        in use) are trusted by the machine that moves it, as moved (unless
        that record cannot be written, which is said on stderr, `--json`
        too). On another machine
        signed in to the same ERPC account they are trusted once, with a
        yes at a terminal; `--yes` never gives it, and `--json` or no
        terminal is refused. A change asks again: a deploy from another
        machine adds that machine's address to the SSH list, so this one
        asks again.
      - A server in use the account does not show as active (suspended,
        held, gone, or with no address or host key yet) is not reached:
        `status` shows the record alone, and the other commands that reach
        the server are refused before SSH, `stop` included (`delete
        --release-server` does not reach the server at all; below).
      - What the account says of the server after a deploy's or a
        firewall change's write is trusted only when it reaches the server
        the way this machine wrote it; otherwise, or when this machine's
        record of what it trusts cannot be written then, it is said, and
        the next command that reaches the server asks at a terminal.
      - This machine's record of what it trusts (`worker_account.json`,
        beside erpc's config) that cannot be read stops each command above
        that still works on it, `delete --release-server` aside, until it
        is fixed or moved away (`list` and `check` do not read it, and
        `move` says the environment is moved already). That delete reads
        none before the account ends what the environment runs on (a line
        bought as part of a Bundle is only taken off); then it
        cannot put the environment away here: `erpc.toml` still names it,
        said as a warning (`erpc_toml: false` in `--json`), and the same
        command, run again once the record is fixed, finishes.
      - A record the account keeps in an older form, which this erpc does
        not read its server and lines from, is refused by every command,
        `status` included.
      - When SSH cannot connect, its error is said as it came, without
        the hint to forget the environment.
      - `--json` never gives the trust, and a `delete --release-server
        --json` without `--yes` is refused (`needs_terminal`) where, kept in
        `erpc.toml`, it would ask at the terminal.
      - Another ERPC account does not see it: signed in to that account,
        erpc finds no such app or environment.
    - **Commands.**
      - `rollback`, `backup` (`on`, `off`, `status`, `now`), `api`,
        `trades` and `bench` are refused: they do not work on it
        yet. A deploy's last line still names `rollback`, and the warning
        on open positions still names `api`; neither works there yet.
      - `status` says what the account's record holds (each server by
        slot, size, region and state, each line by kind), then the
        worker's own state; it no longer says what the environment costs
        by the hour, the price of each item, or the account's credit and
        how long it lasts. `--json` has `account` in place of `hourly`.
      - `start` and `restart` have the account record that the app runs
        (on an ERPC server) before the trading key is handed over; a record
        the account refuses starts nothing, and one that fails after it
        says the account now says the app runs. `stop` has it record that
        the app is stopped (on an ERPC server); a record not written is a
        warning (exit 0, and `accountRecorded`, `accountError` in
        `--json`), and what is still charged is read from the account's
        record.
      - `firewall list`, `allow`, `deny` and `sync` work on the account's
        lists, at most 16 addresses each, erpc's own counted in the SSH
        list (a list of 16 that erpc's own address is not on moves, and
        then every deploy and firewall change is refused until a `deny`);
        even an answer that changes nothing needs the sign-in and the
        trust above, and the record is read again after the yes. A
        change goes to the server first, then to the account, and each
        write that fails is said with whether the server has the change;
        another sign-in's change in between is not written over. While
        the account's lists hold what erpc would not put on the server
        (an entry erpc does not read, a network on the SSH list, and the
        rest `firewall list` names), `allow` and `sync` are refused and
        the server's firewall is not changed; `deny` can take those
        entries off, and a `deny` while something else stops the lists
        lands in the account alone. `sync` puts the account's lists on the
        server, and writes erpc's own address back to the account when it
        adds it. A deploy or firewall command says how the account's list
        of who may reach the app changed since this machine last put it on
        the server; when that record cannot be written, it is a warning,
        and the next one compares with the record before.
      - `firewall --json` answers the account's lists under `account`
        where an environment kept in `erpc.toml` answers `erpc_toml` (in
        `list` and in an `allow` or `deny` that changes nothing); `list`
        also answers `unread`, `app_allow_changed` and `stopped`, and no
        `udp`; a `deny` that lands in the account alone stops with
        `account_only` in its error's details.
      - `list` shows the environment as kept in the account; `check` does
        not check its ports and lists, which are in the account.
    - **Deploy.**
      - It no longer takes `--host`, `--user`, `--port`, `--fingerprint`,
        `--server`, `--udp`, `--udp-port`, `--udp-region`,
        `--udp-any-source`, `--forget-line`, `--vault` or `--inline`. It
        takes `--grpc`, `--shreds` or `--unlimited` only before its first
        deploy there (the record names no deploy yet), when the line is
        started in the account, its price asked, as on a first deploy (a
        line kept on this machine for it is started too); and
        `--new-server`, `--region` and `--plan` only while the account's record names
        no server, address, line or deploy for it (as after `server end` of
        a server moved in, with no deploy since), when it starts a server as
        the first deploy does. Its server cannot be chosen, no line taken off
        the record, nor one added once it is deployed to, and a deploy
        cannot bring it back into `erpc.toml` or 1Password. A setting that comes from a line erpc does not start
        there says so.
      - It is refused while the account's record holds a server coming in
        or going out, a UDP line, a line not active or with no endpoint
        yet, a line of a kind this erpc does not know or with an endpoint
        not in its form, two lines of a kind, or lists erpc would not put
        on the server; ended lines are left out.
      - It asks when the account's list of who may reach the app changed
        since this machine last put it on the server (`--yes` answers
        that one).
      - Before the trading key is handed over, the record is read again,
        and the account records that the app runs (on an ERPC server);
        otherwise nothing is handed over.
      - At most 128 settings and 128 secret settings: the account keeps
        their names, and where each secret is kept, never their values,
        with the release, the app's port, the WAF's port and the services
        it uses; the move wrote the chain, the template, the wallet's
        public key and where its key is kept. A move of an app with more
        than 128 of either is refused before anything.
      - A write another sign-in got in before is not written over; the
        `--json` answer says `account_updated`, and the summary no longer
        names the lines charged by the hour.
    - **Delete.**
      - A plain `delete`, `delete --forget` and `delete --forget-line` are
        refused.
      - `delete --release-server` never reaches the server or removes the
        worker: it asks the account to end everything the environment
        runs on, a few at a time, then to delete its record. A line bought
        as part of a Bundle is taken off the environment instead, not
        ended, whatever its state: it is billed with its Bundle. The
        account ends nothing unless all the rest can be ended: while a
        server or line on it (a Bundle's line aside) is not paid by the
        hour, is in a
        state its end does not take
        (such as still being set up, or still ending), or is a start with no
        outcome, nothing is ended, the hourly ones included, and they stay
        charged; they are ended only once that is settled and the delete
        is run again.
      - While it runs: an answer that a request ended as many as it may
        is asked again at once; a busy account, or another operation
        holding the environment, is waited for as long as it asks, up to
        two minutes, said as busy; a record changed meanwhile is read
        again, and one that holds anything not asked about is not ended;
        after 24 rounds it stops, said as still ending or busy. A stop is
        said as nothing ended only when every answer in the run was one
        the account gives before it ends anything and the record still
        holds all that was asked about; any other (another refusal, no
        answer, a record that grew) as some of it maybe ended already,
        the rest on record, with the same command to finish it.
      - On a record that names only an address (a server of your own, or
        an ERPC server ended already, which the record does not tell
        apart), it is asked at a terminal only, telling both cases;
        `--yes`, `--json` or no terminal is refused, unless this machine
        recorded, before an earlier run of the same delete sent anything,
        that you agreed to end what the environment held at that address:
        then the same command finishes it, `--yes` included. The worker on
        a server of your own keeps running there.
      - That record of what was agreed to (`worker_delete.json`, beside
        erpc's config) is written before anything is sent: one that
        cannot be read is taken as nothing agreed to, and one that cannot
        be read or written stops the delete with nothing sent.
      - With `--yes`, a delete that would end a server is refused when
        something else may be on it: another environment of this machine
        kept in the account, one in `erpc.toml` at the same address, an
        entry that cannot be read, a record with no address, or a server
        coming in or going out. Without `--yes`, the question names them.
      - An environment the signed-in account does not have is put away
        here: at once when this machine pinned it for that account, else
        after a question that `--yes` answers. Signed in to another
        account, the account that has it keeps it running.
      - The app's record stays in the account, with the names of its
        settings and secret settings, while another environment of the
        app is there; with the app's last environment it goes too (below,
        **Ending it**). The `--json` answer has its own shape.
    - **A line bought as part of a Bundle.** The account refuses to take
      one in; the move stops there, what was already written to the
      account staying there. Until its Bundle is on the account's record
      one may be taken in, and then erpc takes it off the record only by
      deleting the environment, which does not end it, and cannot end it
      apart from its Bundle.
    - **This machine's other environments, and other checkouts.**
      - While an environment of this machine is kept in the account, a
        `delete --release-server --yes` of this machine's other
        environments that would end a server is refused, and of the moved
        one too once another is kept there; without `--yes`, it is asked.
      - Another environment of the same app moved later must match the
        app's record in the account (its chain and wallet).
      - Another machine with the moved `erpc.toml` signs in to the same
        account and trusts the server once, at a terminal.
      - A checkout that still has the old table keeps the `erpc.toml`
        path, by product id.
  - **Deploying:** `erpc worker deploy` ships a release to the server the
    account names, as for any environment, and writes to the account
    instead of `erpc.toml`:
    - Who may reach SSH, when the firewall step changes it, each address
      with its prefix length; erpc adds the address it connects from. The
      account keeps 16 at most: a list that would have more is refused
      before the server's firewall is changed (`erpc worker firewall deny`
      takes an address off first). Each write is
      built on the record the account last answered with, changing only
      what the deploy changed (the backup's keys and the size asked for
      stay), and expects its revision: a write another sign-in made in
      between is refused, not written over. What the account then says of
      the server is pinned again only when it reaches the server the way
      this machine wrote it; a pin that cannot follow is said at once.
    - That the app runs, before the key and the secrets are handed over
      (not under `--prepare`). The record is read again first and must
      still be the one trusted, to be reached, and one the deploy can
      carry (no server moving, its lines as they may be handed over); a
      change during the build, or a record the account does not take,
      hands nothing over.
    - The deploy, once the app runs: the release, and what it shipped, by
      name only (the settings' and secrets' names, where each secret comes
      from, the port, the WAF's port and the services). It is written
      whatever became of the firewall step's write.
    - `--json` says `account_updated` (whether the account took these
      writes) where an environment kept in `erpc.toml` says
      `erpc_toml_updated`.
    - What a deploy says of the firewall and the WAF names the account's
      lists, not `erpc.toml`'s keys; a test holds the firewall step's
      lines and refusals to it (with a WAF and nobody on the app's list,
      erpc's address added, no address at all, a network on the list) and
      every decision on the worker's port. Lists erpc would not put on the
      server as they are (see **The firewall** below) stop the deploy
      before anything is built, bought or changed.
    - A line not active is said by what its state is known to mean, and erpc
      never says to end a line, whatever its state: being set up, deploy
      again once it is active; under maintenance (ERPC's own, or a line
      being ended, which the state does not tell apart), deploy again once
      it is active; suspended (most often for ERPC Credit or a payment),
      every way it may come back is said, none as sure, the same whatever
      its `hourly` says (a line in a Bundle follows the Bundle's billing):
      paid by the hour, once the credit
      covers an hour of all the account's hourly charges; paid from credit
      by the period, once it covers its next period's charge; paid by card,
      once the unpaid invoice is paid. An Unlimited line can be ended if
      left so, so it is said to do it soon; a gRPC or Shreds line paid by
      the hour, or bought in a Bundle paid by the hour, is normally ended by
      the account at once, and one ended does not come back, so it is said
      to add credit on the dashboard now. A gRPC or Shreds line with no
      address registered yet: register this server's address on its
      product's page; a line of a kind this erpc does not know, and any
      other state, deploy again once it is active. Each names ERPC support
      and the line's id; the other refusals of a line (UDP, an unknown kind,
      two of a kind, an endpoint not in its form) name ERPC support, without
      an id.
    - A record found at the hand-over that a deploy cannot carry is said
      as such: the release is on the server, and the key and the secrets
      were not handed over.
    - The app is handed the endpoints of the lines the account names that
      are in use (active), one of each kind; an ended line is left out.
    - So far a deploy there changes no line once it is deployed to. While
      the account's record names no server, address, line or deploy, it
      starts a server first, as the first deploy does (**The first
      deploy**), taking `--new-server`, `--region`, `--plan` and a gRPC,
      Shreds or Unlimited line's flag; while it names a server and no
      deploy, it starts the lines asked, or kept on this machine, before
      the deploy. `--server`, `--host`, a UDP Forwarding line and its
      options, `--forget-line` and a place to keep a new environment
      (`--vault`, `--inline`) are refused before the account or the server
      is reached; `--new-server`, `--region` and `--plan` once the record is
      read (signed in first) and names something; a data line's flag once
      it names a deploy, an address and no server, or a server with
      `--new-server`, `--region` or `--plan` beside the flag. A record
      with a server coming in or
      going out is refused too, and so is a UDP Forwarding line, a line
      with no endpoint yet, a line that is not active, two lines of one
      kind, or an endpoint not in its form: the record's refusals before the
      server is reached, each with what `status` shows and the way out:
      ERPC support for each, and the dashboard for a suspended line or one
      with no address registered. The app is handed a line's
      endpoint as erpc.toml's lines are read (gRPC and Shreds over TLS).
  - **The firewall:** `erpc worker firewall list`, `allow`, `deny` and
    `sync` work on such an environment through the account's lists of who
    may reach SSH and the app; `erpc.toml` is not changed.
    - The account holds its lists to none of `erpc.toml`'s checks where
      they are written. erpc refuses to put on the server lists it would
      not put there as they are: an entry it does not read as an address
      with its prefix length (an address with bits set past its prefix,
      say), a network on the SSH list, everyone on the app's list with no
      WAF in front of the app, and addresses on the app's list with no
      `run.port`. Every problem in both lists is said at once, with one
      `firewall deny` per list naming every entry that stops it (and
      adding `[waf]` or `run.port` where that is the other way out).
      `allow`, `sync` and a deploy are refused before anything is
      changed; a list of more than 16 is refused too.
    - A `deny` that only takes entries off lands while something still
      stops the lists. It takes an entry erpc does not read off by its
      text as the account has it (or as erpc shows it), and a network off
      the SSH list (an environment kept in `erpc.toml` still takes no
      network to SSH). It changes the account's record alone, each other
      entry left as the account had it, and ends with a failure that says
      so (`account_only` in its details): the server's firewall still
      lets in whatever of those it let in before, until `firewall sync`
      puts the lists on it, once nothing stops them. A write it cannot
      make is finished by the same `deny`, named in full in its hint.
      Following the named `deny` commands ends with `sync` going through,
      once erpc can tell which address it connects from: a list of who may
      reach SSH left empty is never put on the server without it (then
      `firewall allow --to ssh` lets an address in, or ERPC support).
    - What changed in the account's list of who may reach the app since
      this machine last put it on the server is said on stderr, `--json`
      or not, before anything is asked: what was added and what was taken
      off, or the whole list when this machine never put it there. The
      firewall commands say it, a `deny` that changes the account alone
      too, and a deploy, which then asks before it goes on (`--yes`
      answers). The list counts as put there once a firewall command has
      put it on the server, or a deploy has written its firewall, and the
      account took the write (a deploy whose WAF's port is held counts it
      too: it was shown and agreed to); `list` shows it without counting
      it. An address listed twice is said so, and written once, by the
      firewall commands; a deploy writes the lists as the account has
      them.
    - `allow` and `deny` take the rules `erpc.toml`'s lists have: single
      addresses for SSH, everyone only to a WAF's port. They say the
      firewall to be (on stderr, but not under `--json`) and ask (`--yes`
      answers); then the account's record is read again, and one another
      sign-in changed since it was read changes nothing. The server's
      firewall is changed first, then the account's record, built on the
      record read and expecting its revision, with this machine's record
      of what it trusts following it. Each address is written as the
      account holds it already, and a new one as the account takes it
      (an IPv4-mapped IPv6 address in hex). erpc's own address stays on
      the SSH list when the change is put on the server, said so when a
      `deny` names it; a `deny` that changes the account alone takes it
      off the account's list if named, and the next `sync` puts it back.
    - What is said of the account's record follows what the account did
      with the write: refused (the same command again writes it, or
      `firewall sync` puts the account's lists back on the server);
      changed meanwhile by another sign-in (`firewall sync`, which may
      first ask at a terminal to trust what it wrote, then the change
      again); an answer lost or failed on the account's side (it may have
      been taken: `firewall list` shows it, and the same command again
      changes nothing when it was, though it may ask at a terminal to
      trust a new SSH list first); taken, with an answer that reaches the
      server another way than this machine trusts (nothing new trusted;
      the next command asks at a terminal); not signed in. Each says
      whether the server's firewall has the change; for a `deny` that
      changes the account alone, the way out is that `deny` again.
    - `sync` puts the account's lists on the server, and writes back the
      address erpc connects from when it adds it.
    - `list` shows the account's lists as the account keeps them
      (`account` in the JSON, each entry as written there, and `unread`
      for what erpc does not read, shown safe), what the server has, what
      changed in the app's list since this machine put it there
      (`app_allow_changed`), and, as a warning, what would stop a change
      (`stopped`).
  - **Whether the app runs:** the account records it for the server in
    use. `start` and `restart` reach the server first (the agent's status),
    then record that it runs, before the key and the secrets are handed
    over (an unlock starts an app that is wanted running) and before the
    app is started; a record the account does not take hands nothing over
    and starts nothing. A server of the person's own, which the account
    knows only by its address, has no such record, and none is written. When the unlock
    or the start then fails, erpc says that the account now says the app
    runs. `stop` records that it no longer runs once it has stopped; a
    record that could not be written is said, with what the account
    answered (and under `--json`, `accountError`); when the account was
    only busy or out of reach and had said the app runs, running the same
    `stop` again writes it, and when the sign-in must be renewed, `erpc
    login` first. A write whose outcome is not known may have been taken,
    and that is said too, by `start` and by `stop`. A write the account
    answers as too many at once is sent again after the wait it asks for.
  - **Ending it:** `erpc worker delete --release-server` has the account
    end every server and line the environment holds, a few in each
    request, a Bundle's line aside (taken off, not ended: below), and
    delete its record; then this machine's record of what it
    trusts for it, and its table in `erpc.toml`, go. While the app has
    another environment in the account, the app's record stays there,
    with the names of its settings and secret settings.
    - When it is the app's last environment in the account (the account's
      record of the app lists it alone, as it lists the environment the
      first deploy made), the question says so, and
      that the app's record goes too, with the settings and secrets the
      account keeps for the app; under `--yes` that is said on stderr as
      the delete starts. Once the environment's record is gone, the app's
      is read again and deleted at its revision when it is the app asked
      about and names no environment; one that has an environment again
      (another sign-in made one meanwhile) stays, and so does one whose
      last environment was not the one the question named. It is deleted
      with `delete_app`, which ends nothing and is refused while an
      environment of the app holds a server, a line or an open start: the
      environment's own delete ended what was asked about. A run that
      stops there says the environment is deleted and the app's record
      not yet, and leaves `erpc.toml` and this machine's records as they
      were, so the same command finishes it. The `--json` answer says
      `app_deleted`.
    - The account decides what is ended, from its own record, and checks
      first that it can end all of it; one end can still fail part way,
      and then what is left stays on record and the same command finishes
      it.
    - When it stops, "nothing was ended" is said only when every answer
      of the run is one the account gives before it ends anything (a
      start with no outcome, something it cannot end yet) and the record
      still holds all that was asked about; anything else, a busy answer
      included, is said as part may be ended.
    - It is asked first at a terminal, saying what is ended (`--yes` goes
      ahead, and says what it ends as it starts, on stderr under `--json`
      too), and the first delete is sent at
      the revision asked about: a server or line that appears after it is
      not ended unasked.
    - While an end is under way it asks again every 15 seconds, at most
      24 times, saying so. When a request has ended as many as one may, it
      asks for the rest at once. A busy account is given the wait it asks
      for, up to two minutes; so is an environment another operation holds
      (a line being pointed elsewhere, or an end), which is said as the
      account being busy. Some of what the request was to end may be ended
      before that answer.
    - Something still being set up or still ending, something not paid by
      the hour (cancel it on the dashboard first), or a start with no
      outcome yet stops it, said as such.
    - A line bought as part of a Bundle (`bundlePart` in the account's
      record) does not stop it: the account takes it off the environment
      without ending it, whatever its state, and it is billed with its
      Bundle. The question names it apart from what is ended, and so does the
      line after the delete; `--json` lists such lines by kind in
      `bundle_parts_taken_off`.
    - The account takes a server it ended off the environment's record
      and keeps its address, so a record with an address and no server in
      use may be one whose ERPC server was ended already, or one on a
      server of your own; the record does not tell them apart. It is asked
      at a terminal only, told both (a server of your own keeps running,
      and erpc no longer reaches it), and `--yes` or `--json` is not
      enough.
    - Before the first delete is sent, this machine records what was
      agreed to (the app's id, the address, the servers and lines) in
      `worker_delete.json` beside the config; nothing is sent when it
      cannot be. Run again after the account took a server off, the same
      command finishes it with `--yes`, or after the ordinary question at a
      terminal, when the app, the address and everything on the record
      are as agreed; a no forgets it. That record is no record of trust,
      and goes with the delete.
    - A server another app or environment on this machine's list is, or
      may be, on (as the `erpc.toml` delete reads that list) is ended only
      after a yes at a terminal, to a question that names them: not with
      `--yes`, and not under `--json`. Another environment kept in the
      account counts as one that may be on it (the list does not say which
      server it is on), and so does a server nothing can be compared by: a
      server in use with no address on record, and one coming in or going
      out.
    - What it says at the end names what was ended only when there was
      something to end; a record that held nothing is said as such.
    - An environment, or an app, the account no longer has is only put
      away here: at once when this machine trusted it under this sign-in,
      and asked first otherwise, which `--yes` answers (signed in to
      another account, it would look the same).
    - Refused: no `--release-server`, and `--forget` or `--forget-line`.
  - **Ending only the server:** `erpc worker server end [--env <name>]
    [--yes]` has the account end the server the environment uses and take
    it off the record, when it is the only server on the record and the
    environment has no line that is not ended; the environment's record
    stays. It then clears the address, host key, login name and SSH port
    from the record's facts, which the account keeps, so that `erpc worker
    server start` can start another for the environment.
    - Refused before anything is sent: another server on the record
      (coming in, going out, or gone); a line not ended (a line bought as
      part of a Bundle counts; the refusal says what `erpc worker delete
      --release-server` does); a server not paid for by the hour; an
      address on the record that is not the server's own (another, or a
      name), so that no other address is ever cleared. The server's own is
      the one the account gives for it; for a server gone since, which the
      account gives none for, it is the one this machine recorded for that
      server of that app before it set out to end it (so a run again takes
      off a server the account ended but left on the record, and clears
      its address); without that record such a server is refused;
      a start of the environment not settled yet (what it bought may not
      be on the record); and a record with no server and no address. A record with an address
      and no server is cleared only as below; otherwise it is refused,
      with nothing changed.
    - It is asked first at a terminal, naming the server's size and
      region; `--yes` goes ahead, and with neither, nobody is asked and
      nothing is sent. A server another app or environment on this
      machine's list may be on, by the address the account gives for it,
      is ended only after a yes at a terminal, to a question that names
      them; a server the account gives no address for is compared with
      nothing. A server the account says is gone is asked about as such,
      and is only taken off.
    - After the yes the record is read and decided on again, and the end
      is sent only for the same server, as live or as gone as it was asked
      about, at the same address: a line or a start added, another
      server, another address, or the server ended elsewhere in the
      meantime stops it, with nothing sent.
    - Before the end is sent, this machine records which server of which
      app it sets out to end, at which address (`worker_server_end.json`
      beside the config); nothing is sent when it cannot be. Run again
      after a stop, the same command clears the address of a record with
      no server and that address on it, without asking, as nothing is
      ended then; and a record with neither puts that record away. That
      record is no record of trust, and goes, with this machine's record
      of what it trusts for the environment, once the address is cleared
      or no longer on the record.
    - The end is said as ended only from its own 200. After any other
      answer (the end under way, a refusal, or no answer), the record is
      read again, and what is said comes from it: the server still on it,
      with the account's status, code and reason in erpc's words, never
      the account's own text (a busy environment says how many seconds to
      wait); no longer on it, said as such, and the clear goes on;
      another server on it, and nothing more is done; or, when that read
      fails, that whether it was ended is not known.
    - The clear is written at the revision read: again after a busy
      answer and after a revision conflict while the record holds the same
      address and no server, at most 3 writes. It is said as cleared only
      from its own answer. After any other failure the record is read
      again: the address gone is said as no longer on the record; the same
      address still there is said with the account's reason; a server or
      another address there is left as it is; a failed read is said as not
      known.
  - **What `stop` says:** what is still charged by the hour, leaving out
    what is gone or cancelled, and how to end it: the delete, or the
    dashboard for a line when no ERPC server is in use.
  - **What status says:** each server by its slot (in use, coming in,
    going out), size, region and state, and whether the app runs on it;
    each line by its kind, state and endpoint, and as part of a Bundle
    when it is one (`bundlePart` under `--json`); and the size asked for when
    the server in use has another. Then the worker's own state, from its
    server.
  - **Trust:** what the account says of the server (its address, host key,
    SSH user and port, who may reach SSH, the app's id there, and which
    server is in use, or none for a server of the person's own) is
    pinned on this machine in `worker_account.json` beside the config,
    per ERPC account, app and environment. The first time a machine sees
    it, and whenever the account says something else, erpc shows it, the
    host key by its fingerprint, and goes on only after a yes at a
    terminal; `--yes` does not give it. What is not to be reached (no
    address or host key yet; a server in use that is not active; a server
    in use this machine pinned that the record no longer names) is not
    such a change: `status` and every command that reaches the server make
    the same decision, refuse it before anyone is asked, and leave the pin
    as it was, and `status` then shows the account's record without
    reaching the server. A pin written before the server in use was
    recorded is asked about again.
  - **One place:** an environment kept in the account writes none of its
    server facts in `erpc.toml` and has no `inventory`; erpc refuses an
    `erpc.toml` that has either.

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
lines    = [
  { kind = "grpc", id = "<line id>", endpoint = "<the line's endpoint>", hourly = true },
  { kind = "udp", id = "<line id>", endpoint = "0.0.0.0:10001", hourly = true, sources = ["192.0.2.21"] },
]                                    # a udp line's sources: the addresses ERPC sends from

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

[env.live]                           # server facts kept in the ERPC account instead
account = true
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

A machine's sealing key (below) is filed under the name
`erpc-worker-seal`, and is never a setting or a key: `check` and every
read of a setting refuse, in any case, a `keychain:` or `keystore:`
reference under that service, a `keychain:` reference that a keychain
filing an entry by one name (Windows: `<account>.<service>`) takes for
such an entry, and an `op://` reference to that field. A `keychain:`
reference that such a keychain takes for a trading key's entry
(`keychain:wallet.erpc-worker/<app>`) is refused as one too.

### This machine's sealing key: `erpc worker seal`

The app's secrets kept in the ERPC account are to be sealed on the
machine that sets them, to the public keys of the machines that may open
them; the account is to keep only what is sealed, and cannot open it.
Each machine has one sealing key per ERPC account.

- `erpc worker seal show` shows this machine's key by its fingerprint
  (`SHA256:` and the SHA-256 of its public key, in unpadded base64). The
  first time, it makes the key, keeps its private half where a secret is
  kept (`--store` and `--vault` as for `erpc worker secret put`; in the
  keystore, as a sealing key, which opens as nothing else; in 1Password,
  in the field `erpc-worker-seal` of an item tagged for the ERPC account),
  and registers its public half in the account, where it waits for
  approval. No label is sent.
- Approve it on the ERPC dashboard by pasting the fingerprint `seal show`
  printed, and check there that it is the same, character for character.
- A key kept in 1Password is held by every machine that reads that vault;
  `seal show` says so, in the text and the JSON (`shared_vault`), each
  time. 1Password must keep the field id erpc gives it: an item that does
  not is refused when it is made.
- This machine's record of its key, `worker_seal.json` beside the config
  (`0600`, per ERPC account), holds where the private half is kept, never
  the key, with its public half, its fingerprint and the account's id of
  it. It is written as soon as the key is kept, before the key is
  registered, and the store is chosen and the key kept under the record's
  lock, so a `seal show` that stopped goes on with the same key, and two
  at once make one. A key kept with no record of it, in the store chosen
  for this run (in the keychain or the keystore under its name, in
  1Password by the item's tag itself), is taken up again rather than made
  twice; nothing kept is written over. Once a key is recorded, `--store`
  and `--vault` are set aside, said so.
- What the account answers of a key is checked against what this machine
  computes from its own, and to be in its form, before any of it is
  recorded or printed: a key answered with other bytes or another
  fingerprint, or an id or account number not in its form, is not taken.
  A key revoked already is said as revoked. A kept key that is not the
  one recorded is not used.
- The account keeps at most 8 keys waiting for approval; `seal show` says
  so, with the dashboard as the way out.
- `erpc worker seal list` lists the account's keys (fingerprint, id,
  status, the label a machine gave it), this machine's and the ones
  trusted here marked. The fingerprint shown is the one this machine
  computes from the key's bytes; one the account lists otherwise is said
  beside it. A key trusted here that the account no longer lists is
  shown too, as such, and one it lists as revoked is marked as revoked
  and still trusted here, with `seal untrust` to take it off. A key is
  marked as this machine's when its id is the one recorded, its bytes
  are this machine's, or, revoked, its fingerprint is: what is said errs
  toward the mark, what is trusted does not. This machine's id listed
  with other bytes is marked as such, and never as this machine's key.
- `erpc worker seal trust <FINGERPRINT>` trusts another machine's key
  here: the one fingerprint that machine's `seal show` printed (the
  `SHA256:` may be left out). The key is found in the account by the
  fingerprint this machine computes from the key's bytes, not the one the
  account says, and is trusted only by a person at a terminal who says
  yes to it, shown its label, status and id: never with `--json`, in a
  script or by an AI tool, never by `--yes` (the command has none), and
  never from what the account says of its approval. What is trusted is
  the key's bytes, kept with its id in `worker_seal.json`, and decided
  again under the record's lock when it is written. Not trusted: a key the
  account lists as revoked, or in a state other than waiting or approved,
  whatever bytes it still gives; two keys with one fingerprint, or one
  id listed for two keys; a key the account lists with a fingerprint
  other than the one its bytes have, whichever of the two is typed, or
  whose fingerprint another row claims for other bytes; and an id
  trusted here with other bytes. This machine's own key, by its bytes,
  needs no trust; this machine's id with other bytes is refused.
- `erpc worker seal untrust <KEY>` stops trusting a key here, by its
  fingerprint or id, under every id it is trusted by; only this machine's
  record changes. A key trusted under an id it is no longer listed by is
  untrusted by its fingerprint, which the refusal says.
- `erpc worker seal revoke <KEY>` revokes a key in the account, by its
  fingerprint or id, for good: nothing is sealed to it any more, and what
  was sealed to it is deleted. It is asked first at a terminal (`--yes`
  goes ahead); revoking a key that may be this machine's own (as `seal
  list` marks it) says what that takes away. Once the account says the
  key is revoked, in its answer or in its listing of a key revoked
  already, the key is no longer trusted here, under any id, fingerprint
  or bytes it was trusted by; an answer that says otherwise, or that is
  lost on the way, is said as one that may have revoked it, with the key
  still trusted and the same command to finish it. One id listed for two
  keys is not revoked.
- Not yet: making a machine a new key after its key was revoked, and
  sealing or opening a secret.

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
server reaches either: the firewall drops every inbound connection but SSH,
`app_allow` and a UDP Forwarding line's port. Their data lives on the
server, outside the worker's state directory, so `erpc worker backup` does
not cover it.

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
| `Rust <version> builds the app here, and it needs <version> or newer (rust-version in its Cargo.toml)` | The app's `Cargo.toml` asks for a newer Rust (`package.rust-version`; the pumpfun template asks for 1.98.1) than the one that builds it here | `rustup update`, or install that version and make it the app's (`rustup override set <version>` in its directory; a `RUSTUP_TOOLCHAIN` set in the environment outranks that); then run it again. When `RUSTC` or `CARGO_BUILD_RUSTC` named the compiler, the hint is to make it name a newer one, or unset it. Nothing was bought |
| `rustc does not run in the app's directory, so cargo would not build it either` | No Rust toolchain is chosen there: rustup has no default, and the app names none | `rustup default stable`, or a `rust-toolchain.toml` in the app; then run it again. Nothing was bought |
| `the compiler RUSTC names does not run in the app's directory, so cargo would not build it either` (or `CARGO_BUILD_RUSTC`) | The variable names a program that does not run there | Unset it, or make it name a rustc that runs; then run it again. Nothing was bought |
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
| `WAF: the note the server keeps while a deploy writes the WAF's files cannot be removed there (<path>: …)` (in `status`, `firewall list`); `the WAF listens on port <port>; the note … could not be removed there (…)` (from `deploy`); `release … runs, and its WAF's files on the server were not changed: the note … cannot be removed there (…)` (from a `deploy` that changes `[waf]` or `run.port`, or the WAF's unit, which fails); `the WAF's port <port> was not opened to …: the note the server keeps … cannot be removed there …` (from `firewall allow`, `deny`, `sync`) | Something is at `/etc/erpc/worker-waf/<id>.applying` that cannot be removed: a directory, or a file made immutable or append-only (`chattr +i`, `+a`). Only root can put it there. The WAF counts as started before its files for as long as it is there, and outside a deploy its port is not opened wider. A deploy that leaves the WAF's config and unit as they are restarts it, which forgets its bans and counts, and opens the port as `erpc.toml` asks; `firewall allow` holds again after. A deploy that would change them (`[waf]` or `run.port` changed, or an erpc that writes the WAF's unit differently) cannot leave its note: it changes nothing, opens the port no wider, and fails; another deploy fails the same way | On the server, as root (only root can): `rm -r` that path, after `chattr -i -a` for a file made so. The next `status` no longer names it, and the next deploy puts `[waf]` in place |
| `the WAF's port <port> was not opened to …: no WAF listens on it yet …` (from `firewall allow`, `sync`) | The app has `[waf]` and was not deployed with it yet, or its WAF is not running. The port stays closed | `erpc worker deploy` starts the WAF, then opens the port |
| `port <port> keeps the limit on new connections that is in force …` (a warning under what `firewall allow`, `deny`, `sync` say, which succeed) | The WAF on the server runs, and is not known to run `erpc.toml`'s rules (the four cases above: `[waf]` changed since the last deploy, an agent that does not report its rules, an earlier agent's WAF, a WAF started before its config or its unit last changed); `app_allow` lets nobody new in and still lists someone (the addresses the port is open to, or some of them, whether or not you changed the list); and the limit in force is not the one `new_connections` gives. The port was applied as `app_allow` has it, with the limit the server had | `erpc worker deploy`: it puts `erpc.toml`'s rules in place, then the limit `[waf]` gives |
| `WAF: the rules it runs are not erpc.toml's` (in `status`, `firewall list`) | As above: `[waf]` changed since the last deploy | `erpc worker deploy` |
| `WAF: it was started by an earlier agent than the one installed …` (in `status`, `firewall list`) | As above: a newer agent was installed since the WAF started | `erpc worker deploy` |
| `WAF: it was started before its config or its unit on the server last changed …` (in `status`, `firewall list`) | As above: the WAF is not known to run its config and its unit as they are on the server, or the server could not tell when it was started | `erpc worker deploy` |
| `WAF: <state>, and its config on the server does not read (…)` (in `status`, `firewall list`) | The agent installed on the server does not take the WAF's config file | `erpc worker deploy` writes it again. Until then the port is opened no wider, as under other rules: it stays open to those it was open to, and `firewall deny` still narrows or closes it |
| `WAF: not running (<state>)` (in `status`) | The WAF's unit ended and systemd did not bring it back, or it was stopped on the server | `erpc worker logs --waf` shows why; `erpc worker deploy` starts it again |
| `could not let <ip> in to line <id>` | user-api did not take the Unlimited RPC's whitelist | Deploy again; the line is on record and is taken up |
| `could not point UDP Forwarding line <id> at <ip>:<port> from <region>` | user-api did not take the line's destination; the code at the end says why. It may pass later when it is the region's (`REGION_DOWN`, or a code ending in `REGION_UNAVAILABLE`), a conflict, a change too soon or a request timed out (409, 429, 408), user-api failing or not answering (a 5xx, no reply, a reply it could not read), or a session to sign in again (`erpc login` first); any other refusal comes back the same (`INVALID_DESTINATION`, an address user-api does not send to although erpc took it for a public one; a route closed to the sign-in) | The hint says which. A line this deploy started is offered to be ended at once, to the person at the terminal (with nobody there it is kept, and the hint says how to end it). One that may pass: deploy again; a line on record is taken up (Standard is charged meanwhile, Premium only once it is pointed); for a region `--udp-region` names another. One that comes back the same: end the line alone (`erpc ai`, or the dashboard), then `--forget-line <id>` takes it off the record, as the hint says; `erpc worker delete --release-server` ends it with the server and everything else |
| `UDP Forwarding sends only to a public IPv4 address, and the server is at <ip>` | A server behind NAT, on a private network, on a carrier or Tailscale address (`100.64.0.0/10`), or in a range set aside for documentation, benchmarks or other special purposes (`192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `240.0.0.0/4`) | Nothing was started for UDP. Deploy `--udp` to a server with a public IPv4 address |
| `UDP Forwarding line <id> on record is <product>, and --udp-plan <plan> is <other product>: a line keeps its product` | The environment's UDP Forwarding line is of the other product than `--udp-plan` names; refused before anything is bought | Deploy without `--udp-plan` to keep the line; for the other product, end it (`erpc ai`, or the dashboard), then deploy with `--forget-line <id> --udp --udp-plan <plan>` |
| `UDP Forwarding line <id> is cancelled` | The environment's UDP Forwarding line on record has ended (in the dashboard, say); refused before anything is bought, or found so while it was waited for | It is charged no more. `--forget-line <id>` takes it off the record; deploy with `--udp` again for a new one |
| `<line> <id> is suspended` | user-api suspended the line on record; a UDP Forwarding line is refused so before anything is bought | The dashboard says why |
| `UDP Forwarding Standard: user-api refused the request (403): …; this deploy started nothing` | user-api does not let erpc's sign-in reach the UDP Forwarding routes | Nothing to undo. Signing in again does not change it; the dashboard starts and points UDP Forwarding lines, and the other lines are not affected |
| `UDP Forwarding Standard: user-api refused the request …; no UDP Forwarding line was started` | The same refusal, at the UDP step of a deploy that had bought its server or other lines already (the list was readable before, and was refused then) | What else is charged is named after it; deploy again to carry on with it, or `erpc worker delete --release-server` to end it |
| `the account has UDP Forwarding Standard line <id>, started before and pointed at no server, and --yes does not decide …` | A deploy under `--yes` found an unpointed hourly Standard line it could take up instead of starting one | Deploy at a terminal, which asks whether to take it up; or end the line (`erpc ai`, the dashboard) if nothing uses it, and deploy again |
| `UDP port <port> stays closed: user-api names no address the line sends from` | The line is active and user-api lists no source address for it | Deploy with `--udp` again once it names them; or `deploy --udp --udp-any-source` to open the port to any IPv4 address |
| `user-api names … as an address UDP Forwarding line <id> sends from, and that is not an IPv4 address` | A source erpc cannot write a firewall rule for | Nothing was opened; deploy again, and tell ERPC support if it stays |
| `<region> is not a UDP Forwarding Standard region` | Neither the server's region nor `--udp-region` is one the plan sends from; dublin is Premium's alone | `--udp-region <another>`, or `--udp-plan` with Premium's product id for dublin |
| `<kind> line <id> did not become active in <n> minutes` | The line is still being set up | Deploy again to wait more; `delete --release-server` ends it once it is active |
| `user-api did not start it (HTTP 409): OUT_OF_STOCK` | No server of that plan free in that region | `--region <another>` |
| `the start may or may not have gone through: …` | The request left and no answer came back, or user-api answered 5xx, 408 or 429 | Run the same command again: it sends the same request, which stays on record |
| `this purchase, or another of the account's, is still being made …` | user-api answered 409 `PURCHASE_IN_PROGRESS`: the first request is still at work, or another purchase holds the account's lock | Run the same command again shortly: it sends the same request |
| `user-api has a purchase under this request and does not give it to this command`, `user-api answered that it started this and did not say which` | A purchase exists that erpc cannot put on record; the server or line may well have been started by the earlier request | Look at the account's servers or lines (the dashboard, `erpc ai`); take a server up with `--server <ID>`, or end what is not wanted; then remove the entry from `[env.<name>.starting]` |
| `… This purchase was ended while it was starting. Nothing more was granted.` | What was bought under the start's key has been ended, and user-api refuses the key from then on; it may have been charged by the hour from its start until it was ended, one hour at the least | Nothing to clear: the entry is gone and its key is not sent again (unless the entry could not be written, which the error says: then the next run of the same command sends the key once more). Look at the dashboard for what was charged. Starting it again is a new purchase, with a new key, at the price the command says |
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
- Start or end anything without showing what it is and its price. Each is
  asked at a terminal; under `--yes` it is said instead: what a deploy
  starts, and what `delete --release-server` ends.
- Leave a server open: the firewall is in force before the app first starts.
- Reach a server whose host key does not match the pinned one.
