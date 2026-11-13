<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

`erpc-cli` is developed and maintained by ELSOUL LABO B.V. (Netherlands), the
operator of the ERPC service.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/elsoul/erpc-cli/security/advisories/new).
Do not open a public issue for security problems.

Include the affected version (`erpc version --json`), the platform, steps to
reproduce, and the impact you observed. Encrypted reports are not required.

We acknowledge reports within 5 business days and aim to publish a fix or a
mitigation within 90 days of confirmation. We follow coordinated disclosure:
we will agree a publication date with you and credit you in the advisory
unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes. Every release so far is a
pre-release.

## Scope

In scope: the `erpc` binary and the crates in this repository, the installer
script served at `install.erpc.global`, the release artifacts and their
signatures.

Out of scope: the ERPC backend services (report those through the ERPC
dashboard support channel), third-party node clients that `erpc` installs on
your servers, and issues that require physical access to an operator machine.

## Verifying releases

Every release ships a signed `release-manifest.json` (minisign), a CycloneDX
SBOM and GitHub build provenance attestations. See `docs/verify-release.md`.

## Secret handling

On the operator's machine `erpc` keeps these secrets:

- the session for your ERPC account, an access token and a refresh token obtained
  through the OAuth device authorization grant, in the store described below;
- the storage and backup secrets listed under the storage section below, in the
  same store, and a machine's own backup keys in `~/.erpc/backup.env`;
- an `erpc worker` app's trading key and secret settings, in 1Password, the
  keychain or, on a machine with neither, the worker keystore described below.

Node keys that erpc holds for you, and the `erpc wallet` key, are made or read in
memory and stored in 1Password; `docs/nodes.md` lists the keys that stay on node
hosts instead. One command writes them to disk: `erpc validator vote-account` writes
the identity and vote keys to 0600 files under the state directory while the
Solana CLI runs, and wipes them afterwards. A process that dies can leave a file
until a later run sweeps it. Adding a restic key also keeps its password in a
temporary file in the configuration directory while restic runs, and a process that dies can leave that file behind.

When it uses a 1Password
service account, it reads `OP_SERVICE_ACCOUNT_TOKEN` from its environment and
passes it to the `op` processes it starts, and to no other process: the
browser `erpc login` opens is started without any variable whose name begins
with `OP_`, in any case. It does not write that token anywhere. A session the
operator opened with `op signin`, on a machine without the 1Password app, is
handled the same way: its `OP_SESSION_<account>` variable goes to `op` and
nowhere else.

### Where the session is kept

The session is kept in one store. `erpc login` at a terminal asks which: the
operating system's keychain, which is the default, or 1Password when it
answers -- the desktop app, or without it an `op signin` session that `op
whoami` accepts -- followed by which vault. `--store` (and
`--vault`) choose without asking. The choice is recorded as `credential_store`
(and `credential_vault`) in `config.toml` beside the state directory, and the
other commands use it.

Without a choice, given or recorded, the store is the first of these that
applies:

1. a 1Password service account, when `OP_SERVICE_ACCOUNT_TOKEN` is set;
2. the operating system's keychain, when there is one;
3. a file in the erpc state directory.

`erpc doctor` reports which store is in use and why.

On Linux the keychain is the Secret Service where one answers on the session
bus, and otherwise the kernel's persistent keyring for the user: in memory,
never on disk, kept across logins until a reboot or a few days unused, after
which `erpc login` is asked for again. The kernel lets a process use that
keyring only when it holds one of the user's keyrings, which a login gives
it; a process started without one (`su` without `-`, `sudo -E`) is refused
and told so.

On macOS the keychain is reached through Apple's `/usr/bin/security`, not
the keychain API directly. An erpc built on the operator's machine has no
lasting code signature, so an item it made itself asked for the login
password on every read and write. The item therefore trusts `security`, and
with it any other program running as the same user, which can read the
session by running `security` too; this is the trade other command-line
tools make. The keychain still keeps the session encrypted at rest and away
from other users, which the file store cannot (`crates/erpc-auth/src/store/security_cli.rs`).

The 1Password item is titled with the machine's name, so that two machines
never share, and keep rotating, one session. `ERPC_HOST_LABEL` overrides the
name.

### When the session is on disk in cleartext

The erpc state directory is `$ERPC_HOME/state` or, without `ERPC_HOME`,
`.erpc/state` in your home directory. `erpc` will not use a state directory
that is not an absolute path.

`erpc` writes a session to that directory in the following cases, and
`erpc doctor` reports each file for as long as it exists:

- **The file store.** `erpc login` warns when the session is going there. If
  the file cannot be parsed, nothing in it can be read: `erpc login` replaces
  it and `erpc logout` removes it, as a whole, and `erpc login` says so.
- **A parked session.** If the issuer has rotated a refresh token and the
  new one cannot reach the store, it is written here so that it is not lost.
  That happens when the store refuses it; when `erpc` is asked to stop
  (Ctrl-C, and on Unix also SIGTERM and the terminal closing) and the store
  has not taken it within ten seconds, or a second request to stop comes
  first; and when `erpc` panics before the store has it. A save that lands
  after all leaves a copy of what the store already holds, which the next
  command removes. The next command that reads the session, such as `erpc
  whoami`, moves it into the store if the store still holds the session it
  replaced. `erpc login` and `erpc logout` revoke it and remove it, and say
  so when they could not.
- **An interrupted write.** The two files above are written to a temporary
  file first and then renamed into place. A crash between the two steps
  leaves that temporary file behind.

On Unix these files are created with mode `0600`. On Windows `erpc` sets no
permissions of its own, so the files have the permissions of the directory
they are in.

### Where the session is sent

- The access token is sent as a bearer token only to the hosts listed for its
  audience in `crates/erpc-auth/src/allowlist.rs`.
- The refresh token is sent only to its issuer's token and revoke endpoints,
  checked against the issuer's host before each request.
- Every request URL's host is a compile-time constant, and so is its path
  up to the one value a path may carry: a storage access key id, an
  integer, or a gasless session id, checked to be a UUID before the URL is
  built. Query values are percent-encoded. On the account routes they are
  a region, a bare metal category, a page cursor or a product id, and are
  letters, digits, `-` and `_` only, checked before the request is sent;
  `erpc storage` sends the file path or prefix the operator named, encoded.
- The HTTP client is configured to accept `https` only and not to follow
  redirects. Neither setting is covered by a test; the reasons are given
  beside them in `crates/erpc-auth/src/client.rs`.

### Storage and backup secrets

- `erpc storage put` encrypts files with an account key before they leave the
  machine; `docs/storage-encryption.md` describes the format. With the file
  store that key sits in `~/.erpc/storage-key` (0600), not encrypted, and the
  backup secrets below are not encrypted either.
- `erpc backup` keeps the restic repository's master password and a
  `read_write` storage access key in the store `erpc login` chose. Each
  machine gets its own `append_only` access key and its own restic key, kept
  in `~/.erpc/backup.env` (0600). `docs/backup.md` sets out who holds what.
  The `append_only` key keeps a machine from deleting backups only where the
  machine holds neither the erpc session nor the account's backup secrets,
  which the machine `erpc backup init` ran on does; `docs/backup.md` explains
  ("What the append-only key protects, and when").
- A storage access key is sent only by the restic that `erpc backup` runs,
  as Basic authentication, to user-api's `/v3/storage/restic`. restic gets
  it, and the repository password, from its environment, never from its
  command line or a URL, and runs with an otherwise cleared environment.
- The restic program is a pinned version. Both the release archive and the
  program inside it are checked against SHA-256 digests compiled into erpc,
  and a newer digest is never read from the network.

### The worker keystore

`erpc worker key new`, `key import` and `secret put` keep an app's trading
key and secret settings in 1Password or the operating system's keychain.
Where `erpc login` does not keep the session in 1Password and the keychain
cannot keep a value past a reboot (Linux with no Secret Service), and
wherever `--store keystore` asks for it, they write them to disk instead,
encrypted: the keystore, the directory `keystore` beside `config.toml`
(`~/.erpc/keystore`). No key or secret value in it is in cleartext. Its
format is set out at the top of `crates/erpc-auth/src/store/keystore.rs`,
and `docs/worker.md` ("The keystore") says how it is used.

- **What is written.** `master.json`: a random 32-byte master key, sealed
  with ChaCha20-Poly1305 under a key that PBKDF2-HMAC-SHA256 (600,000
  iterations, a random 32-byte salt) derives from a passphrase the operator
  chooses. One file per value: the value sealed with ChaCha20-Poly1305
  under a key that HKDF-SHA256 derives from the master key and a salt of
  the entry's own, with the entry's name and its kind (a trading key, or a
  secret) in the associated data. On Unix the directories are created with
  mode `0700` and the files with `0600`; on Windows `erpc` sets no
  permissions of its own. Each file is written under a temporary name and
  renamed into place; a crash between the two steps leaves the temporary
  file, which holds the same sealed text.
- **The passphrase** is read from a hidden prompt at a terminal and from
  nowhere else: not from an argument, an environment variable or a pipe. It
  is not stored. `erpc` cannot recover it, or a keystore whose files are
  lost. On Unix the terminal's echo is held off from the first prompt until
  the last attempt has been checked, so an attempt typed ahead while one is
  checked is not shown; what was typed and not read is discarded.
- **The unlock.** On Linux the unwrapped master key is kept in the kernel's
  persistent keyring for the user, in memory, so that the passphrase is not
  asked for by every command. It stays until a reboot, until that keyring
  has gone unused for the time in
  `/proc/sys/kernel/keys/persistent_keyring_expiry`, or until `erpc worker
  secret lock`, which drops every unlock `erpc` keeps for the user,
  whichever keystore it opens. While it is there, any process running as
  the same user can read it (one whose session does not hold the user's
  keyring can link it in), and with it open every entry. On other systems
  nothing is kept, and each command asks.
- **What it does not protect against.** Someone who has the files and the
  passphrase. A passphrase that can be guessed: PBKDF2 makes each guess
  slow, and no more. A process running as the operator while the keystore
  is unlocked, or one that reads the terminal the passphrase is typed at.
  The names of the entries and the lengths of their values are not hidden,
  and an entry replaced by an older copy of itself opens.
- **The trading key's gate is separate.** `erpc` reads the key that
  `[wallet]` names only for a person at a terminal, and not for an AI tool
  or with a 1Password service account, in whichever store it is kept
  (`crates/erpc-secret/src/gate.rs`). An unlocked keystore does not change
  that. A secret setting is read with no such gate, so a key is kept from
  being read as one:
  - In the keystore, each entry is sealed as a trading key or as a secret.
    One kept as a key (by `key new` or `key import`) opens only as the key
    `[wallet]` names, and not as a secret, whatever names it; a secret does
    not open as a key.
  - `erpc.toml` is refused when a `[secrets]` line names the entry
    `[wallet]` names, or a keychain or keystore account ending in `.wallet`
    (where `erpc` files a key), and `erpc worker bench --url` refuses such
    a reference too.
  - That leaves a key in 1Password, or under a keychain account that does
    not end in `.wallet`: nothing in such a reference says that it is a
    key's. An `erpc.toml` with no `[wallet]` that names it under
    `[secrets]` has it read as a secret, with no gate.

  The gate and the kinds are what `erpc` does; they do not bind other
  programs.
- **One spelling of a name.** An entry's file is named after its service
  and account as they are written. Where file names ignore case (the
  defaults of macOS and Windows) `<app>.WALLET.json` is the file of
  `<app>.wallet.json`, the trading key's. So `erpc worker secret put` keeps
  no setting called `WALLET`, in any case, in the keychain or the keystore,
  `secret rm` removes none, and the keystore reads its directory before
  every read, write and removal: where it holds another spelling of the
  name, it does none of them.

### What the assistant reads

Everything a tool returns is sent to the model, through the ERPC AI
gateway, as part of the conversation. The tools are in
`crates/erpc-ai/src/tools.rs`; besides those below, the assistant reads
ERPC's documentation (`read_skill`), asks the person to choose
(`ask_choice`), and keeps notes between conversations (`remember`,
`forget`), which refuse anything that looks like a secret.

- **Tools that read user-api** with the session: the signed-in account's
  credit balance and history, card subscriptions, RPC and AI usage and the
  services it runs, and what ERPC offers -- the server catalogue, servers in
  stock by region, plan prices, hourly products and the health of each
  region. Each passes on only the fields it names in
  `crates/erpc-ai/src/tools.rs` and `services.rs`: figures, product names,
  plans, regions, states and dates, and a service endpoint only when it is
  an ERPC host with no query, fragment or user in it; for each of the
  account's VPSs, its IP and login user, so the person can ask where it is.
  From these tools, server passwords, IP whitelists, endpoints that carry a key,
  payment details, Stripe ids and metadata, API keys and the session never
  reach the model. None calls the `/list` catalogues, which open a Stripe
  checkout session each time they are read.
- **Tools that act**: `start_hourly_product`, `end_hourly_product`,
  `top_up_credit`, `create_credit_wallet`, `secure_vps` and `restrict_ssh`
  change the account, spend credit or EURC, or change a server. Each asks
  the person first, with the cursor on no, every time; allowing every
  command (below) does not change that.
- **A new VPS's address reaches the model.** `wait_until_ready` returns the
  VPS's state and, once it runs, its IP and login user (never its
  password). `secure_vps` returns the server as `user@ip`, its host key
  fingerprint and the user's own public address; `restrict_ssh` returns
  the addresses SSH is allowed from, the user's included.
- **`run_command`** runs a command on the user's own computer, and **what it
  prints goes to the model**, whatever the command: one that only looks
  and runs without asking (`journalctl`, `docker logs`, `systemctl status`
  among them, so whatever a service logged), one the person said yes to,
  or any command once the person allowed every command for the
  conversation. The only thing hidden is the value of each `api-key=`,
  `api_key=`, `apikey=` and `token=` parameter (`redacted` in
  `crates/erpc-ai/src/commands.rs`). A command that prints a key file, a
  password or a secret under another name hands it to the model. Once every
  command is allowed, nothing is asked before a command runs, including one
  that spends money or changes a server when given `--yes`, until erpc ai
  ends or a new conversation starts (`/new`, `/clear`).

### What to report

Report any of the following as a vulnerability, through the channel above:

- secret material written to disk in any way not described above;
- secret material in a log, an error message, or other output;
- a token sent anywhere not described above.

Do not infer from this repository which protections are already in force. What
the code does today is what the code in this repository does today.
