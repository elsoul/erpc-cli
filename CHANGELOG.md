<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The release gate refuses a tag
whose version has no entry below.

## [Unreleased]

### Added

- Official Linux, macOS and Windows archives include the opt-in Server
  Security Check command, `erpc ai --security-check`, for eligible ERPC
  rentals.
- The Server Security Check searches the rental for private keys and seed
  phrases kept in plain text: key files, seed phrases, keystores without
  encryption, and secrets in environment files, process environments and
  shell histories. Its results stay on the operator's screen with the
  paths; nothing about them is sent to ERPC, and `--json` carries their
  counts and classes only. The collector now reaches the server on
  standard input.
- `erpc worker seal show` and `erpc worker seal list`: this machine's
  sealing key in the ERPC account, which the app's secrets kept there will
  be sealed to. `seal show` makes the key the first time, keeps its private
  half where a secret is kept (in the keystore as a sealing key, which
  opens as nothing else; in 1Password in a reserved field), records where
  it is in `worker_seal.json`, and registers its public half, to be
  approved on the ERPC dashboard by its fingerprint; what the account
  answers is checked against this machine's own computation. `check` and
  every read of a setting refuse a sealing key's place, in any case and
  under any spelling a keychain takes for the same entry.
- `erpc worker seal trust`, `seal untrust` and `seal revoke`: another
  machine's key is trusted here by the fingerprint computed from its
  bytes, only by a person at a terminal after a yes; trust is dropped
  here; a key is revoked in the account after a yes or `--yes`.
  `seal list` marks the keys trusted here, shows the fingerprint computed
  from a key's bytes (and the account's, when it differs), and shows a key
  trusted here that the account no longer lists.

- An `erpc worker` environment can keep its server facts in the ERPC
  account (`account = true` under `[env.<name>]`), where its servers and
  lines are named by the account's own ids, never by product number.
  - `erpc worker move --to account` moves an environment kept in `erpc.toml`
    there: the app's and the environment's records are written, its server and
    lines are taken in, and `erpc.toml` keeps only `account = true`. One way,
    asked first, and written so that a move stopped half way is run again:
    what the account has is read before anything is written, a server already
    in the slot in use is sent again for the account to say it is this one,
    and `erpc.toml` is changed after the account, only if it is as the move
    read it, with this machine's record of what it trusts written after it.
    What this machine trusts of the moved environment is its own record, and
    the account's answer must match it. Before the yes it says what does not
    work on a moved environment yet. It refuses an environment with a start
    not settled, a UDP Forwarding line, no server or a server not set up yet,
    a 1Password item keeping it or a backup; an account app of that name on
    another chain or with another wallet, a record in use from another
    checkout, or a server in the account's record that the move does not take
    in, gone or not; and an account that does not yet let erpc end what such
    an environment runs on. The record is read as the commands that work on a
    moved environment read it before `erpc.toml` is changed. Whatever stops it
    after the account was written to says the move stopped part way; a refusal
    or no answer from the account before it, as not moved. The note before the
    yes says that the move is one way and what changes once moved, in the
    groups of the docs' list "What changes once moved", which names more of
    them: the sign-in every command then needs, the trust at a terminal on
    another machine signed in to the same ERPC account (another ERPC account
    does not see it), the commands and `deploy` options that do not work there
    yet, that `delete --release-server` ends nothing while anything on it but
    a line bought as part of a Bundle (which it takes off without ending,
    whatever its state) is not paid by the hour or cannot be ended yet, its
    hourly items staying charged, a Bundle's line, and this machine's other
    environments. An app
    with more settings or secret settings than the account keeps is not moved.
    A line the account refuses to take in (`not_adoptable`; a line bought as
    part of a Bundle, `bundle_part`) stops it, said by its product ID, without
    changing `erpc.toml`.
  - `erpc worker server start` buys a server, paid for by the hour, for one
    whose record names no server and no address yet: it says the price the
    account gives for the size asked for and asks first. It keeps the start's
    key on this machine before it is sent, so that a run after an answer was
    lost reads the account first and makes no new start while the record names
    a server or a start is open; and it sends a new start at the environment's
    revision read before the price, which the account refuses, buying nothing,
    when the environment changed meanwhile (a start sent again under its key
    while still open is answered as before). It makes the app's and the
    environment's records when the account has none (the app's not yet when
    its `erpc.toml` names a wallet). The question says that `erpc worker
    deploy` then waits for the server, logs in to it once after a yes at a
    terminal and deploys to it, and that erpc ends it with `erpc worker delete
    --release-server` at a terminal, which deletes the environment's record
    with it.
  - `erpc worker server end` ends the server such an environment uses,
    when it is the only server on the record and the environment has no
    line that is not ended (a line bought as part of a Bundle counts), and
    the record's address, if any, is the server's own (the one the account
    gives for it, or, for a server gone since, the one this machine
    recorded for it before it set out to end it); after a yes at a terminal or with `--yes` (a server another app
    on this machine's list may be on: at a terminal only), and after the
    record is read again and still names the same server, as live or as
    gone, at the same address, with no start of the environment open. It
    then clears the address, host key, login name and SSH port the
    account keeps in the record's facts, so that `server start` can
    start another; the record stays. Before the end is sent this machine
    records which server it sets out to end, so that the same command
    finishes a run that stopped before the clear. The end and the clear
    are said as done only from their own answers; after any other answer
    the record is read again and what is said comes from it, or is said as
    not known. The account's refusals of the end and the clear are said by
    their status, code and reason, never in the account's own text.
  - `deploy` to such an environment whose server in use has no host key on
    the account's record (one `server start` started) logs in to it first, at a terminal only
    (`--yes` is not enough, and `--json` asks nobody): it waits about ten
    minutes (40 reads, 15 seconds apart) for the account to say the server is ready and for its SSH to
    answer, while the account has it as available, provisioning or active;
    asks, naming the address, the host key the server offers and the key
    erpc logs in with; reads the record again and goes on only for the same
    server at the same address; reads the server's first login from the
    account once and logs in with its password once, to put the person's key
    on it and turn password logins off (an earlier attempt on the same
    machine that got as far as the key is taken up from the key, and one
    erpc made key-only before is not logged in to again); then writes the
    address, the host key and the login name to the account's record at the
    revision read. The deploy then asks at the terminal whether to trust
    what the account has, as for any record not trusted yet. A wait that
    runs out, a no, a record that changed and each of the account's
    refusals before the login stop it, with nothing written to the
    account's record. A stop after the login says the key is on the server,
    and says the address and host key were not written by this run, or,
    after a write that got no answer, an unreadable one, a 5xx or a refusal
    with no code, that whether they were is not known.
  - One machine reached both as an ERPC VPS (`erpc ai`) and as a server kept
    in the account keeps one pin in `vps_hosts.json`, known by its host key,
    which serves both ways. A pin at the address holding another host key
    stops the first login before anything is sent, unless it is of another
    server the account names; the `erpc ai` login is held the same way to a
    pin with no VPS id.
  - `status` reads one from the account: each server by slot, size, region
    and state and each line by kind, a line bought as part of a Bundle
    said as such (`bundlePart` under `--json`), then the worker's own
    state.
  - `logs`, `start`, `stop`, `restart`, `releases` and `deploy` reach its
    server with what the account says of it, and write nothing to
    `erpc.toml`. Only a server in use the account has as active is
    reached; one gone, given back or held, and a pinned server the record
    no longer names, are refused before anyone is asked.
  - `delete --release-server` has the account end every server and line
    the environment holds, a Bundle's line aside (below), and delete its
    record, then drops this
    machine's record of what it trusts for it and the table in
    `erpc.toml`; the app's record in the account stays, with its secrets.
    It asks first at a terminal, sends the first delete at the revision
    asked about, and says "nothing was ended" only when the account's
    answers and its record show it. A record with an address and no server
    in use is asked about at a terminal only, told both, unless this
    machine recorded before sending that the person agreed to end what it
    held there: then running the same command again finishes it. A server
    something else may be on (another environment at its address on this
    machine's list, another kept in the account, a server with no address
    on record, or one coming in or going out) is ended only after a yes at
    a terminal, to a question that names it: not with `--yes`, under
    `--json` or with no terminal. What it ends is said on stderr under
    `--json` too. A line bought as part of a Bundle is taken off the
    environment without being ended, whatever its state, and billed with its
    Bundle: the question and the line after the delete name it apart from
    what is ended, and `--json` lists such lines by kind
    (`bundle_parts_taken_off`).
  - A server or line not active is said by what its state means, and never
    as one to end. A suspended one is said with every way it may come
    back, none as sure, whatever its `hourly` says: paid by the hour, once
    the credit covers an
    hour of all the account's hourly charges; paid from credit by the
    period, once it covers its next period's charge; paid by card, once
    the unpaid invoice is paid. A server or Unlimited line can be ended if
    left so (soon); a gRPC or Shreds line paid by the hour, or in a Bundle
    paid by the hour, is normally ended at once (now). Each names ERPC
    support and its id.
  - `firewall list`, `allow`, `deny` and `sync` work on one through the
    account's lists of who may reach SSH and the app, with the rules
    `erpc.toml`'s have and at most 16 addresses each; the record is read
    again after the yes, then the server first, then the account's
    record, and what is said follows what the account did with the write.
    Lists erpc would not put on the server as they are (an entry it does
    not read, a network on SSH, everyone with no WAF, addresses with no
    `run.port`) are refused before anything, by `allow`, `sync` and the
    deploy, with every problem said at once and one `firewall deny` per
    list that clears it. A `deny` that only takes entries off lands while
    something still stops the lists, in the account's record alone. What
    changed in the account's list of who may reach the app since this
    machine last put it on the server is said before anything is asked,
    by the firewall commands and by a deploy, which then asks before it
    goes on. A firewall command that cannot write this machine's record of
    what it trusts, or of the app's list it put on the server, says so on
    stderr, under `--json` too. Each address is written as the account
    holds it, and a new IPv4-mapped one in hex, as the account takes it.
  - `deploy` ships a release to the server the account names and writes
    to the account instead of `erpc.toml`: who may reach SSH when it
    changes, that the app runs before the key and secrets are handed over,
    and the deploy and what it shipped (by name only) once the app runs.
    Each write is built on the record the account last answered with and
    expects its revision; what is pinned is this machine's own facts; the
    record is read again before the hand-over and must still be the one
    trusted, and one the deploy can carry. The deploy is recorded whatever
    became of the firewall write, and an SSH list past the account's 16 is
    refused before the server's firewall changes. What it says of the
    firewall and the WAF names the account's lists. Only lines in use are
    handed to the app, one of each kind. It
    buys nothing and changes no line yet, and refuses the options that
    would before the account or the server is reached.
  - `start` and `restart` reach the server first, then record in the
    account that the app runs, before the key and secrets are handed over
    and the app is started; they start nothing when the account does not
    take the record. `stop` records that the app no longer runs, and says
    so, with what the account answered, when the record could not be
    written. A server of the person's own, which the account knows only by
    its address, has no such record.
  - `stop` says what is still charged by the hour, leaving out what is gone
    or cancelled, and how to end it: `delete --release-server`, or the
    dashboard for a line when no ERPC server is in use.
  - `list` and `check` name where it is kept; every other command refuses
    it by name, and a `delete --release-server` of another environment
    counts it as one whose server is not known here, and stops.
  - What the account says of the server (address, host key, SSH user and
    port, SSH allow list, the app's id, the server in use) is pinned per
    account, app and environment in `worker_account.json`, and a first
    sighting or a change goes on only after a yes at a terminal, never on
    `--yes`. What is not to be reached (a pinned server in use the record
    no longer names among it) is refused before anyone is asked, by
    `status` and every command alike, and `status` shows the account's
    record alone then, leaving the pin as it was.
- An `erpc worker` command given no app, run where there is no `erpc.toml`
  in the current directory or above it, asks at a terminal which of the apps
  erpc knows on this machine to act on, each shown by its name and
  directory, and goes on with the one picked as with `--dir`. When erpc
  knows no app on this machine, it says so and points to `erpc worker init`
  first. It asks for a command that only reads, or that asks before it buys,
  ends, deletes, sends or changes anything. The app is picked first; then
  three of those do something free before their own question: `server start`
  makes the app's and the environment's records in the ERPC account when
  they are missing (they cost nothing); `deploy` runs `rustc` (and `rustup`,
  to cross-build) in the app's directory, the `rustc` that `RUSTC` or
  `CARGO_BUILD_RUSTC` names, else the one `RUSTUP_TOOLCHAIN` or the app's
  `rust-toolchain.toml` (a `path` toolchain included) picks, and rustup can
  install the toolchain the file names; and `server end`, run again after a
  stop, may first finish clearing the address of a server whose end was
  already said yes to. Under `--yes`, for a command that changes something
  or runs the app's code without asking (`run`, `build`, `key new`, `key
  import`, `secret put --generate` or `--from-account`, `secret rm`, `api`
  with a method other than GET, `backup now`), under `--json`, with no
  terminal or with `TERM=dumb` it asks nothing and fails as before.
- At a terminal, the steps of `erpc worker build` and `erpc worker deploy`
  that can take minutes (the build, the wait for a new server to be ready,
  the wait for a server kept in the ERPC account to be ready for its first
  login) are a spinner that shows the time taken and a short trading tip
  in the language erpc speaks, the next one every eight seconds. When the
  step ends, the spinner gives way to the line the step printed before.
  Under `--json` or off a terminal nothing changes.

### Changed

- `erpc worker deploy` names the server it deploys to as a server, not a
  VPS: `--server <ID>` and `--new-server`, in every language's help and
  message. `--vps` and `--new-vps`, the names before, still work, so a
  script that uses them is not broken.

### Fixed

- A gRPC or Shreds line start that user-api answers "This purchase was
  ended while it was starting" (what was bought under its key has been
  ended, and the key is refused from then on) leaves
  `[env.<name>.starting]`, and its key is never sent again. Before, the
  entry stayed and was to be removed by hand. The error says it may have
  been charged by the hour from its start until it was ended, one hour at
  the least, which the dashboard shows, and that starting it again is a
  new purchase with a new key; when the entry could not be written, the
  error says so instead, and that the next run sends the key once more.
- `erpc worker delete --release-server` on an environment kept in the
  ERPC account waits as long as the account asks (`retryAfter`, up to two
  minutes) when it answers that another operation holds the environment
  (409 `end_refused` with the reason `operation_in_progress`), says the
  account is busy, and then asks again. Before, it stopped at once and
  asked to be run again. Some of what it was to end may be ended before
  that answer, so a run that then stops says part may be ended.
- `erpc ai` no longer offers `identityPubkey` for an hourly start of
  dedicated gRPC (`geyser-grpc`) or dedicated RPC (`rpc-index`): the node's
  validator identity is generated for you, and user-api refuses a start
  that names one. `hourly_catalog` lists `validatorType` as the only field
  such a start also takes, and `start_hourly_product` refuses
  `identityPubkey` before anything is sent, saying the family does not take
  it.
- A `keychain:` reference that a keychain filing an entry by one name
  (Windows) takes for the trading key's entry, such as
  `keychain:wallet.erpc-worker/<app>`, is refused as a setting, as the
  entry itself is.
- Something at the path of the WAF's note
  (`/etc/erpc/worker-waf/<id>.applying`) that cannot be removed (a
  directory, a file made immutable or append-only, which only root can
  put there) was taken for a deploy that had been ended there: every
  deploy restarted the WAF, `firewall allow` stayed held, and erpc said a
  deploy "was ended". `erpc worker status`, `firewall list`, a deploy and
  a held `firewall allow`, `deny` or `sync` now say that the note cannot
  be removed, with its path, and that root removes it. A deploy that
  changes `[waf]` fails at it, changing nothing, and says the same
  instead of asking for another deploy. The port is held as before. In
  `--json`, `waf_rules` and `held_because` say `note_kept` where they
  said `before_config`, and the WAF under `waf` and a deploy's `waf` carry
  `note_error`: the note's path and why it cannot be removed.

## [0.1.0-rc.7] - 2026-11-18

### Added

- `erpc worker deploy --udp` starts an hourly ERPC UDP Forwarding line for
  the server: the leader's raw shreds, sent over UDP to a port of the
  server's own (`--udp-port`, default 10001) from a node in its region
  (`--udp-region`). The plan is Standard unless `--udp-plan` names Premium
  by product id, and `deploy` shows the hourly catalogue's price before it
  starts either. erpc points the line at the server's public IPv4 address,
  opens the port in the server's firewall to the addresses ERPC sends from
  and to no one else (when ERPC names none, the port stays closed unless
  `--udp-any-source` opens it to any IPv4 address), and gives the app
  `SHREDS_UDP_BIND`. What the UDP step would be refused for is checked
  before the server or any line is bought. `status` shows the line and its
  price, and `delete --release-server` ends it, also when the server has
  ended outside erpc. While a UDP Forwarding line is on record and no server
  it reached is (such a VPS left the record), every deploy stops before it
  buys anything unless it has `--udp` or `--forget-line`, since the line
  would go on sending where it was pointed and being charged. `erpc ai`
  lists the account's UDP Forwarding lines (`my_services`) and points one at
  a server after the person's yes (`point_udp_line`). The `solana/pumpfun`
  template reads the UDP shreds with solana-stream-sdk 5.0.0 (its `udp`
  Cargo feature, on by default, which needs Rust 1.98.1 or newer), takes in
  only shreds their slot's leader signed, buys a graduation from whichever
  source shows it first, stamps each buy in `/api/timing` with the settings
  it was made under, and says there how much sooner the UDP shreds came; its
  Geyser and Shreds streams use the SDK's 16 MiB HTTP/2 receive windows.
  `deploy` names a Rust older than the app's `rust-version` before it buys
  anything, and `build`, `run`, `check` and `deploy` given `--dir erpc.toml`
  take the app's directory as `.`. In the template's lock, solana-stream-sdk
  5.0.0 and the 31 agave and solana 4.4.1 crates its `=` pins bring in are
  younger than the 14 days CONTRIBUTING asks. The maintainers made an
  exception for them on 2026-11-13. It lapses on 2026-11-27, when the SDK is
  14 days old. Every other crate in that lock is at least 14 days old.
- `install.erpc.global` counts the installers it serves: each `GET` of an
  installer writes one data point to Workers Analytics Engine with the
  request's country, continent and Cloudflare data centre, the first language
  of `Accept-Language`, the installer flavour, the version asked for (when
  that release was served) and the version served, and the status. The data
  point holds no address, user agent or anything else that tells one person
  from another, and recording cannot delay or fail an install. The columns
  are in `docs/install-counts.md`.

### Changed

- The pumpfun template's own dependencies move up a major version where
  nothing else in its build holds them: redis 1.8.1 with its default
  features off, rand 0.10 and utoipa 6. redis 1.x gives up after 500 ms
  waiting for an answer and 1 s connecting, where 0.27 waited for ever; a
  write that fails is logged and not retried, as before. At start the
  template reads back its bans, its traced creators and whether trading was
  on: a failed read is logged, and a bot that was trading but could not read
  back its bans comes back sell-only, says so in its notifications, and buys
  again after a restart once Redis answers; traced creators it could not
  read back stop no buy, and later traces follow them again. With
  Redis not reachable at all a start comes up with trading off, as without
  Redis. reqwest stays at 0.12, which the Solana RPC clients use, and the
  template's own Solana crates at 3.x, which ultima-swap-pumpfun pins. Its
  cargo-deny list allows BSL-1.0 for xxhash-rust alone, which redis 1.x
  needs.
- `erpc worker delete --release-server --yes` ends the app's lines and its
  hourly server without asking, and prints what each was and its price (on
  standard error, with `--json` too), as `deploy --yes` does for what it
  starts. Each end used to be asked at a terminal whatever the flags; with
  `--yes` and no terminal the app was removed and its lines and server
  stayed charged, with an error meant for `erpc ai`. No other end is
  answered by `--yes`, and it does not end a server another app or
  environment on this machine's list is on (an environment kept in
  1Password is read from its item), or may be on (its server cannot be
  read): it stops before anything is removed and names them.
- The Intel macOS release (`x86_64-apple-darwin`) is cross-compiled on the
  Apple Silicon `macos-15` runner, beside the Apple Silicon release. The
  `macos-15-intel` runner took 15 to 43 minutes for that build, the longest
  of the five. Worker-agent CI no longer runs there, and every pull request
  now does the same cross build.

## [0.1.0-rc.6] - 2026-11-16

### Changed

- `erpc validator`, `erpc rpc` and `erpc node` with no chain chosen, and
  their `--help`, show an overview drawn as the rest of erpc's help is, in
  colour at a terminal and in the operator's language: what the command is
  for, its usage, the chains and their networks, the chains with no
  validator and why, the commands every chain has, `erpc rpc call` and
  `list-networks` for rpc, the options and examples. It replaces a plain
  English list of `--chain <chain> --help` lines. For a script (`--json`
  before the role's other words, as in `erpc --json validator --help`, or
  `ERPC_JSON=true`) it is plain, even under `CLICOLOR_FORCE`. `erpc rpc help`
  is this overview too, no longer clap's list of `call` and
  `list-networks`; `erpc rpc help call` and `erpc rpc help list-networks`
  still print what `erpc rpc call --help` and `erpc rpc list-networks
  --help` print.
- A chain's own help (`erpc validator --chain solana --help`) has clap's
  headings in the operator's language, offers under `--chain` only the
  chains that have the command, and ends with where a command's options
  are. What the commands and options say stays English.

### Fixed

- Help never asks which chain nor fails for want of one. With no chain
  chosen (no `--chain` or an empty one, no `ERPC_CHAIN`, no
  `default_chain`), a request for help (`--help` or `-h` before `--`,
  `help` as the first word, or a line clap reads as one on some chain, as
  `erpc validator migration help`) shows the overview and where the
  command it names is: what `deploy` takes depends on the chain, `keys` is
  on solana only, and a word that is no command on any chain is said to
  be none. The command it names is the first word that is no option and
  no value of `--chain`, `--network` or `--name`, or, after a leading
  `help`, the word that follows. It opened the chain picker, and with no terminal or under
  `--json` failed with "no chain is chosen"; `erpc --json validator deploy
  --help` now prints the overview and exits 0.
- A chain named where the command goes, as in `erpc validator solana
  --help`, shows that chain's help when the line asks for help or names no
  command. With a command to run (`erpc validator solana deploy`) it is
  refused with the line meant (`erpc validator --chain solana deploy`;
  `erpc rpc call getSlot` for `erpc rpc solana call getSlot`, since `call`
  takes no chain), offered only when that line parses on the chain;
  otherwise it gets the chains the command is on (`erpc validator eth
  keys`: keys is on solana only) or clap's own words for the line. A
  chain without the command says so (`validator N/A for bitcoin`). It is
  never read as `--chain`: nothing runs, and no picker opens.
- A worker whose hourly VPS was ended outside erpc (in the dashboard, or
  by support) after a deploy that never reached it could no longer be
  deleted or deployed: `erpc worker delete --release-server` failed with
  "the account has no hourly vps" and kept the record, asking to be run
  again, and `erpc worker deploy` waited for that VPS each time and
  failed. erpc now asks the account signed in to whether it has the VPS:
  it is missing when it is neither among the account's servers nor
  charged for at every look over more than a minute, so that one bought
  a moment ago, which user-api can take that long to list, is never
  missing. erpc.toml does not say which account bought a VPS, so a VPS
  missing from the account signed in to may be another account's: every
  message that calls it missing names the account looked at, and only a
  person at a terminal, asked with that account named, can say it leaves
  the record. `--yes` does not answer that question, and with no terminal,
  or under `--json`, nothing is done and the error says so.
  - `delete --release-server` asks the account only about a VPS that was
    never reached, or one the person says is not to be reached
    (`--forget`); on the person's yes, such a VPS, when missing, is taken
    off the record without being ended. A server that was reached is
    removed from and ended as before, whatever the account says: erpc
    never takes a failure to reach it for its end.
  - `deploy`, on the person's yes, takes such a VPS off the record and
    chooses a server as for a new environment; otherwise it stops and
    names `delete --release-server`.
- `erpc worker delete` no longer warns about a trading app's positions
  when the worker never ran on a server.

## [0.1.0-rc.5] - 2026-11-16

### Changed

- Help at a terminal shows `Usage:` and its section headings in ERPC Blue,
  and dims the notes after a description (`[env: …]`, `[possible values:
  …]`, `[alias: …]`); command and flag names stay bold. The `Usage:` line
  of a command-line error is blue too; `error:` and the values in it keep
  their colours. The commands listed under 👉 Next and the `›` before a step
  under way are in the same blue instead of cyan. The blue is RGB where
  `COLORTERM` says the terminal takes it, else the nearest of the 256
  colours. Help off a terminal stays plain.

### Fixed

- Japanese and Chinese help, which erpc wraps itself, is plain under
  `CLICOLOR=0` and coloured under `CLICOLOR_FORCE`, as English help is; it
  went by `NO_COLOR` alone before.

## [0.1.0-rc.4] - 2026-11-13

### Added

- `erpc ai --model <SIZE>` and `/model <SIZE>` in the console put every
  turn of the conversation on one model size: `small`, `medium`, `large`
  or `xlarge`, the most capable, which uses tokens at 2x. `/model auto`
  goes back to letting each turn's words decide (small for a greeting,
  large for the rest), as before; `/model` alone says which is in use.
  The choice lasts until erpc ai ends, `/new` included, and the console
  names the size under each answer. A size the service does not offer is
  answered at its default size instead, and the console says so. The suggested next
  message and the summary of a long conversation stay on the small size.
- `erpc worker secret put <NAME> --generate` makes the value itself (64
  random hexadecimal characters, shown to nobody), for a token of the
  app's own such as the bot's `API_TOKEN`, and `--from-account` keeps the
  signed-in account's RPC API key, for `ERPC_API_KEY`: the first of its
  keys the shared RPC takes, said to be the account's primary key or one
  of its other keys (`account_key` with `--json`). Neither asks for a
  value, so a script or an agent can run them once the store is open (the
  keystore unlocked, or 1Password answering): the first use of the
  keystore, or a locked one, still needs a person at a terminal (`erpc
  worker secret unlock`). A command that is going to be refused (a name
  set already without `--replace`, an `erpc.toml` that is not there, a
  store that cannot be opened) is refused before a value is made and
  before anything is asked of the account. `erpc worker init` names them
  in its next steps: the pumpfun bot is set up with no value typed and
  nothing copied from the dashboard. `erpc worker deploy` and `erpc worker
  run` name them too where such a setting is missing, for an app made
  from a template: the hint's command carries the flag `init` named.
- `[waf]` in `erpc.toml` puts an app behind a WAF: `erpc worker deploy`
  runs an HTTP reverse proxy on the server, in a hardened unit of its own,
  on `waf.port`, and forwards to the app on loopback what its rules let
  through. It refuses methods and paths not allowed, oversized heads and
  bodies, a head or a body that takes too long to arrive, scanner probes,
  malformed and smuggling-shaped requests, and an address over its rate
  (429) or its connection limit; an address that keeps being blocked is
  banned for a while. Only `port` is required;
  `rate`, `ban`, `max_connections_per_address` and `new_connections` are
  turned off with `false`. `erpc worker check` says what it will do. It
  speaks plain HTTP/1.1: no TLS, HTTP/2 or WebSocket.
- With `[waf]`, `firewall.app_allow` opens the WAF's port, never the
  app's own, and only once the WAF listens on it; the server's firewall
  also drops new connections over 50 a second from one address
  (`new_connections`). `erpc worker firewall allow --to app 0.0.0.0/0`
  (and `::/0`) lets everyone in to an app behind a WAF; it stays refused
  for an app's own port and for SSH. The port is opened wider only under
  the rules `erpc.toml` makes: while the WAF on the server runs another
  config, or was started by an earlier agent than the one installed
  there, or before its config or its unit there last changed, `firewall allow`
  and `sync` hold a change that would let someone new in and fail saying
  so, a change that only narrows is applied at once, with the limit on
  new connections that is in force, and `deploy` opens the port as
  `erpc.toml` asks, that limit included, after it has put the new rules
  in place. A deploy restarts a WAF that an earlier agent started, or
  that was started before its config or its unit last changed, whether or not
  `[waf]` changed. A deploy that is ended on the server while it writes
  those two files leaves a note there
  (`/etc/erpc/worker-waf/<id>.applying`): until a deploy has restarted
  the WAF it counts as started before them, also when systemd started it
  again by itself in between.
- `erpc worker status` and `erpc worker firewall list` show the WAF: its
  port, where it forwards, since when, requests, forwarded and blocked,
  addresses banned now, in `firewall list` what was blocked by rule, and
  in both whether the rules it runs are `erpc.toml`'s, whether an
  earlier agent started it and whether it was started before its config
  or its unit last changed. `erpc worker logs
  --waf` shows its journal, a line for each request it refused. `--json`
  has the same under `waf` and `waf_rules`.
- `erpc worker import` takes in an app you already have: it reads the
  directory (a Cargo package, its `.env.example` and `.env`, a Dockerfile,
  a compose file, key files) and writes the `erpc.toml` it describes,
  without changing the app. Values are copied from the example files;
  from `.env` only a port number is taken. A line that names no setting
  is left out and counted; its text is not shown. A setting that looks
  like a
  secret, by its name or by a credential in its example's value, and a
  key file, are named with the command that keeps them, and the setting
  is named in `erpc.toml` as a comment. The
  directory may be anyone's: `erpc.toml` is made new and never written
  over a file or through a link, what is read is a regular file inside the
  directory of at most 1 MiB, an example file that is a link is not read
  (its values would be another file's, the app's `.env` among them), one
  that is one file with another name is read for its names only, a quoted
  dotenv value is read through its closing quote, and the next steps are
  quoted for a shell.
- `build.prebuilt` in `erpc.toml` (`erpc worker import --binary <PATH>`)
  ships a Linux binary built by any toolchain as it is, so an app need not
  be written in Rust. erpc reads its header, refuses one a server cannot
  run (a script, a binary for another system or machine, a shared library,
  a file cut short, a loader the servers lack, a link that leads out of
  the app) and says which glibc it needs: in `check`, and in `deploy`
  before a server is bought.
- `erpc worker check` warns of a `[vars]` value that carries a credential,
  in the language of the run: a URL with a password or a token before its
  host, a parameter named for a key, a token, a password or a signature,
  `Bearer` or `Basic` before a token, a private key's header, a JSON Web
  Token, a wallet's key (64 bytes in base58, a keypair's numbers), and a
  service's token by its shape (such as Stripe's, an AWS access key id,
  GitHub's, Slack's, GitLab's `glpat-…`, Google's `AIza…`, `sk-…`, a
  Telegram bot's, a Slack or Discord webhook). `import` also holds back a
  long part of a URL's path and words shaped like a recovery phrase;
  `check` does not warn of those two, which are too often something
  else. The reading goes by shapes: it is a net, not a proof. It warned of `api-key=`
  and `token=` only.
- On a Linux machine of the servers' kind, `erpc worker deploy` needs no
  zig and no cargo-zigbuild: without them the app is built with the
  machine's own toolchain, and the glibc the binary needs is read from it
  and said. With them it is built for glibc 2.31 and up, as before.
- `erpc worker deploy --yes` starts what the command names without asking:
  the price of a new VPS or line, the credit and how long it lasts are
  printed (on standard error, with `--json` too) and the start goes ahead.
  So does the first login to a server erpc has not made key-only yet, a
  new one or one named with `--vps`: your key goes in and password logins
  go off. An hourly product is paid from ERPC Credit, bought beforehand,
  and user-api refuses a start the credit does not cover. A script or an
  agent can so deploy an app with nobody at a terminal. Ending something
  is still asked at a terminal.
- `erpc worker deploy --prepare` does everything that needs neither the
  trading key nor a secret (the server, its firewall, the lines, the
  release installed on the server) and starts, stops and restarts nothing.
  An app already running there runs on, under the agent it had: an agent
  that runs is left running even when a newer one is installed (it holds
  the key, and a restarted one comes back without it), which `--prepare`
  says, in `--json` as `agent.kept`. The next deploy at a terminal hands
  the key and the secrets over and starts the app: it builds and installs
  a release of its own and starts that one (the build is cached, and the
  server is ready), not the one `--prepare` installed. It asks for no
  passphrase: it looks that the entries the app names in the keystore are
  there, and opens nothing.
- `erpc worker init` offers **HelloWorld** first: a small HTTP API in Rust
  (`GET /`, `GET /hello/{name}`, `GET /healthz`) that needs no key, no
  secret and no data line, so `init`, `run` and `deploy` work as they come.
  `--template helloworld` (or `hello`) names it, and it is what `init`
  makes when nobody is there to pick and no `--template` is given, where
  the pumpfun bot used to be. `init`'s next steps end with the deploy.
- `erpc worker api` calls an app that has no `API_TOKEN` in `[secrets]`
  without one, instead of refusing; an app that answers 401 then is told
  where its token goes.
- `erpc worker key new`, `key import` and `secret put` on a Linux machine
  with no Secret Service (a headless server, WSL, an SSH login) and no
  1Password no longer refuse: they keep the trading key and the secrets in
  erpc's keystore, files under `~/.erpc/keystore` encrypted under a
  passphrase you choose (PBKDF2-HMAC-SHA256, ChaCha20-Poly1305), named in
  `erpc.toml` as `keystore:<service>/<account>`. `--store keystore` asks for
  it on any machine. Back the directory up and remember the passphrase:
  erpc can recover neither, and 1Password stays the store that also works
  from another machine. The format and what it does not protect against
  are in `docs/worker.md` and `SECURITY.md`. `erpc worker secret rm`
  deletes a secret's keystore entry with its line in `erpc.toml` (values in
  1Password and the keychain stay, as before), and `erpc worker check`
  warns of a `keystore:` reference this machine's keystore does not hold.
- `erpc worker secret unlock` and `erpc worker secret lock`: on Linux the
  keystore's passphrase is typed once and the unlock kept in the kernel
  keyring until a reboot, its idle expiry, or `lock`; a command with nobody
  at a terminal uses it, and otherwise fails naming `secret unlock`. `lock`
  drops every unlock erpc keeps for you, also that of a keystore under
  another `ERPC_HOME` or one whose files are gone. The key `[wallet]` names
  is still read only for a person at a terminal: each keystore entry is
  sealed as a trading key or as a secret, and one kept as a key does not
  open as a secret, whatever names it.
- The trading key is named by `[wallet]` alone. `erpc.toml` is refused
  (`erpc worker check` says why) when a `[secrets]` line names the entry
  `[wallet]` names, or a `keychain:` or `keystore:` account ending in
  `.wallet`; `erpc worker bench --url` refuses such a reference too. A
  setting cannot be called `WALLET`, in any case, in the keychain or the
  keystore: where file names ignore case (macOS, Windows) its entry would
  be the key's. The keystore holds one spelling of a name, and where its
  directory has a second it reads, writes and removes neither.

### Changed

- `erpc worker status` shows what the environment costs now, not only
  what is on record: each hourly item (the server, each line) with the
  price per hour the account is charged for it, the total, and the
  account's credit with how long it lasts at what all it runs spends. An
  item that is not among the account's charges is said to be not among
  them, and not called ended: that list can be a minute behind a start.
  For a line that was ended somewhere else (the dashboard, `erpc ai`) it
  names `--forget-line`, which takes it off the record. `--json` carries
  the same under `hourly.charged`. Without a session, or when user-api
  does not answer, it says what is on record, as before.
- `-y`/`--yes` on `erpc worker deploy` means more than it did. It used to
  skip only the "Go ahead?" before a deploy: the price of a new VPS or
  line, and the first login to a server, were still asked at a terminal.
  Now it answers those too, and the start goes ahead at the price it
  prints. A command line that passed `-y` and counted on the price being
  asked starts what it names: leave out the flag, or the flags that start
  something (`--new-vps`, `--grpc`, `--shreds`, `--unlimited`).
- `erpc worker deploy` restarts the worker's agent, when a newer one is
  installed or its unit changed, only once it has read the key and is
  about to hand it over, not before the firewall, the lines and the
  upload. A deploy that fails in those leaves a running app running, where
  it used to leave it stopped and locked until `erpc worker start`. In
  `--json`, `agent.restarted` says whether it did; a failure after the
  restart has it in the error's `details`, and says how the key is handed
  over.
- A start that nobody can answer (no terminal, no `--yes`) is refused in
  words for whoever ran the command, naming `--yes`, with the
  `needs_terminal` code and exit status 3, before anything is bought. It
  used to fail as a plain failure with a sentence written for `erpc ai`.
  The first login to a server erpc has not made key-only yet is refused
  the same way, in its own words: it starts nothing and has no price.

### Fixed

- The installer selects the published release in GitHub Actions using its
  workflow token, avoiding anonymous GitHub API limits on shared edge IPs.
  Completed release workflows refresh the deployed selection automatically.
- `erpc ai` stopped every command it ran after five minutes, an `erpc
  worker deploy` included: a first deploy builds the app and waits for a
  new server, which takes longer, and one stopped halfway left a server
  bought with nothing on it. `erpc worker deploy`, `erpc worker build`,
  `erpc worker run --check` and a node's deploy now get 90 minutes once
  the person has agreed to them, when run as they are (inside a script
  they keep five); every other command keeps the limit it had. A command
  still running when erpc is ended by Ctrl-C, a termination or a hangup,
  or by a panic that aborts, is stopped with it (on Unix).
- A package run on the server restarted the workers on it: Ubuntu's and
  Debian's `needrestart` restarts a service whose binary was replaced or
  whose libraries were upgraded, after a deploy that installs a local
  service (Redis) and after an unattended security update alike. A
  restarted agent has forgotten the key and the secrets, so a trading app
  stayed down, locked, until `erpc worker start`. `deploy` now tells
  `needrestart` to leave worker units alone
  (`/etc/needrestart/conf.d/50-erpc-worker.conf`), so a package run does
  not restart a worker: in its automatic mode `needrestart` defers them,
  and asked at a terminal its default answer for them is no. A deploy that
  cannot write the rule says so and goes on, without this protection; in
  `--json`, `agent.needrestart_error` has why. An agent that fails or is
  killed (out of memory, say) is still started again by systemd, and comes
  back locked, as after a reboot, until `erpc worker start` hands the key
  over.
- Two apps on one server that were given the same port: the second one's
  deploy was reported healthy, because the health check was answered by
  the first app while the second could not listen and was restarted over
  and over. A deploy now refuses a release whose health-check port is that
  of another worker on the server that is kept running, naming that
  worker, before the key or a secret is read, and `erpc worker rollback`
  refuses to go back to such a release; an app without a health URL is
  not compared. The agent does not start an app while another program
  listens on its health-check port, and says so in `erpc worker status`
  and `erpc worker logs`; and a start the agent refused ends the deploy at
  once instead of after the health timeout.
- `erpc worker bench`, `erpc rpc call` and `erpc webhook run` took the
  account's primary API key on trust. An account can have several keys,
  and a key can be given an end date: with the primary one run out, the
  shared RPC refused all three although another key of the account
  worked. They, and the new `erpc worker secret put --from-account`, now
  try the account's keys in order, the primary one first, and use the
  first the shared RPC takes. A key it does not refuse and does not take
  either (no answer, a rate limit, a failure of its own) is passed over
  for one it takes. Where it takes none, the three go on with the first
  key it did not refuse, which their own call then tells about, and
  `--from-account` keeps nothing and says to run it again: a key kept
  unseen for a server is kept only once the RPC took it.
  That costs requests: each of the four reads the account's keys from
  user-api and then makes one `getHealth` call to the shared RPC for each
  key it tries, before any call of its own, so `erpc rpc call` sends one
  request more when the primary key is taken. `erpc worker bench` does so
  only once its own arguments hold (the `--url` values, the method, the
  rounds, the interval, the names and their count). The key is judged at the
  shared Solana RPC (`edge.erpc.global`) whatever chain is then called: a
  call or a webhook for Ethereum goes to `eth.erpc.global` with the key
  chosen at the Solana RPC.
  The keys are tried from the machine erpc runs on, and a key can be
  limited to the addresses it is used from, so one that works from the
  app's server may be refused here. When every key is refused, the error
  says that they were tried from this machine. `--from-account` then
  keeps nothing and names the way to keep the key by hand (`erpc worker
  secret put <NAME>`, typed or piped in, with `--replace` when the
  command had it); `erpc worker bench`, whose calls are made from the
  server, goes on with the account's primary key and says so under its
  table, and as `shared_key_refused_here` with `--json`.
- `erpc worker init`'s next steps name the app after `secret put` with
  `--dir`, as that verb takes it: `erpc worker secret put API_TOKEN
  --dir <app>`. The line it printed, with the name alone, was refused.
- `erpc worker firewall allow` and `deny` with `--json` printed plain
  text on standard output when there was nothing to change (the address
  let in already, or not on the list). They now answer with JSON, as
  their other answers are: `{"worker": …, "changed": false, "erpc_toml":
  {…}}`, the lists `erpc.toml` asks for and nothing of the server, which
  is not asked; and an `allow` or `deny` that changed the list says
  `"changed": true`. That answer no longer needs the server's address,
  its host key or an SSH key on this machine, and an address that is none
  is refused before they are looked for.
- A start of an hourly product by `erpc worker deploy` (`--new-vps`,
  `--grpc`, `--shreds`, `--unlimited`) that gets no answer is sent again
  with the same request key when the command is run again, never with a
  new one. The key goes into `[env.<name>.starting]` before the request
  leaves, and stays there until the start is settled: a request sent again
  leaves the record only when user-api answers with the purchase itself,
  and a first request also on a refusal that is certain. On no answer, 409
  `PURCHASE_IN_PROGRESS`, a 409 erpc cannot read, or any refusal of a
  request sent again, the entry stays and the error says which it was and
  what to do. A request sent again and answered 409 `IDEMPOTENCY_CONFLICT`
  starts nothing: the server or line may well have been started by the
  earlier request, and the error says how to look, to take a server up
  with `--vps <ID>` or end what is not wanted, and that the entry is then
  removed by hand. A start with no answer used to be reported as "not
  sent", and a rerun sent a new request; `erpc ai`'s start says it may or
  may not have gone through, too.
- `erpc worker check` and `run` no longer tell an app that needs no key to
  make one with `erpc worker key new`: only an app made from a template
  that trades is told.

## [0.1.0-rc.3] - 2026-11-10

### Added

- `erpc rpc call` sends JSON-RPC to shared Solana and Ethereum mainnet
  endpoints or an operator-provided URL. The x402 option quotes and signs a
  Base EURC payment after terminal confirmation.
- `erpc webhook` manages local subscriptions and delivers matching
  WebSocket notifications to HTTP callbacks. `erpc completions` generates
  shell completion scripts.
- The unversioned installer URLs prefer the latest stable release and select
  the most recently published prerelease when no stable release exists.
  Versioned installer URLs keep selecting the requested tag.

- The `solana/pumpfun` template trades pump.fun graduations as well as
  pools made by hand. It reads a graduation's `create_pool` where it
  happens, inside pump.fun's `migrate_v2` and with accounts from address
  lookup tables; buys and sells with WSOL on either side of the pool and
  with tokens on Token-2022; and buys a graduation from its `create_pool`
  without RPC reads or a simulation first. `graduated_only` keeps it to
  graduations.
- With `SHREDS_ENDPOINT` set, the template reads `migrate_v2` from the
  Shreds stream, and `buy_on_shreds` (off by default) buys from there. A
  transaction in the stream has not run, so a migration is bought only
  when its curve, pool and vaults are the addresses its mint gives them
  and the accounts read are owned by the programs that write them.
  `GET /api/timing` gives p50 and p90 of how long a migration showed in
  Shreds before Geyser processed it and before its slot was confirmed, how
  long a buy took from the pool's first sighting to its send, and how many
  slots late each buy landed. `priority_fee_micro_lamports` and
  `compute_unit_limit` set a buy's priority fee, which the take-profit
  counts as cost.
- `POST /api/bans/trace` in the template bans the wallet that first funded
  each banned creator, and the other wallets that funder sent SOL to
  lately. Wallets with a long history, funders that paid many wallets and
  the bot's own wallet are left alone.
- `erpc worker run --grpc --shreds --ip <IPV4>` gives a run on this machine
  hourly gRPC and Shreds lines that admit its public IPv4. An active line
  that already admits it is taken up; otherwise a new line is bought after
  its price is asked. When the run ends, Ctrl-C included, erpc asks to end
  each line; `--keep-lines` keeps them. Ctrl-C while a line is being bought
  waits for the purchase to be on record, then ends that line with the
  rest.
- `erpc worker api` sends one request to the app's API on its server, over
  SSH, with `API_TOKEN` read here and never shown; `erpc worker trades`
  shows the app's trade history or the profit per trade.
- `erpc ai` runs the `erpc worker` verbs that only look without asking:
  `check`, `list`, `status`, `logs` (not followed), `releases`,
  `key show`, `key balance`, `secret list`, `firewall list` and
  `backup status`. Every other verb is shown and asked as before.
- `erpc worker key send` moves SOL out of the trading wallet to one address
  after a yes: the key is read behind the same gate as a run, and the
  transfer is signed in memory and sent through the app's own RPC. It is
  followed by its own signature until it lands or its blockhash is past,
  and is said to be unsent only when the RPC node refused it before
  sending it on. The address is taken only in its canonical base58 and
  shown as decoded.
- `run.requires` in `erpc.toml` takes a set of settings of which one is
  enough, such as `["ERPC_API_KEY", "SOLANA_RPC_ENDPOINT"]`. The pumpfun
  template asks for its RPC that way, so `erpc worker check` no longer
  calls an app ready that cannot start. Such a set is an array inside
  `missing` in `secret list --json`, beside the names of single
  settings, and in `manifest.run.requires` in `check --json`.
- `erpc rpc` on six more chains, which makes all 18: Polygon PoS (Bor and
  Heimdall v2), BNB Chain (Geth, with full or pruned history), Kaia (an
  endpoint node), Monad, Hyperliquid (a non-validator node) and NEAR (a
  nearcore follower). Each has the same twelve verbs and a guide that
  `docs/nodes.md` links.
- `erpc validator` on eight more chains: Polygon PoS, BNB Chain, Kaia (a
  consensus node or a proxy node), Monad, Hyperliquid, NEAR, Arbitrum One and
  Robinhood Chain. Deposits, staking and registration are signed outside
  erpc; `registration` on Polygon, NEAR and Robinhood Chain prepares and
  checks them. `erpc validator --chain hyperliquid aqa` runs the separate
  AQA publisher. On Arc, `erpc validator` prepares a validator host and runs
  it as an observer; it does not sign.
- Solana on the native backend, for validators and RPC nodes on mainnet and
  testnet: Agave built from source on the server and run under accounts of
  its own. A validator has every verb now (`logs`, `start`, `stop`,
  `restart`, `update`, `update-config`, `plan` and `destroy` were not
  implemented), syncs under a separate identity and starts voting with
  `deploy --activate-validator`. `erpc v registration` reads the vote account
  and prepares what an external wallet signs. `docs/solana-native.md` is the
  guide.
- Live acceptance on real hosts is still under way for most of these chains:
  `docs/chains/README.md` says where each one stands.

### Changed

- `erpc worker stop`, `status` and `delete` say which hourly server and
  lines keep charging and how to end them; `status` carries them in its
  JSON. `deploy` checks the cross-build tools and the SSH key before a VPS
  is bought, and names every missing piece at once; `check` says the same
  of the tools, looking for them on `PATH` without running anything in
  the app's directory.
- Before `stop`, `restart`, `rollback` and `delete`, an app with a wallet
  is warned that its positions wait while it is down; a redeploy says so
  as it restarts the app.
- The pumpfun template keeps whether trading is on in Redis and takes it
  up again at start, so a restart does not leave it idle on paid lines.
- `erpc worker firewall` says, after a change, that the SSH allow list
  outlives the address it was made from, and that a port opened for the
  app answers only if the app binds beyond loopback.
- `erpc worker init` builds its "Next" steps from the manifest. A missing
  line setting points at `--grpc` or `--shreds` instead of `secret put`.
- A line that is becoming active shows a spinner, as does 1Password while
  erpc waits on its app. On Linux without a Secret Service the keychain is
  refused where the store is chosen, with the ways out.
- The `erpc login` store picker and vault question speak en, ja, zh and
  ru.
- CI renders the `solana/pumpfun` template as `erpc worker init` does and
  runs its clippy and tests. The templates are not workspace members, and
  nothing compiled them before.
- **Coming from 0.1.0-rc.2: new Solana nodes use the native backend.**
  `erpc v init` and `erpc r --chain solana init` for a name whose server is
  not in the inventory no longer set up a `solv` node, and `--backend solv`
  is refused for it. The server must be Ubuntu 24.04 with systemd 255, AVX2
  and SHA-NI, at least 24 threads and 300 GiB of memory for a mainnet
  validator or 120 GiB for a testnet validator (32 and 480 GiB for an RPC
  node on either), with three filesystems
  already mounted, which erpc does not partition, format or mount for a new
  node. You make the keys and keep them in 1Password before `init`, which
  takes new flags for them; erpc generates none. There is no choice of
  client, release or RPC type, and making or importing keys and
  `erpc v vote-account` are refused. `docs/solana-native.md` has the
  preparation. A node whose server 0.1.0-rc.2 recorded keeps the commands it
  was set up with, and `erpc v migration` or
  `erpc r --chain solana migration` moves a qualified one to the native
  backend.
- **Coming from 0.1.0-rc.2: nodes it deployed on six other chains.** This
  version looks on the server for helpers and ownership records that a
  0.1.0-rc.2 deploy did not write, so `deploy`, `update`, `start` and
  `restart` fail on such a node until it has been migrated once, and so does
  `status` except on TRON and Bitcoin. Until then erpc cannot stop an
  Ethereum or Arc node either: the Ethereum entries below start by stopping
  the services on the server, and Arc's migration stops them itself. A
  migration leaves the node stopped; the guide named beside each has the
  records of the original server it asks for and the `deploy` or `update`
  that follows.
  - Ethereum RPC: stop Reth and Lighthouse on the server, then
    `erpc r --chain eth init --migrate-authority` with `--original-passwd`,
    `--original-group`, `--original-machine-id` and
    `--original-client-record` (`docs/ethereum-rpc.md`).
  - Ethereum validator: stop its three services, then the same flags on
    `erpc v --chain eth init` (`docs/ethereum-validator.md`).
  - Arc RPC: the same flags on `erpc r --chain arc init`
    (`docs/arc-runtime.md`).
  - Avalanche: `init --migrate-account` (`docs/avalanche.md`).
  - Sui: `init --migrate-account` and `update --migrate-source-history`
    (`crates/erpc-chain-sui/templates/README.md`).
  - Bitcoin: `erpc r --chain bitcoin deploy --original-runtime-record`
    (`docs/bitcoin-rpc.md`).
  - TRON has no migration. This version can stop or destroy a TRON node that
    0.1.0-rc.2 deployed, keeping its data, but cannot start or update it.
- **Coming from 0.1.0-rc.2: what erpc needs on a server.** Every file erpc
  uploads, for a node and for `erpc worker`, is now written on the server by
  a Python program run through `sudo`. The server needs `/usr/bin/python3`
  and `sudo` that asks for no password: check a server of your own before
  `erpc worker deploy --host`. `/opt` must be a real directory owned by root
  that its group and others cannot write, and so must `/opt/erpc` and the
  `runs` and `uploads` directories in it where they exist; none of them may
  be a symbolic link. For a node, the filesystem that holds `/opt/erpc` must
  also keep POSIX ACLs, as ext4 and XFS do by default. To keep `/opt/erpc` on
  another volume, mount the volume there instead of linking it, and keep the
  volume's top directory owned by root and not writable by its group or
  others. Ubuntu ships that Python and such an `/opt`.
- **Coming from 0.1.0-rc.2: your own systemd drop-ins.** The firewall step
  refuses to run while `/etc/systemd/system/<unit>.d/` of a service it
  protects holds any file but erpc's `50-erpc-firewall-guard.conf`, such as
  an `override.conf` made by `systemctl edit`. It changes nothing, and on
  every node whose firewall erpc manages, the command that applies or removes
  the firewall stops there: on a solv Solana RPC node, `deploy`, `update`,
  `update-config` and `destroy`, for `solv.service`, `faithful.service` and
  `of1-index-sync.service`. Move your drop-in out of that directory and run
  the command again.
- **Coming from 0.1.0-rc.2: `erpc v keys` and `erpc v vote-account` on
  mainnet need `--chain solana` on the command line,** as every other command
  that changes a mainnet node does: a chain taken from `ERPC_CHAIN` or
  `default_chain` is refused. `keys` can write a validator's vote account key
  and withdraw authority to 1Password, even without its flags when one is
  missing.
- `erpc v list` and `erpc r --chain solana list` show each node's backend,
  list a validator registered without a host as `[no host yet]`
  (`"backend": null` in `--json`), whose other commands say that the init
  that registered it resumes it, and, when there is no node, point to
  `init --help` and `docs/solana-native.md`.

### Fixed

- Apple Silicon worker-agent CI and release builds use the supported
  `macos-15` runner. GitHub rejected the former `macos-14` image before
  executing a job.

## [0.1.0-rc.2] - 2026-11-05

Everything erpc does beyond signing in, developed since 0.1.0-rc.1 and
brought into this repository as one change. The commands exist and pass
their offline checks; acceptance on real hosts is still under way for most
chains, and each chain's guide in `docs/chains/` says where it stands.

### Added

- `erpc validator` (`v`), `erpc rpc` (`r`) and `erpc node` (`n`): RPC nodes
  on 12 chains (Solana, Ethereum, Base, Optimism, Soneium, Arbitrum,
  Robinhood Chain, Avalanche, Bitcoin, Sui, TRON, Arc) and validators on
  five (Solana, Ethereum, Avalanche, Sui, TRON), with the same verbs:
  `init`, `deploy`, `status`, `logs`, `start`, `stop`, `restart`, `update`,
  `update-config`, `plan` and `destroy`. Solana validators have only `init`,
  `deploy` and `status` of these so far, plus `list`, `keys` and `vote-account`. Six
  more chains (Polygon, BNB Chain, Kaia, Monad, Hyperliquid, NEAR) are
  researched in `docs/chains/` and answer "not implemented yet". Live
  acceptance on real hosts is still under way for most chains. Every deploy
  logs in over SSH with a key from the 1Password SSH agent or `SSH_AUTH_SOCK`
  and pins the host key. What it sets up on the host differs by chain, and
  `docs/nodes.md` lists the differences: Solana nodes run as a login user with
  passwordless sudo, Solana builds its clients at a pinned commit and fetches
  some tools without a checksum, and Solana validators, Ethereum validators and
  Bitcoin nodes get no firewall from erpc. Node and validator records
  live in 1Password, not on the operator's disk. Which keys are in 1Password and which stay on the host differs by chain.
  `docs/nodes.md` has that table, the clients, networks and guides.
- `erpc rpc --chain solana`: Solana mainnet RPC nodes, the port of `slv rpc`,
  with agave or jito and SLV's four RPC types
  (SendTx, Index with Old Faithful, Geyser gRPC, Index + gRPC). The client
  and plugin versions are pinned in its 1Password item;
  the node makes its own identity; an nftables table admits RPC from the
  operator's proxies only and rolls itself back unless erpc reconnects.
- `erpc validator --chain solana`: testnet and mainnet validators with
  agave, jito or Firedancer; the identity made in memory and kept in
  1Password; vote account and withdraw authority keys made or imported;
  `erpc v list` from the 1Password inventory.
- `erpc ai`: the assistant, in a full-screen console. It reads the signed-in
  account (credit balance and history, card subscriptions, RPC usage and the
  AI plan) through read-only tools that pass on only the fields they name;
  knows what ERPC sells and what is free now (the server catalogue, servers
  in stock by region, the prices of RPC, Unlimited and dedicated RPC, gRPC,
  shreds and bundle plans, the services the account runs, each region's
  health, and which server each chain's nodes need); can run commands on
  your computer when you allow it, every command until the conversation
  ends if you say so; opens the ERPC dashboard for monthly and yearly plans,
  and shows the link instead over SSH, without a display, from a script or
  with `--json`; suggests the message you are likely to send next (Tab
  takes it); and speaks English, Japanese, Simplified Chinese and Russian,
  as does the rest of erpc (`erpc config set language`).
- `erpc resume` and `erpc memory` (`list`, `forget`, `clear`): saved
  conversations, and what the assistant remembers between them
  (`~/.erpc/conversations/`, `~/.erpc/memory.json`).
- `erpc ai` skills by subject, named by chain, role and network
  (`solana-validator-mainnet`, `solana-validator-testnet`,
  `solana-rpc-mainnet`, `ethereum-node`, `avalanche-node`, `sui-node`,
  `erpc-account`, `erpc-services`, and more), each a `SKILL.md` the
  assistant reads when a question needs it. The mainnet validator skill
  covers hardware, clients, BLS, node tuning and safe restarts.
- `erpc skills list` and `erpc skills install [--agent claude]`: the skills
  written to `~/.erpc/skills/<name>/SKILL.md`, and to Claude Code's skills
  directory when asked. A file changed since erpc wrote it, or a skill erpc
  did not write, is left as it is. The installer runs `erpc skills install`
  after putting the binary in place.
- `erpc worker` (`w`): your own app as a tuned Rust binary on an ERPC VPS or
  bare metal. `init` picks a template (an HFT scaffold, a pump.fun bot) and
  `check` reads the manifest back; `key new`, `import`, `show` and `balance`
  keep the trading key straight in 1Password; `secret put` and `list` keep
  API tokens there; `run` builds and runs the app here, `build` builds it
  for the server, `bench` measures it; `deploy` (with `--new-vps`, `--grpc`,
  `--shreds`; prices asked first) puts it on a server under a supervising
  agent that holds the keys, and `releases` and `rollback` move between
  deploys; `status`, `logs`, `start`, `stop`, `restart`, `list` and
  `delete` manage it; `firewall` manages the server's nftables rules and
  `backup` its backups. `build` and `deploy` keep cargo's output in
  `target/erpc-build.log` and show only the warning count or the
  diagnostics. The erpc binary embeds the worker agents it installs (static
  musl, `x86_64` and `aarch64` Linux); `erpc version` prints their SHA-256.
  `[services]` in `erpc.toml` puts Redis and PostgreSQL on the server.
- `erpc storage` (`st`) and `erpc backup`: ERPC Global Storage plans
  (`buy`, `resize`, `usage`, `plan`), files `put`, `get`, `list`, `delete`
  and `sync` with an account key that encrypts them before they leave the
  machine (`key`, `keys`; `docs/storage-encryption.md` has the format), and
  machine backups with a pinned restic (`init`, `run`, `snapshots`,
  `restore`, `check`, `prune`, `schedule`, `status`, `password`;
  `docs/backup.md` sets out who holds which key).
- `erpc wallet create` and `show`: one Base wallet per person, made by erpc
  with its key kept only in 1Password, that buys ERPC Credit with EURC
  through x402 (an EIP-712 `TransferWithAuthorization` signed in memory).
- `erpc signup` and `erpc config` (`get`, `set`, `path`, `init`): the
  sign-up page, and the public settings in `~/.erpc/config.toml`.
- On Linux, sessions kept without a desktop: the kernel keyring where no
  Secret Service answers, and 1Password through an `op signin` session where
  there is no 1Password app.
- `erpc --json <command>` works for every command, and a failure reads the
  same everywhere: an `error:` line and a `hint:` line, or one JSON object, with the exit codes
  in `docs/errors.md`.
- A scheduled workflow (`jito-regions`) checks the Jito region table erpc
  carries against Jito's documentation once a week and opens an issue when
  they differ.

### Changed

- The 1Password session item is titled with the machine's own name, read
  from the operating system, instead of `$HOSTNAME`, which shells do not
  export: every machine was `unknown-host`. A session kept in 1Password
  before this needs `erpc login` once; the old `… @unknown-host` item can
  then be deleted.
- The crates `erpc-chain-arc`, `erpc-chain-avax`, `erpc-chain-bitcoin`,
  `erpc-chain-eth`, `erpc-chain-nitro`, `erpc-chain-op`,
  `erpc-chain-rollup`, `erpc-chain-sui`, `erpc-chain-tron`, `erpc-worker`
  and `erpc-worker-agent` join the workspace (26 crates in all).
- `scripts/reserve-crates.sh` reserves the workspace crates missing from
  crates.io with placeholder 0.0.1 packages (a name, a licence, a
  description and an empty library; nothing of the tree), after checking
  that every crate already there is owned as `erpc` is. The 0.0.1-only rule
  stands: a real version comes from the release pipeline alone.
- The endpoint gate learns `NODE_HOSTS`, the hosts a node reaches from the
  playbooks and templates erpc carries, accepted in those trees only, and
  `ADDRESS_ECHO_HOSTS`, the services `erpc ai` may ask for the operator's
  public address. `docs/public-hosts.md` lists both.

### Fixed

- The `solana/pumpfun` template trades on PumpSwap again: its
  `ultima-swap-pumpfun` dependency moves to `dbbe5f6`, which passes the
  buyback fee recipient (and `pool-v2` on pools with a coin creator) that
  `buy` and `sell` now require. Every trade had failed in simulation with
  `BuybackFeeRecipientMissing` (6058).
- `erpc ai` no longer garbles a character that arrives split between two
  network chunks.

## [0.1.0-rc.1] - 2026-11-02

First release through the release pipeline, as a prerelease: binaries for
five targets, the `install.erpc.global` installers, a GitHub Release with a
minisign-signed manifest, and the crates published by Trusted Publishing.
Apart from the entries below, the code is that of 0.0.1.

### Added

- The release signing key (minisign, key ID `A84D7BB71B974545`) in
  `crates/erpc-release/pubkey.txt`, replacing the placeholder.

### Fixed

- The `aarch64-unknown-linux-musl` release build links: the vendored libdbus
  is compiled without outline atomics (`.cargo/config.toml`).
- The rebuild comparison runs on the runner images cargo-dist builds on, with
  the same C compiler. In 0.0.1 it rebuilt on a different image with
  cargo-zigbuild. `docs/verify-release.md` states what the comparison does
  and does not show.
- `scripts/reserve-crates.sh` publishes in dependency order, paces new crates
  to the crates.io rate limit and refuses any version but 0.0.1.

## [0.0.1] - 2026-11-02

Published to crates.io by hand from commit `964b507` to reserve the crate
names. There is no GitHub Release, no binary and no signature for this
version.

### Added

- Cargo workspace (`erpc` binary and 14 library crates), pinned toolchain,
  `cargo-deny` / `cargo-audit` policy, REUSE compliance, security policy,
  contribution and governance documents.
- `erpc version [--json]`.
- `erpc login`, `logout`, `whoami` and `doctor`: sign in to an ERPC account
  through the OAuth device authorization grant, keep the session in the
  1Password desktop app, a 1Password service account, the OS keychain or a
  file, and report where it is and why.
- On Linux, sessions kept without a desktop: the kernel keyring where no
  Secret Service answers, and 1Password through an `op signin` session where
  there is no 1Password app.
- `erpc ai` reads the signed-in account: credit balance and history, card
  subscriptions, RPC usage and the AI plan, through read-only tools that
  pass on only the fields they name.
- `erpc ai` knows what ERPC sells and what is free now: the server
  catalogue (VPS, Super VPS, Premium VPS, bare metal by type), servers in
  stock by region, the prices of RPC, Unlimited and dedicated RPC, gRPC,
  shreds and bundle plans, the services the account runs, and each region's
  health; and which server each chain's nodes need.
- `erpc ai` skills by subject, named by chain, role and network
  (`solana-validator-mainnet`, `solana-validator-testnet`,
  `solana-rpc-mainnet`, `ethereum-node`, `avalanche-node`, `sui-node`,
  `erpc-account`, `erpc-services`), each a `SKILL.md` the assistant reads
  when a question needs it. The mainnet validator skill covers hardware,
  clients, BLS, node tuning and safe restarts.
- `erpc skills list` and `erpc skills install [--agent claude]`: the skills
  written to `~/.erpc/skills/<name>/SKILL.md`, and to Claude Code's skills
  directory when asked. A file changed since erpc wrote it, or a skill erpc
  did not write, is left as it is. The installer runs `erpc skills install`
  after putting the binary in place.
- `erpc-secret`: the key-use gate and the `op://` reference parser.
- `erpc-api`: the account lookup against `user-api`.
- CI (fmt, clippy, tests on Linux/macOS/Windows, deny, audit, reuse, gitleaks,
  public-host check, endpoint allowlist, zizmor, `dist plan`).
- cargo-dist release pipeline with GitHub Attestations, CycloneDX SBOM,
  `cargo-auditable`, release gate, independent rebuild comparison for Linux,
  minisign-signed release manifest and crates.io Trusted Publishing. Release
  artifacts are published on GitHub Releases only. Prerelease tags run the
  full release workflow and are published to crates.io as semver
  prereleases.
- `install.erpc.global` Cloudflare Worker serving the installers.
- `docs/verify-release.md`: verify signatures against a key saved once from
  `main`, not against `pubkey.txt` at the tag being checked.

[Unreleased]: https://github.com/elsoul/erpc-cli/compare/v0.1.0-rc.7...HEAD
[0.1.0-rc.7]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.7
[0.1.0-rc.6]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.6
[0.1.0-rc.5]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.5
[0.1.0-rc.4]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.4
[0.1.0-rc.3]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.1
[0.0.1]: https://github.com/elsoul/erpc-cli/tree/964b507d0276254aeec4451cfbdecc8effd83724
