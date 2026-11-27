<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# The assistant: `erpc ai`

`erpc ai` opens a conversation with the ERPC assistant. It answers from
ERPC's documentation and your account, and with your approval it can act:

- start and end hourly products, and point a UDP Forwarding line at a
  server (it changes no firewall: `erpc worker deploy --udp` does both for
  an app of erpc worker's);
- buy ERPC Credit with EURC from your wallet;
- wait for a new VPS to come up;
- log in to the VPS once with the password ERPC set, put your key in place
  and turn password logins off for good;
- allow SSH only from your address.

Whenever it needs a decision it offers choices to pick with the arrow keys
and Enter. The assistant's own actions above ask first, every time, with the
cursor on "Stop". Its tools that read your account pass on only the fields
SECURITY.md lists.

It can also run commands on your own computer, and what any command prints
goes to the assistant, logs included, with only the values of `api-key=`,
`api_key=`, `apikey=` and `token=` parameters hidden. Commands that only look run at once; any other is shown word
for word and asks each time. You may allow that exact command, or every
command, scripts included, behind a second question. Once every command is
allowed, until erpc ai ends or `/new` (or `/clear`) starts a new
conversation, nothing is asked before a command runs: one given `--yes` that
spends money or changes a server (`erpc v vote-account --yes` pays to create
the vote account) runs too, and one that prints a key file or a password
hands it to the assistant. [SECURITY.md](../SECURITY.md#what-the-assistant-reads)
says what each of its tools passes on.

More about conversations:

- **Model size**: each turn's words decide it, small for a greeting and
  large for the rest. `erpc ai --model xlarge` (also with `-m` or `-c`)
  or `/model xlarge` in the console puts every turn on one size instead:
  `small`, `medium`, `large` or `xlarge`, the most capable, which uses
  your tokens at 2x. `/model auto` goes back, and `/model` alone says
  which size is in use. Changing it in a conversation reads the whole
  conversation again at the new size once.
- **Conversations** are saved under `~/.erpc/conversations/`, readable by
  you alone. `erpc ai -c` continues the last one (also with `-m` or a
  question piped in), and `erpc resume` picks any of them.
- **Suggested next message**: after each answer, the box shows dimmed the
  message you are likely to send next, and Tab puts it in the box for you to
  edit or send; nothing is sent until you press Enter. Each suggestion is one
  extra small request to the assistant, sent the words of the last two turns
  only, never tool results.
- **Long conversations** are summarised automatically to keep them
  affordable. The summarised turns stay on disk.
- **Memory**: the assistant can remember short facts about you, such as your
  hosts, chains and preferences, from one conversation to the next. They are
  kept in `~/.erpc/memory.json`, and nothing that looks like a secret is
  saved. `erpc memory list`, `forget <n>` and `clear` show and delete them.
- **Skills**: what the assistant knows about each chain and service.
  `erpc skills install` (or `erpc skills sync`) writes it out for another AI
  agent to use, `--agent claude` for Claude Code. The skills ship inside erpc,
  checked against its commands, so they always match the version you run.
  After an upgrade `erpc doctor` warns while the copies on disk are older,
  and the next command says so once.

## ERPC Server Security Check

Official binary releases built with the Security Check feature expose
`--security-check` in `erpc ai --help` and include it in generated shell
completions. The ERPC service determines whether the signed-in account and
its rentals are eligible. For a source build or `cargo install erpc`, add
`--features security-check-pilot`. The older `node-check-pilot` feature
name is also supported.

After `erpc login`, run `erpc ai --security-check` from your terminal to
select an eligible VPS or bare-metal rental. The selector starts on
**Cancel**. Use `erpc ai --security-check --list --json` to list rentals,
or add `--kind vps --id 123` or `--kind bare-metal --id 456` to select one
directly. Inspection requires a terminal. In every build, input whose first
word is `/security-check` stays local in the console, with `--message`, and
on standard input. In builds with the feature it points to the terminal command.
`/node-check` locally displays the migration message.

Before inspection, confirm that you own the selected server or have
authorization to assess it and agree to use the check without reselling
it. ERPC then revalidates the rental, provisioning state and public IPv4
assignment before any SSH connection. The CLI uses the SSH identity in
`ssh_key` and the saved VPS host key pin for that rental. You can supply
an independently verified Ed25519 host public key with
`--host-key '<public-key>' --ssh-user '<login>'` for this check.

The collector reads bounded evidence from the remote Linux SSH login's
network namespace and available system configuration.

- TCP listeners and bound UDP ports grouped by bind scope, with service
  classifications when available. External reachability is outside the
  scope of this check.
- SSH password and keyboard-interactive settings from OpenSSH's default
  on-disk configuration, evaluated for the SSH connection. The running
  daemon may use different options or configuration. A configured
  `no` is reported as unknown for billing. The check also reads nftables
  input filter evidence and fail2ban's sshd jail status, and may retry
  denied reads of those two sources with non-interactive sudo.
- File mode counts for systemd environment and credential source references.
  The collector checks a fixed systemd unit allowlist and eligible ERPC
  units that own sockets in the sampled namespace. It follows nested
  socket cgroups to their owning service. The collector counts distinct
  source values separately for `LoadCredential` and
  `LoadCredentialEncrypted`, deduplicating repeated values within each
  kind. Incomplete socket attribution, cgroup discovery
  or systemd reads leave missing evidence unknown. An observed
  `EnvironmentFile` declaration produces a local SSH policy finding
  regardless of its file mode. JSON reports include that finding in
  `localFindings`, alongside any metered findings.
- Security update counts from the local Debian or Ubuntu package cache.
- Private keys and secrets kept in plain text. This part reads file
  contents: files under `/root`, `/home`, `/etc`, `/opt`, `/srv`,
  `/var/lib` (with Docker's volumes), `/tmp` and `/var/tmp`, shell
  histories, and the environments of running processes. It looks for:
  - Solana CLI keypair files (a JSON array of 64 numbers from 0 to 255);
  - files whose name contains `key`, `private` or `wallet` in any case and
    that hold only 64 hexadecimal digits, with or without `0x` (`.pem`
    files excepted);
  - BIP-39 English seed phrases of 12, 15, 18, 21 or 24 lower-case words
    and nothing else;
  - JSON keystores with a private key field (`privateKey`, `private_key`,
    `secretKey` and similar spellings) and no `crypto` object;
  - lines of `.env`, `*.env` and `environment` files that set a variable
    whose name contains `PRIVATE_KEY`, `SECRET_KEY`, `MNEMONIC`,
    `SEED_PHRASE`, `KEYPAIR` or `WALLET_KEY` to a value written out, rather
    than an `op://`, `keychain:`, `keystore:` or `$` reference or a path
    starting with `/`, `~/`, `./` or `../`. A name ending in `_PATH`,
    `_FILE` or `_DIR` is not counted;
  - the same variables, set to a value, in the environments of running
    processes;
  - lines of bash, zsh and fish histories that hold 64 hexadecimal digits
    in a row, 87 or 88 base58 characters in a row (the length of a Solana
    secret key), or set one of those variables. A transaction signature,
    hash or digest of the same length is counted too.

The key search runs on the server in a child process of the collector,
beside the other reads, as the SSH login and with no `sudo`. It opens each
directory and file relative to the directory it was listed in, first as a
path only (`O_PATH`, `O_NOFOLLOW`), so it learns an entry's type, owner,
size and filesystem before opening anything to read. It does not follow
symbolic links, opens no device and waits on no pipe, and does not cross
into another filesystem, though each directory in `/home` may be one of its
own; that is decided before a directory is opened to read. It skips Docker's
`overlay2` image layers and every directory named `ledger`, `accounts`,
`snapshots`, `rocksdb`, `chaindata`, `geth`, `nodes` or `data`, where chains
keep their databases, so a key kept in one of those is not found. It reads
files of up to 64 KiB, the last 1 MiB of a history and process environments
of up to 1 MiB, goes at most 48 directories deep, and stops after 200,000
entries or 20 seconds from the collector's start, counted between one entry
and the next. It opens files and directories without updating their access
times where the system allows it. Nothing is written on the server.

The search reports itself as partial when it ran out of time or entries,
met a deeper tree, a larger environment, a starting directory that is a
symbolic link, a validator whose identity file it cannot tell (Firedancer
among them), or a directory, file, environment or identity file this login
may not read. As an ordinary user it cannot read other users' processes, so
it is partial there. It reports no result when it could read none of its
starting directories, nor found anything. When it fails or stalls, it
reports what it had found so far as partial, or no result if that was
nothing: the child gets one second past its deadline to report, and the
rest of the report does not wait on it. A child still running five seconds
past its deadline is ended by an alarm, and one whose report cannot be
delivered exits at once; only a read the kernel will not interrupt (a hung
network filesystem) can keep it longer.

A Solana keypair counts as the validator identity when its 64 bytes are
those of the identity file a running `agave-validator` or
`solana-validator` was given (`--identity`), found from the command lines
and working directories of running processes. That file is read where the
validator reads it, through symbolic links and on any filesystem, only if
it is a regular file of 1 byte to 64 KiB, not on a kernel filesystem such
as `/proc` or `/sys`, and owned by the validator's user unless the
validator runs as root. Who can read a key is judged from the permission
bits and groups of the file and of the directories above it: everyone when
others may pass every directory and read the file, its group when the
group may read it and pass every directory, and otherwise its owner. That
is an approximation: an account that owns a directory above the file, and
access control lists, are not taken into account.

The key search's results stay on your screen. The report lists each group
of keys by kind, role, kind of place, who can read it and how many, with
up to ten of their paths, then "and N more". Paths are escaped so that a
file's name cannot drive the terminal, and the collector keeps all the
paths it sends to 6 KiB. Each group raises one local finding:
`plaintext_wallet_key` (other keypairs and hexadecimal keys),
`validator_identity_permissions` (the identity keypair, when others than
its owner can read it), `mnemonic_on_disk`, `unencrypted_keystore`,
`secret_in_env_file`, `secret_in_process_env` or `secret_in_shell_history`,
and `key_world_readable` when every account can read one. `--json` lists
those findings in `localFindings` and the groups' counts and classes under
`posture.keys`, without paths. None of it is sent to ERPC or counted in
the billed request. The collector reads contents into bounded buffers and
only classifications, counts and paths leave its child process; Python
cannot wipe memory, so what it read stays in that process until it exits,
right after reporting.

The inventory accepts up to 256 rentals and a 128 KiB reply. Quote and
rental verification replies are capped at 4 KiB each. An oversized reply
stops the check before SSH.

The pricing prompt shows the model, maximum reservation of 28,160 ERPC AI
tokens and rate for a completed report. The current rate is 512 tokens
plus 3 per model input token and 12 per model output token. The check
requires approval of a verified quote before opening SSH. The billed
request contains fixed posture classifications, the rental and request
IDs, and billing parameters. The CLI keeps detailed socket and file-mode
observations in the operator's report. It shows the settled charge,
reports when no tokens were charged, or flags an unconfirmed settlement.

For customer access, the quote also asks for consent to inspect the
selected rental and process the results. For each customer invocation,
ERPC sends Claude fixed finding IDs for ranking, the Anthropic customer
profile ID linked to the ERPC account, and a stable pseudonymous actor ID
for the same user across runs. Anthropic's standard retention policy
applies to the data it receives. ERPC separately keeps
the account, individual user, invocation time and outcome for at least
90 days for attribution and audit. The approval applies to that run only.
If the quote offers Claude Sonnet as a fallback, the same approval covers
that rate of 512 tokens plus 1 per input token and 3 per output token, up
to 9,472 tokens. ERPC may use it if the request could not be sent to the
primary model. The overall reservation remains at most 28,160 tokens.
A completed report identifies the single model used for billing.

## Wallet: `erpc wallet`

`erpc wallet create` sets up your one Base wallet. It uses the ERPC wallet
already in 1Password if there is one, on this machine or another, and makes a
new one only when there is none, so wallets do not multiply. A new wallet's
private key goes straight to 1Password and is never written to disk or shown. Fund the wallet with EURC,
and the assistant can buy ERPC Credit from it after you approve each
purchase (`--no-ai` keeps the assistant from asking). `--vault` takes the
vault's id or name. `erpc wallet show` shows the wallet's address.

