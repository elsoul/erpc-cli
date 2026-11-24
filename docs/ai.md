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

## Local Solana RPC binding check (pilot builds)

Standard releases omit this check. Anyone can compile the local menu and
check by enabling the `node-check-pilot` Cargo feature. Completing a report
requires signing in. The server controls which deployments enable reports
and which accounts can receive them.

With the feature enabled, run `erpc ai --node-check` on a Linux node you
administer, or enter `/node-check` in the interactive `erpc ai` console there.
Select **Check Solana RPC binding on TCP 8899**. The menu starts on **Cancel**
and takes no host, port, or other arguments. In all builds, input whose first word is
`/node-check` stays local, including with `--message` or piped input.

The check reads Linux's IPv4 and IPv6 socket tables in the current network
namespace. It reports a wildcard or non-loopback binding for review,
loopback-only listeners, no observed listener, or an inconclusive result.
A missing table, such as on Linux with IPv6 disabled, an unreadable or
truncated table, or either table exceeding 8 MiB makes the result
inconclusive even when the other table shows a listener. The size limit
counts every row, including established connections.

Only the fixed check name and one classification go to ERPC for the report.
Listener addresses and raw socket data stay on the node. The console shows
the report without adding it to the chat session or saved conversation.

This is a snapshot of listeners on the conventional Solana RPC port,
TCP 8899. It does not identify the process, change the node, or probe
network reachability. If the RPC runs in another network namespace, run
the CLI in that namespace. Other ports and network namespaces are
outside the check's scope.

## Server security check (pilot builds)

Standard releases omit this check. Anyone can compile it by enabling the
`security-check-pilot` Cargo feature. Completing a check requires signing
in, and the server decides which accounts and servers can be checked.

With the feature enabled, run `erpc ai --security-check` on a Linux server
you rent from ERPC. The menu lists the account's servers; pick the one the
command runs on, and confirm that you own it or are authorized to test it
and will not resell the check. The menu takes no host, address or other
arguments, and it starts on **Cancel**. In all builds, input whose first
word is `/security-check` stays local, including with `--message` or piped
input.

The check has two parts. ERPC scans the picked server's ports from outside.
On the server itself, `erpc` reads, without changing anything or starting
any program:

- the listening TCP sockets and bound UDP sockets of the current network
  namespace, on every port, and the program that holds each one;
- the RPC settings on a Solana validator's command line;
- the SSH server's settings in `sshd_config` and the files it includes;
- the host firewall's configuration (ufw, firewalld, nftables), not the
  rules the kernel holds now;
- the operating system's release, the kernel's release, and the versions of
  a fixed list of installed Debian packages.

What goes to ERPC is that list in a fixed form: port numbers, address
classes such as loopback or public, program kinds such as `agave_validator`,
settings such as whether SSH accepts passwords, and version numbers.
Addresses, paths, command lines and file contents stay on the server. Run
it as root to read every process; otherwise the report says that part of
the server could not be read.

The report names each finding from a catalog built into `erpc`, with what
to do about it, and adds the details from this server on your screen. It
covers the ports ERPC's scanners can reach and what could be read at that
moment.

## Wallet: `erpc wallet`

`erpc wallet create` sets up your one Base wallet. It uses the ERPC wallet
already in 1Password if there is one, on this machine or another, and makes a
new one only when there is none, so wallets do not multiply. A new wallet's
private key goes straight to 1Password and is never written to disk or shown. Fund the wallet with EURC,
and the assistant can buy ERPC Credit from it after you approve each
purchase (`--no-ai` keeps the assistant from asking). `--vault` takes the
vault's id or name. `erpc wallet show` shows the wallet's address.

