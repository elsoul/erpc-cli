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

## Check a local Solana RPC binding

The `node-check-pilot` Cargo feature is an opt-in for internal pilot builds.
Standard releases omit the local check. The pilot menu requires an approved
ERPC account.

Run `erpc ai --node-check` on a Linux node you administer, or enter
`/node-check` in the interactive `erpc ai` console on that node.
Select **Check Solana RPC binding on TCP 8899**. The menu starts on
**Cancel** and takes no host, port, or other arguments. A signed-in
ERPC account is required to complete the report.

The check reads Linux's IPv4 and IPv6 socket tables in the current network
namespace. It reports a wildcard or non-loopback binding for review,
loopback-only listeners, no observed listener, or an inconclusive result
if either table could not be read completely. The check sends the fixed
check name and one classification to ERPC for a report. Listener addresses
and raw socket data stay on the node. The console shows the report
without adding it to the chat session or saved conversation.

This is a snapshot of listeners on the conventional Solana RPC port,
TCP 8899. It does not identify the process, change the node, or probe
network reachability. If the RPC runs in another network namespace, run
the CLI in that namespace. Other ports and network namespaces are
outside the check's scope.

## Wallet: `erpc wallet`

`erpc wallet create` sets up your one Base wallet. It uses the ERPC wallet
already in 1Password if there is one, on this machine or another, and makes a
new one only when there is none, so wallets do not multiply. A new wallet's
private key goes straight to 1Password and is never written to disk or shown. Fund the wallet with EURC,
and the assistant can buy ERPC Credit from it after you approve each
purchase (`--no-ai` keeps the assistant from asking). `--vault` takes the
vault's id or name. `erpc wallet show` shows the wallet's address.

