<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Errors and exit codes

Every erpc command reports a failure the same way: one **code** a script can
branch on, one **exit status**, a **message** a person can read, and, when
there is one, a **hint** saying what to do next. The code lives in
`crates/erpc/src/error.rs`; `finish` in `main.rs` is the only place a failure
is printed.

## What it looks like

At a terminal, on standard error, the message comes after a mark that says
what kind it is, with the hint under it:

```text
👋 nothing was changed: you said no
```

```text
🔐 the session has expired or was signed out elsewhere
   💡 run `erpc login`
```

| Code | Mark |
|---|---|
| `failed` | ❌, or a command's own (🔑 for "set already", 🔎 for an app erpc does not know) |
| `usage` | 🤔 |
| `problems_found` | 🩺 (on a check's report, which is not an error) |
| `needs_terminal` | ⌨️ |
| `not_signed_in` | 🔐 |
| `declined` | 👋 |
| `network` | 🌐 |

Anywhere else (a pipe, a file, a log), the same failure is plain lines:

```text
error: the session has expired or was signed out elsewhere
hint: run `erpc login`
```

A result that is a state rather than a failure is not an error at all:
`erpc worker key new` on an app that has a wallet already says so and exits 0
(`"already": true` in JSON; a key made or imported says `"already": false`).

With `--json` (or `ERPC_JSON=true`), on standard output, so a script reads one
stream:

```json
{
  "error": {
    "code": "not_signed_in",
    "exit": 4,
    "message": "the session has expired or was signed out elsewhere",
    "hint": "run `erpc login`"
  }
}
```

`hint` is left out when there is none. `details` is there only when a
command has more to say to a script about what it did before it failed: an
object whose fields are the command's own (`erpc worker delete`'s says what
was ended, dropped and forgotten, and what stays on record). It never
appears at a terminal. A command line clap cannot parse is
reported the same way under `--json` (`usage`). Two cases print clap's own
message and exit 2 instead: any such command line at a terminal, and an
argument the verb of a node tree (`erpc validator`, `rpc`, `node`) does not
take, even under `--json`.

## Codes

| Code | Exit | When |
|---|---|---|
| `failed` | 1 | The command could not do what was asked. The message says why. |
| `usage` | 2 | The command line was not usable as given. |
| `needs_terminal` | 3 | A person has to answer, and no one is at a terminal. |
| `not_signed_in` | 4 | There is no usable ERPC session. |
| `problems_found` | 5 | A check ran and found problems: `status` of a node, `erpc doctor` with a warning. Its report is the output, not an error. |
| `declined` | 6 | A person was asked and said no. Nothing was changed. |
| `network` | 7 | ERPC, or another service, could not be reached. |

0 is success. Stopped by Ctrl-C (or SIGTERM, SIGHUP), erpc ends by the signal
itself, as a shell expects, so a loop in a script stops too.

A published code keeps its name and its exit status. A new kind of failure
gets a new code at the end of the table; a code is never reused.

## Writing a message

The message is for the person who ran the command, who may not know how
erpc works inside.

1. **Say what failed, in their words.** "could not reach the node at
   203.0.113.10", not "SshError::Io". Lowercase, no full stop at the end:
   it follows `error: `.
2. **Then why, if it is known.** Join it with a colon or a semicolon:
   "the vote account exists already; nothing was changed".
3. **Say what was left as it was.** After a failure that might have changed
   something, say whether it did: "nothing was changed", "the previous
   release is still running", "it is put back by itself within 120 s".
4. **The next step goes in the hint**, as the exact command where there is
   one: `run \`erpc login\``, `pass --yes to go ahead without being asked`.
   The codes `usage`, `needs_terminal`, `not_signed_in` and `network` have a
   standard hint, shown when the message does not already say it.
5. **Never a secret.** No password, key, token or seed phrase, not even part
   of one. A value that might be one is not echoed back.
6. **No internals.** No stack traces, no Rust type names, no debug dumps. A
   value the person gave is quoted (`"tokio" is not a region`) so that what
   it contains cannot be mistaken for the message.
7. **One failure, one message.** A command that printed a report of its
   problems (`status`) does not print an error after it.

## In the code

- A command returns an `Outcome`. `Outcome::Failed`, `Usage`,
  `NeedsTerminal` and `NoSession` carry a message and map to `failed`,
  `usage`, `needs_terminal` and `not_signed_in`. `Outcome::Problems` carries a
  report (`problems_found`). `Outcome::Error(CliError)` carries any code, and
  a hint.
- `CliError::from(String)` is `failed`, so `?` keeps working in code that
  says why with a `String`; code that needs another code returns a
  `CliError` (`node_common::go_ahead` returns `declined` or
  `needs_terminal`).
- `error::classify` gives `network` to an error whose cause is a request that
  never reached the server, and `failed` to anything else.
- A command never prints its own error JSON: it returns the failure, and
  `finish` prints it.
