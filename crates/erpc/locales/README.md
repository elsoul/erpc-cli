<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# erpc's words, in every language it speaks

erpc speaks English (`en`), Japanese (`ja`), Simplified Chinese (`zh`) and
Russian (`ru`). Each language is a directory here, and each file in it is
one area of the CLI: `worker_deploy.toml` holds what `erpc worker deploy`
says. The files are embedded in the binary at build time.

## Which language a run speaks

First match wins:

1. `--lang <code>` on the command line
2. `ERPC_LANG`
3. `erpc config set locale <code>` (`~/.erpc/config.toml`)
4. the system locale: `LANGUAGE`, then `LC_ALL`, `LC_MESSAGES`, `LANG`
   (`C` and `POSIX` mean English)
5. on macOS, the language chosen in System Settings
6. English

`--json` output, `warning:` / `hint:` / `Next:` marks off a terminal, and
anything written to a server or a file are the same in every language:
scripts read them.

## Messages

A key is the file's stem and the key inside it: `done` under `[deploy]` in
`worker.toml` is `worker.deploy.done`, said in code as

```rust
t!("worker.deploy.done", name, host = server.ip)
```

`{name}` is a placeholder (`{{` and `}}` for literal braces). A message
that depends on a count is a table of plural forms, chosen by `tn!`, which
also fills `{n}`:

```toml
# en
[servers]
one = "one server"
other = "{n} servers"

# ru
[servers]
one = "{n} сервер"
few = "{n} сервера"
many = "{n} серверов"
```

Japanese and Chinese have only `other`.

## Help

`cli_<command>.toml` translates `erpc <command> --help`. Keys are command
paths: `"worker deploy"` is the command's summary, `"worker deploy @long"`
its long description, `"worker deploy --env"` and `"worker deploy <name>"`
its arguments. The English file holds the doc comments exactly as clap
reads them; a test fails when a doc comment changes and the catalog does
not, so the translations are updated with it. Start a new command's file
from

```sh
ERPC_HELP_DUMP=worker cargo test -p erpc dump_help -- --ignored --nocapture
```

and add the command to `TRANSLATED` in `src/i18n.rs`.

## Rules the tests hold

- Every language has every English key, no more.
- A translation uses exactly the placeholders English does.
- A plural message gives the forms its language needs (`ru`: one, few,
  many).
- Every `t!`/`tn!` key in the source is in `en/`, and every key in `en/`
  is used.

## Adding a language

1. Add a variant to `Lang` in `crates/erpc-core/src/i18n.rs`, with its
   code, its own name, its plural rule and `ALL`.
2. Copy `en/` to `<code>/` here (and in `crates/erpc-ai/locales/`) and
   translate every file.
3. `cargo test -p erpc-core -p erpc -p erpc-ai` until it passes.

Which language comes next is read from where `erpc install` is downloaded.

Terms are fixed per language in [GLOSSARY.md](GLOSSARY.md).

## Translating

- Keep command names, flags, `erpc.toml` keys, file paths, product names
  (ERPC, VPS, 1Password) and anything in backticks as they are.
- Japanese: plain, polite-neutral CLI style (`デプロイしました`, `見つかりません`),
  full-width punctuation, a half-width space around Latin words is not
  needed.
- Chinese: Simplified, mainland technical usage (服务器, 部署, 密钥), full-width
  punctuation.
- Russian: neutral imperative for instructions (`Запустите`), `ё` written,
  «ёлочки» only in prose.
