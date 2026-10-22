<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Public hosts allowed in this repository

The machine-readable source of truth is `crates/erpc-core/src/endpoints.rs`.
This page explains it. The gates read the code, never this page. A unit test
fails if a host declared in the code is missing from this page, including the
documentation hosts below; the reverse direction is not checked, so treat the
code as authoritative if the two ever disagree.

- `scripts/check-endpoints.sh` applies **one rule**: every `http`, `https`,
  `ws` or `wss` URL in a tracked file must name a host declared in the code,
  and plaintext schemes are refused outside loopback. Hosts in
  `DOCUMENTATION_HOSTS` are accepted in prose files only. There is no
  heuristic about code blocks or command verbs; earlier versions had one and
  every review round found both a bypass and a false positive in it.
  A URL whose host is built from an expression is reported unless the literal
  text on both sides of the expression matches a declared `HOST_PATTERNS`
  pair, because an allowlisted prefix on its own says nothing about where the
  request goes. A host that is *entirely* an expression carries no literal to
  check and is skipped; nothing in this repository builds one.
  Some files are not scanned at all. That list is not copied here, because a
  copy drifts: run `scripts/check-endpoints.sh --print-exceptions`.
- `erpc_core::endpoints::ensure_service_url` is the runtime helper callers
  will use to check a destination. It has **no callers in this version**,
  which performs no network requests at all.
- `scripts/check-oss-hygiene.sh` additionally blocks cloud account
  identifiers, bare 1Password vault and item identifiers, bearer-token and
  key-shaped strings, references to the organisation's other repositories,
  and internal documents. Credential *values* are caught by `gitleaks`
  (`.gitleaks.toml`). Read the script for what each rule actually matches.

What this buys: ERPC endpoints are compile-time constants and are never read
from configuration or environment variables, so a tampered configuration
cannot redirect ERPC traffic, and a new destination cannot enter the source
unreviewed. What it does not buy: this is not an egress sandbox, and it does
not constrain what a malicious dependency does at runtime.

Node endpoints the operator names themselves, such as `erpc check rpc --url`,
are not on this list: they are the user's own targets and are validated for
scheme and shape only.

| Host | Purpose | Credentials that may be sent |
|---|---|---|
| `auth-api.erpc.global` | OAuth device flow: issue, refresh, revoke | none (public client `erpc-cli`) |
| `user-api.erpc.global` | ERPC account API | auth-api access token only |
| `mcp-user-api.erpc.global` | ERPC User MCP server | MCP access token only |
| `x402.erpc.global` | x402 payments and credit top-up | x402 billing session token and payment headers only; never auth-api/MCP tokens, never ERPC API keys |
| `edge.erpc.global` | RPC endpoint, for the planned `check` command | RPC API key supplied by the operator |
| `dashboard.erpc.global` | opened in the browser for signup and payment setup | none |
| `erpc.global` | project home page, linked from package metadata | none |
| `solana-snapshot-*.erpc.global` | snapshot mirrors | none |
| `install.erpc.global` | installer script | none |
| `github.com`, `api.github.com` | releases, attestations | none |
| `objects.githubusercontent.com`, `release-assets.githubusercontent.com` | release artifact downloads | none |
| `crates.io`, `index.crates.io`, `static.crates.io` | dependencies (cargo, build time) | none |
| `registry.npmjs.org` | installer worker dependencies (npm, build time) | none |
| `sh.rustup.rs` | toolchain installation in CI | none |
| `127.0.0.1`, `localhost`, `[::1]` | planned OAuth redirect listener and local MCP server; plaintext `http`/`ws` allowed here only | session token for the local MCP server |

Every row except the loopback one describes a destination a future version
will contact. This version contacts nothing.

## Documentation links

`DOCUMENTATION_HOSTS` in the same module lists hosts that may be linked from
prose (`.md`, `.txt`, `NOTICE`, `CHANGELOG`, `AUTHORS`) and nowhere else.
`erpc` never contacts them, and the gate refuses them in code. They exist so
one rule can cover the whole repository instead of guessing whether a link is
an instruction a reader will run.

| Host | Linked from |
|---|---|
| `www.contributor-covenant.org` | `CODE_OF_CONDUCT.md` |
| `keepachangelog.com` | `CHANGELOG.md` |
| `semver.org` | `CHANGELOG.md` |
| `elsoul.nl` | `NOTICE` |

Each row names a file that links the host today. Four hosts were removed from
this list: every URL for them sits in a file the gate never scans (the licence
texts, the generated third-party notices and the generated release workflow),
so the grant bought nothing. A grant is not kept "in case".

This is a standing grant: once a host is here, a later change can turn a prose
link into an install command without the gate objecting. Keep the list short,
and treat an addition as a review question rather than a formality. The same
unit test that checks the table above also checks this one.
