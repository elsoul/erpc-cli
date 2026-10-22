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
  Some files are not scanned at all. That list is not copied here, because a
  copy drifts: run `scripts/check-endpoints.sh --print-exceptions`.
- `erpc_core::endpoints::ensure_service_url` accepts a URL on any host
  declared in the code, of any kind: `https` or `wss` with no explicit
  port, or any of `http`, `https`, `ws` and `wss` with any port on loopback.
  - Every request URL `erpc` builds is a constant, and a test runs each one
    through it.
  - At runtime it is called before `erpc` opens a page in a browser. The only
    such page is the issuer's verification page, and `erpc-auth` has already
    required that to be an `https` URL on the issuer's own host, made of a
    narrow set of characters.
  - Where the access token and the refresh token may each be sent is
    narrower than this list, and is set out in `SECURITY.md`.
- `scripts/check-oss-hygiene.sh` additionally blocks cloud account
  identifiers, 1Password identifiers outside the `op://` reference format,
  bearer-token and key-shaped strings, references to the organisation's other
  repositories, and internal documents. Credential *values* are caught by
  `gitleaks` (`.gitleaks.toml`).

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
| `auth-api.erpc.global` | OAuth device flow: issue, refresh, revoke; its verification page is opened in the browser | the device code, and the refresh token to the token and revoke endpoints only; never the access token |
| `user-api.erpc.global` | ERPC account API | auth-api access token only |
| `mcp-user-api.erpc.global` | ERPC User MCP server, and the issuer of its own tokens | the device code, the MCP refresh token to the token and revoke endpoints, and the MCP access token; never the auth-api tokens |
| `x402.erpc.global` | x402 payments and credit top-up | x402 billing session token and payment headers only; never auth-api/MCP tokens, never ERPC API keys |
| `edge.erpc.global` | RPC endpoint, for the planned `check` command | RPC API key supplied by the operator |
| `dashboard.erpc.global` | opened in the browser for signup and payment setup | none |
| `erpc.global` | project home page, linked from package metadata | none |
| `solana-snapshot-*.erpc.global` | snapshot mirrors | none |
| `dl.erpc.global` | release mirror (R2) | none |
| `install.erpc.global` | installer script | none |
| `github.com`, `api.github.com` | releases, attestations | none |
| `objects.githubusercontent.com`, `release-assets.githubusercontent.com` | release artifact downloads | none |
| `crates.io`, `index.crates.io`, `static.crates.io` | dependencies (cargo, build time) | none |
| `registry.npmjs.org` | installer worker dependencies (npm, build time) | none |
| `sh.rustup.rs` | toolchain installation in CI | none |
| `127.0.0.1`, `localhost`, `[::1]` | planned OAuth redirect listener and local MCP server; plaintext `http`/`ws` allowed here only | session token for the local MCP server |

This version of `erpc` contacts `auth-api.erpc.global` and
`user-api.erpc.global`, and opens the verification page on
`auth-api.erpc.global` in a browser during `erpc login`. The other rows are
contacted by a later version, by the release pipeline, or at build time, as
their purpose says.

## Documentation links

`DOCUMENTATION_HOSTS` in the same module lists hosts that may be linked from
prose (`.md`, `.txt`, `NOTICE`, `CHANGELOG`, `AUTHORS`) and nowhere else.
`erpc` never contacts them, and the gate refuses them in code. They exist so
one rule can cover the whole repository instead of guessing whether a link is
an instruction a reader will run.

| Host | Linked from |
|---|---|
| `www.apache.org` | the licence text and headers |
| `www.contributor-covenant.org` | `CODE_OF_CONDUCT.md` |
| `keepachangelog.com` | `CHANGELOG.md` |
| `semver.org` | `CHANGELOG.md` |
| `elsoul.nl` | `NOTICE` |
| `axodotdev.github.io` | the cargo-dist configuration comment |
| `docs.github.com` | contributor documentation |
| `reuse.software` | licensing documentation |

This is a standing grant: once a host is here, a later change can turn a prose
link into an install command without the gate objecting. Keep the list short,
and treat an addition as a review question rather than a formality. The same
unit test that checks the table above also checks this one.
