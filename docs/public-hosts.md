<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Public hosts allowed in this repository

The machine-readable source of truth is `crates/erpc-core/src/endpoints.rs`.
This page explains it. The gates read the code, not this page, and a unit test
asserts that every host in the code appears below, so the two cannot drift.

- `scripts/check-endpoints.sh` fails any URL in a tracked text file whose host
  is not declared in the code, in pre-commit and in CI. Prose files (`.md`,
  `.txt`, `NOTICE`, `CHANGELOG`) are the exception, since a documentation link
  cannot make the program connect anywhere; a prose line carrying a download
  or execute command is still held to the list.
- `erpc_core::endpoints::ensure_service_url` is the runtime helper callers
  will use to check a destination. It has **no callers in this version**,
  which performs no network requests at all.
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
| `auth-api.erpc.global` | OAuth device flow: issue, refresh, revoke | none (public client `erpc-cli`) |
| `user-api.erpc.global` | ERPC account API | auth-api access token only |
| `mcp-user-api.erpc.global` | ERPC User MCP server | MCP access token only |
| `x402.erpc.global` | x402 payments and credit top-up | x402 billing session token and payment headers only; never auth-api/MCP tokens, never ERPC API keys |
| `edge.erpc.global` | RPC endpoint used by `erpc check` | RPC API key supplied by the operator |
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
| `127.0.0.1`, `localhost`, `[::1]` | OAuth redirect listener and `erpc mcp serve --http`; plaintext `http`/`ws` allowed here only | session token for the local MCP server |
