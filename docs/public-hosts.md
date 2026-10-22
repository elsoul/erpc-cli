<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Public hosts allowed in this repository

The machine-readable source of truth is `crates/erpc-core/src/endpoints.rs`.
This page explains it; the code is what the gates read, so the two cannot
drift. Three checks share it:

- `scripts/check-endpoints.sh` refuses any URL in the tree whose host is not
  declared there, in pre-commit and in CI.
- `erpc_core::endpoints::ensure_service_url` refuses the same at runtime, so a
  compromised dependency or a tampered configuration cannot redirect ERPC
  traffic. Endpoints are never read from configuration or environment.
- `scripts/check-oss-hygiene.sh` additionally blocks cloud account
  identifiers, 1Password identifiers outside the `op://` reference format,
  bearer-token and key-shaped strings, references into the company's private
  repositories, and internal documents. Credential *values* are caught by
  `gitleaks` (`.gitleaks.toml`).

Node endpoints the operator names themselves, such as `erpc check rpc --url`,
are not on this list: they are the user's own targets and are validated for
scheme and shape only.

| Host | Purpose | Credentials that may be sent |
|---|---|---|
| `auth-api.erpc.global` | OAuth device flow: issue, refresh, revoke | none (public client `erpc-cli`) |
| `user-api.erpc.global` | ERPC account API | auth-api access token only |
| `mcp-user-api.erpc.global` | ERPC User MCP server | MCP access token only |
| `x402.erpc.global` | x402 payments and credit top-up | x402 billing session token and payment headers only; never auth-api/MCP tokens, never ERPC API keys |
| `dashboard.erpc.global` | opened in the browser for signup and payment setup | none |
| `edge.erpc.global` | RPC endpoint used by `erpc check` | RPC API key supplied by the operator |
| `solana-snapshot-*.erpc.global` | snapshot mirrors | none |
| `dl.erpc.global` | release mirror (R2) | none |
| `install.erpc.global` | installer script | none |
| `github.com`, `api.github.com`, `objects.githubusercontent.com` | releases, attestations | none |
| `crates.io`, `static.crates.io`, `index.crates.io` | dependencies | none |
