<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Public hosts allowed in this repository

Only the hosts below may appear in source, tests, docs or workflows.
`scripts/check-oss-hygiene.sh` enforces this list in pre-commit and CI.
Anything else under `erpc.global`, any cloud account identifier, any
1Password vault or item identifier outside the `op://` reference format, any
bearer-token-looking string, any key-shaped string, any reference into the
company's private repositories, and any internal document also fail the check.
Credential *values* are caught separately by `gitleaks` (`.gitleaks.toml`).

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
