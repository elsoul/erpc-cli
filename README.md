<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# erpc

`erpc` is the command line for [ERPC](https://erpc.global): multi-chain node
operations (Solana first, then Ethereum, Avalanche and Sui), your ERPC
account, the ERPC AI assistant and credits. It is the Rust successor of
[SLV](https://github.com/ValidatorsDAO/slv).

> Status: **Phase 0**. Only `erpc version` ships. See
> [`docs/architecture.md`](docs/architecture.md) for the roadmap.

## Install

```bash
curl --proto '=https' --tlsv1.2 -sSfL https://install.erpc.global | bash
```

```powershell
irm https://install.erpc.global/ps1 | iex
```

Or `cargo binstall erpc`, or download a release archive and verify it with
[`docs/verify-release.md`](docs/verify-release.md). Operators of mainnet
validators should follow the high-assurance path in that document.

## Design in one paragraph

Role-first commands with a chain context (`erpc v init --chain solana`),
one ERPC login (OAuth device flow), secrets only in 1Password or the OS
keychain, node operations executed on the node from a bundle embedded in the
binary, an AI assistant that can use the ERPC User MCP tools, wallets kept in
1Password for x402 credit top-ups, and signed, reproducible, attested releases.

## Repository layout

| Path | Purpose |
|---|---|
| `crates/erpc` | the binary |
| `crates/erpc-*` | library crates (core, auth, api, secret, ssh, ops, chain, chain-solana, ai, wallet, x402, skills, mcp-server, release) |
| `installer/` | Cloudflare Worker serving `install.erpc.global` |
| `scripts/` | hygiene and release helpers |
| `docs/` | architecture, verification, compliance index, public hosts |

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) and
[`GOVERNANCE.md`](GOVERNANCE.md). Only the public hosts in
[`docs/public-hosts.md`](docs/public-hosts.md) may appear in this repository.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
