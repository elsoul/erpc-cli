<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# erpc

`erpc` is the command line for [ERPC](https://erpc.global): multi-chain node
operations (Solana first, then Ethereum, Avalanche and Sui), your ERPC
account, the ERPC AI assistant and credits. It is the Rust successor of
[SLV](https://github.com/ValidatorsDAO/slv).

> Status: **Phase 0**. Only `erpc version` ships. The remaining commands are
> under development; what exists in this repository is what works today.

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

## Repository layout

| Path | Purpose |
|---|---|
| `crates/erpc` | the binary |
| `crates/erpc-*` | library crates (core, auth, api, secret, ssh, ops, chain, chain-solana, ai, wallet, x402, skills, mcp-server, release) |
| `installer/` | Cloudflare Worker serving `install.erpc.global` |
| `scripts/` | hygiene and release helpers |
| `docs/` | release verification, compliance index, public hosts |

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) and
[`GOVERNANCE.md`](GOVERNANCE.md). Only the public hosts in
[`docs/public-hosts.md`](docs/public-hosts.md) may appear in this repository.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
