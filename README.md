<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# erpc

`erpc` is the command line for [ERPC](https://erpc.global): multi-chain node
operations (Solana first, then Ethereum, Avalanche and Sui), your ERPC
account, the ERPC AI assistant and credits. It is the Rust successor of
[SLV](https://github.com/ValidatorsDAO/slv).

> Status: **Phase 1, in progress**. `erpc version`, `login`, `logout`,
> `whoami` and `doctor` ship. The remaining commands are under development;
> what exists in this repository is what works today.

## Install

**There is no release yet.** No version has been published, the download
host and the installer are not serving, and the package names are not
registered. Install instructions will appear here with the first release;
until then, build from source:

```bash
git clone https://github.com/elsoul/erpc-cli
cd erpc-cli
cargo build --release
```

When releases begin, every artifact will carry a signed manifest, a software
bill of materials and build provenance. The procedure for checking them is
already written down in
[`docs/verify-release.md`](docs/verify-release.md), so it can be reviewed
before it is relied on.

## Repository layout

| Path | Purpose |
|---|---|
| `crates/erpc` | the binary |
| `crates/erpc-*` | library crates (core, auth, api, secret, ssh, ops, chain, chain-solana, ai, wallet, x402, skills, mcp-server, release) |
| `installer/` | Cloudflare Worker serving `install.erpc.global` |
| `scripts/` | hygiene and release helpers |
| `docs/` | release verification, compliance index, public hosts, incident response |

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) and
[`GOVERNANCE.md`](GOVERNANCE.md). Every URL in this repository must name a
host declared in `crates/erpc-core/src/endpoints.rs`, which
[`docs/public-hosts.md`](docs/public-hosts.md) explains;
`lefthook install` wires the pre-commit gates that check it, alongside a
secret scan. Those gates are a mechanical aid, not the whole rule: review is.
If a secret ever lands here, follow
[`docs/secret-exposure-response.md`](docs/secret-exposure-response.md) and
rotate it before rewriting any history.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
