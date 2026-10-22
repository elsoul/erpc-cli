<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Contributing to erpc-cli

Thank you for your interest. This document covers the rules that keep the
project secure and releasable; the architecture is in `docs/architecture.md`.

## Ground rules

1. **No secrets, ever.** Never commit tokens, keys, `.env` files, 1Password
   vault or item identifiers, Cloudflare account identifiers, or internal
   hostnames. Only the public endpoints listed in `docs/public-hosts.md` may
   appear in code or docs. `lefthook` runs `gitleaks` and
   `scripts/check-public-hosts.sh` before every commit; CI runs them again.
2. **Secret types.** Secret material is held only in `secrecy::SecretBox` /
   `SecretString`. Never derive `Debug` output that prints it, never log it,
   never put it in an error message.
3. **Dependencies.** A new crate must be published on crates.io for at least
   14 days before it enters `Cargo.lock`. `cargo deny check` must pass
   (license allowlist, no git or unknown-registry sources, no yanked crates).
   Advisory ignores need a dated reason in `deny.toml` and `.cargo/audit.toml`.
4. **Licensing.** Every file carries an SPDX header or is covered by
   `REUSE.toml`. `reuse lint` must pass. Contributions are accepted under
   Apache-2.0 with a Developer Certificate of Origin sign-off:
   `git commit -s`.
5. **Toolchain.** `rust-toolchain.toml` pins the compiler. `cargo fmt`,
   `cargo clippy --all-targets -- -D warnings` and `cargo test --workspace`
   must pass on Linux, macOS and Windows.
6. **Workflows.** GitHub Actions are pinned to full commit SHAs, run with
   `permissions: contents: read` by default, and never use
   `pull_request_target` or `workflow_run`.

## Development setup

```bash
git clone https://github.com/elsoul/erpc-cli
cd erpc-cli
cargo build
cargo test --workspace
```

Optional local tools: `cargo install cargo-deny cargo-dist`,
`cargo install cargo-about --features cli`, `pipx install reuse`,
`brew install lefthook gitleaks` (or the equivalents for your platform), then
`lefthook install`.

## Pull requests

- Branch from `main`; one topic per PR.
- Fill in the PR template checklist. The "no internal identifiers" items are
  mandatory.
- Releases are cut by maintainers from tags `v*` through the reviewed
  `release.yml` workflow and a protected `release` environment. Contributors
  do not publish.

## Reporting security issues

See `SECURITY.md`. Do not open public issues for vulnerabilities.
