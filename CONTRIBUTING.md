<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Contributing to erpc-cli

Thank you for your interest. This document covers the rules that keep the
project secure and releasable. For how the code is organised, read the crates
under `crates/` and the discussion on the pull request you are working from.

## Ground rules

1. **No secrets, ever.** Never commit tokens, private keys or mnemonics of any
   chain, `.env` files, 1Password vault or item identifiers, cloud account
   identifiers, or internal hostnames. Every URL must name a host declared in
   `crates/erpc-core/src/endpoints.rs`, which `docs/public-hosts.md`
   explains. Install the hooks with
   `lefthook install`: `gitleaks` scans for credential values and
   `scripts/check-oss-hygiene.sh` blocks non-public hosts, infrastructure
   identifiers, key-shaped strings and internal documents. CI runs both again,
   plus the gate's own self-test. Never commit with `--no-verify`; if a rule
   is wrong, change the rule in the same commit and say why.
   If something slipped through, follow `docs/secret-exposure-response.md`
   and rotate the credential before touching the history.
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
5. **Documents.** This repository carries what a user or contributor needs:
   README, policies, release verification, the compliance index and the
   public-host list. Design documents, internal assessments and operational
   records stay in ELSOUL LABO B.V.'s private documentation, so that a
   revision of them cannot leak internal context here. The hygiene gate
   refuses such documents by filename; if you have a genuine need for one,
   raise it rather than renaming the file.
6. **Toolchain.** `rust-toolchain.toml` pins the compiler. `cargo fmt`,
   `cargo clippy --all-targets -- -D warnings` and `cargo test --workspace`
   must pass on Linux, macOS and Windows.
7. **Workflows.** GitHub Actions are pinned to full commit SHAs, run with
   `permissions: contents: read` by default, and never use
   `pull_request_target` or `workflow_run`.
8. **Outbound destinations.** One rule:
   `scripts/check-endpoints.sh` fails any URL whose host is not declared in
   `crates/erpc-core/src/endpoints.rs`. Destinations `erpc` contacts go in the
   host lists; a link that only appears in documentation goes in
   `DOCUMENTATION_HOSTS`, which is refused in code. Plaintext `http`/`ws` is
   refused outside loopback. For the files the gate does not scan, run
   `scripts/check-endpoints.sh --print-exceptions`, and read the script's
   header for its stated limits rather than a summary.
   Because ERPC endpoints are compile-time constants and are never read from
   configuration or environment variables, a tampered config cannot redirect
   traffic. This is a source gate, not a sandbox: it does not constrain what a
   malicious dependency does at runtime, and it cannot see a host assembled
   from fragments. Every request URL `erpc` builds is a constant on a
   declared host, with a test that runs it through `ensure_service_url`. A
   URL received at runtime, such as the verification page the issuer names,
   is checked where it arrives, before it is printed, written to JSON or
   opened.
9. **Gates must be tested.** Any check that can block a commit needs a case in
   `scripts/tests/` proving it blocks a known-bad sample and passes a
   known-good one. A gate that silently stops matching is worse than none.

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
- **Maintainers run this repository's review gate on every pull request
  before merging it**, whatever its size, with `/review`. It judges
  correctness, security, supply chain and whether the change is safe to
  publish, and returns PASS or FAIL. A FAIL is fixed and the gate re-run; it
  is not argued past, and green CI does not substitute for it. The gate's
  criteria are the rules above, written out in the agent definition. This is
  a maintainer practice: the branch ruleset on `main` requires a pull request
  and the CI checks, but it cannot require the gate's verdict.
- Releases are cut by maintainers from tags `v*` through the reviewed
  `release.yml` workflow and a protected `release` environment. Contributors
  do not publish.

## Reporting security issues

See `SECURITY.md`. Do not open public issues for vulnerabilities.
