<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The release gate refuses a tag
whose version has no entry below.

## [Unreleased]

## [0.1.0-rc.1] - 2026-11-02

First release through the release pipeline, as a prerelease: binaries for
five targets, the `install.erpc.global` installers, a GitHub Release with a
minisign-signed manifest, and the crates published by Trusted Publishing.
Apart from the entries below, the code is that of 0.0.1.

### Added

- The release signing key (minisign, key ID `A84D7BB71B974545`) in
  `crates/erpc-release/pubkey.txt`, replacing the placeholder.

### Fixed

- The `aarch64-unknown-linux-musl` release build links: the vendored libdbus
  is compiled without outline atomics (`.cargo/config.toml`).
- The rebuild comparison runs on the runner images cargo-dist builds on, with
  the same C compiler. In 0.0.1 it rebuilt on a different image with
  cargo-zigbuild. `docs/verify-release.md` states what the comparison does
  and does not show.
- `scripts/reserve-crates.sh` publishes in dependency order, paces new crates
  to the crates.io rate limit and refuses any version but 0.0.1.

## [0.0.1] - 2026-11-02

Published to crates.io by hand from commit `964b507` to reserve the crate
names. There is no GitHub Release, no binary and no signature for this
version.

### Added

- Cargo workspace (`erpc` binary and 14 library crates), pinned toolchain,
  `cargo-deny` / `cargo-audit` policy, REUSE compliance, security policy,
  contribution and governance documents.
- `erpc version [--json]`.
- `erpc login`, `logout`, `whoami` and `doctor`: sign in to an ERPC account
  through the OAuth device authorization grant, keep the session in the
  1Password desktop app, a 1Password service account, the OS keychain or a
  file, and report where it is and why.
- `erpc-secret`: the key-use gate and the `op://` reference parser.
- `erpc-api`: the account lookup against `user-api`.
- CI (fmt, clippy, tests on Linux/macOS/Windows, deny, audit, reuse, gitleaks,
  public-host check, endpoint allowlist, zizmor, `dist plan`).
- cargo-dist release pipeline with GitHub Attestations, CycloneDX SBOM,
  `cargo-auditable`, release gate, independent rebuild comparison for Linux,
  minisign-signed release manifest and crates.io Trusted Publishing. Release
  artifacts are published on GitHub Releases only. Prerelease tags run the
  full release workflow and are published to crates.io as semver
  prereleases.
- `install.erpc.global` Cloudflare Worker serving the installers.
- `docs/verify-release.md`: verify signatures against a key saved once from
  `main`, not against `pubkey.txt` at the tag being checked.

[Unreleased]: https://github.com/elsoul/erpc-cli/compare/v0.1.0-rc.1...HEAD
[0.1.0-rc.1]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.1
[0.0.1]: https://github.com/elsoul/erpc-cli/tree/964b507d0276254aeec4451cfbdecc8effd83724
