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

First release through the release pipeline, as a prerelease.

### Added

- `erpc login`, `logout`, `whoami` and `doctor`: sign in to an ERPC account
  through the OAuth device authorization grant, keep the session in the
  1Password desktop app, a 1Password service account, the OS keychain or a
  file, and report where it is and why.
- `erpc-secret`: the key-use gate and the `op://` reference parser.
- `erpc-api`: the account lookup against `user-api`.

### Changed

- Release artifacts are published on GitHub Releases only; the planned
  download mirror was removed before it ever served a release.
- Prerelease tags run the full release workflow (gate, rebuild comparison,
  signature) and are published to crates.io as semver prereleases.
- `docs/verify-release.md`: verify signatures against a key saved once from
  `main`, not against `pubkey.txt` at the tag being checked.

### Fixed

- Endpoint gate: escape sequences, userinfo, quoted and slash-less forms no
  longer slip past it.
- `tokio` 1.53.3 (RUSTSEC-2026-0386).

## [0.0.1] - 2026-10-22

### Added

- Phase 0 foundation: Cargo workspace (`erpc` binary and 14 library crates),
  pinned toolchain, `cargo-deny` / `cargo-audit` policy, REUSE compliance,
  security policy, contribution and governance documents.
- `erpc version [--json]`.
- CI (fmt, clippy, tests on Linux/macOS/Windows, deny, audit, reuse, gitleaks,
  public-host check, zizmor, `dist plan`).
- cargo-dist release pipeline with GitHub Attestations, CycloneDX SBOM,
  `cargo-auditable`, release gate, independent rebuild comparison for Linux,
  minisign-signed release manifest and crates.io Trusted Publishing.
- `install.erpc.global` Cloudflare Worker serving the installers.

[Unreleased]: https://github.com/elsoul/erpc-cli/compare/v0.1.0-rc.1...HEAD
[0.1.0-rc.1]: https://github.com/elsoul/erpc-cli/releases/tag/v0.1.0-rc.1
[0.0.1]: https://github.com/elsoul/erpc-cli/releases/tag/v0.0.1
