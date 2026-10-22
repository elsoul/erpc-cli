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
  minisign-signed release manifest, R2 mirror and crates.io Trusted Publishing.
- `install.erpc.global` Cloudflare Worker serving the installers.

[Unreleased]: https://github.com/elsoul/erpc-cli/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/elsoul/erpc-cli/releases/tag/v0.0.1
