<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

## Summary

<!-- What changes and why. Link the design section in docs/architecture.md if relevant. -->

## Checklist

- [ ] No secrets, tokens, `.env` files, 1Password vault/item identifiers, Cloudflare account identifiers or internal hostnames are included (see `docs/public-hosts.md`).
- [ ] Nothing in this PR belongs in ELSOUL LABO's private operations documentation instead of this public repository.
- [ ] New dependencies have been on crates.io for at least 14 days and `cargo deny check` passes.
- [ ] Every new file has an SPDX header or is covered by `REUSE.toml`.
- [ ] `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace` pass locally.
- [ ] Workflow changes keep actions pinned to full commit SHAs and `permissions: contents: read`.
- [ ] Commits are signed off (`git commit -s`).

## Test evidence

<!-- Commands run and their results. -->
