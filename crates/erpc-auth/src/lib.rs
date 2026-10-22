// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-auth`: ERPC account authentication (RFC 8628 device flow) and credential stores for the erpc CLI.
//!
//! Phase 0 placeholder. The public API is defined in the design document
//! (`docs/architecture.md`) and lands in later phases.

#![forbid(unsafe_code)]

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-auth";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
