// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-api`: Typed client for the public ERPC user API used by the erpc CLI.
//!
//! Phase 0 placeholder. The public API lands in a later phase.

#![forbid(unsafe_code)]

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-api";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
