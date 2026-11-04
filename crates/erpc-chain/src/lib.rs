// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-chain`: Chain and role abstractions for the multi-chain erpc CLI.
//!
//! [`inventory`] keeps the nodes an operator runs (validators, and the
//! primary and spare hosts that run each) in 1Password, for every chain.

#![forbid(unsafe_code)]

pub mod inventory;

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-chain";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
