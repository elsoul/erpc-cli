// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-wallet`: 1Password backed wallets and spending policies for the erpc CLI.
//!
//! [`evm`] holds an EVM key in memory and signs with it; [`eurc`] is the one
//! thing erpc signs with it so far: an EIP-3009 transfer of EURC on Base to
//! ERPC's treasury, buying ERPC Credit.

#![forbid(unsafe_code)]

pub mod eurc;
pub mod evm;

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-wallet";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
