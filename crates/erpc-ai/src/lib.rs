// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-ai`: AI assistant console and tool loop for the erpc CLI.
//!
//! [`session`] is the conversation every front end drives.

#![forbid(unsafe_code)]

pub mod actions;
mod ask;
pub mod commands;
pub mod compact;
pub mod confirm;
pub mod dashboard;
mod i18n;
pub mod memory;
pub mod next;
pub mod policy;
pub mod prompt;
pub mod ready;
pub mod servers;
mod services;
pub mod session;
pub mod tools;

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-ai";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
