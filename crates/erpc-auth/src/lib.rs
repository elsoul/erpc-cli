// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-auth`: signing in, and keeping the session somewhere sensible.
//!
//! Three things live here:
//!
//! * [`credential`] — what a session is and what it is filed under.
//! * [`store`] — the four places a session can be kept, and the rules for
//!   choosing between them.
//! * [`allowlist`] — which hosts a session token may be sent to.
//! * [`device_flow`] — the polling rules of the device authorization grant.
//!
//! What is here is the decision-making: which store to use, whether a
//! token may be attached to a request, and how the device-grant poll
//! behaves. Sending the HTTP requests is the caller's job, so that all of
//! the above is testable without a network and without a keychain.

#![forbid(unsafe_code)]

pub mod allowlist;
pub mod credential;
pub mod device_flow;
pub mod store;

pub use credential::{Audience, CredKey, Credential, check_token_shape};
pub use store::{CredentialStore, StoreError, StoreKind};

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-auth";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
