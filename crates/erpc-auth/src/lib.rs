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
//! * [`http`] — the requests themselves, and the one client that sends them.
//! * [`session`] — signing in, keeping a session current, signing out.
//! * [`lock`] — the exclusive lock a refresh runs under.
//!
//! The decision-making and the network are deliberately separate: every
//! rule about which store to use, whether a token may be attached, and how
//! the poll behaves is testable without a server and without a keychain,
//! and [`http`] is the only module that opens a connection.

#![forbid(unsafe_code)]

pub mod allowlist;
pub mod credential;
pub mod device_flow;
pub mod http;
pub mod lock;
pub mod session;
pub mod store;

pub use credential::{Audience, CredKey, Credential, check_token_shape};
pub use http::{AuthClient, HttpError};
pub use session::{SessionError, current_session, run_device_grant, sign_out};
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
