// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-worker`: what `erpc worker` knows about an app before it touches a
//! server.
//!
//! [`manifest`] is `erpc.toml`, the file at an app's root that says how it
//! is built and run and where each of its environments is deployed. It
//! holds references to secrets, never their values, so it can be committed.
//! [`index`] is `~/.erpc/workers.toml`, the list of app directories on this
//! machine that `erpc worker list` reads. [`template`] holds the app
//! templates `erpc worker init` makes an app from, compiled in. [`release`]
//! is one build for the servers, and [`server`] what erpc and the agent on
//! a server agree on: its layout, its unit, and the agent's protocol.
//! [`waf`] is the config and the stats of the HTTP proxy a worker's app can
//! be put behind.

#![forbid(unsafe_code)]

pub mod bench;
pub mod edit;
pub mod index;
pub mod inventory;
pub mod manifest;
pub mod net;
pub mod release;
pub mod server;
#[cfg(feature = "templates")]
pub mod template;
pub mod waf;

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-worker";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
