// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-secret`: who may resolve a secret, and how a secret is named.
//!
//! Two things live here, and they are deliberately the only two:
//!
//! * [`gate`] decides whether a request for a secret is in scope, from the
//!   profile of the key and the facts about the process asking. It is the
//!   interface the design freezes, so that the validator-key work and the
//!   agent-wallet work stay two profiles of one mechanism rather than two
//!   mechanisms that drift apart.
//! * [`op_ref`] is the only reference form accepted for a secret, by
//!   identifier rather than by name.
//!
//! This crate decides and names; it does not read a secret, and no secret
//! value passes through it.
//!
//! What it does provide is that a caller which asks the gate first cannot
//! reach a key the table does not allow, and that a reference by name is
//! refused before it can resolve to something other than what was meant.

#![forbid(unsafe_code)]

pub mod gate;
pub mod op_ref;

pub use gate::{Confirmation, Context, Decision, Denial, Network, Operation, Profile, evaluate};
pub use op_ref::{OpRef, OpRefError};

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-secret";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_matches_package() {
        assert_eq!(super::CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
