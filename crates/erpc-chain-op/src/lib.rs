// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Qualified follower lifecycle programs. No sequencer or validator signing.
#![forbid(unsafe_code)]

pub mod access;
pub mod network;
pub mod release;
pub mod snapshot;

/// Embedded host programs and configuration templates.
pub static TEMPLATES: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");

/// Component identifier.
pub const CRATE_NAME: &str = "erpc-chain-op";
