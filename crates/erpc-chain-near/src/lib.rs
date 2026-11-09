// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Network-qualified NEAR deployment and dedicated consensus-key contracts.
#![forbid(unsafe_code)]
pub mod network;
pub mod staking;
pub mod validator;
/// Workspace component.
pub const CRATE_NAME: &str = "erpc-chain-near";

/// Reviewed deployment files bundled with the CLI.
pub static TEMPLATES: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");
