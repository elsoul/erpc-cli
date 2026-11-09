// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Network-qualified Nitro follower and Arbitrum assertion-validator contracts.

pub mod network;
pub mod release;
pub mod robinhood_validator;
pub mod validator;

/// Host-side deployment code carried with the reviewed CLI.
pub static TEMPLATES: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");
