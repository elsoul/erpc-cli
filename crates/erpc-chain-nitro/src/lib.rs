// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Network-qualified Nitro follower contracts; no wallet or sequencer ownership.

pub mod network;
pub mod release;

/// Host-side deployment code carried with the reviewed CLI.
pub static TEMPLATES: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");
