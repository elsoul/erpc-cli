// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin Core network, storage and authenticated-release contracts.
//!
//! The metadata client authenticates manifests with both carried public keys.
//! Deployment templates repeat authentication and hash the archive before use;
//! the host controller enforces persistent ownership and private RPC settings.

#![forbid(unsafe_code)]

pub mod download;
pub mod network;
pub mod release;
pub mod status;
pub mod storage;

/// Component name.
pub const CRATE_NAME: &str = "erpc-chain-bitcoin";

/// Carried deployment tasks, helper and release verification keys.
pub static TEMPLATES: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");
