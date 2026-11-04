// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Chain-specific follower profiles and carried host programs.
#![forbid(unsafe_code)]

pub mod profile;
pub mod upstreams;

/// Crate name reported by component discovery.
pub const CRATE_NAME: &str = "erpc-chain-rollup";

/// Host programs and templates shipped with this binary.
pub static TEMPLATES: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");

/// Credential-isolating L1 proxy, shared by followers that consume Ethereum L1.
pub const UPSTREAM_PROXY: &str = include_str!("../templates/scripts/upstreams.py");
