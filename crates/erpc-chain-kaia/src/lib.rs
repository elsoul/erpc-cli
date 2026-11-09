// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Source-qualified Kaia endpoint nodes. EN ownership never implies CN admission.

pub mod corecell;
pub mod custody;
pub mod network;
pub mod release;
pub use network::Network;

/// Exact reviewed source, OCI and bootstrap metadata.
pub const CATALOG_BYTES: &[u8] = include_bytes!("../templates/node/catalog.json");
static CATALOG: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
    serde_json::from_slice(CATALOG_BYTES)
        .unwrap_or_else(|_| panic!("invalid compiled Kaia catalog"))
});

/// Reviewed host programs embedded in the CLI.
pub static TEMPLATES: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");
