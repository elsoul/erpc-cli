// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Qualified Hyperliquid supervisor identity. Child updates remain vendor managed.
pub mod aqa;
pub mod contract;
pub mod validator;

use include_dir::{Dir, include_dir};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::LazyLock;
/// Root-owned operational helpers carried to the host.
pub static TEMPLATES: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");
/// Read one immutable deployment resource.
#[must_use]
pub fn file(path: &str) -> Option<&'static [u8]> {
    TEMPLATES.get_file(path).map(include_dir::File::contents)
}
/// Enumerate every deployment resource in stable bundle order.
#[must_use]
pub fn files() -> Vec<&'static str> {
    fn walk(dir: &'static Dir<'static>, out: &mut Vec<&'static str>) {
        for file in dir.files() {
            if let Some(path) = file.path().to_str() {
                out.push(path);
            }
        }
        for child in dir.dirs() {
            walk(child, out);
        }
    }
    let mut out = Vec::new();
    walk(&TEMPLATES, &mut out);
    out.sort_unstable();
    out
}
static CATALOG: LazyLock<Result<Value, serde_json::Error>> =
    LazyLock::new(|| serde_json::from_slice(include_bytes!("../templates/node/catalog.json")));
/// Hyperliquid's independent mainnet and testnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Hyperliquid mainnet, `HyperEVM` 999.
    Mainnet,
    /// Hyperliquid testnet, `HyperEVM` 998.
    Testnet,
}
impl Network {
    /// Parse only the supported CLI selectors.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mainnet" => Some(Self::Mainnet),
            "testnet" => Some(Self::Testnet),
            _ => None,
        }
    }
    /// Canonical inventory scope.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
    /// Pin the supervisor, not a fictitious immutable child release.
    /// # Errors
    /// Refuses an invalid embedded qualification catalog.
    pub fn profile(self) -> Result<&'static Value, &'static str> {
        Ok(&Self::catalog()?["networks"][self.name()])
    }
    /// Shared public qualification metadata.
    /// # Errors
    /// Refuses an invalid embedded qualification catalog.
    pub fn catalog() -> Result<&'static Value, &'static str> {
        CATALOG
            .as_ref()
            .map_err(|_| "invalid embedded supervisor catalog")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supervisor_pins_are_network_specific_without_claiming_child_source_identity() {
        assert!(Network::parse("sepolia").is_none());
        assert_ne!(
            Network::Mainnet.profile().expect("compiled profile")["supervisor"]["sha256"],
            Network::Testnet.profile().expect("compiled profile")["supervisor"]["sha256"]
        );
        assert_eq!(
            Network::Mainnet.profile().expect("compiled profile")["chain_id"],
            999
        );
        assert_eq!(
            Network::Testnet.profile().expect("compiled profile")["chain_id"],
            998
        );
        assert!(Network::catalog().expect("compiled catalog")["node_source_commit"].is_null());
        assert!(Network::catalog().expect("compiled catalog")["node_stable_tag"].is_null());
        for network in [Network::Mainnet, Network::Testnet] {
            let profile = network.profile().expect("compiled profile");
            assert!(profile["genesis_hash"].is_null());
            for key in ["sha256", "signature_sha256"] {
                let value = profile["supervisor"][key].as_str().expect("digest");
                assert_eq!(value.len(), 64);
                assert!(
                    value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                );
            }
        }
    }
}
