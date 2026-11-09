// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Reference BSC Geth, immutable network/retention and pinned official snapshots.

/// Public validator registration proof verification and read-only contract queries.
pub mod validator;

use serde_json::Value;
use std::sync::LazyLock;

/// Exact public metadata carried to the node, never fetched by the controller.
pub const CATALOG_BYTES: &[u8] = include_bytes!("../networks/catalog.json");
/// Root-owned node programs and playbooks.
pub static TEMPLATES: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates");
static CATALOG: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_slice(CATALOG_BYTES)
        .unwrap_or_else(|_| panic!("invalid compiled BSC release catalog"))
});

/// Mainnet and Chapel have different reviewed release audiences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// BNB Smart Chain mainnet, chain ID 56.
    Mainnet,
    /// BNB Smart Chain Chapel testnet, chain ID 97.
    Chapel,
}
impl Network {
    /// Resolve an explicit CLI network.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mainnet" => Some(Self::Mainnet),
            "chapel" => Some(Self::Chapel),
            _ => None,
        }
    }
    /// Canonical scope name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Chapel => "chapel",
        }
    }
    /// Reviewed public metadata including binary and snapshot content identities.
    #[must_use]
    pub fn catalog(self) -> &'static Value {
        &CATALOG[self.name()]
    }
    /// Default version qualified for this network.
    #[must_use]
    pub fn recommended(self) -> &'static str {
        match self {
            Self::Mainnet => "1.8.2",
            Self::Chapel => "1.8.1",
        }
    }
    /// Accept only the reviewed network-specific release.
    /// # Errors
    /// Refuses preview tags, another network's recommendation and arbitrary versions.
    pub fn qualify(self, version: &str) -> Result<&'static Value, &'static str> {
        self.catalog()["releases"]
            .get(version)
            .ok_or("BSC version is not qualified for this network in the reviewed catalog")
    }
}

#[cfg(test)]
mod tests {
    use super::Network;
    #[test]
    fn release_audience_and_network_genesis_are_not_interchangeable() {
        assert_eq!(Network::Mainnet.recommended(), "1.8.2");
        assert!(Network::Mainnet.qualify("1.7.8").is_ok());
        assert!(Network::Mainnet.qualify("1.8.2").is_ok());
        assert!(Network::Chapel.qualify("1.8.2").is_err());
        assert_eq!(Network::Chapel.recommended(), "1.8.1");
        assert!(Network::Mainnet.qualify("1.8.1").is_err());
        assert!(Network::Chapel.qualify("1.7.8").is_err());
        assert_ne!(
            Network::Mainnet.catalog()["genesis_hash"],
            Network::Chapel.catalog()["genesis_hash"]
        );
        assert!(Network::parse("opbnb").is_none());
    }
}
