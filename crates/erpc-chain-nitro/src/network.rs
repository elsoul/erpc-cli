// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Chain-specific Nitro metadata; Nova `AnyTrust` is not a blob rollup.

/// Explicit follower network qualified by this backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Arbitrum One, Ethereum parent.
    One,
    /// Arbitrum Nova, Ethereum parent with `AnyTrust` data availability.
    Nova,
    /// Arbitrum Sepolia, Sepolia parent.
    Sepolia,
    /// Robinhood mainnet, custom genesis and Ethereum parent.
    Robinhood,
    /// Robinhood testnet, Sepolia parent without a custom genesis file.
    RobinhoodTestnet,
}
impl Network {
    /// Resolve the public chain family and CLI network together.
    #[must_use]
    pub fn parse(family: &str, network: &str) -> Option<Self> {
        match (family, network) {
            ("arbitrum", "mainnet") => Some(Self::One),
            ("arbitrum", "nova") => Some(Self::Nova),
            ("arbitrum", "sepolia") => Some(Self::Sepolia),
            ("robinhood", "mainnet") => Some(Self::Robinhood),
            ("robinhood", "testnet") => Some(Self::RobinhoodTestnet),
            _ => None,
        }
    }
    /// Public CLI family.
    #[must_use]
    pub const fn family(self) -> &'static str {
        match self {
            Self::One | Self::Nova | Self::Sepolia => "arbitrum",
            _ => "robinhood",
        }
    }
    /// Public CLI network.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::One | Self::Robinhood => "mainnet",
            Self::Nova => "nova",
            Self::Sepolia => "sepolia",
            Self::RobinhoodTestnet => "testnet",
        }
    }
    /// Chain ID enforced in the client and health probes.
    #[must_use]
    pub const fn id(self) -> u64 {
        match self {
            Self::One => 42161,
            Self::Nova => 42170,
            Self::Sepolia => 421_614,
            Self::Robinhood => 4663,
            Self::RobinhoodTestnet => 46630,
        }
    }
    /// L1 identity for the credentialed proxy, independent of L2 network names.
    #[must_use]
    pub const fn parent(self) -> &'static str {
        match self {
            Self::Sepolia | Self::RobinhoodTestnet => "sepolia",
            _ => "mainnet",
        }
    }
    /// Canonical Nitro data/config chain name.
    #[must_use]
    pub const fn chain_name(self) -> &'static str {
        match self {
            Self::One => "arb1",
            Self::Nova => "nova",
            Self::Sepolia => "sepolia-rollup",
            Self::Robinhood => "Robinhood Chain",
            Self::RobinhoodTestnet => "Robinhood Chain Sepolia",
        }
    }
    /// Whether parent-chain blobs provide the chain's data availability.
    #[must_use]
    pub const fn blobs(self) -> bool {
        !matches!(self, Self::Nova)
    }
    /// Reviewed bootstrap uses a full `PathDB` snapshot for DAO-governed chains.
    /// Robinhood is initialized from its chain info and network-specific genesis.
    #[must_use]
    pub const fn snapshot(self) -> bool {
        matches!(self, Self::One | Self::Nova | Self::Sepolia)
    }
    /// Exact custom genesis only applies to Robinhood mainnet.
    #[must_use]
    pub const fn custom_genesis(self) -> bool {
        matches!(self, Self::Robinhood)
    }
    /// Chain-provided first-party configuration document and pinned byte hash.
    /// # Errors
    /// Refuses an incomplete compiled document catalog.
    pub fn chain_info(self) -> Result<(&'static str, &'static str), &'static str> {
        document(match self {
            Self::Robinhood => "robinhood-mainnet",
            Self::RobinhoodTestnet => "robinhood-testnet",
            _ => "arbitrum",
        })
    }
}

static DOCUMENTS: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
    serde_json::from_str(include_str!("../networks/documents.json"))
        .unwrap_or_else(|_| panic!("invalid compiled Nitro document catalog"))
});
fn document(name: &str) -> Result<(&'static str, &'static str), &'static str> {
    let value = &DOCUMENTS[name];
    Ok((
        value["url"].as_str().ok_or("missing Nitro document URL")?,
        value["sha256"]
            .as_str()
            .ok_or("missing Nitro document digest")?,
    ))
}
/// Robinhood mainnet's custom genesis URL and reviewed byte digest.
/// # Errors
/// Refuses an incomplete compiled document catalog.
pub fn robinhood_genesis() -> Result<(&'static str, &'static str), &'static str> {
    document("robinhood-genesis")
}

#[cfg(test)]
mod tests {
    use super::Network;
    #[test]
    fn network_qualification_never_infers_a_parent_or_genesis_from_names() {
        assert!(Network::parse("robinhood", "sepolia").is_none());
        assert!(Network::parse("arbitrum", "testnet").is_none());
        assert_eq!(Network::RobinhoodTestnet.parent(), "sepolia");
        assert!(!Network::RobinhoodTestnet.custom_genesis());
        assert!(Network::Robinhood.custom_genesis());
        assert!(!Network::Nova.blobs());
        assert!(Network::One.snapshot());
        assert_ne!(Network::One.id(), Network::Robinhood.id());
    }
}
