// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Selectors checked against the carried releases' embedded chain registries.

use serde::{Deserialize, Serialize};

/// A follower implementation, never a sequencer or permissionless validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    /// OP Mainnet's op-reth and op-node.
    Optimism,
    /// Base's base-reth-node and base-consensus.
    Base,
    /// Soneium's embedded op-reth and op-node registry configurations.
    Soneium,
}

impl Family {
    /// Stable CLI and host directory name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Optimism => "optimism",
            Self::Base => "base",
            Self::Soneium => "soneium",
        }
    }
}

/// The L1 pair must identify the same Ethereum network before serving clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L1 {
    /// Ethereum mainnet.
    Mainnet,
    /// Ethereum Sepolia.
    Sepolia,
}

/// Fixed configuration passed to a particular pair of clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// CLI chain.
    pub family: Family,
    /// CLI network name.
    pub network: &'static str,
    /// Execution chain ID.
    pub chain_id: u64,
    /// Execution client's built-in chain selector.
    pub execution_chain: &'static str,
    /// Consensus client's built-in chain selector.
    pub consensus_chain: &'static str,
    /// Parent network, independently verified through both upstreams.
    pub l1: L1,
    /// OP Mainnet needs the pre-Bedrock history before execution-layer sync.
    pub pre_bedrock: bool,
}

/// Supported configurations. Soneium Minato's upstream selector includes Sepolia.
pub const PROFILES: [Profile; 6] = [
    Profile {
        family: Family::Optimism,
        network: "mainnet",
        chain_id: 10,
        execution_chain: "optimism",
        consensus_chain: "op-mainnet",
        l1: L1::Mainnet,
        pre_bedrock: true,
    },
    Profile {
        family: Family::Optimism,
        network: "sepolia",
        chain_id: 11_155_420,
        execution_chain: "optimism-sepolia",
        consensus_chain: "op-sepolia",
        l1: L1::Sepolia,
        pre_bedrock: false,
    },
    Profile {
        family: Family::Base,
        network: "mainnet",
        chain_id: 8453,
        execution_chain: "base",
        consensus_chain: "8453",
        l1: L1::Mainnet,
        pre_bedrock: false,
    },
    Profile {
        family: Family::Base,
        network: "sepolia",
        chain_id: 84_532,
        execution_chain: "base-sepolia",
        consensus_chain: "84532",
        l1: L1::Sepolia,
        pre_bedrock: false,
    },
    Profile {
        family: Family::Soneium,
        network: "mainnet",
        chain_id: 1868,
        execution_chain: "soneium",
        consensus_chain: "soneium-mainnet",
        l1: L1::Mainnet,
        pre_bedrock: false,
    },
    Profile {
        family: Family::Soneium,
        network: "minato",
        chain_id: 1946,
        execution_chain: "soneium-minato-sepolia",
        consensus_chain: "soneium-minato-sepolia",
        l1: L1::Sepolia,
        pre_bedrock: false,
    },
];

/// Select a supported network without falling back to mainnet.
#[must_use]
pub fn get(family: Family, network: &str) -> Option<Profile> {
    PROFILES
        .iter()
        .copied()
        .find(|p| p.family == family && p.network == network)
}

#[cfg(test)]
mod tests {
    use super::{Family, L1, get};

    #[test]
    fn aliases_cannot_change_network_or_client_family() {
        assert!(get(Family::Soneium, "sepolia").is_none());
        assert!(get(Family::Base, "minato").is_none());
        assert!(get(Family::Optimism, "").is_none());
        let minato = get(Family::Soneium, "minato").expect("Minato");
        assert_eq!(minato.l1, L1::Sepolia);
        assert_eq!(minato.chain_id, 1946);
        assert_eq!(minato.execution_chain, "soneium-minato-sepolia");
        assert_eq!(
            get(Family::Base, "mainnet").expect("Base").consensus_chain,
            "8453"
        );
    }
}
