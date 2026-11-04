// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The Ethereum networks erpc runs RPC nodes on: mainnet, so far. What the
//! node reaches for each (the checkpoint server, the snapshot hosts) is in
//! the carried `templates/ansible/eth-rpc/vars.yml`, where the endpoints
//! gate checks node hosts.

/// One network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    /// erpc's name for it.
    pub name: &'static str,
    /// Reth's `--chain` and Lighthouse's `--network`.
    pub client_name: &'static str,
    /// `eth_chainId`.
    pub chain_id: u64,
}

/// Every network erpc runs Ethereum RPC nodes on.
pub const NETWORKS: [Network; 1] = [Network {
    name: "mainnet",
    client_name: "mainnet",
    chain_id: 1,
}];

/// The network `name` names, if erpc runs nodes on it.
#[must_use]
pub fn get(name: &str) -> Option<Network> {
    NETWORKS.iter().copied().find(|n| n.name == name)
}

#[cfg(test)]
mod tests {
    #[test]
    fn mainnet_is_chain_1_and_nothing_else_is_offered() {
        let mainnet = super::get("mainnet").expect("mainnet");
        assert_eq!(mainnet.chain_id, 1);
        assert!(super::get("sepolia").is_none());
    }
}
