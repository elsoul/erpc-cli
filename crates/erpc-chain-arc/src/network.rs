// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! What a node needs to know about each Arc network: the chain name the
//! binaries take, the chain id to check, where to forward transactions, and
//! the relay endpoints the consensus layer follows.
//!
//! The table is data, `networks/arc.json`, read from the Arc docs on the date
//! it records. The node reaches these hosts; erpc does not.

use serde::Deserialize;

/// The carried table.
const TABLE: &str = include_str!("../networks/arc.json");

/// One relay the consensus layer follows: its HTTPS URL and its WebSocket
/// host and path, as `--follow.endpoint <http>,wss=<ws>` takes them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Follow {
    /// The relay's HTTPS URL.
    pub http: String,
    /// `host[/path]`, without a scheme.
    pub ws: String,
}

impl Follow {
    /// The value of one `--follow.endpoint`.
    #[must_use]
    pub fn flag(&self) -> String {
        format!("{},wss={}", self.http, self.ws)
    }
}

/// One Arc network.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Network {
    /// The name the binaries take with `--chain`: `arc-testnet`.
    pub chain: String,
    /// What `eth_chainId` answers on it.
    pub chain_id: u64,
    /// The genesis block hash pinned by upstream chainspec regression tests.
    pub genesis_hash: String,
    /// Where the execution layer forwards transactions it is sent.
    pub forwarder: String,
    /// A public endpoint to compare the node's head with.
    pub public_rpc: String,
    /// The relays the consensus layer follows.
    pub follow: Vec<Follow>,
}

#[derive(Deserialize)]
struct Table {
    source: String,
    read: String,
    networks: std::collections::BTreeMap<String, Network>,
}

fn table() -> Table {
    // The table is fixed at build time and a test reads it, so a parse
    // failure here is a build that never passed its tests.
    serde_json::from_str(TABLE).unwrap_or_else(|_| Table {
        source: String::new(),
        read: String::new(),
        networks: std::collections::BTreeMap::new(),
    })
}

/// The network called `name` (`testnet`, `mainnet`), if Arc has it.
#[must_use]
pub fn get(name: &str) -> Option<Network> {
    table().networks.remove(name)
}

/// Where the table was read from, and when.
#[must_use]
pub fn source() -> (String, String) {
    let t = table();
    (t.source, t.read)
}

#[cfg(test)]
mod tests {
    use super::{get, source};

    #[test]
    fn both_networks_are_carried_with_their_chain_ids() {
        let testnet = get("testnet").expect("testnet");
        assert_eq!(testnet.chain, "arc-testnet");
        assert_eq!(testnet.chain_id, 5_042_002);
        assert_eq!(testnet.follow.len(), 3);
        let mainnet = get("mainnet").expect("mainnet");
        assert_eq!(mainnet.chain, "arc-mainnet");
        assert_eq!(mainnet.chain_id, 5042);
        assert_eq!(mainnet.follow.len(), 4);
        assert!(get("devnet").is_none());
        assert_eq!(source().1, "2026-10-27");
    }

    #[test]
    fn every_endpoint_is_https_and_the_flag_is_in_the_docs_form() {
        for name in ["testnet", "mainnet"] {
            let n = get(name).expect("network");
            assert!(n.forwarder.starts_with("https://"));
            assert!(n.public_rpc.starts_with("https://"));
            for f in &n.follow {
                assert!(f.http.starts_with("https://"), "{}", f.http);
                assert!(!f.ws.contains("://"), "{}", f.ws);
            }
        }
        let third = &get("testnet").expect("testnet").follow[2];
        assert_eq!(third.flag(), format!("{},wss={}", third.http, third.ws));
        assert!(third.ws.ends_with("/websocket"));
    }
}
