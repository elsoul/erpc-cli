// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Public host ownership with explicit optional consensus-hot authority.
use crate::Network;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Immutable network, advertised address and optional validator ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Public 128-bit ownership nonce, separate from SSH authentication.
    pub owner: String,
    /// Fixed blockchain network.
    pub network: Network,
    /// `rpc` or an explicitly separate `validator` authority boundary.
    pub role: String,
    /// Operator-selected public IPv4 advertisement, never a URL or hostname.
    pub public_ip: String,
    /// Public validator identities only; never a private key or secret reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<crate::validator::Identity>,
}
impl Contract {
    /// Validate before any inventory reservation or host operation.
    /// # Errors
    /// Rejects another role, malformed owner or special-use advertised address.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.owner.len() != 32
            || !self
                .owner
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid Hyperliquid ownership contract");
        }
        match (self.role.as_str(), &self.validator) {
            ("rpc", None) => {}
            ("validator", Some(identity)) => identity.validate()?,
            _ => return Err("Hyperliquid role differs from its explicit custody authority"),
        }
        let ip: Ipv4Addr = self
            .public_ip
            .parse()
            .map_err(|_| "public IPv4 advertisement required")?;
        if ip.to_string() != self.public_ip || !public_ipv4(ip) {
            return Err("advertised address must be public unicast IPv4");
        }
        Ok(())
    }
}
fn public_ipv4(ip: Ipv4Addr) -> bool {
    const EXCLUDED: [([u8; 4], u32); 17] = [
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 31, 196, 0], 24),
        ([192, 52, 193, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([192, 175, 48, 0], 24),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 3),
    ];
    let address = u32::from(ip);
    !EXCLUDED.iter().any(|(base, bits)| {
        let mask = u32::MAX << (32 - bits);
        address & mask == u32::from_be_bytes(*base) & mask
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_owner_cannot_select_a_wallet_role_or_private_peer_advertisement() {
        let mut value = Contract {
            owner: "a".repeat(32),
            network: Network::Mainnet,
            role: "rpc".into(),
            public_ip: "8.8.8.8".into(),
            validator: None,
        };
        value.validate().expect("public fixture");
        for ip in [
            "127.0.0.1",
            "100.64.0.1",
            "192.0.0.9",
            "192.31.196.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "example.invalid",
            "8.8.8.8;id",
        ] {
            value.public_ip = ip.into();
            assert!(value.validate().is_err(), "{ip}");
        }
        value.public_ip = "8.8.8.8".into();
        value.role = "validator".into();
        assert!(value.validate().is_err());
        value.role = "rpc".into();
        value.owner = "$(id)".into();
        assert!(value.validate().is_err());
    }
}
