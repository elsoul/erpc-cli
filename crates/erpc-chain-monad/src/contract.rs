// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Public, immutable identity and physical-device ownership.
use k256::elliptic_curve::sec1::ToSec1Point as _;
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Keccak256};

/// One dedicated host, network, partition and pair of consensus keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Random public inventory ownership nonce, generated once.
    pub owner: String,
    /// Explicit mainnet or testnet.
    pub network: String,
    /// RPC follower or validator intent.
    pub role: String,
    /// Operator-provisioned GPT partition identifier.
    pub partuuid: String,
    /// Public IPv4 advertised by the signed node-name record.
    pub public_ip: String,
    /// Monotonic signed peer-address sequence, chosen explicitly for the key.
    pub name_record_sequence: u64,
    /// Compressed SECP public key; never an account's private key.
    pub secp: String,
    /// Compressed BLS public key.
    pub bls: String,
    /// Public destination for block rewards.
    pub beneficiary: String,
    /// External staking withdrawal authority; zero for followers.
    pub auth_address: String,
}

/// Decode bounded canonical lowercase hex.
/// # Errors
/// Rejects a wrong width, uppercase characters, separators and invalid bytes.
pub fn hex_bytes(value: &str, bytes: usize) -> Result<Vec<u8>, String> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected canonical lowercase hexadecimal public data".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| "invalid hex".into()))
        .collect()
}
/// Canonical hex encoding of public values.
#[must_use]
pub fn hex(value: &[u8]) -> String {
    use std::fmt::Write as _;
    value.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
/// EVM address controlled by a consensus SECP key. It must never be a funding/withdrawal key.
/// # Errors
/// Refuses invalid curve points and noncanonical compressed public keys.
pub fn consensus_address(key: &str) -> Result<String, String> {
    let key = k256::PublicKey::from_sec1_bytes(&hex_bytes(key, 33)?)
        .map_err(|_| "invalid consensus SECP public point")?;
    let encoded = key.to_sec1_point(false);
    let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
    Ok(format!("0x{}", hex(&hash[12..])))
}
impl Contract {
    /// Validate immutable public scope before any host or concealed-field operation.
    /// # Errors
    /// Refuses unsupported networks/roles, mixed wallet roles and malformed identifiers.
    pub fn validate(&self) -> Result<(), String> {
        hex_bytes(&self.owner, 16)?;
        if self.name_record_sequence == 0 {
            return Err("name-record sequence must be positive".into());
        }
        if !["mainnet", "testnet"].contains(&self.network.as_str())
            || !["rpc", "validator"].contains(&self.role.as_str())
        {
            return Err("unsupported Monad network or role".into());
        }
        let parts: Vec<_> = self.partuuid.split('-').collect();
        if parts.iter().map(|p| p.len()).collect::<Vec<_>>() != [8, 4, 4, 4, 12] {
            return Err("use a canonical GPT PARTUUID".into());
        }
        hex_bytes(&self.partuuid.replace('-', ""), 16)?;
        let ip: std::net::Ipv4Addr = self
            .public_ip
            .parse()
            .map_err(|_| "Monad requires public IPv4")?;
        if ip.to_string() != self.public_ip || !public_ipv4(ip) {
            return Err("Monad peer address must be public unicast IPv4".into());
        }
        let consensus = consensus_address(&self.secp)?;
        let bls = hex_bytes(&self.bls, 48)?;
        if bls.iter().all(|&b| b == 0) {
            return Err("invalid BLS public key".into());
        }
        for address in [&self.beneficiary, &self.auth_address] {
            hex_bytes(
                address
                    .strip_prefix("0x")
                    .ok_or("expected public EVM address")?,
                20,
            )?;
            if address == &consensus {
                return Err(
                    "consensus keys must be separate from rewards and withdrawal wallets".into(),
                );
            }
        }
        let zero = format!("0x{}", "0".repeat(40));
        if self.role == "rpc" {
            if self.beneficiary != zero || self.auth_address != zero {
                return Err("followers use zero reward/withdrawal addresses".into());
            }
        } else if self.beneficiary == zero || self.auth_address == zero {
            return Err(
                "validator intent requires explicit external rewards and withdrawal addresses"
                    .into(),
            );
        }
        Ok(())
    }
    /// Fixed network chain ID.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        if self.network == "mainnet" {
            143
        } else {
            10143
        }
    }
}
fn public_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let n = u32::from(ip);
    // Conservative IANA special-purpose, documentation, multicast and reserved ranges.
    let denied = [
        (0, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc01f_c400, 24),
        (0xc034_c100, 24),
        (0xc058_6300, 24),
        (0xc0a8_0000, 16),
        (0xc0af_3000, 24),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 3),
    ];
    !denied
        .into_iter()
        .any(|(network, prefix)| n & (u32::MAX << (32 - prefix)) == network)
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn fixture() -> Contract {
        let public = k256::AffinePoint::GENERATOR.to_sec1_point(true);
        Contract {
            owner: "ab".repeat(16),
            network: "testnet".into(),
            role: "validator".into(),
            partuuid: "abcdefab-abcd-abcd-abcd-abcdefabcdef".into(),
            public_ip: "8.8.8.8".into(),
            name_record_sequence: 1,
            secp: hex(public.as_bytes()),
            bls: "ab".repeat(48),
            beneficiary: format!("0x{}", "cd".repeat(20)),
            auth_address: format!("0x{}", "ef".repeat(20)),
        }
    }
    #[test]
    fn public_point_is_validated_and_consensus_wallet_cannot_control_funds() {
        let mut c = fixture();
        c.validate().unwrap();
        c.auth_address = consensus_address(&c.secp).unwrap();
        assert!(c.validate().is_err());
        c = fixture();
        c.beneficiary = consensus_address(&c.secp).unwrap();
        assert!(c.validate().is_err());
        c = fixture();
        c.secp = "ab".repeat(33);
        assert!(c.validate().is_err());
    }
    #[test]
    fn roles_devices_and_peer_address_are_explicit() {
        let mut c = fixture();
        for address in [
            "127.0.0.1",
            "192.0.0.9",
            "192.52.193.1",
            "192.175.48.1",
            "198.19.1.1",
            "224.0.0.1",
            "::ffff:8.8.8.8",
        ] {
            c.public_ip = address.into();
            assert!(c.validate().is_err(), "{address}");
        }
        c = fixture();
        c.role = "rpc".into();
        assert!(c.validate().is_err());
        c.beneficiary = format!("0x{}", "0".repeat(40));
        c.auth_address = c.beneficiary.clone();
        c.validate().unwrap();
        c.partuuid = "/dev/nvme1n1".into();
        assert!(c.validate().is_err());
    }
}
