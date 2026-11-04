// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Non-signing Primary Network registration review. Never constructs/submits a transaction.
use crate::Network;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Human-reviewed registration inputs, amounts are integer nAVAX (no float rounding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    /// Network binding.
    pub network: Network,
    /// `NodeID` from the pinned host.
    pub node_id: String,
    /// BLS public key and proof as returned by info.getNodeID.
    pub node_pop: Value,
    /// Self stake in nAVAX.
    pub stake_navax: u64,
    /// Preparation timestamp, not a requested staking start (Durango starts on acceptance).
    pub prepared_at: u64,
    /// Unix end time in seconds.
    pub end: u64,
    /// Reward destination, a checksummed P-Chain Bech32 address.
    pub rewards_address: String,
    /// Delegation fee in basis points; 200 means 2%.
    pub delegation_fee_bps: u16,
}
/// Validate CB58-encoded 20-byte `NodeIDs` including their checksum.
#[must_use]
pub fn node_id_valid(id: &str) -> bool {
    let Some(text) = id.strip_prefix("NodeID-") else {
        return false;
    };
    if text.len() > 40 {
        return false;
    }
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes = vec![0u8];
    for c in text.bytes() {
        let Some(mut carry) = alphabet
            .iter()
            .position(|b| *b == c)
            .and_then(|n| u32::try_from(n).ok())
        else {
            return false;
        };
        for b in bytes.iter_mut().rev() {
            carry += u32::from(*b) * 58;
            *b = (carry & 255) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 255) as u8);
            carry >>= 8;
        }
    }
    for _ in text.bytes().take_while(|b| *b == b'1') {
        bytes.insert(0, 0);
    }
    bytes.len() == 24 && Sha256::digest(&bytes[..20])[28..] == bytes[20..]
}
fn address_valid(text: &str, network: Network) -> bool {
    let Some(value) = text.strip_prefix("P-") else {
        return false;
    };
    let Some((hrp, body)) = value.rsplit_once('1') else {
        return false;
    };
    if hrp
        != match network {
            Network::Mainnet => "avax",
            Network::Fuji => "fuji",
        }
        || body.len() != 38
    {
        return false;
    }
    let alphabet = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut values = Vec::new();
    for c in body.bytes() {
        let Some(v) = alphabet.iter().position(|b| *b == c) else {
            return false;
        };
        values.push(u32::try_from(v).unwrap_or(0));
    }
    let expanded = hrp
        .bytes()
        .map(|b| u32::from(b >> 5))
        .chain([0])
        .chain(hrp.bytes().map(|b| u32::from(b & 31)))
        .chain(values);
    let mut chk = 1u32;
    for v in expanded {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v;
        for (i, g) in [
            0x3b6a_57b2,
            0x2650_8e6d,
            0x1ea1_19fa,
            0x3d42_33dd,
            0x2a14_62b3,
        ]
        .iter()
        .enumerate()
        {
            if (top >> i) & 1 != 0 {
                chk ^= g;
            }
        }
    }
    chk == 1
}
impl Registration {
    /// Validate network, identity binding, stake, term and rewards address before review.
    /// # Errors
    /// Rejects malformed/cross-network or already-expired inputs. Cryptographic
    /// BLS verification and live fees/UTXOs belong to the official external signer.
    pub fn validate(
        &self,
        network: Network,
        identity: &str,
        pop: &Value,
        now: u64,
    ) -> Result<(), String> {
        if self.network != network
            || self.node_id != identity
            || &self.node_pop != pop
            || !node_id_valid(identity)
        {
            return Err("registration identity/network does not match the pinned live node".into());
        }
        for (key, size) in [("publicKey", 96), ("proofOfPossession", 192)] {
            let hex = self.node_pop[key]
                .as_str()
                .and_then(|s| s.strip_prefix("0x"))
                .ok_or("missing BLS public proof")?;
            if hex.len() != size
                || !hex.bytes().all(|b| b.is_ascii_hexdigit())
                || hex.bytes().all(|b| b == b'0')
            {
                return Err("invalid BLS proof encoding".into());
            }
        }
        let minimum = match network {
            Network::Mainnet => 2_000_000_000_000,
            Network::Fuji => 1_000_000_000,
        };
        let min_term = match network {
            Network::Mainnet => 172_800,
            Network::Fuji => 43_200,
        };
        let duration = self
            .end
            .checked_sub(now)
            .ok_or("staking end must be in the future")?;
        if self.stake_navax < minimum || self.stake_navax > 3_000_000_000_000_000 {
            return Err("stake is outside Primary Network bounds".into());
        }
        if self.prepared_at > now
            || now.saturating_sub(self.prepared_at) > 600
            || !(min_term + 300..=365 * 86400).contains(&duration)
        {
            return Err("reprepare after 10 minutes; end must allow the network minimum term plus 5 minutes for submission, at most one year".into());
        }
        if !(200..=10_000).contains(&self.delegation_fee_bps)
            || !address_valid(&self.rewards_address, network)
        {
            return Err("invalid delegation fee or rewards P-Chain address".into());
        }
        Ok(())
    }
    /// Explicit external-signing handoff, not a signed transaction or deposit receipt.
    #[must_use]
    pub fn review(&self) -> Value {
        json!({"status":"prepared-not-submitted","registration":self,"network_id":self.network.id(),"c_chain_id":self.network.evm_id(),"proof_validation":"encoding and pinned-live-node binding; cryptographic PoP checked by external signer and P-Chain","transaction_fee":"resolve live using official wallet; amount is not included in stake_navax","next":"Use Core Stake, select the same network and Add Validator; review NodeID, BLS proof, stake, end time, reward address and delegation fee on the signing device. Check for already submitted/pending transactions in the wallet before signing. Submit externally, then run erpc v --chain avax status.","start":"when accepted by P-Chain (Durango)","signed":false,"submitted":false})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn official_node_id_fixture_rejects_checksum_tampering() {
        let id = "NodeID-5mb46qkSBj81k9g9e4VFjGGSbaaSLFRzD";
        assert!(node_id_valid(id));
        assert!(!node_id_valid("NodeID-5mb46qkSBj81k9g9e4VFjGGSbaaSLFRzE"));
    }
    #[test]
    fn registration_checks_network_term_fee_stake_and_freshness() {
        let request = Registration {
            network: Network::Mainnet,
            node_id: "NodeID-5mb46qkSBj81k9g9e4VFjGGSbaaSLFRzD".into(),
            // Encoding fixtures only: external signer must verify the actual PoP.
            node_pop: json!({"publicKey":format!("0x{}","ab".repeat(48)),"proofOfPossession":format!("0x{}","cd".repeat(96))}),
            stake_navax: 2_000_000_000_000,
            prepared_at: 1_800_000_000,
            end: 1_800_000_000 + 172_800 + 600,
            rewards_address: "P-avax1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxpdk7q".into(),
            delegation_fee_bps: 200,
        };
        let check = |r: &Registration, now| {
            r.validate(Network::Mainnet, &request.node_id, &request.node_pop, now)
        };
        assert!(check(&request, request.prepared_at).is_ok());
        assert!(check(&request, request.prepared_at + 601).is_err());
        for bad in [
            Registration {
                network: Network::Fuji,
                ..request.clone()
            },
            Registration {
                stake_navax: 1_000_000_000,
                ..request.clone()
            },
            Registration {
                delegation_fee_bps: 199,
                ..request.clone()
            },
            Registration {
                end: request.prepared_at + 172_799,
                ..request.clone()
            },
            Registration {
                rewards_address: "P-fuji1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2nffjl".into(),
                ..request.clone()
            },
            Registration {
                node_pop: json!({}),
                ..request.clone()
            },
        ] {
            assert!(check(&bad, request.prepared_at).is_err());
        }
        assert_eq!(request.review()["submitted"], false);
    }
    #[test]
    fn malformed_id_and_wrong_network_addresses_fail() {
        assert!(!node_id_valid("NodeID-nope"));
        assert!(!node_id_valid("NodeID-111111111111111111111111"));
        assert!(!address_valid("P-fuji1notanaddress", Network::Fuji));
        assert!(!address_valid(
            "P-avax1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxpdk7q",
            Network::Fuji
        ));
    }
}
