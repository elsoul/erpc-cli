// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public SR metadata and the external owner-signing boundary.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// The owner and dedicated block-signing addresses, never a private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    /// Public candidate/SR account whose owner wallet stays external.
    pub owner: String,
    /// A separate address authorized only by the owner's Witness permission.
    pub signer: String,
    /// Public candidate URL included in external registration preparation.
    pub url: String,
}

/// Decode the network's canonical public address form and verify its checksum.
/// # Errors
/// Refuses Ethereum hex addresses, malformed Base58 or a non-TRON prefix/checksum.
pub fn address(value: &str) -> Result<[u8; 21], String> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if value.len() != 34 || !value.starts_with('T') {
        return Err("expected a canonical TRON Base58Check public address".into());
    }
    let mut bytes = [0_u8; 25];
    for character in value.bytes() {
        let mut carry = u32::try_from(
            ALPHABET
                .iter()
                .position(|&b| b == character)
                .ok_or("invalid Base58 public address")?,
        )
        .map_err(|_| "invalid address")?;
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = carry.to_le_bytes()[0];
            carry >>= 8;
        }
        if carry != 0 {
            return Err("public address is too large".into());
        }
    }
    let digest = Sha256::digest(Sha256::digest(&bytes[..21]));
    if bytes[0] != 65 || bytes[21..] != digest[..4] {
        return Err("TRON public address has an invalid prefix or checksum".into());
    }
    bytes[..21]
        .try_into()
        .map_err(|_| "invalid address length".into())
}

impl Witness {
    /// Validate the public signing boundary before any host or secret operation.
    /// # Errors
    /// Refuses owner-key reuse and non-public/unsupported registration URLs.
    pub fn validate(&self) -> Result<(), String> {
        address(&self.owner)?;
        address(&self.signer)?;
        if self.owner == self.signer {
            return Err(
                "use a separate delegated witness key; owner keys must stay external".into(),
            );
        }
        let url =
            reqwest::Url::parse(&self.url).map_err(|_| "candidate URL must be public HTTPS")?;
        if self.url.len() > 256
            || !self.url.is_ascii()
            || self.url.chars().any(char::is_control)
            || url.scheme() != "https"
            || !url.has_host()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "candidate URL must be public HTTPS without embedded credentials or fragment"
                    .into(),
            );
        }
        Ok(())
    }

    /// Public request data for external official tooling. Nothing is submitted.
    #[must_use]
    pub fn preparation(&self, network: &str) -> Value {
        let encoded = self
            .url
            .as_bytes()
            .iter()
            .fold(String::new(), |mut text, byte| {
                use std::fmt::Write as _;
                let _ = write!(text, "{byte:02x}");
                text
            });
        json!({"network":network,"owner":self.owner,"witness_signer":self.signer,
            "candidate_method":"wallet/createwitness",
            "candidate_request":{"owner_address":self.owner,"url":encoded,"visible":true},
            "registration":"Construct the unsigned candidate transaction with official external tooling, inspect the correct network and current fee, then sign and broadcast with the external owner wallet.",
            "delegation":"After candidacy exists, configure a single dedicated Witness permission (id 1, threshold 1, signer weight 1) using official account permission tooling. Preserve the complete existing Owner/Active permissions and keep this signer out of both; erpc never submits permission replacement.",
            "activation":"Registration does not imply election. The active 27 by votes produce blocks; use registration status and actual production observations.",
            "fee":"Read getAccountUpgradeCost from the current network; preparation does not assume a permanently fixed fee or stake amount.",
            "submission":"External official tooling only; no owner signing, stake funding or broadcast in erpc."})
    }
}

/// Accept only unambiguous field references, never a CLI-supplied private value.
/// # Errors
/// Refuses malformed vault/item/field references before invoking 1Password.
pub fn reference(value: &str) -> Result<(), String> {
    erpc_secret::OpRef::parse(value)
        .map(|_| ())
        .map_err(|_| "TRON credentials require identifier-only 1Password field references".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_addresses_have_tron_prefix_and_valid_checksum() {
        let public = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb";
        let raw = address(public).unwrap();
        assert_eq!(raw[0], 65);
        assert_eq!(raw[1..], [0; 20]);
        assert!(address(&format!("{}a", &public[..33])).is_err());
        assert!(address(&format!("0x{}", "0".repeat(40))).is_err());
        assert!(
            Witness {
                owner: public.into(),
                signer: public.into(),
                url: "https://github.com".into()
            }
            .validate()
            .is_err()
        );
        assert!(
            reference(&format!(
                "op://{}/{}/password",
                "a".repeat(26),
                "b".repeat(26)
            ))
            .is_ok()
        );
        assert!(reference("op://vault/item/password").is_err());
        assert!(reference("op://vault/item/password/extra").is_err());
    }
}
