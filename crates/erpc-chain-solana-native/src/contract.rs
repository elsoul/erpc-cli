// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Immutable public ownership for a dedicated native validator host.
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Operator-provisioned filesystems; the CLI never formats or wipes a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volumes {
    /// Accounts filesystem UUID.
    pub accounts: String,
    /// Ledger filesystem UUID.
    pub ledger: String,
    /// Snapshot filesystem UUID.
    pub snapshots: String,
}

/// Identity and disk ownership that an update cannot silently replace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Contract schema, currently one.
    pub schema: u8,
    /// Profile discriminator; prevents adopting a legacy Solv host.
    pub profile: String,
    /// Exact secret-store metadata item identity, never a signer secret.
    pub inventory_id: String,
    /// Human-selected inventory name.
    pub name: String,
    /// Mainnet or Testnet.
    pub network: String,
    /// SHA256 binding of the pinned SSH host key and original address.
    pub host_binding: String,
    /// Original validator or non-voting RPC identity public key.
    pub identity_account: String,
    /// Public vote account; its private key is not a runtime credential.
    pub vote_account: Option<String>,
    /// External withdrawal authority public key; never imported into the host.
    pub authority_account: Option<String>,
    /// Three distinct, explicitly mounted filesystems.
    pub volumes: Volumes,
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        && value.bytes().any(|byte| byte != b'0' && byte != b'-')
}

fn public_key(value: &str) -> bool {
    (32..=44).contains(&value.len()) && encoded_key::<32>(value)
}

pub(crate) fn encoded_key<const N: usize>(value: &str) -> bool {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if value.is_empty() || value.len() > N * 2 {
        return false;
    }
    let mut bytes = [0_u8; N];
    for character in value.bytes() {
        let Some(index) = ALPHABET.iter().position(|byte| *byte == character) else {
            return false;
        };
        let Ok(mut carry) = u32::try_from(index) else {
            return false;
        };
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 255) as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return false;
        }
    }
    // Exact decoded size including leading zero bytes rules out noncanonical
    // padding; positional base58 has only one representation for the integer.
    let leading = value.bytes().take_while(|byte| *byte == b'1').count();
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map_or(0, |i| N - i);
    significant > 0 && leading + significant == N
}

/// Stable binding of public SSH connection coordinates; callers canonicalize the host key.
#[must_use]
pub fn host_binding(address: &str, user: &str, port: u16, host_key: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"erpc-solana-native-host-v1");
    for value in [address, user, &port.to_string(), host_key] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

/// The rule for a native node's name, which the host's controller holds it
/// to as well: a lowercase letter, then lowercase letters, digits and `-`,
/// 32 characters at most.
/// # Errors
/// Says what the name must look like.
pub fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 32
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "{name:?} is not a native Solana node name: start with a lowercase letter \
             and use at most 32 lowercase letters, digits and `-`"
        ));
    }
    Ok(())
}

impl Contract {
    /// A dedicated non-voting RPC host has no vote or withdrawal account.
    #[must_use]
    pub fn is_rpc(&self) -> bool {
        self.profile == "agave-native-rpc"
    }
    /// Refuse ambiguous ownership, unsupported profiles and unsafe disk bindings.
    /// # Errors
    /// Any malformed or unsupported public field is refused before remote use.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 || !matches!(self.profile.as_str(), "agave-native" | "agave-native-rpc")
        {
            return Err("unsupported native Solana ownership format".into());
        }
        check_name(&self.name)?;
        if self.inventory_id.len() != 26
            || !self
                .inventory_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            || !matches!(self.network.as_str(), "mainnet" | "testnet")
            || self.host_binding.len() != 64
            || !self
                .host_binding
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid native Solana host ownership".into());
        }
        if !public_key(&self.identity_account) {
            return Err("native node requires a canonical public identity".into());
        }
        let keys = if self.is_rpc() {
            if self.vote_account.is_some() || self.authority_account.is_some() {
                return Err("native RPC ownership cannot contain financial accounts".into());
            }
            vec![self.identity_account.as_str()]
        } else {
            vec![
                self.identity_account.as_str(),
                self.vote_account
                    .as_deref()
                    .ok_or("validator vote account is missing")?,
                self.authority_account
                    .as_deref()
                    .ok_or("validator withdrawal authority is missing")?,
            ]
        };
        if keys.iter().any(|key| !public_key(key))
            || keys
                .iter()
                .enumerate()
                .any(|(index, key)| keys[..index].contains(key))
        {
            return Err("native validator requires distinct canonical public accounts".into());
        }
        let volumes = [
            &self.volumes.accounts,
            &self.volumes.ledger,
            &self.volumes.snapshots,
        ];
        if volumes.iter().any(|value| !uuid(value))
            || volumes[0] == volumes[1]
            || volumes[0] == volumes[2]
            || volumes[1] == volumes[2]
        {
            return Err("native validator requires three distinct filesystem UUIDs".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> Contract {
        Contract {
            schema: 1,
            profile: "agave-native".into(),
            inventory_id: "a".repeat(26),
            name: "fixture".into(),
            network: "mainnet".into(),
            host_binding: "b".repeat(64),
            identity_account: "2".repeat(44),
            vote_account: Some("3".repeat(44)),
            authority_account: Some("4".repeat(44)),
            volumes: Volumes {
                accounts: "10000000-0000-0000-0000-000000000001".into(),
                ledger: "10000000-0000-0000-0000-000000000002".into(),
                snapshots: "10000000-0000-0000-0000-000000000003".into(),
            },
        }
    }
    #[test]
    fn wrong_profiles_account_padding_and_duplicate_disks_are_rejected() {
        let valid = contract();
        valid.validate().unwrap();
        for (field, replacement) in [
            ("profile", "solv"),
            ("name", "../../escape"),
            ("network", "devnet"),
            ("identity_account", &"1".repeat(32)),
            ("identity_account", &"z".repeat(44)),
            ("identity_account", &format!("1{}", valid.identity_account)),
            ("identity_account", valid.vote_account.as_deref().unwrap()),
        ] {
            let mut value = serde_json::to_value(&valid).unwrap();
            value[field] = replacement.into();
            let changed: Contract = serde_json::from_value(value).unwrap();
            assert!(changed.validate().is_err(), "{field}");
        }
        let mut changed = valid.clone();
        changed
            .volumes
            .snapshots
            .clone_from(&changed.volumes.accounts);
        assert!(changed.validate().is_err());
        let mut extra = serde_json::to_value(valid).unwrap();
        extra["private_key"] = "inert unexpected field".into();
        assert!(serde_json::from_value::<Contract>(extra).is_err());
    }

    #[test]
    fn a_name_the_host_would_refuse_is_refused_with_the_rule() {
        for name in ["a", "tv2", "rpc-test", "v1-2-3", &"a".repeat(32)] {
            check_name(name).unwrap();
        }
        for name in [
            "",
            "my_val",
            "1val",
            "MyVal",
            "my.val",
            "-val",
            "val/x",
            &"a".repeat(33),
        ] {
            assert_eq!(
                check_name(name).unwrap_err(),
                format!(
                    "{name:?} is not a native Solana node name: start with a lowercase letter \
                     and use at most 32 lowercase letters, digits and `-`"
                )
            );
            let mut named = contract();
            named.name = name.into();
            assert_eq!(named.validate(), check_name(name), "{name:?}");
        }
        // The rest of the ownership keeps its own message.
        let mut other = contract();
        other.network = "devnet".into();
        assert_eq!(
            other.validate().unwrap_err(),
            "invalid native Solana host ownership"
        );
    }

    #[test]
    fn rpc_identity_is_explicit_and_does_not_invent_financial_accounts() {
        let mut rpc = contract();
        rpc.profile = "agave-native-rpc".into();
        assert!(rpc.validate().is_err());
        rpc.vote_account = None;
        rpc.authority_account = None;
        rpc.validate().unwrap();
        let encoded = serde_json::to_value(&rpc).unwrap();
        assert!(encoded["vote_account"].is_null());
        assert!(encoded["authority_account"].is_null());
        rpc.profile = "agave-native".into();
        assert!(rpc.validate().is_err());
    }
}
