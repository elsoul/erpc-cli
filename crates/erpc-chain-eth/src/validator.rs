// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Network-qualified validator custody and release policy. No transaction submission.

use serde_json::Value;

/// A validator network, distinct from the existing RPC network contract.
#[derive(Debug, Clone, Copy)]
pub struct Network {
    /// Client network selector.
    pub name: &'static str,
    /// Execution chain ID.
    pub chain_id: u64,
    /// Consensus genesis validators root (EIP-3076 identity).
    pub genesis_root: &'static str,
    /// Deposit signing fork version.
    pub fork_version: &'static str,
}

/// Qualified networks. Sepolia's restricted validator set is deliberately excluded.
/// Roots: eth-clients/mainnet and eth-clients/hoodi network metadata.
#[must_use]
pub fn network(name: &str) -> Option<Network> {
    match name {
        "mainnet" => Some(Network {
            name: "mainnet",
            chain_id: 1,
            genesis_root: "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            fork_version: "00000000",
        }),
        "hoodi" => Some(Network {
            name: "hoodi",
            chain_id: 560_048,
            genesis_root: "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
            fork_version: "10000910",
        }),
        _ => None,
    }
}

/// Strict fixed-length hex; accepting only this alphabet also makes values safe in config files.
#[must_use]
pub fn hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validate a nonzero EVM destination, returning its canonical spelling.
/// # Errors
/// Returns a fixed diagnostic without echoing untrusted input.
pub fn address(value: &str) -> Result<String, String> {
    let raw = value
        .strip_prefix("0x")
        .ok_or("address must start with 0x")?;
    if !hex(raw, 20) || raw.bytes().all(|b| b == b'0') {
        return Err("address must contain 20 nonzero-address bytes".into());
    }
    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}

/// Validate EIP-2335 metadata without decrypting or logging secret material.
/// # Errors
/// Refuses malformed keystores, missing crypto modules and ambiguous public keys.
pub fn keystore(value: &Value) -> Result<String, String> {
    let pubkey = value["pubkey"]
        .as_str()
        .ok_or("keystore has no public key")?;
    if value["version"] != 4 || !hex(pubkey, 48) || !value["crypto"].is_object() {
        return Err("expected an EIP-2335 version 4 keystore".into());
    }
    for part in ["kdf", "checksum", "cipher"] {
        if !value["crypto"][part]["function"].is_string()
            || !value["crypto"][part]["params"].is_object()
            || !value["crypto"][part]["message"].is_string()
        {
            return Err("keystore is missing a crypto module".into());
        }
    }
    Ok(format!("0x{}", pubkey.to_ascii_lowercase()))
}

/// Validate complete, single-key EIP-3076 interchange metadata before an import.
/// Lighthouse performs its own cryptographic/database checks after this structural gate.
/// # Errors
/// Refuses wrong-network, duplicate, absent or malformed signing history.
pub fn history(value: &Value, net: Network, pubkey: &str, fresh: bool) -> Result<(), String> {
    if value["metadata"]["interchange_format_version"] != "5"
        || value["metadata"]["genesis_validators_root"] != net.genesis_root
    {
        return Err("slashing history network or interchange version does not match".into());
    }
    let data = value["data"]
        .as_array()
        .ok_or("history data must be an array")?;
    if data.len() != 1 || data[0]["pubkey"].as_str() != Some(pubkey) {
        return Err("history must contain exactly the imported validator public key".into());
    }
    for (kind, fields) in [
        ("signed_blocks", &["slot"][..]),
        ("signed_attestations", &["source_epoch", "target_epoch"][..]),
    ] {
        let entries = data[0][kind]
            .as_array()
            .ok_or("history signing records are missing")?;
        if fresh && !entries.is_empty() {
            return Err(
                "new-key import refuses existing signing history; use managed migration".into(),
            );
        }
        for entry in entries {
            for field in fields {
                if entry[field]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_none()
                {
                    return Err("invalid slashing history slot or epoch".into());
                }
            }
            if let Some(root) = entry.get("signing_root").filter(|v| !v.is_null())
                && !root
                    .as_str()
                    .and_then(|v| v.strip_prefix("0x"))
                    .is_some_and(|v| hex(v, 32))
            {
                return Err("invalid signing root".into());
            }
        }
    }
    Ok(())
}

/// Refuse unsupported network releases and all downgrades. No fallback is permitted
/// for a new validator pin: clients must be fetched live by the caller.
/// # Errors
/// Invalid, obsolete or decreasing release tags are refused.
pub fn release(
    client: crate::releases::Client,
    proposed: &str,
    previous: Option<&str>,
) -> Result<(), String> {
    use crate::releases::{Client, read};
    let minimum = match client {
        Client::Reth => "v2.8.1",
        Client::Lighthouse => "v8.3.2",
    };
    let next = read(proposed).ok_or("invalid stable client release")?;
    if next.pre.is_some()
        || next < read(minimum).ok_or("invalid built-in release floor")?
        || previous.is_some_and(|old| read(old).is_none_or(|old| next < old))
    {
        return Err("validator release is below the network floor or is a downgrade".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn network_and_history_mismatch_fail_closed() {
        let net = network("hoodi").expect("hoodi");
        assert!(network("sepolia").is_none());
        assert!(network("holesky").is_none());
        let pk = format!("0x{}", "ab".repeat(48));
        let mut v = json!({"metadata":{"interchange_format_version":"5","genesis_validators_root":net.genesis_root},"data":[{"pubkey":pk,"signed_blocks":[],"signed_attestations":[]}]});
        assert!(history(&v, net, &pk, true).is_ok());
        assert!(history(&v, network("mainnet").expect("mainnet"), &pk, true).is_err());
        v["data"][0]["signed_blocks"] = json!([{"slot":"10"}]);
        assert!(history(&v, net, &pk, true).is_err());
        assert!(history(&v, net, &pk, false).is_ok());
        v["data"][0]["signed_blocks"][0]["slot"] = json!("bad");
        assert!(history(&v, net, &pk, false).is_err());
    }

    #[test]
    fn old_hoodi_schedule_and_downgrade_are_refused() {
        use crate::releases::Client;
        assert!(release(Client::Lighthouse, "v8.3.1", None).is_err());
        assert!(release(Client::Reth, "v2.8.1", Some("v2.9.0")).is_err());
        assert!(release(Client::Reth, "v2.8.1", None).is_ok());
    }
}
