// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public deposit-data validation (SSZ and BLS). This module has no signing or RPC transport.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::validator::{Network, address, hex};

fn bytes(value: &Value, length: usize) -> Result<Vec<u8>, String> {
    let text = value.as_str().ok_or("deposit field must be hex text")?;
    if !hex(text, length) {
        return Err("deposit field has invalid length or hex".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| "invalid hex".into()))
        .collect()
}

fn hash(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

fn same(value: &Value, expected: &[u8; 32]) -> Result<(), String> {
    if bytes(value, 32)? != expected {
        return Err("deposit SSZ root mismatch".into());
    }
    Ok(())
}

/// Validated public deposit details. No transaction is constructed or submitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewed {
    /// Validator BLS public key, with 0x prefix.
    pub pubkey: String,
    /// Expected execution withdrawal address, distinct from fee recipient.
    pub withdrawal_address: String,
    /// Initial activation deposit, in gwei.
    pub amount_gwei: u64,
}

/// Validate one initial 32 ETH deposit against independently supplied destination and key.
///
/// Validates network/fork, withdrawal prefix (01/02), amount, SSZ message/data roots,
/// and proof-of-possession BLS signature over the deposit domain. Multi-key batches,
/// legacy BLS withdrawal authority and top-ups are not silently accepted.
/// # Errors
/// Refuses any mismatched field, invalid root, public key or signature.
pub fn review(
    data: &Value,
    net: Network,
    expected_pubkey: &str,
    withdrawal: &str,
) -> Result<Reviewed, String> {
    let entries = data.as_array().ok_or("deposit file must be an array")?;
    if entries.len() != 1 {
        return Err("review one validator deposit at a time".into());
    }
    let d = &entries[0];
    if d["network_name"] != net.name || d["fork_version"] != net.fork_version {
        return Err("deposit network or genesis fork version mismatch".into());
    }
    let pk = bytes(&d["pubkey"], 48)?;
    let key = format!(
        "0x{}",
        d["pubkey"]
            .as_str()
            .ok_or("missing key")?
            .to_ascii_lowercase()
    );
    if key != expected_pubkey {
        return Err("deposit public key differs from imported validator".into());
    }
    let withdrawal = address(withdrawal)?;
    let wc = bytes(&d["withdrawal_credentials"], 32)?;
    let expected = bytes(&Value::String(withdrawal[2..].to_owned()), 20)?;
    if ![1, 2].contains(&wc[0]) || wc[1..12].iter().any(|b| *b != 0) || wc[12..] != expected {
        return Err("deposit withdrawal credentials differ from reviewed address".into());
    }
    let amount = d["amount"].as_u64().ok_or("invalid deposit amount")?;
    if amount != 32_000_000_000 {
        return Err("only an initial 32 ETH activation deposit is supported".into());
    }
    let mut amount_root = [0u8; 32];
    amount_root[..8].copy_from_slice(&amount.to_le_bytes());
    let zero = [0u8; 32];
    let pk_root = hash(&pk, &[0u8; 16]);
    let left = hash(&pk_root, &wc);
    let message_root = hash(&left, &hash(&amount_root, &zero));
    same(&d["deposit_message_root"], &message_root)?;
    let signature = bytes(&d["signature"], 96)?;
    let signature_root = hash(&hash(&signature[..64], &[]), &hash(&signature[64..], &zero));
    same(
        &d["deposit_data_root"],
        &hash(&left, &hash(&amount_root, &signature_root)),
    )?;
    let fork = bytes(&d["fork_version"], 4)?;
    let mut fork_chunk = zero;
    fork_chunk[..4].copy_from_slice(&fork);
    let fork_root = hash(&fork_chunk, &zero);
    let mut domain = zero;
    domain[0] = 3;
    domain[4..].copy_from_slice(&fork_root[..28]);
    let signing_root = hash(&message_root, &domain);
    let public =
        blst::min_pk::PublicKey::key_validate(&pk).map_err(|_| "invalid BLS public key")?;
    let sig = blst::min_pk::Signature::sig_validate(&signature, true)
        .map_err(|_| "invalid BLS signature")?;
    if sig.verify(
        true,
        &signing_root,
        b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
        &[],
        &public,
        true,
    ) != blst::BLST_ERROR::BLST_SUCCESS
    {
        return Err("deposit signature verification failed".into());
    }
    Ok(Reviewed {
        pubkey: key,
        withdrawal_address: withdrawal,
        amount_gwei: amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_batch_or_wrong_network_can_be_reviewed() {
        let net = crate::validator::network("hoodi").expect("network");
        assert!(review(&serde_json::json!([]), net, "", "").is_err());
        assert!(review(&serde_json::json!([{}, {}]), net, "", "").is_err());
        assert!(
            review(
                &serde_json::json!([{"network_name":"mainnet","fork_version":"00000000"}]),
                net,
                "",
                ""
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod signature_tests {
    #[test]
    fn matching_ssz_with_wrong_signature_still_fails_bls() {
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("../tests/deposit-hoodi.json"))
                .expect("public vector");
        let pk = super::bytes(&value[0]["pubkey"], 48).expect("pubkey");
        let wc = super::bytes(&value[0]["withdrawal_credentials"], 32).expect("credentials");
        let zero = [0u8; 32];
        let mut amount = zero;
        amount[..8].copy_from_slice(&32_000_000_000u64.to_le_bytes());
        let signature = [0u8; 96];
        let root = super::hash(
            &super::hash(&super::hash(&pk, &[0u8; 16]), &wc),
            &super::hash(
                &amount,
                &super::hash(
                    &super::hash(&signature[..64], &[]),
                    &super::hash(&signature[64..], &zero),
                ),
            ),
        );
        value[0]["signature"] = serde_json::json!("00".repeat(96));
        value[0]["deposit_data_root"] =
            serde_json::json!(root.iter().fold(String::new(), |mut text, byte| {
                use core::fmt::Write as _;
                write!(text, "{byte:02x}").expect("string");
                text
            }));
        let key = format!("0x{}", value[0]["pubkey"].as_str().expect("key"));
        let withdrawal = format!(
            "0x{}",
            &value[0]["withdrawal_credentials"]
                .as_str()
                .expect("credentials")[24..]
        );
        assert!(
            super::review(
                &value,
                crate::validator::network("hoodi").expect("hoodi"),
                &key,
                &withdrawal
            )
            .expect_err("invalid BLS")
            .contains("BLS")
        );
    }
}
