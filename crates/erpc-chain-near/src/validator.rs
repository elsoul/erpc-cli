// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated Ed25519 consensus keys; owner account transaction keys stay external.
use ed25519_dalek::{SigningKey, VerifyingKey};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use zeroize::Zeroizing;

/// Validate a NEAR named or implicit account without accepting path/shell syntax.
/// # Errors
/// Refuses malformed account IDs and ambiguous separators.
pub fn account(value: &str) -> Result<(), String> {
    if !(2..=64).contains(&value.len()) {
        return Err("NEAR account IDs must be 2 to 64 bytes".into());
    }
    let mut separator = true;
    for byte in value.bytes() {
        let next_separator = matches!(byte, b'.' | b'-' | b'_');
        if (!byte.is_ascii_lowercase() && !byte.is_ascii_digit() && !next_separator)
            || (separator && next_separator)
        {
            return Err("invalid NEAR account ID".into());
        }
        separator = next_separator;
    }
    if separator {
        return Err("invalid NEAR account ID".into());
    }
    Ok(())
}

/// Bounded canonical-size Base58 decoding for public and private Ed25519 material.
fn decode(value: &str, length: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if value.is_empty() || value.len() > 90 {
        return Err("invalid NEAR key encoding".into());
    }
    let mut out = Zeroizing::new(vec![0_u8; length]);
    for byte in value.bytes() {
        let mut carry = u32::try_from(
            ALPHABET
                .iter()
                .position(|b| *b == byte)
                .ok_or("invalid NEAR key encoding")?,
        )
        .map_err(|_| "invalid NEAR key encoding")?;
        for item in out.iter_mut().rev() {
            carry += u32::from(*item) * 58;
            *item = (carry & 255) as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return Err("NEAR key exceeds its expected size".into());
        }
    }
    let leading = value.bytes().take_while(|b| *b == b'1').count();
    let significant = out
        .iter()
        .position(|b| *b != 0)
        .map_or(0, |start| length - start);
    if leading + significant != length {
        return Err("NEAR key has noncanonical length".into());
    }
    Ok(out)
}

/// Validate an Ed25519 public key without accepting another signing scheme.
/// # Errors
/// Refuses unsupported schemes and invalid encoded lengths.
pub fn public_key(value: &str) -> Result<(), String> {
    let key = value
        .strip_prefix("ed25519:")
        .ok_or("NEAR validator keys must use Ed25519")?;
    let bytes = decode(key, 32)?;
    let bytes: &[u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid NEAR public key")?;
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| "invalid NEAR public point")?;
    if key.is_weak() {
        return Err("weak NEAR public keys are refused".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    account_id: String,
    public_key: String,
    secret_key: SecretString,
}

/// Check dedicated consensus material before sending it to a reserved host.
/// # Errors
/// Rejects other identities, malformed key files and mismatched derived public keys.
/// This cannot prove that a key has never been hosted; that assertion is separately required.
pub fn validate_key(
    input: &SecretString,
    expected_account: &str,
    expected_public: &str,
) -> Result<(), String> {
    account(expected_account)?;
    public_key(expected_public)?;
    if input.expose_secret().len() > 4096 {
        return Err("NEAR key file exceeds 4 KiB".into());
    }
    let parsed: KeyFile = serde_json::from_str(input.expose_secret())
        .map_err(|_| "invalid NEAR consensus key file")?;
    if parsed.account_id != expected_account || parsed.public_key != expected_public {
        return Err("NEAR key does not match the reserved validator identity".into());
    }
    let raw = decode(
        parsed
            .secret_key
            .expose_secret()
            .strip_prefix("ed25519:")
            .ok_or("NEAR consensus key must use Ed25519")?,
        64,
    )?;
    let public = decode(
        expected_public.strip_prefix("ed25519:").unwrap_or_default(),
        32,
    )?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    seed.copy_from_slice(&raw[..32]);
    let signer = SigningKey::from_bytes(&seed);
    if signer.verifying_key().as_bytes() != public.as_slice() || raw[32..] != public[..] {
        return Err("NEAR consensus secret does not derive the reserved public key".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn base58(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let zeroes = bytes.iter().take_while(|b| **b == 0).count();
        let mut digits = Vec::<u8>::new();
        for byte in &bytes[zeroes..] {
            let mut carry = u32::from(*byte);
            for digit in &mut digits {
                carry += u32::from(*digit) * 256;
                *digit = u8::try_from(carry % 58).unwrap();
                carry /= 58;
            }
            while carry != 0 {
                digits.push(u8::try_from(carry % 58).unwrap());
                carry /= 58;
            }
        }
        let mut output = "1".repeat(zeroes);
        for digit in digits.iter().rev() {
            output.push(char::from(ALPHABET[usize::from(*digit)]));
        }
        output
    }

    #[test]
    fn dedicated_key_file_must_derive_the_reserved_identity() {
        // Deliberately fixed inert test seed, never a funded account or live signer.
        let seed = [7_u8; 32];
        let signer = SigningKey::from_bytes(&seed);
        let public = signer.verifying_key().to_bytes();
        let expected = format!("ed25519:{}", base58(&public));
        public_key(&expected).unwrap();
        let mut bytes = seed.to_vec();
        bytes.extend_from_slice(&public);
        let payload = |bytes: &[u8]| {
            SecretString::from(
                serde_json::json!({
                    "account_id":"pool.testnet", "public_key":expected,
                    "secret_key":format!("ed25519:{}",base58(bytes)),
                })
                .to_string(),
            )
        };
        validate_key(&payload(&bytes), "pool.testnet", &expected).unwrap();
        assert!(validate_key(&payload(&bytes), "another.testnet", &expected).is_err());
        bytes[0] ^= 1;
        assert!(validate_key(&payload(&bytes), "pool.testnet", &expected).is_err());
        for bytes in [vec![0; 32], vec![1; 32], vec![255; 32]] {
            assert_eq!(*decode(&base58(&bytes), 32).unwrap(), bytes);
        }
    }

    #[test]
    fn account_ids_and_public_keys_refuse_injection_and_other_schemes() {
        for good in ["pool.near", "pool-1.testnet", "account_2", &"a".repeat(64)] {
            account(good).unwrap();
        }
        for bad in [
            "A.near",
            "a",
            ".pool",
            "pool.",
            "a..near",
            "a-_b",
            "x/../../secret",
            "x\ny",
        ] {
            assert!(account(bad).is_err());
        }
        assert!(public_key(&format!("ed25519:{}", "1".repeat(32))).is_err());
        assert!(public_key(&format!("ed25519:{}", "1".repeat(33))).is_err());
        assert!(public_key("secp256k1:refused").is_err());
        let private = SecretString::from("{\"secret_key\":\"private fixture\"}");
        let error = validate_key(
            &private,
            "node.near",
            &format!("ed25519:{}", "1".repeat(32)),
        )
        .unwrap_err();
        assert!(!error.contains("private fixture"));
    }
}
