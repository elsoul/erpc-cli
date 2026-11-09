// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated consensus-hot custody and public identity; no transaction signing.
use k256::elliptic_curve::sec1::ToSec1Point as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Keccak256};
use zeroize::Zeroizing;

fn decode<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid bounded hexadecimal key encoding");
    }
    let mut result = [0; N];
    for (index, slot) in result.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid bounded hexadecimal key encoding")?;
    }
    Ok(result)
}

fn hex(value: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(value.len() * 2);
    for byte in value {
        text.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        text.push(char::from(ALPHABET[usize::from(byte & 15)]));
    }
    text
}

pub(crate) fn point_address(value: &str) -> Result<String, &'static str> {
    let bytes = decode::<65>(value)?;
    if bytes[0] != 4 || hex(&bytes) != value {
        return Err("canonical uncompressed public key required");
    }
    k256::PublicKey::from_sec1_bytes(&bytes).map_err(|_| "invalid public point")?;
    let hash = Keccak256::digest(&bytes[1..]);
    Ok(format!("0x{}", hex(&hash[12..])))
}

/// Canonical public Ethereum-style address; no key material is accepted here.
/// # Errors
/// Refuses zero, noncanonical case or malformed addresses.
pub fn address(value: &str) -> Result<(), &'static str> {
    let digits = value
        .strip_prefix("0x")
        .ok_or("canonical public address required")?;
    let bytes = decode::<20>(digits)?;
    if bytes == [0; 20] || hex(&bytes) != digits {
        return Err("nonzero lowercase public address required");
    }
    Ok(())
}

/// An explicitly selected positive USDC ceiling in fixed six-decimal units.
/// # Errors
/// Refuses ambiguous notation, overflow and zero; never chooses a funding amount.
pub fn usdc_units(value: &str) -> Result<u64, &'static str> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || whole.len() > 12
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || (whole.len() > 1 && whole.starts_with('0'))
        || fraction.len() > 6
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || (value.contains('.') && fraction.is_empty())
    {
        return Err("explicit positive USDC ceiling with at most six decimals required");
    }
    let whole = whole.parse::<u64>().map_err(|_| "invalid USDC ceiling")?;
    let fraction = format!("{fraction:0<6}")
        .parse::<u64>()
        .map_err(|_| "invalid USDC ceiling")?;
    let units = whole
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_add(fraction))
        .ok_or("USDC ceiling overflows")?;
    if units == 0 {
        return Err("dedicated hot-balance ceiling must be positive");
    }
    Ok(units)
}

/// Separate public cold validator and dedicated consensus-hot identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// External validator/funds-management account; its private key stays external.
    pub validator: String,
    /// Dedicated minimum-balance consensus signer address.
    pub signer: String,
    /// Original uncompressed SEC1 public point, allowing native host verification.
    pub signer_public_key: String,
    /// Operator-selected ceiling before first custody and first activation.
    pub max_hot_usdc: String,
}
impl Identity {
    /// Bind the public point to the hot address and keep cold authority separate.
    /// # Errors
    /// Refuses malformed or identical roles and substituted public material.
    pub fn validate(&self) -> Result<(), &'static str> {
        address(&self.validator)?;
        address(&self.signer)?;
        usdc_units(&self.max_hot_usdc)?;
        let bytes = decode::<65>(&self.signer_public_key)?;
        if bytes[0] != 4 || hex(&bytes) != self.signer_public_key {
            return Err("canonical uncompressed consensus public key required");
        }
        k256::PublicKey::from_sec1_bytes(&bytes).map_err(|_| "invalid consensus public point")?;
        let hash = Keccak256::digest(&bytes[1..]);
        if self.validator == self.signer || self.signer != format!("0x{}", hex(&hash[12..])) {
            return Err(
                "consensus signer and external validator authority differ from their binding",
            );
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeKey {
    key: SecretString,
}

/// Original native JSON is retained as concealed text, without formatting changes.
pub struct HotMaterial {
    original: SecretString,
    signer: String,
    public_key: String,
}
impl std::fmt::Debug for HotMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HotMaterial([REDACTED])")
    }
}
impl HotMaterial {
    /// Validate an operator-provided native `node_config.json` key object.
    /// No key is generated and no signature is produced.
    /// # Errors
    /// Refuses extra fields, malformed scalar or oversized content without echoing it.
    pub fn parse(original: SecretString) -> Result<Self, &'static str> {
        if original.expose_secret().len() > 4096 {
            return Err("native consensus key object exceeds its bound");
        }
        let value: NativeKey = serde_json::from_str(original.expose_secret())
            .map_err(|_| "invalid concealed native consensus key object")?;
        let encoded = value.key.expose_secret();
        let scalar = Zeroizing::new(decode::<32>(encoded.strip_prefix("0x").unwrap_or(encoded))?);
        let key =
            k256::SecretKey::from_slice(scalar.as_ref()).map_err(|_| "invalid consensus scalar")?;
        let point = key.public_key().to_sec1_point(false);
        let public_key = hex(point.as_bytes());
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        Ok(Self {
            original,
            signer: format!("0x{}", hex(&hash[12..])),
            public_key,
        })
    }
    /// Build the public identity while refusing to import the cold key as hot.
    /// # Errors
    /// Refuses invalid or identical cold/hot identities.
    pub fn identity(&self, validator: &str, max_hot_usdc: &str) -> Result<Identity, &'static str> {
        let value = Identity {
            validator: validator.into(),
            signer: self.signer.clone(),
            signer_public_key: self.public_key.clone(),
            max_hot_usdc: max_hot_usdc.into(),
        };
        value.validate()?;
        Ok(value)
    }
    /// Original native bytes, only for concealed transport to encrypted custody.
    #[must_use]
    pub fn original(&self) -> &SecretString {
        &self.original
    }
    pub(crate) fn public_identity(&self) -> (&str, &str) {
        (&self.signer, &self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> SecretString {
        // Public test scalar, constructed only in tests; never an operational key.
        format!("{{\"key\":\"{}\"}}", "01".repeat(32)).into()
    }
    #[test]
    fn original_material_is_retained_and_cold_authority_cannot_be_reused() {
        let original = fixture();
        let key = HotMaterial::parse(original.clone()).unwrap();
        assert_eq!(key.original().expose_secret(), original.expose_secret());
        assert_eq!(format!("{key:?}"), "HotMaterial([REDACTED])");
        assert!(key.identity(&key.signer, "0.01").is_err());
        let mut public = key
            .identity(&format!("0x{}", "ab".repeat(20)), "0.01")
            .unwrap();
        public.validate().unwrap();
        public.signer = format!("0x{}", "cd".repeat(20));
        assert!(public.validate().is_err());
    }
    #[test]
    fn malformed_key_objects_do_not_echo_key_material_or_accept_extra_authority() {
        for input in [
            format!("{{\"key\":\"{}\"}}", "00".repeat(32)),
            format!("{{\"key\":\"{}\",\"cold_key\":\"inert\"}}", "01".repeat(32)),
            format!(
                "{{\"key\":\"{}\",\"key\":\"{}\"}}",
                "01".repeat(32),
                "02".repeat(32)
            ),
            "{\"key\":\"private fixture invalid\"}".into(),
        ] {
            let error = HotMaterial::parse(input.clone().into()).unwrap_err();
            assert!(!error.contains(&input));
            assert!(!error.contains("private fixture"));
        }
        assert!(address(&format!("0x{}", "AB".repeat(20))).is_err());
        assert!(address(&format!("0x{}", "00".repeat(20))).is_err());
    }
    #[test]
    fn funding_ceiling_is_explicit_fixed_point_and_not_an_implicit_transfer() {
        assert_eq!(usdc_units("0.000001"), Ok(1));
        assert_eq!(usdc_units("1.25"), Ok(1_250_000));
        for value in [
            "0",
            "-1",
            "1e3",
            "NaN",
            "1.",
            "01",
            "0.0000001",
            "999999999999999999999",
        ] {
            assert!(usdc_units(value).is_err());
        }
    }
}
