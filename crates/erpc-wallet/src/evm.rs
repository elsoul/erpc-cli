// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! An EVM account in memory: its key, its address, and signing a digest.
//!
//! The key arrives as text from 1Password and lives only in this value; it
//! is zeroed when dropped and never formatted.

use core::fmt;
use core::fmt::Write as _;

use k256::ecdsa::SigningKey;
use sha3::{Digest as _, Keccak256};
use zeroize::Zeroizing;

/// Keccak-256 of `data`.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// A 20-byte EVM address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Parses `0x` and 40 hex digits, any case.
    ///
    /// # Errors
    ///
    /// [`WalletError::Address`] for anything else.
    pub fn parse(text: &str) -> Result<Self, WalletError> {
        let hex = text.strip_prefix("0x").ok_or(WalletError::Address)?;
        let bytes = from_hex::<20>(hex).ok_or(WalletError::Address)?;
        Ok(Self(bytes))
    }

    /// The address with the EIP-55 checksum, as wallets show it.
    #[must_use]
    pub fn checksummed(&self) -> String {
        let lower = hex(&self.0)[2..].to_owned();
        let hash = keccak256(lower.as_bytes());
        let mut out = String::from("0x");
        for (i, c) in lower.chars().enumerate() {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
            out.push(if nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            });
        }
        out
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.checksummed())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.checksummed())
    }
}

/// `N` bytes from exactly `2 * N` hex digits.
pub(crate) fn from_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// What went wrong with a key, an address or a signature.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalletError {
    /// The key is not 32 bytes of hex, or not a valid secp256k1 key.
    #[error("the wallet key is not a private key: 64 hex digits, with or without 0x")]
    Key,
    /// An address is not `0x` and 40 hex digits.
    #[error("not an address: 0x and 40 hex digits")]
    Address,
    /// Signing failed.
    #[error("the wallet could not sign: {0}")]
    Sign(String),
    /// What is to be signed is not what erpc signs for a top-up.
    #[error("{0}")]
    Refused(String),
}

/// A private key, held only while it signs.
pub struct EvmKey(SigningKey);

impl fmt::Debug for EvmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EvmKey({})", self.address())
    }
}

impl EvmKey {
    /// The key from its hex text (64 digits, `0x` optional, surrounding
    /// whitespace ignored). The text is the caller's to drop.
    ///
    /// # Errors
    ///
    /// [`WalletError::Key`] when it is not a key.
    pub fn from_hex(text: &str) -> Result<Self, WalletError> {
        let trimmed = text.trim();
        let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let bytes = Zeroizing::new(from_hex::<32>(hex).ok_or(WalletError::Key)?);
        SigningKey::from_slice(bytes.as_ref())
            .map(Self)
            .map_err(|_| WalletError::Key)
    }

    /// A new key from the system's random source.
    ///
    /// # Errors
    ///
    /// [`WalletError::Key`] when there is no randomness (or, vanishingly,
    /// every draw falls outside the curve's order).
    pub fn generate() -> Result<Self, WalletError> {
        for _ in 0..8 {
            let mut bytes = Zeroizing::new([0u8; 32]);
            getrandom::fill(bytes.as_mut()).map_err(|_| WalletError::Key)?;
            if let Ok(key) = SigningKey::from_slice(bytes.as_ref()) {
                return Ok(Self(key));
            }
        }
        Err(WalletError::Key)
    }

    /// The key as 64 hex digits with `0x`, for storing it in 1Password; the
    /// text is wiped when dropped.
    #[must_use]
    pub fn secret_hex(&self) -> Zeroizing<String> {
        // The raw bytes are a copy of the key too: wiped as well.
        let bytes = Zeroizing::new(<[u8; 32]>::from(self.0.to_bytes()));
        Zeroizing::new(hex(bytes.as_ref()))
    }

    /// The account's address.
    #[must_use]
    pub fn address(&self) -> Address {
        let point = self.0.verifying_key().to_sec1_point(false);
        let hash = keccak256(&point.as_bytes()[1..]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        Address(out)
    }

    /// Signs a 32-byte digest: `r || s || v`, with `v` 27 or 28.
    ///
    /// # Errors
    ///
    /// Retained as a fallible interface for callers; signing a fixed-length
    /// digest with an already validated key is infallible in this backend.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], WalletError> {
        let (signature, recovery) = self.0.sign_prehash_recoverable(digest);
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&signature.to_bytes());
        out[64] = 27 + recovery.to_byte();
        Ok(out)
    }
}

/// `bytes` as `0x` and lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Address, EvmKey, WalletError, keccak256};

    /// The EIP-712 example's key: keccak256("cow").
    pub(crate) fn cow() -> EvmKey {
        EvmKey::from_hex(&super::hex(&keccak256(b"cow"))).expect("key")
    }

    #[test]
    fn the_eip712_examples_key_has_its_address() {
        assert_eq!(
            cow().address().to_string(),
            "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
        );
        assert_eq!(
            Address::parse("0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826"),
            Ok(cow().address())
        );
    }

    #[test]
    fn a_key_or_address_that_is_not_one_is_refused() {
        for bad in ["", "0x12", &"g".repeat(64), &"00".repeat(32)] {
            assert_eq!(
                EvmKey::from_hex(bad).err(),
                Some(WalletError::Key),
                "{bad:?}"
            );
        }
        assert!(Address::parse("cd2a3d9f938e13cd947ec05abc7fe734df8dd826").is_err());
        assert!(Address::parse("0xcd2a").is_err());
    }

    #[test]
    fn a_new_key_reads_back_from_its_text_as_the_same_account() {
        let key = EvmKey::generate().expect("key");
        let again = EvmKey::from_hex(&key.secret_hex()).expect("parse");
        assert_eq!(key.address(), again.address());
        assert_ne!(key.address(), EvmKey::generate().expect("key").address());
    }

    #[test]
    fn debug_shows_the_address_not_the_key() {
        let shown = format!("{:?}", cow());
        assert!(shown.contains("CD2a3d9F"));
        assert!(!shown.contains("c85ef7d7"));
    }
}
