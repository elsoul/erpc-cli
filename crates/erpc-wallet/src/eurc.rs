// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Buying ERPC Credit with EURC on Base: the one EIP-3009
//! `TransferWithAuthorization` erpc signs.
//!
//! user-api prepares the transfer and relays it, paying the gas. erpc does
//! not sign what it is handed: the contract, its EIP-712 domain and the
//! receiving treasury are fixed here, and a transfer to anywhere else, on
//! another chain or for another amount than the person agreed to, is
//! refused before the key is read. A changed treasury therefore needs a new
//! erpc, which is the point.

use crate::evm::{Address, EvmKey, WalletError, from_hex, keccak256};

/// Base mainnet.
pub const CHAIN_ID: u64 = 8453;

/// Circle's EURC on Base (developers.circle.com/stablecoins/eurc-contract-addresses).
pub const EURC_CONTRACT: &str = "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42";

/// The EURC contract's EIP-712 name and version on Base.
pub const DOMAIN_NAME: &str = "EURC";
/// See [`DOMAIN_NAME`].
pub const DOMAIN_VERSION: &str = "2";

/// ERPC's treasury on Base, the only address a top-up pays.
pub const TREASURY: &str = "0x490842c32b83653dfd06eeeb53b9dbbf5d87f597";

/// EURC has six decimal places.
pub const DECIMALS: u32 = 6;

const DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const TRANSFER_TYPE: &[u8] = b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

/// A transfer of EURC on Base, as EIP-3009 authorises it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferAuthorization {
    /// The paying wallet.
    pub from: Address,
    /// Who receives it.
    pub to: Address,
    /// The amount in EURC's smallest unit (six decimals).
    pub value: u128,
    /// Valid after this Unix time.
    pub valid_after: u64,
    /// Valid before this Unix time.
    pub valid_before: u64,
    /// The authorisation's one-time nonce.
    pub nonce: [u8; 32],
}

fn word_u128(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

fn word_address(address: &Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&address.0);
    out
}

fn domain_separator() -> Result<[u8; 32], WalletError> {
    let contract = Address::parse(EURC_CONTRACT)?;
    let mut data = Vec::with_capacity(32 * 5);
    data.extend_from_slice(&keccak256(DOMAIN_TYPE));
    data.extend_from_slice(&keccak256(DOMAIN_NAME.as_bytes()));
    data.extend_from_slice(&keccak256(DOMAIN_VERSION.as_bytes()));
    data.extend_from_slice(&word_u128(u128::from(CHAIN_ID)));
    data.extend_from_slice(&word_address(&contract));
    Ok(keccak256(&data))
}

impl TransferAuthorization {
    /// The EIP-712 digest a wallet signs.
    ///
    /// # Errors
    ///
    /// Only if the pinned contract address were malformed.
    pub fn digest(&self) -> Result<[u8; 32], WalletError> {
        let mut data = Vec::with_capacity(32 * 7);
        data.extend_from_slice(&keccak256(TRANSFER_TYPE));
        data.extend_from_slice(&word_address(&self.from));
        data.extend_from_slice(&word_address(&self.to));
        data.extend_from_slice(&word_u128(self.value));
        data.extend_from_slice(&word_u128(u128::from(self.valid_after)));
        data.extend_from_slice(&word_u128(u128::from(self.valid_before)));
        data.extend_from_slice(&self.nonce);
        let mut message = Vec::with_capacity(66);
        message.extend_from_slice(b"\x19\x01");
        message.extend_from_slice(&domain_separator()?);
        message.extend_from_slice(&keccak256(&data));
        Ok(keccak256(&message))
    }

    /// Refuses a transfer that is not the top-up the person agreed to: to
    /// another address than the treasury, from another wallet, for another
    /// amount, or one that has expired or lasts more than a day.
    ///
    /// # Errors
    ///
    /// [`WalletError::Refused`] naming what does not match.
    pub fn check(&self, payer: &Address, agreed_value: u128, now: u64) -> Result<(), WalletError> {
        let refuse = |why: String| Err(WalletError::Refused(why));
        if self.to != Address::parse(TREASURY)? {
            return refuse(format!(
                "the transfer pays {}, not ERPC's treasury {TREASURY}",
                self.to
            ));
        }
        if self.from != *payer {
            return refuse(format!(
                "the transfer is from {}, not this wallet {payer}",
                self.from
            ));
        }
        if self.value != agreed_value {
            return refuse(format!(
                "the transfer is for {} EURC, not the {} agreed",
                format_eurc(self.value),
                format_eurc(agreed_value)
            ));
        }
        if self.valid_before <= now || self.valid_before > now + 86_400 {
            return refuse(
                "the transfer's validity window is not from now to within a day".to_owned(),
            );
        }
        Ok(())
    }

    /// Signs it with `key`, after [`Self::check`].
    ///
    /// # Errors
    ///
    /// What [`Self::check`] refuses, and [`WalletError::Sign`].
    pub fn sign(
        &self,
        key: &EvmKey,
        agreed_value: u128,
        now: u64,
    ) -> Result<[u8; 65], WalletError> {
        self.check(&key.address(), agreed_value, now)?;
        key.sign_digest(&self.digest()?)
    }
}

/// An amount in EURC's smallest unit, as `12.345678`.
#[must_use]
pub fn format_eurc(atomic: u128) -> String {
    let unit = 10u128.pow(DECIMALS);
    format!("{}.{:06}", atomic / unit, atomic % unit)
}

/// A uint256 given as decimal text, when it fits in 128 bits.
///
/// # Errors
///
/// [`WalletError::Refused`] for anything else.
pub fn parse_decimal(text: &str) -> Result<u128, WalletError> {
    if text.is_empty() || text.len() > 39 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(WalletError::Refused(format!("{text:?} is not an amount")));
    }
    text.parse()
        .map_err(|_| WalletError::Refused(format!("{text:?} is out of range")))
}

/// A bytes32 given as `0x` and 64 hex digits.
///
/// # Errors
///
/// [`WalletError::Refused`] for anything else.
pub fn parse_bytes32(text: &str) -> Result<[u8; 32], WalletError> {
    text.strip_prefix("0x")
        .and_then(from_hex::<32>)
        .ok_or_else(|| WalletError::Refused(format!("{text:?} is not 32 bytes of hex")))
}

#[cfg(test)]
mod tests {
    use super::{TREASURY, TransferAuthorization, format_eurc, parse_decimal};
    use crate::evm::{Address, EvmKey, WalletError, hex, keccak256};

    fn cow() -> EvmKey {
        EvmKey::from_hex(&hex(&keccak256(b"cow"))).expect("key")
    }

    fn transfer() -> TransferAuthorization {
        TransferAuthorization {
            from: cow().address(),
            to: Address::parse(TREASURY).expect("treasury"),
            value: 12_345_678,
            valid_after: 0,
            valid_before: 1_792_900_000,
            nonce: [0x11; 32],
        }
    }

    /// Made with viem 2.57.4 (`hashTypedData`, `signTypedData`) for the same
    /// key, domain and message.
    #[test]
    fn the_digest_and_signature_are_the_reference_implementations() {
        let t = transfer();
        assert_eq!(
            hex(&t.digest().expect("digest")),
            "0x1e2993864d72ebab30e9c1fa34e7d68794458c23b14857c61b7e0d6e257f4167"
        );
        let now = 1_792_899_000;
        assert_eq!(
            hex(&t.sign(&cow(), 12_345_678, now).expect("signature")),
            "0xbf4068dff607960f603b8e04c8e06a39db0f2a4ea08365261dafcb33eda8c9a456aef4ff9625fe2110439fecde176119790f464ef782f32c373de8b447be2d7f1b"
        );
    }

    #[test]
    fn a_transfer_that_is_not_the_agreed_top_up_is_not_signed() {
        let now = 1_792_899_000;
        let elsewhere = TransferAuthorization {
            to: Address([0x22; 20]),
            ..transfer()
        };
        let more = 12_345_679;
        let stale = TransferAuthorization {
            valid_before: now,
            ..transfer()
        };
        let other_payer = TransferAuthorization {
            from: Address([0x33; 20]),
            ..transfer()
        };
        for (t, agreed) in [
            (elsewhere, 12_345_678),
            (transfer(), more),
            (stale, 12_345_678),
            (other_payer, 12_345_678),
        ] {
            assert!(matches!(
                t.sign(&cow(), agreed, now),
                Err(WalletError::Refused(_))
            ));
        }
    }

    #[test]
    fn amounts_read_and_print_with_six_decimals() {
        assert_eq!(format_eurc(12_345_678), "12.345678");
        assert_eq!(format_eurc(5), "0.000005");
        assert_eq!(parse_decimal("12345678"), Ok(12_345_678));
        assert!(parse_decimal("-1").is_err());
        assert!(parse_decimal("1.5").is_err());
    }
}
