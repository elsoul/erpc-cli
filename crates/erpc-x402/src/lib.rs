// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc-x402`: x402 payment client (EIP-3009) for the erpc CLI.
//!
//! Selects the ERPC Base EURC offer and signs one v2 payment payload.

#![forbid(unsafe_code)]

/// Crate name, used by `erpc version --json` to list workspace components.
pub const CRATE_NAME: &str = "erpc-x402";

use base64::{Engine as _, engine::general_purpose::STANDARD};
use erpc_wallet::{
    eurc::{
        DOMAIN_NAME, DOMAIN_VERSION, EURC_CONTRACT, TREASURY, TransferAuthorization, parse_decimal,
    },
    evm::{Address, EvmKey, hex},
};
use serde_json::{Value, json};

/// A validated offer from the requested ERPC resource.
pub struct Quote {
    resource: Value,
    accepted: Value,
    amount: u128,
    timeout: u64,
}

impl Quote {
    /// Select the pinned Base EURC rail for exactly this resource and RPC method.
    ///
    /// # Errors
    /// Refuses unsupported or malformed payment requirements.
    pub fn parse(body: &Value, url: &str, method: &str) -> Result<Self, String> {
        if body["x402Version"] != 2 || body["resource"]["url"] != url {
            return Err("x402 version or resource URL does not match the request".into());
        }
        let accepted = body["accepts"]
            .as_array()
            .and_then(|offers| {
                offers.iter().find(|r| {
                    r["network"] == "eip155:8453"
                        && r["scheme"] == "exact"
                        && r["asset"]
                            .as_str()
                            .is_some_and(|s| s.eq_ignore_ascii_case(EURC_CONTRACT))
                        && r["payTo"]
                            .as_str()
                            .is_some_and(|s| s.eq_ignore_ascii_case(TREASURY))
                        && r["extra"]["name"] == DOMAIN_NAME
                        && r["extra"]["version"] == DOMAIN_VERSION
                        && r["extra"]["erpc"]["methods"] == json!([method])
                })
            })
            .ok_or("ERPC did not offer the expected Base EURC payment for this method")?;
        let timeout = accepted["maxTimeoutSeconds"]
            .as_u64()
            .filter(|t| (1..=86400).contains(t))
            .ok_or("invalid x402 payment timeout")?;
        let amount = parse_decimal(accepted["amount"].as_str().unwrap_or_default())
            .map_err(|e| e.to_string())?;
        if amount == 0 {
            return Err("invalid zero x402 payment".into());
        }
        Ok(Self {
            resource: body["resource"].clone(),
            accepted: accepted.clone(),
            amount,
            timeout,
        })
    }

    /// Amount the operator must confirm, in millionths of a EURC.
    #[must_use]
    pub fn amount(&self) -> u128 {
        self.amount
    }

    /// Sign the confirmed amount for a single retry, using a fresh random nonce.
    ///
    /// # Errors
    /// Returns an error on RNG, clock or signing failure.
    pub fn sign(&self, key: &EvmKey, agreed_units: u128, now: u64) -> Result<String, String> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| "cannot generate an x402 nonce")?;
        let t = TransferAuthorization {
            from: key.address(),
            to: Address::parse(TREASURY).map_err(|e| e.to_string())?,
            value: self.amount,
            valid_after: now.saturating_sub(600),
            valid_before: now.checked_add(self.timeout).ok_or("invalid clock")?,
            nonce,
        };
        let signature = t.sign(key, agreed_units, now).map_err(|e| e.to_string())?;
        let payment = json!({"x402Version":2, "resource":self.resource, "accepted":self.accepted,
        "payload":{"signature":hex(&signature), "authorization":{
            "from":t.from.to_string(),"to":t.to.to_string(),"value":t.value.to_string(),
            "validAfter":t.valid_after.to_string(),"validBefore":t.valid_before.to_string(),"nonce":hex(&nonce)
        }}});
        Ok(STANDARD.encode(payment.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_matches_package() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
    }

    const URL: &str = "https://x402.erpc.global/v1/eth-mainnet";

    fn offer() -> Value {
        json!({"x402Version":2,"resource":{"url":URL},"accepts":[{
            "scheme":"exact","network":"eip155:8453","amount":"1000","asset":EURC_CONTRACT,
            "payTo":TREASURY,"maxTimeoutSeconds":120,
            "extra":{"name":"EURC","version":"2","erpc":{"methods":["eth_blockNumber"]}}
        }]})
    }

    #[test]
    fn validates_resource_method_domain_amount_and_recipient_before_signing() {
        for (pointer, bad) in [
            ("/x402Version", json!(1)),
            ("/resource/url", json!("other")),
            ("/accepts/0/extra/erpc/methods", json!(["eth_call"])),
            ("/accepts/0/payTo", json!(EURC_CONTRACT)),
            ("/accepts/0/asset", json!(TREASURY)),
            ("/accepts/0/network", json!("eip155:1")),
            ("/accepts/0/extra/version", json!("3")),
            ("/accepts/0/amount", json!("-1")),
            ("/accepts/0/maxTimeoutSeconds", json!(0)),
        ] {
            let mut challenge = offer();
            *challenge.pointer_mut(pointer).expect("fixture path") = bad;
            assert!(
                Quote::parse(&challenge, URL, "eth_blockNumber").is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn encoded_payment_carries_selected_offer_and_exact_signed_authorization() {
        let body = offer();
        let quote = Quote::parse(&body, URL, "eth_blockNumber").expect("quote");
        let key = EvmKey::generate().expect("test wallet");
        assert!(quote.sign(&key, 999, 12345).is_err());
        let signed = quote.sign(&key, 1000, 12345).expect("proof");
        let payload: Value =
            serde_json::from_slice(&STANDARD.decode(signed).expect("base64")).expect("payload");
        let auth = &payload["payload"]["authorization"];
        assert_eq!(payload["accepted"], body["accepts"][0]);
        assert_eq!(payload["resource"], body["resource"]);
        assert_eq!(auth["value"], "1000");
        assert_eq!(auth["validBefore"], "12465");
        assert_eq!(auth["from"], key.address().to_string());
        let transfer = TransferAuthorization {
            from: key.address(),
            to: Address::parse(TREASURY).expect("treasury"),
            value: 1000,
            valid_after: 11745,
            valid_before: 12465,
            nonce: erpc_wallet::eurc::parse_bytes32(auth["nonce"].as_str().expect("nonce"))
                .expect("bytes"),
        };
        assert_eq!(
            payload["payload"]["signature"],
            hex(&transfer.sign(&key, 1000, 12345).expect("signature"))
        );
    }
}
