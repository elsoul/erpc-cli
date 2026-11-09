// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Public registration payloads only. Consensus proofs, financial signing and broadcast are external.
use crate::contract::{Contract, hex, hex_bytes};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
/// Reviewed intent for the native staking precompile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    /// Bound immutable node/network/public-key ownership.
    pub contract: Contract,
    /// Decimal wei, avoiding JSON floating point.
    pub stake_wei: String,
    /// Commission in units of 1e18.
    #[serde(
        serialize_with = "serialize_commission",
        deserialize_with = "deserialize_commission"
    )]
    pub commission: u64,
}
// Serde serialize_with requires a borrowed field value.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_commission<S: serde::Serializer>(
    value: &u64,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}
fn deserialize_commission<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    let text = String::deserialize(deserializer)?;
    let value = text.parse::<u64>().map_err(serde::de::Error::custom)?;
    if text != value.to_string() {
        return Err(serde::de::Error::custom(
            "commission must be a canonical decimal string",
        ));
    }
    Ok(value)
}
impl Registration {
    /// Read a bare intent or the complete public review document without ignoring altered calldata.
    /// # Errors
    /// Refuses unknown fields, malformed values and any changed generated review field.
    pub fn parse_prepared(value: Value) -> Result<Self, String> {
        if let Some(inner) = value.get("registration") {
            let registration: Self =
                serde_json::from_value(inner.clone()).map_err(|_| "invalid registration schema")?;
            if registration.review()? != value {
                return Err(
                    "prepared review fields differ from the derived unsigned registration".into(),
                );
            }
            Ok(registration)
        } else {
            serde_json::from_value(value).map_err(|_| "invalid registration schema".into())
        }
    }
    /// Validate intent and create the exact 165-byte packed message.
    /// # Errors
    /// Refuses key-wallet reuse, too little self-stake, noncanonical amounts or excessive commission.
    pub fn payload(&self) -> Result<Vec<u8>, String> {
        self.contract.validate()?;
        if self.contract.role != "validator" {
            return Err("registration requires validator intent".into());
        }
        let stake = self
            .stake_wei
            .parse::<u128>()
            .map_err(|_| "invalid decimal wei amount")?;
        if stake.to_string() != self.stake_wei
            || stake < 100_000_000_000_000_000_000_000
            || self.commission > 1_000_000_000_000_000_000
        {
            return Err(
                "registration requires at least 100000 MON and commission at most 100%".into(),
            );
        }
        let mut payload = hex_bytes(&self.contract.secp, 33)?;
        payload.extend(hex_bytes(&self.contract.bls, 48)?);
        payload.extend(hex_bytes(&self.contract.auth_address[2..], 20)?);
        payload.extend([0; 16]);
        payload.extend(stake.to_be_bytes());
        payload.extend([0; 24]);
        payload.extend(self.commission.to_be_bytes());
        Ok(payload)
    }
    /// Render unsigned request data. It is not executable calldata without both external proofs.
    /// # Errors
    /// Propagates validation failures.
    pub fn review(&self) -> Result<Value, String> {
        Ok(
            json!({"registration":self,"chain_id":self.contract.chain_id(),
          "to":"0x0000000000000000000000000000000000001000","method":"addValidator(bytes,bytes,bytes)",
          "selector":"0xf145204c","unsigned_payload":format!("0x{}",hex(&self.payload()?)),
          "value_wei":self.stake_wei,"submitted":false,
          "external_steps":["Verify the complete payload and intended chain on the external signing machine", "Use the official SDK add_validator(keygen, amount_wei, auth_address, commission); its CLI wrapper currently defaults commission to zero", "After the receipt succeeds, query registration-status with the resulting validator ID"],
          "activation":"Registration alone is insufficient: 100000 MON self-stake, 10000000 MON total stake and top-200 stake rank are required; membership is observed separately"}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToSec1Point as _;
    #[test]
    fn packed_payload_has_native_widths_big_endian_amount_and_external_authority() {
        let c = Contract {
            owner: "ab".repeat(16),
            network: "testnet".into(),
            role: "validator".into(),
            partuuid: "abcdefab-abcd-abcd-abcd-abcdefabcdef".into(),
            public_ip: "8.8.8.8".into(),
            name_record_sequence: 1,
            secp: hex(k256::AffinePoint::GENERATOR.to_sec1_point(true).as_bytes()),
            bls: "ab".repeat(48),
            beneficiary: format!("0x{}", "cd".repeat(20)),
            auth_address: format!("0x{}", "ef".repeat(20)),
        };
        let mut r = Registration {
            contract: c,
            stake_wei: "100000000000000000000000".into(),
            commission: 50_000_000_000_000_000,
        };
        let p = r.payload().unwrap();
        assert_eq!(p.len(), 165);
        assert_eq!(&p[81..101], &vec![0xef; 20]);
        assert_eq!(
            &p[117..133],
            &100_000_000_000_000_000_000_000_u128.to_be_bytes()
        );
        assert_eq!(&p[157..165], &r.commission.to_be_bytes());
        assert_eq!(r.review().unwrap()["submitted"], false);
        r.commission = 50_000_000_000_000_001;
        let encoded = r.review().unwrap();
        assert_eq!(encoded["registration"]["commission"], "50000000000000001");
        let decoded = Registration::parse_prepared(encoded.clone()).unwrap();
        for field in [
            "unsigned_payload",
            "value_wei",
            "to",
            "chain_id",
            "submitted",
        ] {
            let mut changed = encoded.clone();
            changed[field] = json!("altered");
            assert!(Registration::parse_prepared(changed).is_err(), "{field}");
        }
        assert_eq!(decoded.commission, r.commission);
        r.stake_wei = "099999999999999999999999".into();
        assert!(r.payload().is_err());
        r.stake_wei = "99999999999999999999999".into();
        assert!(r.payload().is_err());
    }
}
