// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Network-qualified source builds and epoch-specific public voting observations.
//! Operational signatures and native voting history remain the client's concern.

use serde_json::Value;
use std::collections::BTreeMap;

/// Exact upstream source/toolchain pair for the recommended Agave profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    /// ERPC network selector.
    pub network: &'static str,
    /// Native expected genesis identity.
    pub genesis: &'static str,
    /// Qualified upstream release, without its tag prefix.
    pub version: &'static str,
    /// Resolved Git commit, checked before compiling.
    pub commit: &'static str,
    /// Toolchain from that exact source's rust-toolchain.toml.
    pub rust: &'static str,
}

/// Pinned production/test network source profiles.
/// The official CLI archives were inspected and do not contain agave-validator;
/// a production validator must be built from this source, not installed from
/// solana-test-validator or guessed release-archive contents.
#[must_use]
pub fn source(network: &str) -> Option<Source> {
    match network {
        "mainnet" => Some(Source {
            network: "mainnet",
            genesis: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
            version: "4.3.2",
            commit: "a203300045b405f86c9c84308b2eae76af69ac3b",
            rust: "1.97.1",
        }),
        "testnet" => Some(Source {
            network: "testnet",
            genesis: "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
            version: "4.4.0-beta.1",
            commit: "3ad9da2c390eb7ad2630ed15afcd463e72e007a8",
            rust: "1.98.1",
        }),
        _ => None,
    }
}

/// Canonical public Base58 bytes, with an exact protocol-defined size.
/// # Errors
/// Refuses noncanonical size, overflow, unsupported characters and empty values.
pub fn public_bytes(value: &str, length: usize) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if ![32, 48].contains(&length) || value.is_empty() || value.len() > 70 {
        return Err("invalid public key length".into());
    }
    let mut bytes = vec![0_u8; length];
    for byte in value.bytes() {
        let mut carry = u32::try_from(
            ALPHABET
                .iter()
                .position(|b| *b == byte)
                .ok_or("invalid public key encoding")?,
        )
        .map_err(|_| "invalid public key encoding")?;
        for item in bytes.iter_mut().rev() {
            carry += u32::from(*item) * 58;
            *item = (carry & 255) as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return Err("public key exceeds its protocol size".into());
        }
    }
    let leading = value.bytes().take_while(|byte| *byte == b'1').count();
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map_or(0, |index| length - index);
    if leading + significant != length
        || crate::identity::base58(&bytes) != value
        || bytes.iter().all(|byte| *byte == 0)
    {
        return Err("invalid canonical public key".into());
    }
    Ok(bytes)
}

/// Public vote-account metadata observed at a known cluster epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteState {
    /// Node identity bound by the vote account.
    pub identity: String,
    /// External withdrawal authority, never an online consensus key.
    pub withdrawer: String,
    /// Voter effective at the observed epoch, not the latest scheduled voter.
    pub current_voter: String,
    /// Future authorizations are retained so startup can detect a pending rotation.
    pub future_voters: BTreeMap<u64, String>,
    /// Registered BLS compressed public key, when present.
    pub bls: Option<String>,
    /// Commission percentage, required rather than defaulting unknown data to zero.
    pub commission: u8,
    /// Exact lamport balance reported by the native public account view.
    pub balance: u64,
}

impl VoteState {
    /// Parse the qualified native CLI's public JSON using the observer's epoch.
    /// # Errors
    /// Rejects malformed schedules, missing current authority, amounts or identities.
    /// The caller must separately bind the observation to network and freshness.
    pub fn parse(value: &Value, epoch: u64) -> Result<Self, String> {
        let key = |name: &str| -> Result<String, String> {
            let value = value[name]
                .as_str()
                .ok_or("missing public vote-account key")?;
            public_bytes(value, 32)?;
            Ok(value.into())
        };
        let entries = value["authorizedVoters"]
            .as_object()
            .ok_or("missing authorized voter schedule")?;
        if entries.is_empty() || entries.len() > 64 {
            return Err("invalid voter schedule length".into());
        }
        let mut schedule = BTreeMap::new();
        for (when, public) in entries {
            let parsed = when.parse::<u64>().map_err(|_| "invalid voter epoch")?;
            if parsed.to_string() != *when {
                return Err("noncanonical voter epoch".into());
            }
            let public = public.as_str().ok_or("invalid authorized voter")?;
            public_bytes(public, 32)?;
            schedule.insert(parsed, public.to_owned());
        }
        let current_voter = schedule
            .range(..=epoch)
            .next_back()
            .ok_or("no voter is effective at this epoch")?
            .1
            .clone();
        let future_voters = schedule
            .into_iter()
            .filter(|(when, _)| *when > epoch)
            .collect();
        let bls = match value.get("blsPubkeyCompressed") {
            None | Some(Value::Null) => None,
            Some(Value::String(public)) if public.is_empty() => None,
            Some(Value::String(public)) => {
                public_bytes(public, 48)?;
                Some(public.clone())
            }
            _ => return Err("invalid BLS public-key metadata".into()),
        };
        let commission = value["commission"]
            .as_u64()
            .filter(|fee| *fee <= 100)
            .ok_or("invalid commission percentage")?;
        Ok(Self {
            identity: key("validatorIdentity")?,
            withdrawer: key("authorizedWithdrawer")?,
            current_voter,
            future_voters,
            bls,
            commission: u8::try_from(commission).map_err(|_| "invalid commission percentage")?,
            balance: value["accountBalance"]
                .as_u64()
                .ok_or("invalid lamport account balance")?,
        })
    }

    /// Refuse another identity/authority or a scheduled unsupported signer change.
    /// # Errors
    /// Any mismatch prevents authorizing this dedicated identity-only voter profile.
    pub fn bind(
        &self,
        identity: &str,
        withdrawer: &str,
        bls: &str,
        commission: u8,
    ) -> Result<(), String> {
        self.bind_authorities(identity, withdrawer, commission)?;
        public_bytes(bls, 48)?;
        if self.bls.as_deref() != Some(bls) {
            return Err("registered BLS identity differs from the original native signer".into());
        }
        Ok(())
    }

    fn bind_authorities(
        &self,
        identity: &str,
        withdrawer: &str,
        commission: u8,
    ) -> Result<(), String> {
        public_bytes(identity, 32)?;
        public_bytes(withdrawer, 32)?;
        if identity == withdrawer
            || self.identity != identity
            || self.withdrawer != withdrawer
            || self.current_voter != identity
            || self.future_voters.values().any(|voter| voter != identity)
            || self.commission != commission
        {
            return Err(
                "vote account or current/future signing authority differs from its reservation"
                    .into(),
            );
        }
        Ok(())
    }
}

/// Public registration reservation; no signer reference or secret material.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    /// Qualified mainnet/testnet scope.
    pub network: String,
    /// Online node identity and recommended vote authority.
    pub identity: String,
    /// Immutable vote-account public address.
    pub vote_account: String,
    /// Separate external withdrawal authority.
    pub withdrawer: String,
    /// BLS public key derived by the qualified native tool from this identity.
    pub bls: String,
    /// Explicit operator-selected commission percentage.
    pub commission: u8,
}

impl Registration {
    /// Validate public scope and separate hot/withdrawal authorities.
    /// # Errors
    /// Refuses malformed keys, reused authorities, unsupported networks or fees.
    pub fn validate(&self) -> Result<(), String> {
        source(&self.network).ok_or("unsupported validator network")?;
        for key in [&self.identity, &self.vote_account, &self.withdrawer] {
            public_bytes(key, 32)?;
        }
        public_bytes(&self.bls, 48)?;
        if self.identity == self.withdrawer
            || self.vote_account == self.identity
            || self.vote_account == self.withdrawer
            || self.commission > 100
        {
            return Err("identity, vote account and external withdrawer must be distinct; commission must be explicit".into());
        }
        Ok(())
    }

    /// Describe exact public content for official external signing/submission tools.
    /// This is not a serialized transaction: blockhash, instruction encoding,
    /// rent/fee quotation, BLS possession proof and signatures are supplied by
    /// the external native CLI/wallet using its current network observation.
    /// # Errors
    /// Refuses ambiguous amounts, recipient misuse and unverified withdrawal floors.
    pub fn prepare(
        &self,
        step: &str,
        amount: Option<u64>,
        recipient: Option<&str>,
        observed: Option<&VoteState>,
        retained_floor: Option<u64>,
    ) -> Result<Value, String> {
        self.validate()?;
        let network = source(&self.network).ok_or("unsupported network")?;
        if let Some(state) = observed {
            state.bind_authorities(&self.identity, &self.withdrawer, self.commission)?;
            if state.bls.as_deref().is_some_and(|key| key != self.bls) {
                return Err(
                    "an existing different BLS signer requires explicit rotation review".into(),
                );
            }
        }
        let content = match step {
            "create-vote" => {
                if amount.is_some() || recipient.is_some() || observed.is_some() {
                    return Err("vote creation requires an absent account and an external rent quotation, with no transfer override".into());
                }
                serde_json::json!({"method":"create-vote-account", "vote_account":self.vote_account,
                    "validator_identity":self.identity,"authorized_voter":self.identity,"authorized_withdrawer":self.withdrawer,
                    "commission_percent":self.commission,"rent":"quote with the qualified native CLI for the current cluster feature set"})
            }
            "register-bls" => {
                if amount.is_some() || recipient.is_some() || observed.is_none() {
                    return Err("BLS registration requires an existing verified account, without amount or recipient".into());
                }
                serde_json::json!({"method":"vote-authorize-voter-checked", "vote_account":self.vote_account,
                    "current_voter":self.identity,"new_voter":self.identity,"expected_bls_public_key":self.bls,
                    "proof":"derive and verify the possession proof with the external qualified native CLI"})
            }
            "fund-identity" | "fund-vote" => {
                if step == "fund-vote" && observed.is_none() {
                    return Err("create and verify the vote account before funding it".into());
                }
                if recipient.is_some() || amount.is_none_or(|value| value == 0) {
                    return Err("funding requires a positive explicit lamport amount and the reserved recipient".into());
                }
                let destination = if step == "fund-identity" {
                    &self.identity
                } else {
                    &self.vote_account
                };
                serde_json::json!({"method":"transfer", "recipient":destination, "amount_lamports":amount.map(|value| value.to_string()),
                    "fee_payer":"external funding wallet"})
            }
            "withdraw-vote" => {
                let state =
                    observed.ok_or("withdrawal requires a verified current vote account")?;
                let floor = retained_floor
                    .ok_or("current rent and admission retention floor must be observed")?;
                if floor == 0 {
                    return Err("vote-account retention floor must be positive".into());
                }
                let amount = amount
                    .filter(|value| *value > 0)
                    .ok_or("withdrawal requires a positive explicit lamport amount")?;
                let recipient =
                    recipient.ok_or("withdrawal requires an explicit public recipient")?;
                public_bytes(recipient, 32)?;
                if state
                    .balance
                    .checked_sub(amount)
                    .is_none_or(|remaining| remaining < floor)
                {
                    return Err(
                        "withdrawal would consume the verified rent/admission retention floor"
                            .into(),
                    );
                }
                serde_json::json!({"method":"withdraw-from-vote-account", "vote_account":self.vote_account,
                    "recipient":recipient,"amount_lamports":amount.to_string(),"authorized_withdrawer":self.withdrawer,
                    "minimum_retained_lamports":floor.to_string()})
            }
            _ => return Err("unsupported external registration step".into()),
        };
        Ok(
            serde_json::json!({"schema":"erpc.solana.registration.v1","network":self.network,
            "genesis_hash":network.genesis,"source_commit":network.commit,"native_cli_version":network.version,
            "content":content,"submission":"inspect, quote, construct, sign and submit with official external tooling"}),
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    fn fixture() -> Value {
        let key = crate::identity::base58(&[7; 32]);
        let owner = crate::identity::base58(&[8; 32]);
        json!({"validatorIdentity":key,"authorizedWithdrawer":owner,"authorizedVoters":{"10":key},
               "commission":5,"accountBalance":1_000_000_000_u64,"blsPubkeyCompressed":crate::identity::base58(&[9;48])})
    }
    use super::*;

    #[test]
    fn external_preparation_keeps_lamports_exact_and_can_register_a_missing_bls_key() {
        let mut observed = VoteState::parse(&fixture(), 11).unwrap();
        let registration = Registration {
            network: "testnet".into(),
            identity: observed.identity.clone(),
            withdrawer: observed.withdrawer.clone(),
            vote_account: crate::identity::base58(&[11; 32]),
            bls: observed.bls.clone().unwrap(),
            commission: observed.commission,
        };
        let create = registration
            .prepare("create-vote", None, None, None, None)
            .unwrap();
        assert_eq!(
            create["content"]["authorized_withdrawer"],
            registration.withdrawer
        );
        assert!(
            registration
                .prepare("create-vote", None, None, Some(&observed), None)
                .is_err()
        );
        observed.bls = None;
        registration
            .prepare("register-bls", None, None, Some(&observed), None)
            .unwrap();
        assert!(
            registration
                .prepare("register-bls", None, None, None, None)
                .is_err()
        );
        assert!(
            registration
                .prepare("fund-vote", Some(1), None, None, None)
                .is_err()
        );
        let funding = registration
            .prepare("fund-vote", Some(u64::MAX), None, Some(&observed), None)
            .unwrap();
        assert_eq!(funding["content"]["amount_lamports"], u64::MAX.to_string());
        assert!(funding.get("signature").is_none());
        let destination = crate::identity::base58(&[12; 32]);
        assert!(
            registration
                .prepare(
                    "withdraw-vote",
                    Some(1),
                    Some(&destination),
                    Some(&observed),
                    None
                )
                .is_err()
        );
        assert!(
            registration
                .prepare(
                    "withdraw-vote",
                    Some(1),
                    Some(&destination),
                    Some(&observed),
                    Some(0)
                )
                .is_err()
        );
        assert!(
            registration
                .prepare(
                    "withdraw-vote",
                    Some(observed.balance),
                    Some(&destination),
                    Some(&observed),
                    Some(100)
                )
                .is_err()
        );
        registration
            .prepare(
                "withdraw-vote",
                Some(observed.balance - 100),
                Some(&destination),
                Some(&observed),
                Some(100),
            )
            .unwrap();
        assert!(
            registration
                .prepare("fund-identity", Some(1), Some(&destination), None, None)
                .is_err()
        );
        assert!(
            registration
                .prepare("submit", None, None, None, None)
                .is_err()
        );
    }

    #[test]
    fn future_voter_never_becomes_current_early_and_cannot_authorize_startup() {
        let mut value = fixture();
        let future = crate::identity::base58(&[10; 32]);
        value["authorizedVoters"]["12"] = json!(future);
        let current = VoteState::parse(&value, 11).unwrap();
        assert_eq!(current.current_voter, value["validatorIdentity"]);
        assert_eq!(current.future_voters[&12], future);
        assert_eq!(VoteState::parse(&value, 12).unwrap().current_voter, future);
        assert!(VoteState::parse(&value, 9).is_err());
        assert!(
            current
                .bind(
                    &current.identity,
                    &current.withdrawer,
                    current.bls.as_deref().unwrap(),
                    current.commission
                )
                .is_err()
        );
        let clean = VoteState::parse(&fixture(), 11).unwrap();
        clean
            .bind(
                &clean.identity,
                &clean.withdrawer,
                clean.bls.as_deref().unwrap(),
                clean.commission,
            )
            .unwrap();
    }

    #[test]
    fn unknown_fee_balance_and_noncanonical_public_data_cannot_default_to_safe_values() {
        for (field, invalid) in [
            ("commission", json!(null)),
            ("commission", json!(101)),
            ("accountBalance", json!(1.5)),
            ("accountBalance", json!(-1)),
            ("blsPubkeyCompressed", json!("invalid")),
        ] {
            let mut value = fixture();
            value[field] = invalid;
            assert!(VoteState::parse(&value, 11).is_err());
        }
        let mut value = fixture();
        value["authorizedVoters"]["010"] = value["validatorIdentity"].clone();
        assert!(VoteState::parse(&value, 11).is_err());
        for invalid in ["", "1", &"1".repeat(32), "$(command)", &"z".repeat(70)] {
            assert!(public_bytes(invalid, 32).is_err());
        }
    }
}
