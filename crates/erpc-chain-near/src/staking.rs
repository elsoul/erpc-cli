// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Public staking-pool intent; account signatures and transaction submission stay external.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Official CLI-selected legacy staking factory code, observed on both networks.
/// This is a deployed code identity, not a claim of a reproducible source build.
pub const FACTORY_CODE_HASH: &str = "FjtxkkaKDKCW1F6HgsuYvnQ9GMxrzhnkQwCm52G9gYuA";

/// Select the factory from the official near-cli-rs network configuration.
#[must_use]
pub fn factory(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("poolv1.near"),
        "testnet" => Some("pool.f863973.m0"),
        _ => None,
    }
}

/// Reserved public producer and pool ownership, with an explicit operator fee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    /// Explicit mainnet/testnet scope.
    pub network: String,
    /// Full staking-pool account used by the native consensus signer.
    pub validator_account: String,
    /// Account that owns the pool and signs financial actions externally.
    pub owner_account: String,
    /// Dedicated Ed25519 consensus key, never an owner transaction key.
    pub staking_public_key: String,
    /// Commission chosen explicitly by the operator, 0 to 10000 basis points.
    pub commission_basis_points: u16,
}

impl Registration {
    /// Bind a public intent to a fresh host-observed pool state and owner balance.
    /// # Errors
    /// Rejects a different factory, wrong creation phase, insufficient balance or locked withdrawal.
    pub fn prepare_observed(
        &self,
        step: &str,
        amount: Option<&str>,
        observed: &Value,
    ) -> Result<Value, String> {
        self.validate()?;
        if observed["factory"].as_str() != factory(&self.network)
            || observed["factory_code_hash"] != FACTORY_CODE_HASH
        {
            return Err("observed factory differs from the reserved network".into());
        }
        let exists = observed["pool_exists"]
            .as_bool()
            .ok_or("pool existence was not established")?;
        if (step == "create-pool") == exists {
            return Err("selected step does not match current pool existence".into());
        }
        if ["unstake", "withdraw"].contains(&step) {
            let amount = quantity(amount.ok_or("explicit yoctoNEAR amount is required")?)?;
            let field = if step == "unstake" {
                "staked_yocto"
            } else {
                "unstaked_yocto"
            };
            let available = quantity(
                observed["owner_balance"][field]
                    .as_str()
                    .ok_or("owner balance observation is missing")?,
            )?;
            if amount == 0
                || amount > available
                || (step == "withdraw" && observed["owner_balance"]["withdrawal_available"] != true)
            {
                return Err("amount exceeds the observed owner balance or the withdrawal epoch has not arrived".into());
            }
        }
        let intent = self.prepare(step, amount, observed["minimum_deposit_yocto"].as_str())?;
        Ok(json!({"intent":intent,"observation":observed}))
    }

    /// Validate the exact network/account/key relationship without network access.
    /// # Errors
    /// Rejects unsupported factories, nested pool prefixes and malformed identities.
    pub fn validate(&self) -> Result<(), String> {
        let factory = factory(&self.network).ok_or("unsupported NEAR staking network")?;
        crate::validator::account(&self.validator_account)?;
        crate::validator::account(&self.owner_account)?;
        crate::validator::public_key(&self.staking_public_key)?;
        let suffix = format!(".{factory}");
        let prefix = self
            .validator_account
            .strip_suffix(&suffix)
            .ok_or("validator account must belong to the reviewed network factory")?;
        if prefix.is_empty()
            || prefix.contains('.')
            || self.owner_account == self.validator_account
            || self.commission_basis_points > 10000
        {
            return Err("invalid pool prefix, external owner or commission".into());
        }
        Ok(())
    }

    /// Prepare public function-call parameters for an external official wallet.
    /// Values are not a serialized/signable transaction: its nonce, block hash,
    /// owner access key and signature are deliberately left to external tooling.
    /// # Errors
    /// Amounts must be canonical yoctoNEAR integers; no spending amount is defaulted.
    pub fn prepare(
        &self,
        step: &str,
        amount: Option<&str>,
        observed_minimum: Option<&str>,
    ) -> Result<Value, String> {
        self.validate()?;
        let factory = factory(&self.network).ok_or("unsupported factory")?;
        let (receiver, method, args, deposit) = match step {
            "create-pool" => {
                let deposit =
                    amount.ok_or("pool creation requires an explicit yoctoNEAR deposit")?;
                let minimum = observed_minimum
                    .ok_or("observe the current factory minimum before preparing creation")?;
                if quantity(deposit)? < quantity(minimum)? {
                    return Err("pool deposit is below the current factory minimum".into());
                }
                let prefix = self
                    .validator_account
                    .strip_suffix(&format!(".{factory}"))
                    .ok_or("invalid pool account")?;
                (
                    factory,
                    "create_staking_pool",
                    json!({"staking_pool_id":prefix,"owner_id":self.owner_account,
                    "stake_public_key":self.staking_public_key,"reward_fee_fraction":{"numerator":self.commission_basis_points,"denominator":10000}}),
                    deposit,
                )
            }
            "stake" => {
                let deposit = amount.ok_or("staking requires an explicit yoctoNEAR deposit")?;
                if quantity(deposit)? == 0 {
                    return Err("stake deposit must be positive".into());
                }
                (
                    self.validator_account.as_str(),
                    "deposit_and_stake",
                    json!({}),
                    deposit,
                )
            }
            "ping" => {
                if amount.is_some() {
                    return Err("ping does not accept a deposit override".into());
                }
                (self.validator_account.as_str(), "ping", json!({}), "0")
            }
            "unstake" | "withdraw" => {
                let amount =
                    amount.ok_or("unstake/withdraw requires an explicit yoctoNEAR amount")?;
                if quantity(amount)? == 0 {
                    return Err("unstake/withdraw amount must be positive".into());
                }
                (
                    self.validator_account.as_str(),
                    step,
                    json!({"amount":amount}),
                    "0",
                )
            }
            "resume" => {
                if amount.is_some() {
                    return Err("resume does not accept a deposit override".into());
                }
                (
                    self.validator_account.as_str(),
                    "resume_staking",
                    json!({}),
                    "0",
                )
            }
            "pause" => {
                if amount.is_some() {
                    return Err("pause does not accept a deposit override".into());
                }
                (
                    self.validator_account.as_str(),
                    "pause_staking",
                    json!({}),
                    "0",
                )
            }
            _ => return Err("unsupported external registration step".into()),
        };
        Ok(
            json!({"schema":"erpc.near.registration.v1","network":self.network,
            "factory":factory,"factory_code_hash":FACTORY_CODE_HASH,"validator_account":self.validator_account,
            "staking_public_key":self.staking_public_key,"signer_account":self.owner_account,
            "receiver_account":receiver,"function_call":{"method_name":method,"args":args,
                "gas":300_000_000_000_000_u64,"deposit_yocto":deposit},
            "submission":"Construct, simulate where supported, sign and broadcast with official external tooling; erpc does not submit."}),
        )
    }
}

/// Parse a bounded canonical yoctoNEAR quantity without rounding floating-point amounts.
/// # Errors
/// Refuses signs, decimals, exponent notation, leading zeroes and u128 overflow.
pub fn quantity(value: &str) -> Result<u128, String> {
    if value.is_empty()
        || value.len() > 39
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("amount must be a canonical integer in yoctoNEAR".into());
    }
    value
        .parse::<u128>()
        .map_err(|_| "yoctoNEAR amount exceeds protocol range".into())
}

#[cfg(test)]
mod tests {
    fn registration() -> super::Registration {
        super::Registration {
            network: "mainnet".into(),
            validator_account: "fixture.poolv1.near".into(),
            owner_account: "owner.near".into(),
            staking_public_key: "ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z".into(),
            commission_basis_points: 500,
        }
    }

    #[test]
    fn external_requests_bind_receiver_owner_key_fee_and_exact_integer_amount() {
        let value = registration();
        value.validate().unwrap();
        let amount = "30000000000000000000000000";
        let create = value
            .prepare("create-pool", Some(amount), Some(amount))
            .unwrap();
        assert_eq!(create["receiver_account"], "poolv1.near");
        assert_eq!(create["signer_account"], "owner.near");
        assert_eq!(create["function_call"]["deposit_yocto"], amount);
        assert_eq!(
            create["function_call"]["args"]["reward_fee_fraction"]["numerator"],
            500
        );
        assert_eq!(
            create["function_call"]["args"]["stake_public_key"],
            value.staking_public_key
        );
        assert!(create.get("signature").is_none());
        assert!(
            value
                .prepare("create-pool", Some("1"), Some(amount))
                .is_err()
        );
        assert!(value.prepare("create-pool", Some(amount), None).is_err());
        assert!(value.prepare("stake", None, None).is_err());
        assert!(value.prepare("stake", Some("0"), None).is_err());
        assert_eq!(
            value.prepare("ping", None, None).unwrap()["function_call"]["deposit_yocto"],
            "0"
        );
        assert!(value.prepare("ping", Some("1"), None).is_err());
        assert!(value.prepare("broadcast", None, None).is_err());
        for method in ["unstake", "withdraw"] {
            let request = value.prepare(method, Some("123"), None).unwrap();
            assert_eq!(request["function_call"]["method_name"], method);
            assert_eq!(request["function_call"]["args"]["amount"], "123");
            assert_eq!(request["function_call"]["deposit_yocto"], "0");
            assert!(value.prepare(method, Some("0"), None).is_err());
        }
        assert_eq!(
            value.prepare("resume", None, None).unwrap()["function_call"]["method_name"],
            "resume_staking"
        );
        let mut wrong = value.clone();
        wrong.network = "testnet".into();
        assert!(wrong.validate().is_err());
        wrong.validator_account = "fixture.pool.f863973.m0".into();
        assert!(wrong.validate().is_ok());
        wrong.owner_account = wrong.validator_account.clone();
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn amount_input_cannot_round_or_select_another_network_factory() {
        assert_eq!(super::factory("mainnet"), Some("poolv1.near"));
        assert_eq!(super::factory("testnet"), Some("pool.f863973.m0"));
        assert!(super::factory("localnet").is_none());
        for value in [
            "",
            "+1",
            "-1",
            "1.5",
            "1e24",
            "01",
            "340282366920938463463374607431768211456",
        ] {
            assert!(super::quantity(value).is_err());
        }
        assert_eq!(
            super::quantity("30000000000000000000000000").unwrap(),
            30_000_000_000_000_000_000_000_000
        );
    }

    #[test]
    fn preparation_refuses_wrong_factory_missing_pool_and_locked_or_excess_withdrawals() {
        let registration = registration();
        let mut observed = serde_json::json!({"factory":"poolv1.near", "factory_code_hash":super::FACTORY_CODE_HASH,
            "pool_exists":true, "minimum_deposit_yocto":"30000000000000000000000000",
            "owner_balance":{"staked_yocto":"100", "unstaked_yocto":"50", "withdrawal_available":false}});
        assert!(
            registration
                .prepare_observed("create-pool", Some("30000000000000000000000000"), &observed)
                .is_err()
        );
        assert!(
            registration
                .prepare_observed("withdraw", Some("1"), &observed)
                .is_err()
        );
        assert!(
            registration
                .prepare_observed("unstake", Some("101"), &observed)
                .is_err()
        );
        registration
            .prepare_observed("unstake", Some("100"), &observed)
            .unwrap();
        observed["owner_balance"]["withdrawal_available"] = serde_json::json!(true);
        registration
            .prepare_observed("withdraw", Some("50"), &observed)
            .unwrap();
        assert!(
            registration
                .prepare_observed("withdraw", Some("51"), &observed)
                .is_err()
        );
        observed["pool_exists"] = serde_json::json!(false);
        assert!(
            registration
                .prepare_observed("stake", Some("1"), &observed)
                .is_err()
        );
        registration
            .prepare_observed("create-pool", Some("30000000000000000000000000"), &observed)
            .unwrap();
        observed["factory"] = serde_json::json!("pool.near");
        assert!(
            registration
                .prepare_observed("create-pool", Some("30000000000000000000000000"), &observed)
                .is_err()
        );
    }
}
