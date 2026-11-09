// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Public Solana registration observations and external-signing intent.
//! Reads public inventory fields only; never reads signer references or submits.

use crate::commands::Outcome;
use clap::{Arg, ArgMatches, Command, value_parser};
use erpc_chain_solana::validator_observer::{self, Observation};
use erpc_chain_solana::validator_profile::Registration;
use serde_json::{Value, json};

pub(crate) fn command() -> Command {
    Command::new("registration")
        .about("Observe public vote-account state or prepare intent for official external signing tools")
        .arg(Arg::new("action").long("action").required(true).value_parser(["status","validate","prepare"]))
        .arg(Arg::new("bls").long("bls").required(true).help("Expected public BLS key from the qualified native solana-keygen bls_pubkey tool"))
        .arg(Arg::new("commission").long("commission").required(true).value_parser(value_parser!(u8).range(0..=100)).help("Explicit commission percentage to match"))
        .arg(Arg::new("step").long("step").value_parser(["create-vote","register-bls","fund-identity","fund-vote","withdraw-vote"]))
        .arg(Arg::new("amount-lamports").long("amount-lamports").value_parser(value_parser!(u64).range(1..)).help("Exact positive integer lamports; no SOL rounding"))
        .arg(Arg::new("recipient").long("recipient").help("Explicit public withdrawal recipient"))
        .arg(Arg::new("admission-reserve-lamports").long("admission-reserve-lamports").value_parser(value_parser!(u64).range(1..))
            .help("Operator-selected admission reserve beyond rent and pending delegator rewards; external signer must verify the current protocol requirement"))
}

fn inputs(sub: &ArgMatches) -> Result<(), String> {
    let action = sub
        .get_one::<String>("action")
        .ok_or("missing registration action")?;
    let step = sub.get_one::<String>("step").map(String::as_str);
    let amount = sub.get_one::<u64>("amount-lamports");
    let recipient = sub.get_one::<String>("recipient");
    let reserve = sub.get_one::<u64>("admission-reserve-lamports");
    if action == "prepare" {
        match step {
            Some("create-vote"|"register-bls") if amount.is_none() && recipient.is_none() && reserve.is_none()=>{},
            Some("fund-identity"|"fund-vote") if amount.is_some() && recipient.is_none() && reserve.is_none()=>{},
            Some("withdraw-vote") if amount.is_some() && recipient.is_some() && reserve.is_some()=>{},
            _=>return Err("prepare needs --step and its exact inputs: funding needs --amount-lamports; withdrawal also needs --recipient and --admission-reserve-lamports; creation/BLS registration take none of these overrides".into()),
        }
    } else if step.is_some() || amount.is_some() || recipient.is_some() || reserve.is_some() {
        return Err("status/validate do not accept preparation overrides".into());
    }
    if let Some(public) = recipient {
        erpc_chain_solana::validator_profile::public_bytes(public, 32)?;
    }
    erpc_chain_solana::validator_profile::public_bytes(
        sub.get_one::<String>("bls")
            .ok_or("missing public BLS key")?,
        48,
    )?;
    Ok(())
}

pub(crate) async fn run(sub: &ArgMatches, json_out: bool) -> Outcome {
    let (Some(network), Some(name)) = (
        sub.get_one::<String>("network"),
        sub.get_one::<String>("name"),
    ) else {
        return Outcome::Usage("Solana registration requires --network and --name".into());
    };
    if !["mainnet", "testnet"].contains(&network.as_str()) {
        return Outcome::Usage("public validator registration supports mainnet and testnet".into());
    }
    if let Err(error) = inputs(sub) {
        return Outcome::Usage(error);
    }
    match run_inner(sub, network, name).await {
        Ok(value) => {
            if json_out {
                crate::print_json(&value);
                Outcome::Done(String::new())
            } else {
                Outcome::Done(serde_json::to_string_pretty(&value).unwrap_or_default())
            }
        }
        Err(error) => Outcome::Failed(error),
    }
}

async fn run_inner(sub: &ArgMatches, network: &str, name: &str) -> Result<Value, String> {
    let vault = crate::node_common::vault_for(network, None, "initialize a validator first")?;
    let runner = crate::node_common::op_runner()?;
    let store = crate::node_common::store(&runner, &vault, "solana", network)?;
    let validator = store
        .public_solana_validator(name)
        .map_err(|error| error.to_string())?;
    let registration = Registration {
        network: network.into(),
        identity: validator.identity_account.clone(),
        vote_account: validator.vote_account.clone(),
        withdrawer: validator.authority_account.clone(),
        bls: sub
            .get_one::<String>("bls")
            .ok_or("missing public BLS key")?
            .clone(),
        commission: *sub
            .get_one::<u8>("commission")
            .ok_or("missing explicit commission")?,
    };
    registration.validate()?;
    let observation = validator_observer::observe(&registration).await?;
    result(sub, &registration, &observation)
}

fn result(
    sub: &ArgMatches,
    registration: &Registration,
    observation: &Observation,
) -> Result<Value, String> {
    let report = observation.report(registration);
    match sub.get_one::<String>("action").map(String::as_str) {
        Some("status") => Ok(report),
        Some("validate") => {
            observation
                .vote
                .as_ref()
                .ok_or("reserved vote account does not exist")?
                .bind(
                    &registration.identity,
                    &registration.withdrawer,
                    &registration.bls,
                    registration.commission,
                )?;
            Ok(report)
        }
        Some("prepare") => {
            let reserve = sub.get_one::<u64>("admission-reserve-lamports").copied();
            let floor = reserve
                .map(|reserve| retention(observation, reserve))
                .transpose()?;
            let mut intent = registration.prepare(
                sub.get_one::<String>("step").ok_or("missing step")?,
                sub.get_one::<u64>("amount-lamports").copied(),
                sub.get_one::<String>("recipient").map(String::as_str),
                observation.vote.as_ref(),
                floor,
            )?;
            intent["observation"] = report;
            intent["admission_reserve"] = json!({"lamports":reserve.map(|v|v.to_string()),
                "source":"explicit operator selection, not a protocol fee quote; the external signer must recheck rent, pending rewards, fees and admission requirements before signing"});
            Ok(intent)
        }
        _ => Err("unsupported registration action".into()),
    }
}

fn retention(observation: &Observation, reserve: u64) -> Result<u64, String> {
    let pending = observation.account["data"]["parsed"]["info"]["pendingDelegatorRewards"]
        .as_str()
        .ok_or("missing native pending delegator rewards")?;
    let amount = pending
        .parse::<u64>()
        .map_err(|_| "invalid native pending delegator rewards")?;
    if amount.to_string() != pending {
        return Err("noncanonical pending delegator rewards".into());
    }
    observation
        .rent_lamports
        .ok_or("missing rent quote")?
        .checked_add(amount)
        .and_then(|n| n.checked_add(reserve))
        .ok_or_else(|| "retention amount overflow".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> ArgMatches {
        command()
            .try_get_matches_from(std::iter::once("registration").chain(args.iter().copied()))
            .unwrap()
    }
    #[test]
    fn every_preparation_step_has_reachable_and_unambiguous_inputs() {
        let bls = erpc_chain_solana::identity::base58(&[10; 48]);
        let recipient = erpc_chain_solana::identity::base58(&[11; 32]);
        let base = ["--action", "prepare", "--bls", &bls, "--commission", "5"];
        for step in [
            "create-vote",
            "register-bls",
            "fund-identity",
            "fund-vote",
            "withdraw-vote",
        ] {
            let mut args = base.to_vec();
            args.extend(["--step", step]);
            if step.starts_with("fund") || step == "withdraw-vote" {
                args.extend(["--amount-lamports", "1"]);
            }
            if step == "withdraw-vote" {
                args.extend([
                    "--recipient",
                    &recipient,
                    "--admission-reserve-lamports",
                    "800000000",
                ]);
            }
            assert!(inputs(&parse(&args)).is_ok());
            args.extend(["--admission-reserve-lamports", "1"]);
            if step != "withdraw-vote" {
                assert!(inputs(&parse(&args)).is_err());
            }
        }
        assert!(inputs(&parse(&base)).is_err());
        assert!(
            inputs(&parse(&[
                "--action",
                "status",
                "--bls",
                &bls,
                "--commission",
                "5",
                "--step",
                "create-vote"
            ]))
            .is_err()
        );
    }
    #[test]
    fn retention_includes_pending_rewards_and_rejects_overflow_or_missing_data() {
        let mut observation = Observation {
            epoch: 1,
            slot: 1,
            block_time: 1,
            vote: None,
            rent_lamports: Some(10),
            account: json!({"data":{"parsed":{"info":{"pendingDelegatorRewards":"20"}}}}),
        };
        assert_eq!(retention(&observation, 30).unwrap(), 60);
        assert!(retention(&observation, u64::MAX).is_err());
        observation.account["data"]["parsed"]["info"]["pendingDelegatorRewards"] = json!("020");
        assert!(retention(&observation, 30).is_err());
        observation.account = Value::Null;
        assert!(retention(&observation, 30).is_err());
    }
}
