// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc v vote-account`: the validator's vote account on chain, created
//! when it is not there, with its BLS key registered.
//!
//! The identity pays. When it has too little, erpc asks testnet's faucet,
//! and when the faucet refuses, says how much to send and where. Once the
//! account exists and is checked to vote for the identity and be withdrawn by
//! the authority, the vote account's own key has done its work: its public
//! key stays in the validator item and the key is deleted from 1Password.

use std::path::PathBuf;

use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, Validator};
use erpc_chain_solana::cli::{SolanaCli, rpc_url};
use erpc_chain_solana::identity;
use erpc_chain_solana::vote::{self, CREATE_LAMPORTS, VoteAccount};
use serde_json::json;

use crate::commands::Outcome;
use crate::node_common::{Say, confirm};
use crate::validator_init::open_vault;

/// What `erpc v vote-account` was asked about.
#[derive(Debug, Clone)]
pub struct Args {
    /// The network.
    pub network: String,
    /// The validator.
    pub name: String,
    /// Do not ask before sending a transaction.
    pub yes: bool,
}

/// The CLI, the cluster and where its signer pipes go.
struct Chain {
    cli: SolanaCli,
    url: &'static str,
    dir: PathBuf,
}

/// Runs `erpc v vote-account`.
pub fn run(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    match vote_account(args, &say) {
        Ok((v, account)) => {
            if json_out {
                crate::print_json(&json!({
                    "validator": v.name,
                    "vote_account": v.vote_account,
                    "identity": account.identity,
                    "withdrawer": account.withdrawer,
                    "voter": account.voter,
                    "bls": account.bls,
                    "commission": account.commission,
                }));
                return Outcome::Done(String::new());
            }
            Outcome::Done(format!(
                "vote account {} of {}\n  identity   {}\n  withdrawer {}\n  voter      {}\n  bls        {}\n  commission {}%",
                v.vote_account,
                v.name,
                account.identity,
                account.withdrawer,
                account.voter,
                account.bls.as_deref().unwrap_or("not registered"),
                account.commission
            ))
        }
        Err(e) => Outcome::Failed(e),
    }
}

fn vote_account(args: &Args, say: &Say) -> Result<(Validator, VoteAccount), String> {
    let (_, runner, store, inventory) = open_vault(&args.network, None, say)?;
    let validator = inventory
        .validators
        .iter()
        .find(|v| v.name == args.name)
        .cloned()
        .ok_or_else(|| format!("there is no validator {}", args.name))?;
    if validator.vote_account.is_empty() || validator.authority_account.is_empty() {
        return Err(format!(
            "{} has no vote account or authority key yet: run `erpc v keys -n {} --name {}`",
            validator.name, args.network, validator.name
        ));
    }
    let chain = Chain {
        cli: SolanaCli::find().map_err(|e| e.to_string())?,
        url: rpc_url(&args.network)
            .ok_or_else(|| format!("erpc has no RPC for {}", args.network))?,
        dir: crate::session::state_dir()?,
    };
    say.line(&format!(
        "solana     {} ({})",
        chain.cli.version,
        chain.cli.path().display()
    ));

    let account = match vote::read(&chain.cli, chain.url, &validator.vote_account, &chain.dir)
        .map_err(|e| e.to_string())?
    {
        Some(account) => {
            say.line(&format!("vote       {} exists", validator.vote_account));
            account
        }
        None => create(&chain, &runner, &validator, args, say)?,
    };
    if let Some(why) = account.mismatch(&validator.identity_account, &validator.authority_account) {
        return Err(format!(
            "the vote account {} is not this validator's: {why}. Nothing was changed",
            validator.vote_account
        ));
    }
    let account = bls(&chain, &runner, &validator, account, args.yes, say)?;
    let validator = forget_vote_key(&store, &runner, validator, say)?;
    Ok((validator, account))
}

/// Funds the identity if it must, creates the account, and reads it back.
fn create(
    chain: &Chain,
    runner: &OpCli,
    validator: &Validator,
    args: &Args,
    say: &Say,
) -> Result<VoteAccount, String> {
    if validator.vote_ref.is_empty() {
        return Err(format!(
            "the vote account {} does not exist, and its key is not in 1Password to create it",
            validator.vote_account
        ));
    }
    fund(chain, &validator.identity_account, args, say)?;
    say.line(&format!(
        "plan       create vote account {} for identity {}, withdrawer {}, commission 0%, the identity paying",
        validator.vote_account, validator.identity_account, validator.authority_account
    ));
    go_ahead(args.yes, "Create it?")?;
    let identity_key =
        identity::read_keypair(runner, &validator.identity_ref).map_err(|e| e.to_string())?;
    let vote_key =
        identity::read_keypair(runner, &validator.vote_ref).map_err(|e| e.to_string())?;
    if vote_key.pubkey() != validator.vote_account
        || identity_key.pubkey() != validator.identity_account
    {
        return Err(
            "the keys in 1Password are not the validator item's; nothing was sent".to_owned(),
        );
    }
    vote::create(
        &chain.cli,
        chain.url,
        &vote_key.to_json(),
        &identity_key.to_json(),
        &validator.authority_account,
        &chain.dir,
    )
    .map_err(|e| e.to_string())?;
    say.line(&format!("vote       {} created", validator.vote_account));
    vote::read(&chain.cli, chain.url, &validator.vote_account, &chain.dir)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            format!(
                "{} was sent but does not read back yet; run this again",
                validator.vote_account
            )
        })
}

/// Makes sure the identity can pay for the account: testnet's faucet, or a
/// transfer from the operator.
fn fund(chain: &Chain, identity: &str, args: &Args, say: &Say) -> Result<(), String> {
    let lamports =
        vote::balance(&chain.cli, chain.url, identity, &chain.dir).map_err(|e| e.to_string())?;
    if lamports >= CREATE_LAMPORTS {
        return Ok(());
    }
    #[allow(clippy::cast_precision_loss)]
    let need = CREATE_LAMPORTS as f64 / 1e9;
    let ask = || {
        format!(
            "the identity {identity} has {} SOL, and creating the vote account needs about {need} SOL. \
             Send at least that to {identity}, then run `erpc v vote-account -n {} --name {}` again",
            lamports_to_sol(lamports),
            args.network,
            args.name
        )
    };
    if args.network != "testnet" {
        return Err(ask());
    }
    say.line(&format!(
        "fund       asking testnet's faucet for 1 SOL for {identity}…"
    ));
    if let Err(e) = vote::airdrop(&chain.cli, chain.url, identity, &chain.dir) {
        say.line(&format!("           the faucet refused: {e}"));
        return Err(ask());
    }
    for _ in 0..15 {
        let now = vote::balance(&chain.cli, chain.url, identity, &chain.dir)
            .map_err(|e| e.to_string())?;
        if now >= CREATE_LAMPORTS {
            say.line(&format!(
                "fund       {identity} has {} SOL",
                lamports_to_sol(now)
            ));
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    Err(ask())
}

#[allow(clippy::cast_precision_loss)]
fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1e9
}

/// Registers the BLS key when the account has none (SIMD-0387). The voter
/// signs, and on a new account the voter is the identity.
fn bls(
    chain: &Chain,
    runner: &OpCli,
    validator: &Validator,
    account: VoteAccount,
    yes: bool,
    say: &Say,
) -> Result<VoteAccount, String> {
    if account.bls.is_some() {
        say.line("bls        registered");
        return Ok(account);
    }
    if account.voter != validator.identity_account {
        return Err(format!(
            "the vote account's voter is {}, not the identity: register its BLS key with that key",
            account.voter
        ));
    }
    say.line(&format!(
        "plan       register the BLS key of voter {} on {}",
        account.voter, validator.vote_account
    ));
    go_ahead(yes, "Register it?")?;
    let identity_key =
        identity::read_keypair(runner, &validator.identity_ref).map_err(|e| e.to_string())?;
    vote::register_bls(
        &chain.cli,
        chain.url,
        &validator.vote_account,
        &identity_key.to_json(),
        &chain.dir,
    )
    .map_err(|e| e.to_string())?;
    let account = vote::read(&chain.cli, chain.url, &validator.vote_account, &chain.dir)
        .map_err(|e| e.to_string())?
        .ok_or("the vote account no longer reads")?;
    if account.bls.is_none() {
        return Err("the BLS key was sent but does not read back yet; run this again".to_owned());
    }
    say.line("bls        registered");
    Ok(account)
}

/// Deletes the vote account's key from 1Password, keeping its public key.
fn forget_vote_key(
    store: &Store<OpCli>,
    runner: &OpCli,
    validator: Validator,
    say: &Say,
) -> Result<Validator, String> {
    if validator.vote_ref.is_empty() {
        return Ok(validator);
    }
    identity::delete_item(runner, &validator.vote_ref).map_err(|e| e.to_string())?;
    let validator = store
        .update_validator(&Validator {
            vote_ref: String::new(),
            ..validator
        })
        .map_err(|e| e.to_string())?;
    say.line(&format!(
        "vote key   deleted from 1Password; the account {} is kept by its public key",
        validator.vote_account
    ));
    Ok(validator)
}

fn go_ahead(yes: bool, question: &str) -> Result<(), String> {
    if yes {
        return Ok(());
    }
    if !crate::session::has_terminal() {
        return Err("nothing was sent: pass --yes to go ahead without a terminal".to_owned());
    }
    if confirm(question)? {
        Ok(())
    } else {
        Err("nothing was sent".to_owned())
    }
}
