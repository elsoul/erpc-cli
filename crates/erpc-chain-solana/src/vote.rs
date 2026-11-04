// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! A validator's vote account on chain: reading it, funding the identity
//! that pays for it, creating it, and registering its BLS key, all through
//! the operator's Solana CLI with keys from memory ([`crate::cli`]).

use std::path::Path;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::cli::{Arg, CliError, SolanaCli};

/// What the vote account says on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteAccount {
    /// The node identity the account votes for.
    pub identity: String,
    /// Who may withdraw from it.
    pub withdrawer: String,
    /// The authorized voter of the latest epoch it lists.
    pub voter: String,
    /// The BLS public key (SIMD-0387), once registered.
    pub bls: Option<String>,
    /// The commission, in percent.
    pub commission: u64,
}

impl VoteAccount {
    /// Reads `solana vote-account --output json`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let v: Value = serde_json::from_str(text).ok()?;
        let s = |k: &str| v[k].as_str().map(str::to_owned);
        // `authorizedVoters` maps epochs to voters; the latest epoch wins.
        let voter = v["authorizedVoters"].as_object().and_then(|m| {
            m.iter()
                .filter_map(|(epoch, voter)| Some((epoch.parse::<u64>().ok()?, voter.as_str()?)))
                .max_by_key(|(epoch, _)| *epoch)
                .map(|(_, voter)| voter.to_owned())
        });
        Some(Self {
            identity: s("validatorIdentity")?,
            withdrawer: s("authorizedWithdrawer")?,
            voter: voter.unwrap_or_default(),
            bls: s("blsPubkeyCompressed").filter(|b| !b.is_empty()),
            commission: v["commission"].as_u64().unwrap_or_default(),
        })
    }

    /// Why this account is not the validator's, if it is not: it must vote
    /// for `identity` and be withdrawn by `withdrawer`.
    #[must_use]
    pub fn mismatch(&self, identity: &str, withdrawer: &str) -> Option<String> {
        if self.identity != identity {
            return Some(format!(
                "it votes for the identity {}, not {identity}",
                self.identity
            ));
        }
        if !withdrawer.is_empty() && self.withdrawer != withdrawer {
            return Some(format!(
                "its withdrawer is {}, not {withdrawer}",
                self.withdrawer
            ));
        }
        None
    }
}

/// The lamports a new vote account and its transaction need: rent for the
/// account (about 0.02 SOL on testnet) and fees, with room to spare.
pub const CREATE_LAMPORTS: u64 = 30_000_000;

/// The vote account at `address`, or `None` when there is none.
///
/// # Errors
///
/// Returns [`CliError`] when the CLI fails for another reason, or prints
/// something that is not a vote account.
pub fn read(
    cli: &SolanaCli,
    url: &str,
    address: &str,
    dir: &Path,
) -> Result<Option<VoteAccount>, CliError> {
    let out = cli.run(
        &[
            Arg::Text("vote-account"),
            Arg::Text(address),
            Arg::Text("--output"),
            Arg::Text("json"),
            Arg::Text("--url"),
            Arg::Text(url),
        ],
        dir,
    );
    match out {
        Ok(text) => VoteAccount::parse(&text).map(Some).ok_or(CliError::Failed {
            command: "vote-account".to_owned(),
            message: format!("{address} is not a vote account"),
        }),
        Err(CliError::Failed { message, .. }) if message.contains("does not exist") => Ok(None),
        Err(e) => Err(e),
    }
}

/// The balance of `address`, in lamports.
///
/// # Errors
///
/// Returns [`CliError`] when the CLI fails or prints no number.
pub fn balance(cli: &SolanaCli, url: &str, address: &str, dir: &Path) -> Result<u64, CliError> {
    let out = cli.run(
        &[
            Arg::Text("balance"),
            Arg::Text(address),
            Arg::Text("--lamports"),
            Arg::Text("--url"),
            Arg::Text(url),
        ],
        dir,
    )?;
    parse_lamports(&out).ok_or(CliError::Failed {
        command: "balance".to_owned(),
        message: format!("no balance in {out:?}"),
    })
}

fn parse_lamports(text: &str) -> Option<u64> {
    text.split_whitespace().next()?.parse().ok()
}

/// Asks the cluster's faucet for one SOL for `address`. Testnet's faucet is
/// rate limited, so a refusal is normal: the operator funds it instead.
///
/// # Errors
///
/// Returns [`CliError`] when the faucet refuses.
pub fn airdrop(cli: &SolanaCli, url: &str, address: &str, dir: &Path) -> Result<(), CliError> {
    cli.run(
        &[
            Arg::Text("airdrop"),
            Arg::Text("1"),
            Arg::Text(address),
            Arg::Text("--url"),
            Arg::Text(url),
        ],
        dir,
    )
    .map(|_| ())
}

/// Creates the vote account `vote` for `identity`, withdrawn by
/// `withdrawer`, commission 0, the identity paying.
///
/// The cluster decides the instruction: with `VoteInitV2` (SIMD-0464) not
/// active, as on testnet on 2026-10-23, it is `VoteInit`, whose commission
/// defaults to 100%, so it is always given.
///
/// # Errors
///
/// Returns [`CliError`] when the CLI fails.
pub fn create(
    cli: &SolanaCli,
    url: &str,
    vote: &Zeroizing<String>,
    identity: &Zeroizing<String>,
    withdrawer: &str,
    dir: &Path,
) -> Result<String, CliError> {
    cli.run(
        &[
            Arg::Text("create-vote-account"),
            Arg::Signer(vote),
            Arg::Signer(identity),
            Arg::Text(withdrawer),
            Arg::Text("--commission"),
            Arg::Text("0"),
            Arg::Text("--fee-payer"),
            Arg::Signer(identity),
            Arg::Text("--keypair"),
            Arg::Signer(identity),
            Arg::Text("--url"),
            Arg::Text(url),
        ],
        dir,
    )
}

/// Registers the BLS key derived from the authorized voter, `identity`
/// (SIMD-0387), by authorizing it again as voter with the v2 instruction.
///
/// # Errors
///
/// Returns [`CliError`] when the CLI is older than 4.1.0 or fails.
pub fn register_bls(
    cli: &SolanaCli,
    url: &str,
    vote: &str,
    identity: &Zeroizing<String>,
    dir: &Path,
) -> Result<String, CliError> {
    cli.require(crate::cli::BLS_VERSION, "registering a BLS key")?;
    cli.run(
        &[
            Arg::Text("vote-authorize-voter-checked"),
            Arg::Text(vote),
            Arg::Signer(identity),
            Arg::Signer(identity),
            Arg::Text("--use-v2-instruction"),
            Arg::Text("--fee-payer"),
            Arg::Signer(identity),
            Arg::Text("--keypair"),
            Arg::Signer(identity),
            Arg::Text("--url"),
            Arg::Text(url),
        ],
        dir,
    )
}

#[cfg(test)]
mod tests {
    use super::{VoteAccount, parse_lamports};

    /// The fields of `solana vote-account --output json`, as solana-cli 4.3.1
    /// printed them for a testnet vote account.
    const JSON: &str = r#"{"accountBalance":12887896251329,"validatorIdentity":"2jmA6Jbouwxj5mzZjwH9Xg1ui3iswEAatZDcHt3TVGX8","authorizedVoters":{"1049":"TKMNqvfwb7PKkc9KFEJJ8EaNK9s5XjNWgFS6oyqSLkp","1051":"2jmA6Jbouwxj5mzZjwH9Xg1ui3iswEAatZDcHt3TVGX8"},"authorizedWithdrawer":"GTMBqgoXVMnnWidyQ8JRuMjaazWVtqEugPMiDge61wUE","commission":7,"blsPubkeyCompressed":"7YTkw7P2Up5H7rqjdRZPanhf5eRcs256rAuaXmzAitEVutWV9eE95jMqXgeah5DFJz"}"#;

    #[test]
    fn a_vote_account_reads_with_its_latest_voter_and_bls_key() {
        let v = VoteAccount::parse(JSON).expect("parses");
        assert_eq!(v.identity, "2jmA6Jbouwxj5mzZjwH9Xg1ui3iswEAatZDcHt3TVGX8");
        assert_eq!(v.voter, "2jmA6Jbouwxj5mzZjwH9Xg1ui3iswEAatZDcHt3TVGX8");
        assert!(v.bls.is_some());
        assert_eq!(v.commission, 7);
        let unset = JSON.replace(
            "\"7YTkw7P2Up5H7rqjdRZPanhf5eRcs256rAuaXmzAitEVutWV9eE95jMqXgeah5DFJz\"",
            "null",
        );
        assert_eq!(VoteAccount::parse(&unset).expect("parses").bls, None);
    }

    #[test]
    fn an_account_for_another_identity_or_withdrawer_is_not_ours() {
        let v = VoteAccount::parse(JSON).expect("parses");
        assert_eq!(
            v.mismatch(
                "2jmA6Jbouwxj5mzZjwH9Xg1ui3iswEAatZDcHt3TVGX8",
                "GTMBqgoXVMnnWidyQ8JRuMjaazWVtqEugPMiDge61wUE"
            ),
            None
        );
        assert!(
            v.mismatch("Other1111111111111111111111111111111111111", "")
                .is_some()
        );
        assert!(
            v.mismatch("2jmA6Jbouwxj5mzZjwH9Xg1ui3iswEAatZDcHt3TVGX8", "Other")
                .is_some()
        );
    }

    #[test]
    fn a_balance_reads_from_lamports_output() {
        assert_eq!(parse_lamports("0 lamports\n"), Some(0));
        assert_eq!(parse_lamports("1000000000 lamports"), Some(1_000_000_000));
        assert_eq!(parse_lamports("Error"), None);
    }
}
