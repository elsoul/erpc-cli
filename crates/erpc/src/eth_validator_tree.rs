// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Ethereum validator CLI contract, including explicit key import and deposit review.

use crate::commands::Outcome;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use erpc_core::chain::{Source, Verb};

pub(crate) fn args(mut sub: Command, verb: &str) -> Command {
    if verb != "list" {
        sub = sub
            .arg(
                Arg::new("ssh-key")
                    .long("ssh-key")
                    .value_parser(value_parser!(std::path::PathBuf)),
            )
            .arg(
                Arg::new("ssh-agent")
                    .long("ssh-agent")
                    .value_parser(value_parser!(std::path::PathBuf)),
            );
    }
    if !["status", "logs", "list", "plan", "deposit-review"].contains(&verb) {
        sub = sub.arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue),
        );
    }
    if ["init", "update"].contains(&verb) {
        sub = sub
            .arg(Arg::new("reth-version").long("reth-version"))
            .arg(Arg::new("lighthouse-version").long("lighthouse-version"));
    }
    if ["init", "update-config"].contains(&verb) {
        sub = sub.arg(
            Arg::new("fee-recipient")
                .long("fee-recipient")
                .help("Execution fee destination; never withdrawal authority"),
        );
    }
    match verb {
        "init" => sub.about("Reserve and prepare a dedicated Reth/Lighthouse validator host; never import keys or deposit")
            .arg(Arg::new("host").long("host"))
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16)))
            .arg(Arg::new("fingerprint").long("fingerprint"))
            .arg(Arg::new("vault").long("vault")),
        "logs" => sub.arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32)))
            .arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "keys-import" => sub.about("Import one never-used EIP-2335 key and matching empty EIP-3076 history; never start signing")
            .arg(Arg::new("keystore").long("keystore").required(true).value_parser(value_parser!(std::path::PathBuf)))
            .arg(Arg::new("password-file").long("password-file").required(true).value_parser(value_parser!(std::path::PathBuf)))
            .arg(Arg::new("slashing-history").long("slashing-history").required(true).value_parser(value_parser!(std::path::PathBuf)))
            .arg(Arg::new("new-key").long("new-key").required(true).action(ArgAction::SetTrue).help("Assert this key has never signed anywhere; used keys require managed migration")),
        "migrate" => sub.about("Fence the old managed signer and transfer its current encrypted key and signing history; leave destination stopped")
            .arg(Arg::new("to").long("to").required(true).help("Prepared destination inventory name in the same network/vault")),
        "deposit-review" => sub.about("Verify public deposit SSZ/BLS, destination, network, amount and activation absence; never sign or submit")
            .arg(Arg::new("deposit-data").long("deposit-data").required(true).value_parser(value_parser!(std::path::PathBuf)))
            .arg(Arg::new("withdrawal-address").long("withdrawal-address").required(true)),
        "destroy" => sub.about("Fence and disable all owned services; retain keys, slashing history, data and inventory"),
        "deploy" | "update" | "update-config" => sub.about("Configure verified supporting clients with the signer stopped; use start explicitly after readiness checks"),
        _ => sub,
    }
}

pub(crate) fn extras(command: Command) -> Command {
    ["keys-import", "migrate", "deposit-review"]
        .into_iter()
        .fold(command, |cmd, verb| {
            cmd.subcommand(args(Command::new(verb), verb))
        })
}

pub(crate) async fn run(verb: &str, sub: &ArgMatches, source: Source, json: bool) -> Outcome {
    let Some(network) = sub.get_one::<String>("network") else {
        return Outcome::Usage("Ethereum validators require --network hoodi or mainnet".into());
    };
    if erpc_chain_eth::validator::network(network).is_none() {
        return Outcome::Usage("Ethereum validator networks: hoodi, mainnet; Sepolia is permissioned and Holesky is retired".into());
    }
    let readonly = ["list", "status", "logs", "plan", "deposit-review"].contains(&verb);
    if !readonly && network == "mainnet" && source != Source::Flag {
        return Outcome::Usage("mainnet validator changes require explicit --chain eth".into());
    }
    crate::eth_validator::run(verb, sub, network, json).await
}

pub(crate) fn common(sub: Command, verb: &Verb) -> Command {
    args(sub, verb.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn custody_commands_require_explicit_files_and_freshness_assertion() {
        assert!(
            args(Command::new("keys-import"), "keys-import")
                .try_get_matches_from(["keys-import"])
                .is_err()
        );
        assert!(
            args(Command::new("destroy"), "destroy")
                .try_get_matches_from(["destroy", "--purge-data"])
                .is_err()
        );
        extras(Command::new("validator")).debug_assert();
    }
    #[tokio::test]
    async fn unsupported_validator_network_and_implicit_mainnet_fail_before_inventory() {
        for (network, source) in [("sepolia", Source::Flag), ("mainnet", Source::Env)] {
            let matches = crate::tree::command(
                erpc_core::chain::Role::Validator,
                erpc_core::chain::Chain::Eth,
            )
            .try_get_matches_from([
                "validator",
                "start",
                "--network",
                network,
                "--name",
                "fixture",
            ])
            .expect("parse");
            let (_, sub) = matches.subcommand().expect("command");
            assert!(matches!(
                run("start", sub, source, true).await,
                Outcome::Usage(_)
            ));
        }
        let mainnet_rpc =
            crate::tree::command(erpc_core::chain::Role::Rpc, erpc_core::chain::Chain::Eth);
        assert!(
            mainnet_rpc
                .try_get_matches_from(["rpc", "status", "--network", "mainnet"])
                .is_ok()
        );
    }
}
