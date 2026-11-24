// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! BSC RPC arguments; validator activation is a separate role.

use clap::{Arg, ArgAction, Command, value_parser};
use erpc_core::chain::Verb;

pub(crate) fn args(mut command: Command, verb: &Verb, validator: bool) -> Command {
    if validator && verb.name == "init" {
        command = command.arg(
            Arg::new("operator")
                .long("operator")
                .help("External financial operator public address; its key stays off the node"),
        );
    }
    if validator && verb.name == "update-config" {
        command=command.arg(Arg::new("restore-custody").long("restore-custody").action(ArgAction::SetTrue).conflicts_with("management-allow").help("Restore only this owner's identical custody backup; keep native vote history and leave the signer stopped"));
    }
    if verb.name != "list" {
        command = command
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
    if !verb.read_only {
        command = command.arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue),
        );
    }
    if ["init", "update-config"].contains(&verb.name) {
        command = command.arg(
            Arg::new("management-allow")
                .long("management-allow")
                .action(ArgAction::Append)
                .value_delimiter(',')
                .help(
                    "Stable management IPv4 addresses/CIDRs; current SSH address is also admitted",
                ),
        );
    }
    match verb.name {
        "init" => command.about(if validator {"Reserve a BSC validator host with an external operator address; hot keys are created by deploy"} else {"Reserve a dedicated BSC RPC host and pin a reviewed binary"})
            .arg(Arg::new("host").long("host"))
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16)))
            .arg(Arg::new("fingerprint").long("fingerprint"))
            .arg(Arg::new("vault").long("vault"))
            .arg(Arg::new("version").long("version").help("BSC version from the network-specific release catalog; default is recommended"))
            .arg(Arg::new("storage").long("storage").value_parser(["full","pruned"]).help("Immutable initial history contract; recommended default: full")),
        "update" => command.about("Authenticate an explicitly selected stable release; preserve data, refuse downgrade and never auto-rollback")
            .arg(Arg::new("version").long("version").required(true)),
        "plan" => command.arg(Arg::new("change").long("change").default_value("deploy").value_parser(if validator {vec!["deploy", "update", "update-config", "register"]} else {vec!["deploy", "update", "update-config"]}))
            .arg(Arg::new("version").long("version")),
        "logs" => command.arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32)))
            .arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "destroy" => command.about("Retire and disable the owned service; retain database, node identity and ownership"),
        "deploy" => command.about(if validator {"Bootstrap the node, seal fresh hot keys, verify concealed backup and observe external registration"}else{"Authenticate the reviewed binary, bootstrap the official snapshot and start guarded RPC"}),
        "update-config" => command.about("Reapply management ranges and reviewed service configuration, preserving history"),
        _ => command,
    }
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role};
    #[test]
    fn bsc_arguments_refuse_wrong_network_retention_and_arbitrary_release_inputs() {
        let tree = crate::tree::command(Role::Rpc, Chain::Bsc);
        tree.clone().debug_assert();
        assert!(
            tree.clone()
                .try_get_matches_from(["rpc", "init", "-n", "chapel", "--storage", "full"])
                .is_ok()
        );
        for args in [
            vec!["rpc", "init", "-n", "sepolia"],
            vec!["rpc", "init", "--storage", "fast"],
            vec!["rpc", "destroy", "--purge-data"],
            vec!["rpc", "deploy", "--public-rpc"],
            vec!["rpc", "update"],
        ] {
            assert!(tree.clone().try_get_matches_from(args).is_err());
        }
    }
    #[test]
    fn validator_arguments_keep_registration_external_and_recovery_explicit() {
        let tree = crate::tree::command(Role::Validator, Chain::Bsc);
        tree.clone().debug_assert();
        assert!(
            tree.clone()
                .try_get_matches_from([
                    "validator",
                    "init",
                    "-n",
                    "chapel",
                    "--operator",
                    "0x1111111111111111111111111111111111111111"
                ])
                .is_ok()
        );
        assert!(
            tree.clone()
                .try_get_matches_from(["validator", "plan", "--change", "register"])
                .is_ok()
        );
        assert!(
            tree.clone()
                .try_get_matches_from(["validator", "update-config", "--restore-custody"])
                .is_ok()
        );
        for args in [
            vec!["validator", "deploy", "--stake"],
            vec!["validator", "init", "--operator-private-key", "fixture"],
            vec!["validator", "init", "--import-key", "fixture"],
            vec![
                "validator",
                "update-config",
                "--restore-custody",
                "--management-allow",
                "192.0.2.1",
            ],
        ] {
            assert!(tree.clone().try_get_matches_from(args).is_err());
        }
    }
}
