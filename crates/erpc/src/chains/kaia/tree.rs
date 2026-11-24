// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Kaia RPC arguments; validator activation is a separate role.

use clap::{Arg, ArgAction, Command, value_parser};
use erpc_core::chain::Verb;

pub(crate) fn args(mut command: Command, verb: &Verb, validator: bool) -> Command {
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
    command = match verb.name {
        "init" => command.about("Reserve a dedicated Kaia host and pin a reviewed OCI image; no validator or funded account")
            .arg(Arg::new("host").long("host"))
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16)))
            .arg(Arg::new("fingerprint").long("fingerprint"))
            .arg(Arg::new("vault").long("vault"))
            .arg(Arg::new("version").long("version").help("Kaia version from the reviewed OCI catalog; default is recommended"))
            .arg(Arg::new("storage").long("storage").value_parser(["full","pruned"]).help("Immutable initial history contract; recommended default: pruned; full syncs from genesis")),
        "update" => command.about("Authenticate an explicitly selected stable release; preserve data, refuse downgrade and never auto-rollback")
            .arg(Arg::new("version").long("version").required(true)),
        "plan" => command.arg(Arg::new("change").long("change").default_value("deploy").value_parser(["deploy", "update", "update-config"]))
            .arg(Arg::new("version").long("version")),
        "logs" => command.arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32).range(1..=10_000)))
            .arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "destroy" => command.about("Retire and disable the owned service; retain database, node identity and ownership"),
        "deploy" => command.about("Authenticate the reviewed image, bootstrap the selected database and start guarded RPC"),
        "update-config" => command.about("Reapply management ranges and reviewed service configuration, preserving history"),
        _ => command,
    };
    if validator {
        if ["init", "update-config"].contains(&verb.name) {
            for name in [
                "reward-address",
                "manager-address",
                "staking-address",
                "gc-id",
            ] {
                command = command.arg(Arg::new(name).long(name));
            }
            command = command.arg(
                Arg::new("peer")
                    .long("peer")
                    .action(ArgAction::Append)
                    .help("Approved role-qualified KNI static peer; repeat for CN and PN links"),
            );
        }
        if verb.name == "init" {
            command=command.arg(Arg::new("node-kind").long("node-kind").value_parser(["cn","pn"]))
            .arg(Arg::new("advertise-ip").long("advertise-ip"))
            .about("Reserve a dedicated CN or PN; seal original keys and verify a concealed backup before deployment");
        }
        if verb.name == "deploy" {
            command=command.arg(Arg::new("restore-custody").long("restore-custody").action(ArgAction::SetTrue)
            .help("Restore the verified original backup only on its original stopped host; retain all native history"))
            .about("Deploy the admitted core-cell role; native qualified-membership checks control consensus; financial registration remains external");
        }
    }
    command
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role};
    #[test]
    fn core_cell_cli_has_all_lifecycle_verbs_without_financial_or_private_key_arguments() {
        use erpc_core::chain::COMMON_VERBS;
        let tree = crate::tree::command(Role::Validator, Chain::Kaia);
        tree.clone().debug_assert();
        for verb in COMMON_VERBS {
            let mut args = vec!["validator", verb.name, "--network", "kairos"];
            if verb.name == "update" {
                args.extend(["--version", "2.2.2"]);
            }
            assert!(tree.clone().try_get_matches_from(args).is_ok());
        }
        for flag in [
            "--nodekey",
            "--private-key",
            "--unlock",
            "--send",
            "--fund",
            "--purge-data",
        ] {
            assert!(
                tree.clone()
                    .try_get_matches_from(["validator", "init", flag, "inert"])
                    .is_err()
            );
        }
        assert!(
            tree.clone()
                .try_get_matches_from([
                    "validator",
                    "init",
                    "--node-kind",
                    "cn",
                    "--advertise-ip",
                    "10.1.2.1"
                ])
                .is_ok()
        );
        assert!(
            tree.clone()
                .try_get_matches_from(["validator", "deploy", "--restore-custody"])
                .is_ok()
        );
        assert!(
            tree.try_get_matches_from(["validator", "stop", "--restore-custody"])
                .is_err()
        );
        assert!(
            crate::tree::command(Role::Rpc, Chain::Kaia)
                .try_get_matches_from(["rpc", "init", "--node-kind", "cn"])
                .is_err()
        );
    }

    #[test]
    fn kaia_arguments_refuse_wrong_network_retention_and_arbitrary_release_inputs() {
        let tree = crate::tree::command(Role::Rpc, Chain::Kaia);
        tree.clone().debug_assert();
        assert!(
            tree.clone()
                .try_get_matches_from(["rpc", "init", "-n", "kairos", "--storage", "full"])
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
}
