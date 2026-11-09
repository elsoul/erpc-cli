// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Explicit assertion-validator mode and external funding preparation commands.
use clap::{Arg, ArgAction, Command, value_parser};
use erpc_core::chain::Verb;

pub(crate) const EXTRA: &[Verb] = &[
    Verb {
        name: "prepare-registration",
        about: "Observe finalized protocol requirements and prepare unsigned external funding/wrap/allowance data",
        read_only: true,
    },
    Verb {
        name: "validate-registration",
        about: "Revalidate current original validator admission and funding without submitting transactions",
        read_only: true,
    },
    Verb {
        name: "registration-status",
        about: "Observe original native staking and assertion-validator admission",
        read_only: true,
    },
];
pub(crate) fn args(mut command: Command, verb: &Verb) -> Command {
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
        command=command.arg(Arg::new("l1-upstreams").long("l1-upstreams").help("Identifier-only reference to concealed HTTPS execution and beacon provider configuration")).arg(Arg::new("management-allow").long("management-allow").action(ArgAction::Append).value_delimiter(','));
    }
    match verb.name{
        "init"=>command.about("Reserve an original dedicated wallet in 1Password and prepare an Arbitrum One host; do not fund or activate signing").arg(Arg::new("host").long("host")).arg(Arg::new("user").long("user").default_value("ubuntu")).arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16))).arg(Arg::new("fingerprint").long("fingerprint")).arg(Arg::new("vault").long("vault"))
            .arg(Arg::new("upgrade-volume-authority").long("upgrade-volume-authority").action(ArgAction::SetTrue).conflicts_with_all(["host","user","port","fingerprint","l1-upstreams","management-allow"]).help("Fence and stop an existing original validator, bind its historical volume receipts, and leave it stopped"))
            .arg(Arg::new("original-root-volume-record").long("original-root-volume-record").value_parser(value_parser!(std::path::PathBuf)).requires("upgrade-volume-authority").help("Independent historical ROOT UUID/type/inode JSON; required when old ROOT/DATA records do not prove the same filesystem")),
        "deploy"=>command.about("Deploy in observing mode, or explicitly enable original native MakeNodes signing after protocol/history/funding checks").arg(Arg::new("activate-signer").long("activate-signer").action(ArgAction::SetTrue)).arg(Arg::new("restore-custody").long("restore-custody").action(ArgAction::SetTrue).help("Restore only the original active wallet from its original 1Password item before continuing deployment")),
        "update"=>command.arg(Arg::new("version").long("version").required(true)),
        "logs"=>command.arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32))).arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "plan"=>command.arg(Arg::new("change").long("change").default_value("deploy").value_parser(["deploy","update","update-config"])).arg(Arg::new("version").long("version")),
        "destroy"=>command.about("Cancel and retire the original assertion validator; retain original wallet, data and signing history"),
        _=>command,
    }
}

pub(crate) fn extras(command: Command) -> Command {
    EXTRA.iter().fold(command, |cmd, verb| {
        cmd.subcommand(args(Command::new(verb.name).about(verb.about), verb))
    })
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role, Source};
    #[test]
    fn explicit_stopped_volume_upgrade_parses_without_private_or_deployment_authority() {
        let verb = erpc_core::chain::Verb {
            name: "init",
            about: "inert",
            read_only: false,
        };
        let command = super::args(clap::Command::new("init"), &verb);
        let args = command
            .clone()
            .try_get_matches_from([
                "init",
                "--upgrade-volume-authority",
                "--original-root-volume-record",
                "original.json",
            ])
            .unwrap();
        assert!(args.get_flag("upgrade-volume-authority"));
        assert!(
            args.get_one::<std::path::PathBuf>("original-root-volume-record")
                .is_some()
        );
        assert!(
            command
                .clone()
                .try_get_matches_from(["init", "--original-root-volume-record", "original.json"])
                .is_err()
        );
        assert!(
            command
                .try_get_matches_from(["init", "--upgrade-volume-authority", "--host", "192.0.2.1"])
                .is_err()
        );
    }

    #[test]
    fn explicit_activation_and_retention_arguments_are_role_scoped() {
        let tree = crate::tree::command(Role::Validator, Chain::Arbitrum);
        tree.clone().debug_assert();
        assert!(
            tree.clone()
                .try_get_matches_from([
                    "validator",
                    "deploy",
                    "--activate-signer",
                    "--network",
                    "mainnet"
                ])
                .is_ok()
        );
        assert!(
            tree.clone()
                .try_get_matches_from(["validator", "destroy", "--purge-data"])
                .is_err()
        );
        assert!(
            tree.clone()
                .try_get_matches_from(["validator", "init", "--import-used-key", "secret"])
                .is_err()
        );
        assert!(
            crate::tree::command(Role::Rpc, Chain::Arbitrum)
                .try_get_matches_from(["rpc", "deploy", "--activate-signer"])
                .is_err()
        );
        for command in [
            "prepare-registration",
            "validate-registration",
            "registration-status",
        ] {
            assert!(
                tree.clone()
                    .try_get_matches_from(["validator", command, "--network", "mainnet"])
                    .is_ok()
            );
        }
    }
    #[tokio::test]
    async fn unsupported_network_stops_before_inventory_or_keys() {
        for network in ["nova", "sepolia"] {
            let args = [
                "--chain",
                "arbitrum",
                "deploy",
                "--network",
                network,
                "--name",
                "fixture",
                "--yes",
            ]
            .map(String::from);
            assert!(matches!(
                crate::tree::run(Role::Validator, &args, true).await,
                crate::commands::Outcome::Usage(_)
            ));
        }
        let verb = erpc_core::chain::COMMON_VERBS
            .iter()
            .find(|v| v.name == "deploy")
            .unwrap();
        assert!(
            erpc_core::chain::guard_mainnet(verb, Chain::Arbitrum, Source::Env, Some("mainnet"))
                .is_err()
        );
    }
}
