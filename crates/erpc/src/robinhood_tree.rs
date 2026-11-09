// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Explicit assertion-validator mode and external funding preparation commands.
use clap::{Arg, ArgAction, Command, value_parser};
use erpc_core::chain::Verb;

pub(crate) const EXTRA: &[Verb] = &[
    crate::robinhood_admission::REGISTRATION,
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
        "init"=>command.about("Reserve an original dedicated wallet in 1Password and prepare a Robinhood Defensive host; do not fund or activate signing").arg(Arg::new("host").long("host")).arg(Arg::new("user").long("user").default_value("ubuntu")).arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16))).arg(Arg::new("fingerprint").long("fingerprint")).arg(Arg::new("vault").long("vault")),

        "deploy"=>command.about("Deploy in observing mode, or explicitly enable original native Defensive rival assertion/stake signing after protocol/history/funding checks").arg(Arg::new("activate-signer").long("activate-signer").action(ArgAction::SetTrue)).arg(Arg::new("restore-custody").long("restore-custody").action(ArgAction::SetTrue).help("Restore only the original active wallet from its original 1Password item before continuing deployment")),
        "update"=>command.arg(Arg::new("version").long("version").required(true)),
        "logs"=>command.arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32))).arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "plan"=>command.arg(Arg::new("change").long("change").default_value("deploy").value_parser(["deploy","update","update-config"])).arg(Arg::new("version").long("version")),
        "destroy"=>command.about("Cancel and retire the original Defensive validator; retain original wallet, data and signing history"),
        _=>command,
    }
}

pub(crate) fn extras(command: Command) -> Command {
    EXTRA
        .iter()
        .filter(|verb| verb.name != "registration")
        .fold(command, |cmd, verb| {
            cmd.subcommand(args(Command::new(verb.name).about(verb.about), verb))
        })
}
