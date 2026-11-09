// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Explicit native ownership, device authorization and external registration.
use clap::{Arg, ArgAction, Command, value_parser};
use erpc_core::chain::Verb;
pub(crate) const EXTRA: &[Verb] = &[
    Verb {
        name: "check-identity",
        about: "Verify original sealed native keystores and both public keys",
        read_only: true,
    },
    Verb {
        name: "identity-restore",
        about: "Restore original keystore bytes on the same stopped host",
        read_only: false,
    },
    Verb {
        name: "recover-device",
        about: "Validate an interrupted initial TrieDB creation without formatting",
        read_only: false,
    },
    Verb {
        name: "recover-data-filesystem",
        about: "Bind an independently recorded original consensus filesystem UUID on the stopped host",
        read_only: false,
    },
    Verb {
        name: "prepare-registration",
        about: "Prepare public Monad staking payload for external proof/signing",
        read_only: true,
    },
    Verb {
        name: "validate-registration",
        about: "Validate an external staking intent against this healthy node",
        read_only: true,
    },
    Verb {
        name: "registration-status",
        about: "Observe an externally registered validator ID and epoch membership",
        read_only: true,
    },
];
pub(crate) fn extras(validator: bool) -> &'static [Verb] {
    if validator { EXTRA } else { &EXTRA[..4] }
}
#[allow(clippy::too_many_lines)]
pub(crate) fn args(mut command: Command, verb: &Verb, validator: bool) -> Command {
    command = command.arg(Arg::new("vault").long("vault"));
    if verb.name != "list" {
        for name in ["ssh-key", "ssh-agent"] {
            command = command.arg(
                Arg::new(name)
                    .long(name)
                    .value_parser(value_parser!(std::path::PathBuf)),
            );
        }
    }
    if !verb.read_only {
        command = command.arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue),
        );
    }
    if ["init", "update-config", "plan"].contains(&verb.name) {
        for name in ["rpc-allow", "management-allow", "monitoring-allow"] {
            command = command.arg(
                Arg::new(name)
                    .long(name)
                    .action(ArgAction::Append)
                    .value_delimiter(','),
            );
        }
    }
    match verb.name {
        "init"=> {
            for name in ["host","fingerprint","device-partuuid","public-ip","secp-public-key","bls-public-key","keys-ref"] {command=command.arg(Arg::new(name).long(name));}
            command=command.arg(Arg::new("user").long("user").default_value("ubuntu"))
                .arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16)))
                .arg(Arg::new("name-record-sequence").long("name-record-sequence").value_parser(value_parser!(u64)))
                .arg(Arg::new("exclusive-identity").long("exclusive-identity").action(ArgAction::SetTrue)
                     .help("Assert these dedicated consensus keys have never been hosted elsewhere and are not transaction keys"));
            if validator {for name in ["beneficiary","auth-address"] {command=command.arg(Arg::new(name).long(name));}}
            command
        },
        "deploy"=>command.arg(Arg::new("initialize-device").long("initialize-device").action(ArgAction::SetTrue)
             .help("Explicit first-write authorization for the preselected blank raw partition; never truncate existing data")),
        "recover-data-filesystem"=>command.arg(Arg::new("original-uuid").long("original-uuid").required(true)),
        "update"=>command.arg(Arg::new("version").long("version").required(true)),
        "plan"=>command.arg(Arg::new("change").long("change").value_parser(["deploy","update","update-config"]).default_value("deploy"))
             .arg(Arg::new("version").long("version")),
        "logs"=>command.arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32)))
             .arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "prepare-registration"=>command.arg(Arg::new("stake-wei").long("stake-wei").required(true))
             .arg(Arg::new("commission").long("commission").required(true).value_parser(value_parser!(u64))),
        "validate-registration"=>command.arg(Arg::new("file").long("file").required(true).value_parser(value_parser!(std::path::PathBuf))),
        "registration-status"=>command.arg(Arg::new("validator-id").long("validator-id").required(true).value_parser(value_parser!(u64))),
        "destroy"=>command.about("Retire native services and preserve the raw device, data, credentials and ownership"),
        _=>command,
    }
}

pub(crate) fn add_extras(mut command: Command, validator: bool) -> Command {
    for verb in extras(validator) {
        command = command.subcommand(args(
            Command::new(verb.name).about(verb.about),
            verb,
            validator,
        ));
    }
    command
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role, Source, guard_mainnet};
    #[test]
    fn native_lifecycle_and_external_registration_have_explicit_boundaries() {
        for role in [Role::Rpc, Role::Validator] {
            let tree = crate::tree::command(role, Chain::Monad);
            tree.clone().debug_assert();
            for verb in [
                "init",
                "deploy",
                "list",
                "status",
                "logs",
                "start",
                "stop",
                "restart",
                "update-config",
                "plan",
                "destroy",
            ] {
                tree.clone()
                    .try_get_matches_from(["node", verb, "-n", "testnet"])
                    .expect("lifecycle verb");
            }
            tree.clone()
                .try_get_matches_from(["node", "update", "-n", "mainnet", "--version", "0.16.5"])
                .expect("explicit update");
            assert!(
                tree.clone()
                    .try_get_matches_from(["node", "destroy", "--purge-data"])
                    .is_err()
            );
            assert!(
                tree.clone()
                    .try_get_matches_from(["node", "deploy", "--private-key", "secret"])
                    .is_err()
            );
            tree.clone()
                .try_get_matches_from(["node", "deploy", "--initialize-device"])
                .expect("separate first-write intent");
            tree.clone()
                .try_get_matches_from([
                    "node",
                    "recover-data-filesystem",
                    "-n",
                    "testnet",
                    "--original-uuid",
                    "00000000-0000-0000-0000-000000000001",
                ])
                .expect("explicit stopped filesystem recovery");
            assert!(
                tree.clone()
                    .try_get_matches_from(["node", "recover-data-filesystem", "-n", "testnet"])
                    .is_err()
            );
            assert_eq!(
                tree.clone()
                    .try_get_matches_from([
                        "node",
                        "prepare-registration",
                        "--stake-wei",
                        "100000000000000000000000",
                        "--commission",
                        "0"
                    ])
                    .is_ok(),
                role == Role::Validator
            );
        }
        for verb in super::EXTRA.iter().filter(|v| {
            [
                "identity-restore",
                "recover-device",
                "recover-data-filesystem",
            ]
            .contains(&v.name)
        }) {
            assert!(guard_mainnet(verb, Chain::Monad, Source::Env, Some("mainnet")).is_err());
            assert!(guard_mainnet(verb, Chain::Monad, Source::Flag, Some("mainnet")).is_ok());
        }
    }
}
