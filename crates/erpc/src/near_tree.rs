// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! NEAR follower operations and explicit trusted ingress ranges.
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use erpc_core::chain::Verb;

pub(crate) const REGISTRATION: Verb = Verb {
    name: "registration",
    about: "Prepare public external staking calls, validate custody or observe membership",
    read_only: true,
};

pub(crate) fn effective_verb(verb: &Verb, args: &ArgMatches) -> Verb {
    Verb {
        read_only: verb.read_only
            && !(verb.name == "registration"
                && args
                    .try_get_one::<String>("action")
                    .ok()
                    .flatten()
                    .is_some_and(|action| action == "restore-key")),
        ..*verb
    }
}

pub(crate) fn validate_registration_inputs(args: &ArgMatches) -> Result<(), String> {
    let action = args.get_one::<String>("action").map(String::as_str);
    let step = args.get_one::<String>("step").map(String::as_str);
    let amount = args.get_one::<String>("amount-yocto").map(String::as_str);
    if action == Some("prepare") {
        match step {
            Some("create-pool" | "stake" | "unstake" | "withdraw") => {
                if erpc_chain_near::staking::quantity(
                    amount.ok_or("this step requires --amount-yocto")?,
                )? == 0
                {
                    return Err("the explicit amount must be positive".into());
                }
            }
            Some("ping" | "pause" | "resume") if amount.is_none() => {}
            _ => {
                return Err(
                    "select a supported --step; ping/pause/resume do not accept --amount-yocto"
                        .into(),
                );
            }
        }
    } else if step.is_some() || amount.is_some() {
        return Err("--step and --amount-yocto apply only to preparation".into());
    }
    Ok(())
}

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
        for name in ["management-allow", "rpc-allow", "metrics-allow"] {
            command = command.arg(
                Arg::new(name)
                    .long(name)
                    .action(ArgAction::Append)
                    .value_delimiter(','),
            );
        }
        for name in ["clear-rpc-allow", "clear-metrics-allow"] {
            command = command.arg(Arg::new(name).long(name).action(ArgAction::SetTrue));
        }
    }
    if validator && verb.name == "init" {
        for name in [
            "validator-account",
            "owner-account",
            "staking-public-key",
            "validator-key",
        ] {
            command = command.arg(Arg::new(name).long(name));
        }
        command = command.arg(
            Arg::new("commission-bps")
                .long("commission-bps")
                .value_parser(value_parser!(u16)),
        );
    }
    if validator && verb.name == "deploy" {
        command = command.arg(
            Arg::new("keys-unhosted")
                .long("keys-unhosted")
                .action(ArgAction::SetTrue)
                .help(
                    "Assert the original dedicated consensus key has never been hosted elsewhere",
                ),
        );
    }
    if validator && verb.name == "registration" {
        command = registration_args(command);
    }
    match verb.name {
        "init"=>command.about("Reserve a dedicated NEAR follower; deployment preserves its native peer identity")
            .arg(Arg::new("host").long("host"))
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16)))
            .arg(Arg::new("fingerprint").long("fingerprint"))
            .arg(Arg::new("vault").long("vault")),
        "update"=>command.arg(Arg::new("version").long("version").required(true)),
        "logs"=>command.arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32)))
            .arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "destroy"=>command.about("Retire and stop the owned follower; retain database, original peer identity and ownership"),
        "deploy"=>command.about("Verify network-qualified image and genesis, preserve peer identity, confirm ingress and start synchronization"),
        _=>command,
    }
}

fn registration_args(mut command: Command) -> Command {
    command = command
        .arg(
            Arg::new("action")
                .long("action")
                .required(true)
                .value_parser(["prepare", "validate", "status", "restore-key"]),
        )
        .arg(
            Arg::new("step")
                .long("step")
                .required_if_eq("action", "prepare")
                .value_parser([
                    "create-pool",
                    "stake",
                    "ping",
                    "pause",
                    "resume",
                    "unstake",
                    "withdraw",
                ]),
        )
        .arg(
            Arg::new("amount-yocto")
                .long("amount-yocto")
                .required_if_eq_any([
                    ("step", "create-pool"),
                    ("step", "stake"),
                    ("step", "unstake"),
                    ("step", "withdraw"),
                ]),
        )
        .arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue),
        );
    command
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role};
    #[test]
    fn chain_network_and_mutation_inputs_are_closed() {
        let command = crate::tree::command(Role::Rpc, Chain::Near);
        command.clone().debug_assert();
        assert!(
            command
                .clone()
                .try_get_matches_from([
                    "rpc",
                    "init",
                    "-n",
                    "testnet",
                    "--rpc-allow",
                    "192.0.2.0/24"
                ])
                .is_ok()
        );
        for args in [
            vec!["rpc", "init", "-n", "localnet"],
            vec!["rpc", "update"],
            vec!["rpc", "destroy", "--purge-data"],
            vec!["rpc", "deploy", "--image", "unreviewed"],
        ] {
            assert!(command.clone().try_get_matches_from(args).is_err());
        }
    }

    #[test]
    fn validator_exposes_all_operations_and_external_registration_without_submission() {
        let command = crate::tree::command(Role::Validator, Chain::Near);
        command.clone().debug_assert();
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
            command
                .clone()
                .try_get_matches_from(["validator", verb, "-n", "testnet"])
                .expect("operation routed");
        }
        command
            .clone()
            .try_get_matches_from([
                "validator",
                "update",
                "-n",
                "testnet",
                "--version",
                "2.14.0-rc.6",
            ])
            .expect("qualified update input");
        for action in ["validate", "status", "restore-key"] {
            command
                .clone()
                .try_get_matches_from([
                    "validator",
                    "registration",
                    "-n",
                    "testnet",
                    "--action",
                    action,
                ])
                .expect("external workflow");
        }
        for args in [
            vec!["validator", "registration", "--action", "submit"],
            vec!["validator", "deploy", "--private-key", "refused"],
            vec!["validator", "destroy", "--purge-data"],
        ] {
            assert!(command.clone().try_get_matches_from(args).is_err());
        }
        let rpc = crate::tree::command(Role::Rpc, Chain::Near);
        assert!(
            rpc.try_get_matches_from(["rpc", "registration", "--action", "prepare"])
                .is_err()
        );
    }

    #[test]
    fn all_seven_registration_steps_enforce_amount_boundaries_before_store_or_host_access() {
        let command = crate::tree::command(Role::Validator, Chain::Near);
        for step in [
            "create-pool",
            "stake",
            "ping",
            "pause",
            "resume",
            "unstake",
            "withdraw",
        ] {
            let needs_amount = ["create-pool", "stake", "unstake", "withdraw"].contains(&step);
            let mut args = vec![
                "validator",
                "registration",
                "-n",
                "testnet",
                "--action",
                "prepare",
                "--step",
                step,
            ];
            if needs_amount {
                assert!(command.clone().try_get_matches_from(&args).is_err());
                args.extend(["--amount-yocto", "1"]);
            }
            let parsed = command
                .clone()
                .try_get_matches_from(&args)
                .expect("every documented step parses");
            let sub = parsed
                .subcommand_matches("registration")
                .expect("registration");
            super::validate_registration_inputs(sub).expect("valid explicit amount policy");
            if needs_amount {
                for invalid in ["0", "01", "1e24", "340282366920938463463374607431768211456"] {
                    let last = args.len() - 1;
                    args[last] = invalid;
                    let parsed = command
                        .clone()
                        .try_get_matches_from(&args)
                        .expect("amount is validated before access");
                    assert!(
                        super::validate_registration_inputs(
                            parsed.subcommand_matches("registration").unwrap()
                        )
                        .is_err()
                    );
                }
            } else {
                args.extend(["--amount-yocto", "1"]);
                let parsed = command.clone().try_get_matches_from(&args).unwrap();
                assert!(
                    super::validate_registration_inputs(
                        parsed.subcommand_matches("registration").unwrap()
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn restore_key_has_mutating_production_guards_while_observations_stay_read_only() {
        use erpc_core::chain::{Source, guard_mainnet};
        let command = crate::tree::command(Role::Validator, Chain::Near);
        for action in ["restore-key", "status", "validate", "prepare"] {
            let mut args = vec!["validator", "registration", "--action", action];
            if action == "prepare" {
                args.extend(["--step", "ping"]);
            }
            let parsed = command.clone().try_get_matches_from(args).unwrap();
            let effective = super::effective_verb(
                &super::REGISTRATION,
                parsed.subcommand_matches("registration").unwrap(),
            );
            assert_eq!(effective.read_only, action != "restore-key");
            for source in [Source::Env, Source::Config] {
                assert_eq!(
                    guard_mainnet(&effective, Chain::Near, source, Some("mainnet")).is_err(),
                    action == "restore-key"
                );
            }
            assert!(guard_mainnet(&effective, Chain::Near, Source::Flag, Some("mainnet")).is_ok());
        }
    }
}
