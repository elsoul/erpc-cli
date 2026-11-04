// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Avalanche command surface: node/rpc aliases and explicit validator intent.
use crate::commands::Outcome;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use erpc_core::chain::{Role, Verb};

pub(crate) const EXTRA: &[Verb] = &[
    Verb {
        name: "identity-backup",
        about: "Back up the sealed staking identity into 1Password",
        read_only: false,
    },
    Verb {
        name: "identity-restore",
        about: "Recover the same stopped host's identity from 1Password",
        read_only: false,
    },
    Verb {
        name: "prepare-registration",
        about: "Prepare P-Chain staking data for external signing; never submit",
        read_only: true,
    },
    Verb {
        name: "validate-registration",
        about: "Validate prepared staking data against the synced pinned node",
        read_only: true,
    },
];
#[allow(clippy::too_many_lines)]
pub(crate) fn args(sub: Command, verb: &Verb) -> Command {
    let mut sub = sub;
    if verb.name != "list" {
        sub = sub
            .arg(
                Arg::new("ssh-key")
                    .long("ssh-key")
                    .value_parser(value_parser!(std::path::PathBuf))
                    .help("Public key of the login identity in the SSH agent"),
            )
            .arg(
                Arg::new("ssh-agent")
                    .long("ssh-agent")
                    .value_parser(value_parser!(std::path::PathBuf)),
            );
    }
    if !verb.read_only {
        sub = sub.arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue),
        );
    }
    if verb.name == "init" {
        sub = sub
            .arg(Arg::new("host").long("host"))
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(
                Arg::new("port")
                    .long("port")
                    .default_value("22")
                    .value_parser(value_parser!(u16)),
            )
            .arg(Arg::new("fingerprint").long("fingerprint"))
            .arg(Arg::new("vault").long("vault"))
            .arg(
                Arg::new("type")
                    .long("type")
                    .value_parser(["full", "archive"])
                    .help("Fixed history policy; full uses state sync, archive replays genesis"),
            );
    }
    if ["init", "update", "plan"].contains(&verb.name) {
        sub = sub.arg(
            Arg::new("version")
                .long("version")
                .help("Reviewed stable AvalancheGo 1.15 patch tag; no downgrades"),
        );
    }
    if ["init", "update-config", "plan"].contains(&verb.name) {
        for name in ["rpc-allow", "management-allow", "monitoring-allow"] {
            sub = sub.arg(
                Arg::new(name)
                    .long(name)
                    .action(ArgAction::Append)
                    .value_delimiter(','),
            );
        }
    }
    if verb.name == "status" {
        sub = sub.arg(Arg::new("registration").long("registration").value_parser(value_parser!(std::path::PathBuf)).help("Prepared registration JSON, to compare the intended term with observed admission"));
    }
    if verb.name == "logs" {
        sub = sub
            .arg(
                Arg::new("lines")
                    .long("lines")
                    .default_value("100")
                    .value_parser(value_parser!(u32)),
            )
            .arg(
                Arg::new("follow")
                    .long("follow")
                    .short('f')
                    .action(ArgAction::SetTrue),
            );
    }
    if verb.name == "destroy" {
        sub = sub.arg(
            Arg::new("purge-data")
                .long("purge-data")
                .action(ArgAction::SetTrue)
                .help("Delete chain database/logs only; identity and inventory always remain"),
        );
    }
    if verb.name == "plan" {
        sub = sub.arg(
            Arg::new("change")
                .long("change")
                .default_value("deploy")
                .value_parser(["deploy", "update", "update-config"]),
        );
    }
    if verb.name == "prepare-registration" {
        for (name, help) in [
            (
                "stake-navax",
                "Integer stake in nAVAX, excluding transaction fees",
            ),
            ("end", "End Unix timestamp in seconds"),
        ] {
            sub = sub.arg(
                Arg::new(name)
                    .long(name)
                    .required(true)
                    .help(help)
                    .value_parser(value_parser!(u64)),
            );
        }
        sub = sub
            .arg(
                Arg::new("rewards-address")
                    .long("rewards-address")
                    .required(true),
            )
            .arg(
                Arg::new("delegation-fee-bps")
                    .long("delegation-fee-bps")
                    .default_value("200")
                    .value_parser(value_parser!(u16)),
            );
    }
    if verb.name == "validate-registration" {
        sub = sub.arg(
            Arg::new("file")
                .long("file")
                .required(true)
                .value_parser(value_parser!(std::path::PathBuf)),
        );
    }
    sub
}
pub(crate) async fn run(
    role: Role,
    verb: &Verb,
    sub: &ArgMatches,
    network: Option<&str>,
    name: Option<&str>,
    json: bool,
) -> Outcome {
    match crate::avax_ops::run(role, verb.name, sub, network, name, json).await {
        Ok(body) => {
            if json {
                crate::print_json(&body);
                Outcome::Done(String::new())
            } else {
                Outcome::Done(serde_json::to_string_pretty(&body).unwrap_or_default())
            }
        }
        Err(e) => Outcome::from(e),
    }
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role};
    #[test]
    fn rpc_node_aliases_and_validator_have_working_argument_contracts() {
        for role in [Role::Rpc, Role::Node, Role::Validator] {
            let command = crate::tree::command(role, Chain::Avax);
            for verb in erpc_core::chain::COMMON_VERBS {
                let mut args = vec![
                    role.as_str(),
                    "--chain",
                    "avax",
                    "--network",
                    "fuji",
                    "--name",
                    "node1",
                    verb.name,
                ];
                if verb.name == "update" {
                    args.extend(["--version", "v1.15.2"]);
                }
                assert!(
                    command.clone().try_get_matches_from(args).is_ok(),
                    "{} {}",
                    role,
                    verb.name
                );
            }
            assert!(
                command
                    .clone()
                    .try_get_matches_from([
                        role.as_str(),
                        "--chain",
                        "avax",
                        "--network",
                        "fuji",
                        "prepare-registration",
                        "--stake-navax",
                        "1000000000",
                        "--end",
                        "2000000000",
                        "--rewards-address",
                        "P-fixture"
                    ])
                    .is_ok()
            );
            assert!(
                command
                    .try_get_matches_from([
                        role.as_str(),
                        "--chain",
                        "avax",
                        "--network",
                        "fuji",
                        "prepare-registration",
                        "--start",
                        "2000000000"
                    ])
                    .is_err()
            );
        }
    }
}
