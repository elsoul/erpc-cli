// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Qualified follower command arguments; no sequencer or staking role.
use clap::{Arg, ArgAction, Command, value_parser};
use erpc_core::chain::Verb;

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
    if verb.name == "init" {
        command = command
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
                    .help("Immutable history policy, full by default"),
            );
    }
    if ["init", "update-config", "plan"].contains(&verb.name) {
        command = command.arg(Arg::new("advertise-ip").long("advertise-ip").help("Explicit public IPv4 address for peer advertisement"))
            .arg(Arg::new("l1-upstreams").long("l1-upstreams").help("Identifier-only op:// vault/item reference ending in the unique concealed field label"));
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
        "plan" => command.arg(Arg::new("change").long("change").default_value("deploy").value_parser(["deploy", "update", "update-config"])),
        "logs" => command.arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32)))
            .arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "update" => command.about("Move to this CLI's reviewed chain-specific pair; reject downgrades and never roll back a database"),
        "deploy" => command.about("Confirm network policy, install verified clients, then resume background bootstrap and synchronization")
            .arg(Arg::new("reset-bootstrap").long("reset-bootstrap").action(ArgAction::SetTrue).help("Explicitly quarantine incomplete bootstrap data and select fresh official metadata; completed databases always refuse")),
        "destroy" => command.about("Retire and disable this owned follower; preserve its database, peer identity and encrypted credentials"),
        _ => command,
    }
}
