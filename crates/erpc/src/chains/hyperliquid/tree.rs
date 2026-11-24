// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Hyperliquid non-validator node operations and explicit advertised peer address.
use clap::{Arg, ArgAction, Command, value_parser};
use erpc_core::chain::Verb;

pub(crate) fn args(mut command: Command, verb: &Verb) -> Command {
    command = command.arg(Arg::new("vault").long("vault"));
    if !["list", "plan"].contains(&verb.name) {
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
        for name in ["host", "user", "fingerprint", "public-ip"] {
            command = command.arg(Arg::new(name).long(name));
        }
        command = command.arg(
            Arg::new("port")
                .long("port")
                .value_parser(value_parser!(u16)),
        );
    }
    if ["init", "update-config", "plan"].contains(&verb.name) {
        for name in ["rpc-allow", "management-allow"] {
            command = command.arg(
                Arg::new(name)
                    .long(name)
                    .value_delimiter(',')
                    .action(ArgAction::Append),
            );
        }
    }
    if verb.name == "logs" {
        command = command
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
    if ["deploy", "update", "update-config"].contains(&verb.name) {
        command = command.arg(
            Arg::new("recover-preparation")
                .long("recover-preparation")
                .action(ArgAction::SetTrue)
                .help("Abandon unfinished host preparation after owned shutdown; preserve all native data"),
        );
    }
    command.about(match verb.name {
        "init" => "Reserve a non-validator host and its original numeric service identities",
        "deploy" => {
            "Authenticate the pinned supervisor and start under freshly confirmed filtering"
        }
        "update" => "Install this CLI's qualified supervisor; child releases remain vendor managed",
        "destroy" => "Retire owned services while preserving native data and filtering",
        "status" => {
            "Verify owned native sockets, network freshness and observed child executable hashes"
        }
        _ => verb.about,
    })
}
