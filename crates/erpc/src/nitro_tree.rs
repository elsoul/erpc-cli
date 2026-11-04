// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Nitro follower arguments; validator activation is a separate role.

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
        "init" => command.about("Reserve a dedicated Nitro host and pin a reviewed image; no wallet or sequencer")
            .arg(Arg::new("host").long("host"))
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16)))
            .arg(Arg::new("fingerprint").long("fingerprint"))
            .arg(Arg::new("vault").long("vault"))
            .arg(Arg::new("version").long("version").help("Nitro version from the reviewed image catalog; default is recommended"))
            .arg(Arg::new("l1-upstreams").long("l1-upstreams").help("Identifier-only op reference to concealed execution/beacon configuration")),
        "update" => command.about("Authenticate an explicitly selected stable release; preserve data, refuse downgrade and never auto-rollback")
            .arg(Arg::new("version").long("version").required(true)),
        "plan" => command.arg(Arg::new("change").long("change").default_value("deploy").value_parser(["deploy", "update", "update-config"]))
            .arg(Arg::new("version").long("version")),
        "logs" => command.arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32)))
            .arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "destroy" => command.about("Retire and disable the owned service; retain data, encrypted upstream credentials and immutable ownership"),
        "deploy" => command.about("Pull the reviewed image digest, verify chain metadata and start guarded follower services"),
        "update-config" => command.about("Reapply the owned services and refresh concealed L1 credentials, preserving data")
            .arg(Arg::new("l1-upstreams").long("l1-upstreams")),
        _ => command,
    }
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role};
    #[test]
    fn nitro_network_and_command_boundaries_are_explicit() {
        for chain in [Chain::Arbitrum, Chain::Robinhood] {
            let tree = crate::tree::command(Role::Rpc, chain);
            tree.clone().debug_assert();
            assert!(
                tree.clone()
                    .try_get_matches_from(["rpc", "update"])
                    .is_err()
            );
            assert!(
                tree.clone()
                    .try_get_matches_from(["rpc", "deploy", "--public-rpc"])
                    .is_err()
            );
            assert!(
                tree.try_get_matches_from(["rpc", "destroy", "--purge-data"])
                    .is_err()
            );
        }
        assert!(
            crate::tree::command(Role::Rpc, Chain::Arbitrum)
                .try_get_matches_from([
                    "rpc",
                    "init",
                    "-n",
                    "nova",
                    "--management-allow",
                    "192.0.2.0/24"
                ])
                .is_ok()
        );
        assert!(
            crate::tree::command(Role::Rpc, Chain::Robinhood)
                .try_get_matches_from(["rpc", "init", "-n", "sepolia"])
                .is_err()
        );
    }
}
