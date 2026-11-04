// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin RPC argument contract; Bitcoin validator commands remain N/A.

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
    match verb.name {
        "init" => command.about("Reserve a dedicated Bitcoin Core host and pin an authenticated release; no wallet or mining")
            .arg(Arg::new("host").long("host"))
            .arg(Arg::new("user").long("user").default_value("ubuntu"))
            .arg(Arg::new("port").long("port").default_value("22").value_parser(value_parser!(u16)))
            .arg(Arg::new("fingerprint").long("fingerprint"))
            .arg(Arg::new("vault").long("vault"))
            .arg(Arg::new("version").long("version").help("Stable Core version; default is the reviewed recommendation"))
            .arg(Arg::new("type").long("type").value_parser(["full", "pruned"]).help("Default full retains blocks and enables txindex; immutable for this owner"))
            .arg(Arg::new("prune-mib").long("prune-mib").value_parser(value_parser!(u64)).requires("type").help("Explicit pruned target; default 10240 MiB plus chainstate overhead")),
        "update" => command.about("Authenticate an explicitly selected stable release; preserve data, refuse downgrade and never auto-rollback")
            .arg(Arg::new("version").long("version").required(true)),
        "plan" => command.arg(Arg::new("change").long("change").default_value("deploy").value_parser(["deploy", "update", "update-config"]))
            .arg(Arg::new("version").long("version")),
        "logs" => command.arg(Arg::new("lines").long("lines").default_value("100").value_parser(value_parser!(u32)))
            .arg(Arg::new("follow").long("follow").short('f').action(ArgAction::SetTrue)),
        "destroy" => command.about("Retire and disable the owned service; retain data, cookie permissions and immutable ownership"),
        "deploy" => command.about("Verify both manifest signers and archive digest, then start Core with private cookie RPC; IBD runs in background"),
        "update-config" => command.about("Reapply the owned service and immutable private RPC configuration, preserving data"),
        _ => command,
    }
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role};
    #[test]
    fn explicit_network_and_retention_contracts_are_parsed() {
        let tree = crate::tree::command(Role::Rpc, Chain::Bitcoin);
        tree.clone().debug_assert();
        assert!(
            tree.clone()
                .try_get_matches_from([
                    "rpc",
                    "init",
                    "--network",
                    "signet",
                    "--type",
                    "pruned",
                    "--prune-mib",
                    "10240"
                ])
                .is_ok()
        );
        assert!(
            tree.clone()
                .try_get_matches_from(["rpc", "init", "--network", "testnet"])
                .is_err()
        );
        assert!(
            tree.clone()
                .try_get_matches_from(["rpc", "update"])
                .is_err()
        );
        assert!(
            tree.try_get_matches_from(["rpc", "destroy", "--purge-data"])
                .is_err()
        );
    }
}
