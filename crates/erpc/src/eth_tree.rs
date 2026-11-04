// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc rpc --chain eth <verb>`: the flags of each verb, and where each is
//! sent. Kept beside `tree.rs` so the Ethereum commands do not grow the tree
//! the other chains share.

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use erpc_core::chain::Verb;
use erpc_ssh::arc::Action;

use crate::commands::Outcome;

/// What each verb does on an Ethereum RPC node, for `--help`.
fn about(verb: &Verb) -> &'static str {
    match verb.name {
        "init" => {
            "Check the server, pin the Reth and Lighthouse releases, store the node in 1Password and prepare the host"
        }
        "deploy" => {
            "Install the pinned releases, fetch Reth's snapshot, apply the firewall and start both layers"
        }
        "list" => "List the Ethereum RPC nodes in the inventory",
        "status" => {
            "Show both layers' state, sync and head, and the head's lag behind the public endpoint"
        }
        "logs" => "Show the journal of one layer or both",
        "start" => "Start Reth, then Lighthouse",
        "stop" => "Stop Lighthouse, then Reth",
        "restart" => "Restart both layers in order, or one",
        "update" => {
            "Move the node to another Reth and Lighthouse release pair, rolling back on failure"
        }
        "update-config" => {
            "Write the units and the firewall again from the inventory, restarting only on a change"
        }
        "plan" => "Show what deploy, update or update-config would change, without changing it",
        "destroy" => {
            "Stop and remove the services and the firewall; the chain data only with --purge-data"
        }
        _ => verb.about,
    }
}

/// The flags of each `erpc r --chain eth` verb: how to log in, the verb's
/// own, and `--yes` on anything that changes the node.
pub(crate) fn args(sub: Command, verb: &Verb) -> Command {
    let mut sub = sub.about(about(verb));
    if verb.name != "list" {
        sub = sub
            .arg(
                Arg::new("ssh-key")
                    .long("ssh-key")
                    .value_parser(value_parser!(std::path::PathBuf))
                    .help("The .pub file of the key that logs in"),
            )
            .arg(
                Arg::new("ssh-agent")
                    .long("ssh-agent")
                    .value_parser(value_parser!(std::path::PathBuf))
                    .help(
                        "The SSH agent's socket (default: 1Password's agent, else SSH_AUTH_SOCK)",
                    ),
            );
    }
    sub = sub.args(verb_args(verb.name));
    if verb.read_only {
        sub
    } else {
        sub.arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue)
                .help("Do not ask before changing the node"),
        )
    }
}

/// `init`'s own flags: where the server is, the vault, and the node's type.
fn init_args() -> Vec<Arg> {
    vec![
        Arg::new("host").long("host").help("The server's address"),
        Arg::new("user")
            .long("user")
            .default_value("ubuntu")
            .help("The sudo user erpc logs in as"),
        Arg::new("port")
            .long("port")
            .default_value("22")
            .value_parser(value_parser!(u16))
            .help("The SSH port"),
        Arg::new("fingerprint")
            .long("fingerprint")
            .help("The server's host key fingerprint, SHA256:…, to pin without asking"),
        Arg::new("vault")
            .long("vault")
            .help("The 1Password vault id for this network, when none is saved yet"),
        Arg::new("type")
            .long("type")
            .value_parser(["full", "archive"])
            .help("full: pruned, the usual RPC (default); archive: all history and state, with debug and trace. Fixed once stored"),
    ]
}

/// The flags only one verb, or a few, take.
fn verb_args(verb: &str) -> Vec<Arg> {
    let allow_lists = || {
        [
            ("rpc-allow", "Who may reach JSON-RPC (8545) and WebSocket (8546)"),
            ("management-allow", "Who may reach SSH, besides this machine"),
            ("monitoring-allow", "Who may scrape the metrics ports"),
        ]
        .map(|(id, what)| {
            Arg::new(id)
                .long(id)
                .action(ArgAction::Append)
                .value_delimiter(',')
                .help(format!(
                    "{what}: IPv4 addresses or CIDRs, repeated or comma-separated; replaces the stored list"
                ))
        })
    };
    let layer = || {
        Arg::new("layer")
            .long("layer")
            .default_value("both")
            .value_parser(["execution", "consensus", "both"])
            .help("Which layer: Reth (execution), Lighthouse (consensus), or both in order")
    };
    let versions = || {
        [
            Arg::new("reth-version").long("reth-version").help(
                "The Reth release tag, such as v2.8.1 (default: the newest at or above the floor)",
            ),
            Arg::new("lighthouse-version").long("lighthouse-version").help(
                "The Lighthouse release tag, such as v8.3.2 (default: the newest at or above the floor)",
            ),
        ]
    };
    match verb {
        "init" => {
            let mut args = init_args();
            args.extend(versions());
            args.extend(allow_lists());
            args
        }
        "update" => versions().into(),
        "update-config" => allow_lists().into(),
        "logs" => vec![
            layer(),
            Arg::new("lines")
                .long("lines")
                .default_value("100")
                .value_parser(value_parser!(u32))
                .help("How many lines from the end"),
            Arg::new("follow")
                .long("follow")
                .short('f')
                .action(ArgAction::SetTrue)
                .help("Keep printing new lines"),
        ],
        "start" | "stop" | "restart" => vec![layer()],
        "plan" => {
            let mut args = vec![
                Arg::new("change")
                    .long("change")
                    .default_value("deploy")
                    .value_parser(["deploy", "update", "update-config"])
                    .help("Which change to show"),
            ];
            args.extend(versions());
            args.extend(allow_lists());
            args
        }
        "destroy" => vec![
            Arg::new("purge-data")
                .long("purge-data")
                .action(ArgAction::SetTrue)
                .help("Also delete the chain data (the 1Password item is kept)"),
            Arg::new("forget")
                .long("forget")
                .action(ArgAction::SetTrue)
                .requires("purge-data")
                .help("With --purge-data: then remove the node's 1Password item"),
        ],
        _ => Vec::new(),
    }
}

fn many(sub: &ArgMatches, id: &str) -> Option<Vec<String>> {
    sub.try_get_many::<String>(id)
        .ok()
        .flatten()
        .map(|v| v.cloned().collect())
}

fn one(sub: &ArgMatches, id: &str) -> Option<String> {
    sub.try_get_one::<String>(id).ok().flatten().cloned()
}

/// `status`, `logs`, `start`, `stop` and `restart`.
fn ops(
    verb: &str,
    args: &crate::eth_ops::Args,
    sub: &ArgMatches,
    yes: bool,
    json: bool,
) -> Outcome {
    let layer = one(sub, "layer").unwrap_or_else(|| "both".to_owned());
    match verb {
        "status" => crate::eth_ops::status(args, json),
        "logs" => crate::eth_ops::logs(
            args,
            &layer,
            sub.get_one::<u32>("lines").copied().unwrap_or(100),
            sub.get_flag("follow"),
        ),
        other => {
            let action = match other {
                "start" => Action::Start,
                "stop" => Action::Stop,
                _ => Action::Restart,
            };
            crate::eth_ops::service(args, action, &layer, yes, json)
        }
    }
}

/// Runs `erpc r --chain eth <verb>`.
pub(crate) async fn run(
    verb: &Verb,
    sub: &ArgMatches,
    network: Option<&str>,
    name: Option<&str>,
    json: bool,
) -> Outcome {
    let login = crate::eth_rpc::Login {
        ssh_key: sub
            .try_get_one::<std::path::PathBuf>("ssh-key")
            .ok()
            .flatten()
            .cloned(),
        ssh_agent: sub
            .try_get_one::<std::path::PathBuf>("ssh-agent")
            .ok()
            .flatten()
            .cloned(),
    };
    let yes = sub
        .try_get_one::<bool>("yes")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false);
    if verb.name == "list" {
        return crate::eth_ops::list(network, json);
    }
    let (Some(network), Some(name)) = (network, name) else {
        return Outcome::Usage(format!(
            "`erpc r --chain eth {}` needs --network and --name, the node's name",
            verb.name
        ));
    };
    match verb.name {
        "init" => {
            let args = crate::eth_init::Args {
                network: network.to_owned(),
                name: name.to_owned(),
                host: one(sub, "host"),
                user: one(sub, "user").unwrap_or_default(),
                port: sub.get_one::<u16>("port").copied().unwrap_or(22),
                fingerprint: one(sub, "fingerprint"),
                vault: one(sub, "vault"),
                rpc_type: one(sub, "type"),
                reth_version: one(sub, "reth-version"),
                lighthouse_version: one(sub, "lighthouse-version"),
                rpc_allow: many(sub, "rpc-allow"),
                management_allow: many(sub, "management-allow"),
                monitoring_allow: many(sub, "monitoring-allow"),
                login,
                yes,
            };
            crate::eth_init::run(args, json).await
        }
        "status" | "logs" | "start" | "stop" | "restart" => {
            let args = crate::eth_ops::Args {
                network: network.to_owned(),
                name: name.to_owned(),
                login,
            };
            ops(verb.name, &args, sub, yes, json)
        }
        _ => {
            let args = crate::eth_deploy::Args {
                network: network.to_owned(),
                name: name.to_owned(),
                login,
                yes,
                reth_version: one(sub, "reth-version"),
                lighthouse_version: one(sub, "lighthouse-version"),
                rpc_allow: many(sub, "rpc-allow"),
                management_allow: many(sub, "management-allow"),
                monitoring_allow: many(sub, "monitoring-allow"),
                purge_data: sub
                    .try_get_one::<bool>("purge-data")
                    .ok()
                    .flatten()
                    .copied()
                    .unwrap_or(false),
                forget: sub
                    .try_get_one::<bool>("forget")
                    .ok()
                    .flatten()
                    .copied()
                    .unwrap_or(false),
                change: one(sub, "change").unwrap_or_else(|| "deploy".to_owned()),
            };
            match verb.name {
                "deploy" => crate::eth_deploy::deploy(&args, json),
                "update-config" => crate::eth_deploy::update_config(&args, json),
                "update" => crate::eth_deploy::update(&args, json).await,
                "plan" => crate::eth_deploy::plan(&args, json).await,
                "destroy" => crate::eth_deploy::destroy(&args, json),
                other => Outcome::Usage(format!("`erpc r --chain eth {other}` is not a verb")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use erpc_core::chain::{Chain, Role};

    #[test]
    fn every_verb_is_there_with_its_flags() {
        let tree = crate::tree::command(Role::Rpc, Chain::Eth);
        let init = tree
            .clone()
            .try_get_matches_from([
                "erpc rpc",
                "init",
                "-n",
                "mainnet",
                "--name",
                "eth1",
                "--host",
                "192.0.2.10",
                "--type",
                "archive",
                "--reth-version",
                "v2.8.1",
                "--rpc-allow",
                "198.51.100.0/24,203.0.113.5",
            ])
            .expect("init parses");
        let (_, init) = init.subcommand().expect("verb");
        assert_eq!(
            init.get_one::<String>("type").map(String::as_str),
            Some("archive")
        );
        assert_eq!(
            init.get_many::<String>("rpc-allow").expect("allow").count(),
            2
        );
        assert!(
            tree.clone()
                .try_get_matches_from(["erpc rpc", "init", "--type", "provider"])
                .is_err()
        );
        for verb in [
            "deploy",
            "list",
            "status",
            "logs",
            "start",
            "stop",
            "restart",
            "update",
            "update-config",
            "plan",
            "destroy",
        ] {
            assert!(
                tree.clone()
                    .try_get_matches_from(["erpc rpc", verb])
                    .is_ok(),
                "{verb}"
            );
        }
    }
}
