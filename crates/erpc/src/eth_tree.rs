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
            "Move the original node to a qualified release pair; preserve fenced data on failure"
        }
        "update-config" => {
            "Apply inventory access through an original guarded cutover and restart the pair"
        }
        "plan" => "Show what deploy, update or update-config would change, without changing it",
        "destroy" => {
            "Retire the original node and fence startup while retaining native data, JWT and ownership"
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
        Arg::new("migrate-authority").long("migrate-authority").action(ArgAction::SetTrue)
            .requires_all(["original-passwd","original-group","original-machine-id","original-client-record"])
            .help("Migrate a stopped legacy host using independently retained original numeric account records; retain data/JWT and do not start it"),
        Arg::new("original-passwd").long("original-passwd").value_parser(value_parser!(std::path::PathBuf)).requires("migrate-authority")
            .help("Original host backup's passwd file; a current NSS export is not evidence of original identity"),
        Arg::new("original-group").long("original-group").value_parser(value_parser!(std::path::PathBuf)).requires("migrate-authority")
            .help("Original host backup's group file"),
        Arg::new("original-machine-id").long("original-machine-id").value_parser(value_parser!(std::path::PathBuf)).requires("migrate-authority")
            .help("Original host backup's machine-id file"),
        Arg::new("original-client-record").long("original-client-record").value_parser(value_parser!(std::path::PathBuf)).requires("migrate-authority")
            .help("Independently retained highest-opened Reth/Lighthouse version and commit JSON; never inferred from current inventory"),
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
        "deploy" | "update" | "update-config" => {
            let mut args=vec![Arg::new("recover-cutover").long("recover-cutover").value_name("ORIGINAL_INTENT")
                .help("Stop and archive an interrupted original deployment, preserving identity/data; do not restart")];
            if verb == "deploy" {
                args.push(Arg::new("upgrade-volume-authority").long("upgrade-volume-authority")
                    .value_parser(value_parser!(std::path::PathBuf)).conflicts_with("recover-cutover")
                    .help("Fence and stop the original node, bind an independently retained original filesystem UUID record, and publish current helpers; no deploy/start"));
            }
            if verb == "update" {
                args.extend(versions());
            }
            if verb == "update-config" {
                args.extend(allow_lists());
            }
            args
        }
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
                .help("Unsupported for original-authority retirement; data and identity are retained"),
            Arg::new("forget")
                .long("forget")
                .action(ArgAction::SetTrue)
                .requires("purge-data")
                .help("Unsupported for original-authority retirement; the original inventory binding is retained"),
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
            json,
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

fn init_request(
    sub: &ArgMatches,
    network: &str,
    name: &str,
    login: crate::eth_rpc::Login,
    yes: bool,
) -> crate::eth_init::Args {
    crate::eth_init::Args {
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
        migrate_authority: sub.get_flag("migrate-authority"),
        original_passwd: sub
            .get_one::<std::path::PathBuf>("original-passwd")
            .cloned(),
        original_group: sub.get_one::<std::path::PathBuf>("original-group").cloned(),
        original_client_record: sub
            .get_one::<std::path::PathBuf>("original-client-record")
            .cloned(),
        original_machine_id: sub
            .get_one::<std::path::PathBuf>("original-machine-id")
            .cloned(),
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
            let args = init_request(sub, network, name, login, yes);
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
                recover_cutover: one(sub, "recover-cutover"),
                upgrade_volume_authority: sub
                    .try_get_one::<std::path::PathBuf>("upgrade-volume-authority")
                    .ok()
                    .flatten()
                    .cloned(),
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
    fn legacy_migration_requires_explicit_historical_source_records() {
        let tree = crate::tree::command(Role::Rpc, Chain::Eth);
        let mut args = vec![
            "rpc",
            "init",
            "--migrate-authority",
            "--original-passwd",
            "inert-passwd",
            "--original-group",
            "inert-group",
            "--original-machine-id",
            "inert-machine",
        ];
        assert!(tree.clone().try_get_matches_from(args.clone()).is_err());
        args.extend(["--original-client-record", "inert-client-record"]);
        let parsed = tree
            .try_get_matches_from(args)
            .expect("complete original evidence parses without external tools");
        let (_, sub) = parsed.subcommand().unwrap();
        assert_eq!(
            sub.get_one::<std::path::PathBuf>("original-client-record")
                .unwrap(),
            &std::path::PathBuf::from("inert-client-record")
        );
    }
    #[test]
    fn volume_upgrade_is_an_explicit_deploy_only_recovery_action() {
        let tree = crate::tree::command(Role::Rpc, Chain::Eth);
        let parsed = tree
            .clone()
            .try_get_matches_from([
                "erpc rpc",
                "deploy",
                "-n",
                "mainnet",
                "--name",
                "eth1",
                "--upgrade-volume-authority",
                "original-volume.json",
            ])
            .unwrap();
        let sub = parsed.subcommand().unwrap().1;
        assert_eq!(
            sub.get_one::<std::path::PathBuf>("upgrade-volume-authority")
                .unwrap(),
            &std::path::PathBuf::from("original-volume.json")
        );
        for verb in ["start", "update", "update-config", "destroy", "init"] {
            assert!(
                tree.clone()
                    .try_get_matches_from([
                        "erpc rpc",
                        verb,
                        "--upgrade-volume-authority",
                        "original-volume.json"
                    ])
                    .is_err()
            );
        }
        assert!(
            tree.try_get_matches_from([
                "erpc rpc",
                "deploy",
                "--upgrade-volume-authority",
                "original-volume.json",
                "--recover-cutover",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ])
            .is_err()
        );
    }

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
