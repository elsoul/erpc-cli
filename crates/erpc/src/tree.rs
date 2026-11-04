// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc validator|rpc|node <verb>`: the node command tree.
//!
//! The chain is read from the arguments before they are parsed, and the
//! tree is built for that chain, so `--help` shows only what the chain
//! has. The verbs are a skeleton: they resolve the chain and the network,
//! apply the mainnet rule, and say what they would run on.

use clap::{Arg, ArgMatches, Command};
use erpc_core::chain::{COMMON_VERBS, Chain, Role, Source, Verb, guard_mainnet, resolve};

use crate::commands::Outcome;

/// Finds `--chain X` or `--chain=X` without parsing anything else, so the
/// tree can be built for that chain first.
fn chain_flag(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--chain=") {
            return Some(value.to_owned());
        }
        if arg == "--chain" {
            return iter.next().cloned();
        }
    }
    None
}

/// For a bare `erpc <role>` whose chain is not set anywhere, while more
/// than one chain has the role: how to see each chain's commands. `None`
/// when the chain is known, so its own help is shown.
fn overview(role: Role) -> Option<String> {
    let env = std::env::var("ERPC_CHAIN").ok();
    let configured = crate::session::config_path()
        .ok()
        .and_then(|path| crate::config::get(&path, "default_chain").ok().flatten());
    if !matches!(
        resolve(None, env.as_deref(), configured.as_deref()),
        Ok(None)
    ) {
        return None;
    }
    let chains: Vec<Chain> = Chain::ALL
        .into_iter()
        .filter(|c| c.roles().contains(&role))
        .collect();
    if chains.len() < 2 {
        return None;
    }
    Some(overview_text(role, &chains))
}

fn overview_text(role: Role, chains: &[Chain]) -> String {
    use core::fmt::Write as _;
    let names: Vec<&str> = chains.iter().map(|c| c.as_str()).collect();
    let mut text = format!(
        "erpc {role}: commands on {}. Pick the chain with --chain:\n\n",
        names.join(", ")
    );
    for chain in chains {
        let _ = writeln!(text, "  erpc {role} --chain {chain} --help");
    }
    text.push_str("\nOr set a default: erpc config set default_chain <chain>\n");
    text
}

/// Resolves the chain for `role`, asking at a terminal when nothing names
/// one and more than one chain has the role.
fn chain_for(role: Role, args: &[String], json: bool) -> Result<(Chain, Source), Outcome> {
    let flag = chain_flag(args);
    let env = std::env::var("ERPC_CHAIN").ok();
    let configured = crate::session::config_path()
        .ok()
        .and_then(|path| crate::config::get(&path, "default_chain").ok().flatten());
    match resolve(flag.as_deref(), env.as_deref(), configured.as_deref()) {
        Err(e) => Err(Outcome::Usage(e)),
        Ok(Some(found)) => Ok(found),
        Ok(None) => {
            let candidates: Vec<Chain> = Chain::ALL
                .into_iter()
                .filter(|c| c.roles().contains(&role))
                .collect();
            if let [only] = candidates.as_slice() {
                return Ok((*only, Source::Prompt));
            }
            if json || !crate::session::has_terminal() {
                return Err(Outcome::Usage(
                    "no chain is chosen: pass --chain, set ERPC_CHAIN, or \
                     `erpc config set default_chain <chain>`"
                        .to_owned(),
                ));
            }
            let labels: Vec<String> = candidates.iter().map(ToString::to_string).collect();
            let index =
                crate::prompt::pick("Which chain?", &labels, Some(0)).map_err(Outcome::Failed)?;
            Ok((candidates[index], Source::Prompt))
        }
    }
}

/// The clap tree for `role` on `chain`.
pub(crate) fn command(role: Role, chain: Chain) -> Command {
    let networks: Vec<&'static str> = chain.networks().to_vec();
    let mut command = Command::new(role.as_str())
        .bin_name(format!("erpc {role}"))
        .about(format!("{role} commands on {chain}"))
        .arg(
            Arg::new("chain")
                .long("chain")
                .global(true)
                .help(format!("The chain: {}", Chain::names())),
        )
        .arg(
            Arg::new("network")
                .long("network")
                .short('n')
                .global(true)
                .value_parser(networks)
                .help("The network; mainnet changes need --chain on the command line too"),
        )
        .arg(
            Arg::new("name")
                .long("name")
                .global(true)
                .help("The host, by its inventory name"),
        );
    for verb in COMMON_VERBS {
        let mut sub = Command::new(verb.name).about(verb.about);
        if role == Role::Validator && chain == Chain::Solana {
            match verb.name {
                "init" => sub = init_args(sub),
                "deploy" | "status" => sub = deploy_args(sub, verb.name == "deploy"),
                _ => {}
            }
        }
        if role == Role::Rpc && chain == Chain::Arc {
            sub = arc_args(sub, verb);
        }
        if role == Role::Rpc && chain == Chain::Solana {
            sub = solana_rpc_args(sub, verb);
        }
        if role == Role::Rpc && chain == Chain::Eth {
            sub = crate::eth_tree::args(sub, verb);
        }
        if role == Role::Validator && chain == Chain::Eth {
            sub = crate::eth_validator_tree::common(sub, verb);
        }
        if chain == Chain::Avax {
            sub = crate::avax_tree::args(sub, verb);
        }
        if chain == Chain::Sui && matches!(role, Role::Rpc | Role::Node | Role::Validator) {
            sub = crate::sui_tree::args(sub, verb, role == Role::Validator);
        }
        if role == Role::Rpc && matches!(chain, Chain::Optimism | Chain::Base | Chain::Soneium) {
            sub = crate::rollup_tree::args(sub, verb);
        }
        if role == Role::Rpc && chain == Chain::Bitcoin {
            sub = crate::bitcoin_tree::args(sub, verb);
        }
        if role == Role::Rpc && matches!(chain, Chain::Arbitrum | Chain::Robinhood) {
            sub = crate::nitro_tree::args(sub, verb);
        }
        if chain == Chain::Tron {
            sub = crate::tron_tree::args(sub, verb, role == Role::Validator);
        }
        command = command.subcommand(sub);
    }
    if role == Role::Validator && chain == Chain::Eth {
        command = crate::eth_validator_tree::extras(command);
    }
    if role == Role::Validator && chain == Chain::Solana {
        command = command.subcommand(keys_command()).subcommand(
            Command::new("vote-account")
                .about("Create the validator's vote account on chain and register its BLS key")
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .short('y')
                        .action(clap::ArgAction::SetTrue)
                        .help("Do not ask before sending a transaction"),
                ),
        );
    }
    if chain == Chain::Avax {
        for verb in crate::avax_tree::EXTRA {
            command = command.subcommand(crate::avax_tree::args(
                Command::new(verb.name).about(verb.about),
                verb,
            ));
        }
    }
    registration_command(command, role, chain)
}

fn registration_command(mut command: Command, role: Role, chain: Chain) -> Command {
    if role == Role::Validator {
        let registration = Command::new("registration");
        command = match chain {
            Chain::Sui => command.subcommand(crate::sui_tree::args(
                registration,
                &crate::sui_tree::REGISTRATION,
                true,
            )),
            Chain::Tron => command.subcommand(crate::tron_tree::args(
                registration,
                &crate::tron_tree::REGISTRATION,
                true,
            )),
            _ => command,
        };
    }
    command
}

/// The flags of `erpc v deploy` and `erpc v status`.
fn deploy_args(sub: Command, asks: bool) -> Command {
    use clap::ArgAction;
    use clap::value_parser;
    let sub = sub
        .arg(
            Arg::new("host-name").long("host-name").help(
                "Which of the validator's hosts, by inventory name, when it has more than one",
            ),
        )
        .arg(
            Arg::new("ssh-key")
                .long("ssh-key")
                .value_parser(value_parser!(std::path::PathBuf))
                .help("The .pub file of the key that logs in as solv"),
        )
        .arg(
            Arg::new("ssh-agent")
                .long("ssh-agent")
                .value_parser(value_parser!(std::path::PathBuf))
                .help("The SSH agent's socket (default: 1Password's agent, else SSH_AUTH_SOCK)"),
        );
    if asks {
        sub.arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue)
                .help("Do not ask before running"),
        )
    } else {
        sub
    }
}

/// The flags of `erpc v init`.
fn init_args(sub: Command) -> Command {
    use clap::ArgAction;
    use clap::value_parser;
    sub.arg(Arg::new("host").long("host").help("The server's address"))
        .arg(
            Arg::new("user")
                .long("user")
                .default_value("ubuntu")
                .help("The user that logs in before solv exists"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("22")
                .value_parser(value_parser!(u16))
                .help("The SSH port"),
        )
        .arg(
            Arg::new("spare")
                .long("spare")
                .action(ArgAction::SetTrue)
                .help("Add the server as a spare of an existing validator"),
        )
        .arg(
            Arg::new("ssh-key")
                .long("ssh-key")
                .value_parser(value_parser!(std::path::PathBuf))
                .help("The .pub file of the key that logs in; it is authorized for solv too"),
        )
        .arg(
            Arg::new("ssh-agent")
                .long("ssh-agent")
                .value_parser(value_parser!(std::path::PathBuf))
                .help("The SSH agent's socket (default: 1Password's agent, else SSH_AUTH_SOCK)"),
        )
        .arg(
            Arg::new("fingerprint")
                .long("fingerprint")
                .help("The server's host key fingerprint, SHA256:…, to pin without asking"),
        )
        .arg(
            Arg::new("vault")
                .long("vault")
                .help("The 1Password vault id for this network, when none is saved yet"),
        )
        .arg(
            Arg::new("client")
                .long("client")
                .default_value("agave")
                .value_parser(["agave", "jito", "allnodes-jito", "firedancer"])
                .help("The validator client (firedancer is the full Firedancer)"),
        )
        .arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue)
                .help("Do not ask before writing"),
        )
        .args(key_source_args(true))
}

/// The flags that name where a validator's keys come from.
fn key_source_args(with_identity: bool) -> Vec<Arg> {
    const FORMS: &str = "new, op://<vault>/<item>/keypair, a file (such as ~/.slv/keys/<pubkey>.json), \
                         node:<host>:<path>, ssh:<user>@<address>:<path>";
    let mut out = Vec::new();
    if with_identity {
        out.push(Arg::new("identity").long("identity").help(format!(
            "Where the identity comes from (default: new): {FORMS}"
        )));
    }
    out.push(Arg::new("vote-account").long("vote-account").help(format!(
        "Where the vote account's key comes from (default: new): {FORMS}, or its public key"
    )));
    out.push(Arg::new("authority").long("authority").help(format!(
        "Where the withdraw authority comes from (default: new): {FORMS}, or its public key"
    )));
    out.push(
        Arg::new("source-fingerprint")
            .long("source-fingerprint")
            .help("The host key fingerprint, SHA256:…, of the machine an ssh: key is read from"),
    );
    out
}

/// What each verb does on an Arc RPC node, for `--help`.
fn arc_about(verb: &Verb) -> &'static str {
    match verb.name {
        "init" => {
            "Check the server, pin the release, make the consensus key in 1Password and prepare the host"
        }
        "deploy" => {
            "Install the pinned release, fetch snapshots, apply the firewall and start both layers"
        }
        "list" => "List the Arc RPC nodes in the inventory",
        "status" => "Show both layers' state, the head and its lag behind the public endpoint",
        "logs" => "Show the journal of one layer or both",
        "start" => "Start the execution layer, then the consensus layer",
        "stop" => "Stop the consensus layer, then the execution layer",
        "restart" => "Restart both layers in order, then check the head moves",
        "update" => "Move to another release, rolling back when it does not come up",
        "update-config" => {
            "Re-render the units and firewall from the inventory, restarting only on a change"
        }
        "plan" => "Show what deploy, update or update-config would change, without changing it",
        "destroy" => "Stop and remove the services and firewall; data only with --purge-data",
        _ => verb.about,
    }
}

/// The flags of each `erpc r --chain arc` verb: how to log in, the verb's
/// own, and `--yes` on anything that changes the node.
fn arc_args(sub: Command, verb: &Verb) -> Command {
    use clap::ArgAction;
    use clap::value_parser;
    let mut sub = sub.about(arc_about(verb));
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
    sub = sub.args(arc_verb_args(verb.name));
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

/// `debug` and `trace`, and a provider node's peers from Arc's onboarding:
/// the flags init and update-config share.
fn arc_kind_args() -> [Arg; 3] {
    use clap::ArgAction;
    use clap::value_parser;
    [
        Arg::new("debug-api")
            .long("debug-api")
            .num_args(0..=1)
            .default_missing_value("true")
            .value_parser(value_parser!(bool))
            .help("Serve debug and trace too (not on provider nodes); --debug-api false turns them off"),
        Arg::new("trusted-peers")
            .long("trusted-peers")
            .action(ArgAction::Append)
            .value_delimiter(',')
            .help("Provider nodes: the execution-layer peers from onboarding, enode URLs; replaces the stored list"),
        Arg::new("sentry-peers")
            .long("sentry-peers")
            .action(ArgAction::Append)
            .value_delimiter(',')
            .help("Provider nodes: the consensus-layer sentries from onboarding, multiaddrs; replaces the stored list"),
    ]
}

/// `destroy`'s flags.
fn arc_destroy_args() -> Vec<Arg> {
    use clap::ArgAction;
    vec![
    Arg::new("purge-data")
        .long("purge-data")
        .action(ArgAction::SetTrue)
        .help("Also delete the chain data (the 1Password items are kept)"),
    Arg::new("forget")
        .long("forget")
        .action(ArgAction::SetTrue)
        .requires("purge-data")
        .help("With --purge-data: then remove the node's 1Password item, so init can set the server up again as any type (the consensus key's item stays)"),
    ]
}

/// The flags only one Arc verb, or a few, take.
fn arc_verb_args(verb: &str) -> Vec<Arg> {
    use clap::ArgAction;
    use clap::value_parser;
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
            .help("Which layer: the execution layer, the consensus layer, or both in order")
    };
    let version = || {
        Arg::new("version").long("version").help(
            "The arc-node release tag, such as v0.8.1 (default: the newest at or above the floor)",
        )
    };
    match verb {
        "init" => {
            let mut args = vec![
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
                version(),
                Arg::new("type")
                    .long("type")
                    .value_parser(erpc_chain_arc::kind::RpcType::NAMES)
                    .help("full: follows the public relays, keeps recent history (default); archive: keeps all history; provider: an RPC provider node Arc onboarded, peering with its sentries. Fixed once stored"),
            ];
            args.extend(allow_lists());
            args.extend(arc_kind_args());
            args
        }
        "update" => vec![version()],
        "update-config" => {
            let mut args: Vec<Arg> = allow_lists().into();
            args.extend(arc_kind_args());
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
                version(),
            ];
            // What update-config would be given, to show what it changes.
            args.extend(allow_lists());
            args.extend(arc_kind_args());
            args
        }
        "destroy" => arc_destroy_args(),
        _ => Vec::new(),
    }
}

/// What each verb does on a Solana RPC node, for `--help`.
fn solana_rpc_about(verb: &Verb) -> &'static str {
    match verb.name {
        "init" => {
            "Check the server, pin the client and its plugins, store the node in 1Password and make the solv user"
        }
        "deploy" => {
            "Build the client, make the node's identity, fetch a snapshot, start it and apply the firewall"
        }
        "list" => "List the Solana RPC nodes in the inventory",
        "status" => {
            "Show the validator's health and slot, Old Faithful, the identity and the firewall"
        }
        "logs" => "Show the validator's log, or a service's journal",
        "start" => "Start the validator, or Old Faithful",
        "stop" => "Stop the validator, or Old Faithful",
        "restart" => "Restart the validator, or Old Faithful",
        "update" => "Build another client release and restart the validator on it",
        "update-config" => {
            "Write the startup and firewall again from the inventory, restarting only on a change"
        }
        "plan" => "Show what deploy, update or update-config would change, without changing it",
        "destroy" => "Stop and remove the services and firewall; the ledger only with --purge-data",
        _ => verb.about,
    }
}

/// The flags of each `erpc r --chain solana` verb: how to log in, the verb's
/// own, and `--yes` on anything that changes the node.
fn solana_rpc_args(sub: Command, verb: &Verb) -> Command {
    use clap::ArgAction;
    use clap::value_parser;
    let mut sub = sub.about(solana_rpc_about(verb));
    if verb.name != "list" {
        sub = sub
            .arg(
                Arg::new("ssh-key")
                    .long("ssh-key")
                    .value_parser(value_parser!(std::path::PathBuf))
                    .help("The .pub file of the key that logs in; init authorizes it for solv too"),
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
    sub = sub.args(solana_rpc_verb_args(verb.name));
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

/// The flags only one Solana RPC verb, or a few, take.
// One table of every verb's flags reads better than pieces of it.
#[allow(clippy::too_many_lines)]
fn solana_rpc_verb_args(verb: &str) -> Vec<Arg> {
    use clap::ArgAction;
    use clap::value_parser;
    let allow_lists = || {
        [
            (
                "rpc-allow",
                "Who may reach JSON-RPC (7211), WebSocket (7212), gRPC (10000) and Old Faithful (8888)",
            ),
            ("management-allow", "Who may reach SSH, besides this machine"),
            ("monitoring-allow", "Who may scrape the metrics ports (9100, 8999, 7999)"),
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
    let version = || {
        Arg::new("version").long("version").help(
            "The client release: an agave or jito tag (v4.3.2, v4.3.2-jito); default: the recommended one",
        )
    };
    let geyser = || {
        Arg::new("geyser-version").long("geyser-version").help(
            "The Yellowstone gRPC tag for the gRPC types (default: the newest built for the client's agave)",
        )
    };
    let service = || {
        Arg::new("service")
            .long("service")
            .default_value("validator")
            .value_parser(["validator", "faithful"])
            .help("The validator (solv), or Old Faithful")
    };
    match verb {
        "init" => {
            let mut args = vec![
                Arg::new("host").long("host").help("The server's address"),
                Arg::new("user")
                    .long("user")
                    .default_value("ubuntu")
                    .help("The user that logs in before solv exists"),
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
                Arg::new("client")
                    .long("client")
                    .value_parser(["jito", "agave"])
                    .help("The client (default for a new node: jito)"),
                Arg::new("type")
                    .long("type")
                    .value_parser(["send-tx", "index", "grpc", "index-grpc"])
                    .help(
                        "The RPC type: send-tx, index (with Old Faithful), grpc (Yellowstone) or index-grpc",
                    ),
                version(),
                geyser(),
            ];
            args.extend(allow_lists());
            args
        }
        "update" => vec![version(), geyser()],
        "update-config" => allow_lists().into(),
        "logs" => vec![
            Arg::new("source")
                .long("source")
                .default_value("validator")
                .value_parser(["validator", "journal", "faithful", "firewall"])
                .help(
                    "The validator's log, its unit's journal, Old Faithful's journal, or the firewall's",
                ),
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
        "start" | "stop" | "restart" => vec![service()],
        "plan" => {
            let mut args = vec![
                Arg::new("change")
                    .long("change")
                    .default_value("deploy")
                    .value_parser(["deploy", "update", "update-config"])
                    .help("Which change to show"),
                version(),
                geyser(),
            ];
            args.extend(allow_lists());
            args
        }
        "destroy" => vec![
            Arg::new("purge-data")
                .long("purge-data")
                .action(ArgAction::SetTrue)
                .help("Also delete the ledger, accounts and snapshots (the 1Password item is kept)"),
        ],
        _ => Vec::new(),
    }
}

/// `erpc v keys`: its flags.
fn keys_command() -> Command {
    use clap::ArgAction;
    use clap::value_parser;
    Command::new("keys")
        .about("Show a validator's keys, and make or import its vote account key and withdraw authority")
        .args(key_source_args(false))
        .arg(
            Arg::new("ssh-key")
                .long("ssh-key")
                .value_parser(value_parser!(std::path::PathBuf))
                .help("The .pub of the key that logs in, to read a key from node: or ssh:"),
        )
        .arg(
            Arg::new("ssh-agent")
                .long("ssh-agent")
                .value_parser(value_parser!(std::path::PathBuf))
                .help("The SSH agent's socket"),
        )
        .arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue)
                .help("Do not ask before writing"),
        )
}

/// Runs `erpc <role> ...`.
pub async fn run(role: Role, args: &[String], json: bool) -> Outcome {
    // Nothing after the role, or only a request for help: its help,
    // without asking for a chain first.
    let help_only = matches!(args, [one] if ["--help", "-h", "help"].contains(&one.as_str()));
    if args.is_empty() && json {
        // A script gets an error it can test for, not help text.
        return Outcome::Usage(format!(
            "erpc {role} needs a verb; `erpc {role} --help` lists them"
        ));
    }
    if (args.is_empty() || help_only)
        && let Some(overview) = overview(role)
    {
        return Outcome::Done(overview);
    }
    let (chain, source) = match chain_for(role, args, json) {
        Ok(found) => found,
        Err(outcome) => return outcome,
    };
    if !chain.roles().contains(&role) {
        if role == Role::Validator
            && let Some(reason) = chain.validator_na_reason()
        {
            return Outcome::Usage(format!("validator N/A for {chain}: {reason}"));
        }
        let roles: Vec<&str> = chain.roles().iter().map(|r| r.as_str()).collect();
        return Outcome::Usage(format!(
            "{chain} has no {role} commands (chain from {source}); use `erpc {}`",
            roles.join("` or `erpc ")
        ));
    }
    let full = std::iter::once(format!("erpc {role}")).chain(args.iter().cloned());
    let matches = match command(role, chain).try_get_matches_from(full) {
        Ok(matches) => matches,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                Outcome::Usage(String::new())
            } else {
                Outcome::Done(String::new())
            };
        }
    };
    let Some((name, sub)) = matches.subcommand() else {
        // No verb: what the verbs are, as --help shows them; a script
        // (--json) gets an error it can test for instead.
        if json {
            return Outcome::Usage(format!(
                "erpc {role} needs a verb; `erpc {role} --chain {chain} --help` lists them"
            ));
        }
        return Outcome::Done(command(role, chain).render_help().to_string());
    };
    if role == Role::Validator && chain == Chain::Eth {
        return crate::eth_validator_tree::run(name, sub, source, json).await;
    }
    if role == Role::Validator && chain == Chain::Solana && name == "vote-account" {
        let (Some(network), Some(vname)) = (
            sub.get_one::<String>("network"),
            sub.get_one::<String>("name"),
        ) else {
            return Outcome::Usage("`erpc v vote-account` needs --network and --name".to_owned());
        };
        let args = crate::validator_vote::Args {
            network: network.clone(),
            name: vname.clone(),
            yes: sub.get_flag("yes"),
        };
        return crate::validator_vote::run(&args, json);
    }
    if role == Role::Validator && chain == Chain::Solana && name == "keys" {
        let (Some(network), Some(vname)) = (
            sub.get_one::<String>("network"),
            sub.get_one::<String>("name"),
        ) else {
            return Outcome::Usage("`erpc v keys` needs --network and --name".to_owned());
        };
        let args = crate::validator_keys::Args {
            network: network.clone(),
            name: vname.clone(),
            vote: sub.get_one::<String>("vote-account").cloned(),
            authority: sub.get_one::<String>("authority").cloned(),
            ssh_key: sub.get_one::<std::path::PathBuf>("ssh-key").cloned(),
            ssh_agent: sub.get_one::<std::path::PathBuf>("ssh-agent").cloned(),
            source_fingerprint: sub.get_one::<String>("source-fingerprint").cloned(),
            yes: sub.get_flag("yes"),
        };
        return crate::validator_keys::run(&args, json);
    }
    let Some(verb) = COMMON_VERBS
        .iter()
        .chain(extra_verbs(role, chain))
        .find(|v| v.name == name)
    else {
        return Outcome::Usage(format!("{name} is not a {role} verb on {chain}"));
    };
    respond(role, chain, source, verb, sub, json).await
}

fn extra_verbs(role: Role, chain: Chain) -> &'static [Verb] {
    if chain == Chain::Avax {
        crate::avax_tree::EXTRA
    } else if chain == Chain::Sui && role == Role::Validator {
        std::slice::from_ref(&crate::sui_tree::REGISTRATION)
    } else if chain == Chain::Tron && role == Role::Validator {
        std::slice::from_ref(&crate::tron_tree::REGISTRATION)
    } else {
        &[]
    }
}

async fn respond(
    role: Role,
    chain: Chain,
    source: Source,
    verb: &Verb,
    sub: &ArgMatches,
    json: bool,
) -> Outcome {
    let network = sub.get_one::<String>("network").map(String::as_str);
    let host = sub.get_one::<String>("name").map(String::as_str);
    if !verb.read_only && network.is_none() {
        return Outcome::Usage(format!(
            "`{}` changes a node, so it needs --network ({})",
            verb.name,
            chain.networks().join(", ")
        ));
    }
    if let Err(e) = guard_mainnet(verb, chain, source, network) {
        return Outcome::Usage(e);
    }
    if role == Role::Rpc && chain == Chain::Arc {
        return arc(verb, sub, network, host, json).await;
    }
    if role == Role::Rpc && chain == Chain::Solana {
        return solana_rpc(verb, sub, network, host, json).await;
    }
    if role == Role::Rpc && chain == Chain::Eth {
        return crate::eth_tree::run(verb, sub, network, host, json).await;
    }
    if role == Role::Rpc && matches!(chain, Chain::Arbitrum | Chain::Robinhood) {
        return crate::nitro_rpc::run(verb.name, chain.as_str(), sub, network, json);
    }
    if chain == Chain::Avax {
        return crate::avax_tree::run(role, verb, sub, network, host, json).await;
    }
    if chain == Chain::Sui && matches!(role, Role::Rpc | Role::Node | Role::Validator) {
        return crate::sui_tree::run(verb, sub, network, host, json, role == Role::Validator);
    }
    if role == Role::Rpc && matches!(chain, Chain::Optimism | Chain::Base | Chain::Soneium) {
        return crate::rollup_ops::run(chain, verb.name, sub, network, json).await;
    }
    if role == Role::Rpc && chain == Chain::Bitcoin {
        return crate::bitcoin_rpc::run(verb.name, sub, network, json).await;
    }
    if chain == Chain::Tron {
        return crate::tron_tree::run(verb, sub, network, host, json, role == Role::Validator);
    }
    // The verbs that are implemented so far.
    if role == Role::Validator && chain == Chain::Solana && verb.name == "list" {
        return crate::nodes::list_validators(network, json);
    }
    if role == Role::Validator && chain == Chain::Solana && verb.name == "init" {
        return solana_validator_init(sub, network, host, json).await;
    }
    if role == Role::Validator
        && chain == Chain::Solana
        && (verb.name == "deploy" || verb.name == "status")
    {
        let (Some(network), Some(name)) = (network, host) else {
            return Outcome::Usage(format!(
                "`erpc v {}` needs --network and --name, the validator's name",
                verb.name
            ));
        };
        let args = crate::validator_deploy::Args {
            network: network.to_owned(),
            name: name.to_owned(),
            host: sub.get_one::<String>("host-name").cloned(),
            ssh_key: sub.get_one::<std::path::PathBuf>("ssh-key").cloned(),
            ssh_agent: sub.get_one::<std::path::PathBuf>("ssh-agent").cloned(),
            yes: verb.name == "deploy" && sub.get_flag("yes"),
        };
        return if verb.name == "deploy" {
            crate::validator_deploy::deploy(&args, json)
        } else {
            crate::validator_deploy::status(&args, json)
        };
    }
    Outcome::Failed(format!(
        "`erpc {role} {}` is not implemented yet; it would run on {chain} (from {source}){}{}",
        verb.name,
        network.map_or_else(String::new, |n| format!(", network {n}")),
        host.map_or_else(String::new, |h| format!(", host {h}")),
    ))
}

async fn solana_validator_init(
    sub: &ArgMatches,
    network: Option<&str>,
    host: Option<&str>,
    json: bool,
) -> Outcome {
    let Some(name) = host else {
        return Outcome::Usage("`erpc v init` needs --name, the validator's name".to_owned());
    };
    let args = crate::validator_init::Args {
        network: network.unwrap_or_default().to_owned(),
        name: name.to_owned(),
        host: sub.get_one::<String>("host").cloned(),
        user: sub.get_one::<String>("user").cloned().unwrap_or_default(),
        port: sub.get_one::<u16>("port").copied().unwrap_or(22),
        spare: sub.get_flag("spare"),
        ssh_key: sub.get_one::<std::path::PathBuf>("ssh-key").cloned(),
        ssh_agent: sub.get_one::<std::path::PathBuf>("ssh-agent").cloned(),
        fingerprint: sub.get_one::<String>("fingerprint").cloned(),
        vault: sub.get_one::<String>("vault").cloned(),
        client: sub
            .get_one::<String>("client")
            .cloned()
            .unwrap_or_else(|| "agave".to_owned()),
        yes: sub.get_flag("yes"),
        identity: sub.get_one::<String>("identity").cloned(),
        vote_account: sub.get_one::<String>("vote-account").cloned(),
        authority: sub.get_one::<String>("authority").cloned(),
        source_fingerprint: sub.get_one::<String>("source-fingerprint").cloned(),
    };
    crate::validator_init::run(args, json).await
}

/// The strings of a repeatable flag, or `None` when it was not given.
fn many(sub: &ArgMatches, id: &str) -> Option<Vec<String>> {
    sub.try_get_many::<String>(id)
        .ok()
        .flatten()
        .map(|v| v.cloned().collect())
}

/// Runs an `erpc r --chain arc` verb.
async fn arc(
    verb: &Verb,
    sub: &ArgMatches,
    network: Option<&str>,
    name: Option<&str>,
    json: bool,
) -> Outcome {
    let login = crate::arc_rpc::Login {
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
        return crate::arc_ops::list(network, json);
    }
    let (Some(network), Some(name)) = (network, name) else {
        return Outcome::Usage(format!(
            "`erpc r --chain arc {}` needs --network and --name, the node's name",
            verb.name
        ));
    };
    match verb.name {
        "init" => {
            let args = crate::arc_init::Args {
                network: network.to_owned(),
                name: name.to_owned(),
                host: sub.get_one::<String>("host").cloned(),
                user: sub.get_one::<String>("user").cloned().unwrap_or_default(),
                port: sub.get_one::<u16>("port").copied().unwrap_or(22),
                fingerprint: sub.get_one::<String>("fingerprint").cloned(),
                vault: sub.get_one::<String>("vault").cloned(),
                version: sub.get_one::<String>("version").cloned(),
                rpc_allow: many(sub, "rpc-allow"),
                management_allow: many(sub, "management-allow"),
                monitoring_allow: many(sub, "monitoring-allow"),
                kind: arc_kind(sub),
                login,
                yes,
            };
            crate::arc_init::run(args, json).await
        }
        "status" | "logs" | "start" | "stop" | "restart" => {
            let args = crate::arc_ops::Args {
                network: network.to_owned(),
                name: name.to_owned(),
                login,
            };
            arc_ops(verb.name, &args, sub, yes, json)
        }
        _ => {
            let args = crate::arc_deploy::Args {
                network: network.to_owned(),
                name: name.to_owned(),
                login,
                yes,
                version: sub.try_get_one::<String>("version").ok().flatten().cloned(),
                rpc_allow: many(sub, "rpc-allow"),
                management_allow: many(sub, "management-allow"),
                monitoring_allow: many(sub, "monitoring-allow"),
                kind: arc_kind(sub),
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
                change: sub
                    .try_get_one::<String>("change")
                    .ok()
                    .flatten()
                    .cloned()
                    .unwrap_or_else(|| "deploy".to_owned()),
            };
            match verb.name {
                "deploy" => crate::arc_deploy::deploy(&args, json),
                "update-config" => crate::arc_deploy::update_config(&args, json),
                "update" => crate::arc_deploy::update(&args, json).await,
                "plan" => crate::arc_deploy::plan(&args, json).await,
                "destroy" => crate::arc_deploy::destroy(&args, json),
                other => Outcome::Usage(format!("{other} is not an Arc RPC verb")),
            }
        }
    }
}

/// The login flags every node verb but `list` takes.
fn login(sub: &ArgMatches) -> crate::arc_rpc::Login {
    crate::arc_rpc::Login {
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
    }
}

/// A string flag a verb may not have.
fn opt(sub: &ArgMatches, id: &str) -> Option<String> {
    sub.try_get_one::<String>(id).ok().flatten().cloned()
}

/// A switch a verb may not have.
fn flag(sub: &ArgMatches, id: &str) -> bool {
    sub.try_get_one::<bool>(id)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}

/// Runs an `erpc r --chain solana` verb.
async fn solana_rpc(
    verb: &Verb,
    sub: &ArgMatches,
    network: Option<&str>,
    name: Option<&str>,
    json: bool,
) -> Outcome {
    use erpc_ssh::arc::Action;
    if verb.name == "list" {
        return crate::solana_rpc_ops::list(network, json);
    }
    let (Some(network), Some(name)) = (network, name) else {
        return Outcome::Usage(format!(
            "`erpc r --chain solana {}` needs --network and --name, the node's name",
            verb.name
        ));
    };
    let yes = flag(sub, "yes");
    match verb.name {
        "init" => {
            let args = crate::solana_rpc_init::Args {
                network: network.to_owned(),
                name: name.to_owned(),
                host: opt(sub, "host"),
                user: opt(sub, "user").unwrap_or_default(),
                port: sub.get_one::<u16>("port").copied().unwrap_or(22),
                fingerprint: opt(sub, "fingerprint"),
                vault: opt(sub, "vault"),
                client: opt(sub, "client"),
                rpc_type: opt(sub, "type"),
                version: opt(sub, "version"),
                geyser_version: opt(sub, "geyser-version"),
                rpc_allow: many(sub, "rpc-allow"),
                management_allow: many(sub, "management-allow"),
                monitoring_allow: many(sub, "monitoring-allow"),
                login: login(sub),
                yes,
            };
            crate::solana_rpc_init::run(args, json).await
        }
        "status" | "logs" | "start" | "stop" | "restart" => {
            let args = crate::solana_rpc_ops::Args {
                network: network.to_owned(),
                name: name.to_owned(),
                login: login(sub),
            };
            let service = opt(sub, "service").unwrap_or_else(|| "validator".to_owned());
            match verb.name {
                "status" => crate::solana_rpc_ops::status(&args, json),
                "logs" => crate::solana_rpc_ops::logs(
                    &args,
                    &opt(sub, "source").unwrap_or_else(|| "validator".to_owned()),
                    sub.get_one::<u32>("lines").copied().unwrap_or(100),
                    sub.get_flag("follow"),
                ),
                "start" => {
                    crate::solana_rpc_ops::service(&args, Action::Start, &service, yes, json)
                }
                "stop" => crate::solana_rpc_ops::service(&args, Action::Stop, &service, yes, json),
                _ => crate::solana_rpc_ops::service(&args, Action::Restart, &service, yes, json),
            }
        }
        _ => {
            let args = crate::solana_rpc_deploy::Args {
                network: network.to_owned(),
                name: name.to_owned(),
                login: login(sub),
                yes,
                version: opt(sub, "version"),
                geyser_version: opt(sub, "geyser-version"),
                rpc_allow: many(sub, "rpc-allow"),
                management_allow: many(sub, "management-allow"),
                monitoring_allow: many(sub, "monitoring-allow"),
                purge_data: flag(sub, "purge-data"),
                change: opt(sub, "change").unwrap_or_else(|| "deploy".to_owned()),
            };
            match verb.name {
                "deploy" => crate::solana_rpc_deploy::deploy(&args, json),
                "update-config" => crate::solana_rpc_deploy::update_config(&args, json),
                "update" => crate::solana_rpc_deploy::update(&args, json).await,
                "plan" => crate::solana_rpc_deploy::plan(&args, json).await,
                "destroy" => crate::solana_rpc_deploy::destroy(&args, json),
                other => Outcome::Usage(format!("{other} is not a Solana RPC verb")),
            }
        }
    }
}

/// The type flags a verb was given; a verb without them gives none.
fn arc_kind(sub: &ArgMatches) -> crate::arc_rpc::KindFlags {
    crate::arc_rpc::KindFlags {
        rpc_type: sub.try_get_one::<String>("type").ok().flatten().cloned(),
        debug_api: sub.try_get_one::<bool>("debug-api").ok().flatten().copied(),
        trusted_peers: many(sub, "trusted-peers"),
        sentry_peers: many(sub, "sentry-peers"),
    }
}

/// The Arc verbs that read a node or run its services.
fn arc_ops(
    verb: &str,
    args: &crate::arc_ops::Args,
    sub: &ArgMatches,
    yes: bool,
    json: bool,
) -> Outcome {
    use erpc_ssh::arc::Action;
    let layer = sub
        .try_get_one::<String>("layer")
        .ok()
        .flatten()
        .map_or("both", String::as_str);
    match verb {
        "status" => crate::arc_ops::status(args, json),
        "logs" => crate::arc_ops::logs(
            args,
            layer,
            sub.get_one::<u32>("lines").copied().unwrap_or(100),
            sub.get_flag("follow"),
        ),
        "start" => crate::arc_ops::service(args, Action::Start, layer, yes, json),
        "stop" => crate::arc_ops::service(args, Action::Stop, layer, yes, json),
        _ => crate::arc_ops::service(args, Action::Restart, layer, yes, json),
    }
}

#[cfg(test)]
mod tests {
    use super::{chain_flag, command};
    use erpc_core::chain::{Chain, Role};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn follower_verbs_and_explicit_incomplete_reset_have_closed_arguments() {
        for (chain, network) in [
            (Chain::Optimism, "sepolia"),
            (Chain::Base, "sepolia"),
            (Chain::Soneium, "minato"),
        ] {
            for verb in [
                "init",
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
                    command(Role::Rpc, chain)
                        .try_get_matches_from(["erpc rpc", verb, "-n", network])
                        .is_ok(),
                    "{chain} {verb}"
                );
            }
            assert!(
                command(Role::Rpc, chain)
                    .try_get_matches_from([
                        "erpc rpc",
                        "deploy",
                        "-n",
                        network,
                        "--reset-bootstrap"
                    ])
                    .is_ok()
            );
            assert!(
                command(Role::Rpc, chain)
                    .try_get_matches_from([
                        "erpc rpc",
                        "destroy",
                        "-n",
                        network,
                        "--reset-bootstrap"
                    ])
                    .is_err()
            );
            assert!(
                command(Role::Rpc, chain)
                    .try_get_matches_from(["erpc rpc", "init", "-n", network, "--type", "pruned"])
                    .is_err()
            );
        }
    }

    #[test]
    fn the_chain_is_found_before_parsing_in_either_form() {
        assert_eq!(
            chain_flag(&args(&["deploy", "--chain", "eth"])).as_deref(),
            Some("eth")
        );
        assert_eq!(
            chain_flag(&args(&["--chain=sol", "status"])).as_deref(),
            Some("sol")
        );
        assert_eq!(chain_flag(&args(&["status"])), None);
    }

    #[test]
    fn a_network_the_chain_does_not_have_is_refused() {
        let ok = command(Role::Node, Chain::Avax).try_get_matches_from([
            "erpc node",
            "status",
            "-n",
            "fuji",
        ]);
        assert!(ok.is_ok());
        let bad = command(Role::Node, Chain::Avax).try_get_matches_from([
            "erpc node",
            "status",
            "-n",
            "testnet",
        ]);
        assert!(bad.is_err());
    }

    #[test]
    fn new_chain_networks_are_isolated_at_argument_parsing() {
        for (chain, network, wrong) in [
            (Chain::Bitcoin, "testnet4", "sepolia"),
            (Chain::Base, "sepolia", "fuji"),
            (Chain::Arbitrum, "nova", "amoy"),
            (Chain::Polygon, "amoy", "chapel"),
            (Chain::Bsc, "chapel", "amoy"),
            (Chain::Kaia, "kairos", "testnet"),
            (Chain::Soneium, "minato", "sepolia"),
            (Chain::Tron, "nile", "shasta"),
        ] {
            assert!(
                command(Role::Rpc, chain)
                    .try_get_matches_from(["erpc rpc", "status", "-n", network])
                    .is_ok()
            );
            assert!(
                command(Role::Rpc, chain)
                    .try_get_matches_from(["erpc rpc", "status", "-n", wrong])
                    .is_err()
            );
        }
        for chain in Chain::ALL {
            for role in chain.roles() {
                command(*role, chain).debug_assert();
            }
        }
    }

    #[tokio::test]
    async fn registering_a_namespace_does_not_report_a_deployment_as_successful() {
        let matches = command(Role::Rpc, Chain::Kaia)
            .try_get_matches_from([
                "erpc rpc", "deploy", "--chain", "kaia", "-n", "kairos", "--name", "btc1",
            ])
            .expect("recognized command namespace");
        let (_, sub) = matches.subcommand().expect("verb");
        let verb = erpc_core::chain::COMMON_VERBS
            .iter()
            .find(|v| v.name == "deploy")
            .expect("deploy");
        let result = super::respond(
            Role::Rpc,
            Chain::Kaia,
            erpc_core::chain::Source::Flag,
            verb,
            sub,
            true,
        )
        .await;
        assert!(
            matches!(result, crate::commands::Outcome::Failed(ref reason) if reason.contains("not implemented"))
        );
    }

    #[test]
    fn arc_has_every_rpc_verb_with_its_flags() {
        let arc = command(Role::Rpc, Chain::Arc);
        let verbs: Vec<&str> = arc.get_subcommands().map(clap::Command::get_name).collect();
        for verb in erpc_core::chain::COMMON_VERBS {
            assert!(verbs.contains(&verb.name), "{}", verb.name);
        }
        let parsed = command(Role::Rpc, Chain::Arc)
            .try_get_matches_from([
                "erpc rpc",
                "init",
                "-n",
                "testnet",
                "--name",
                "arc1",
                "--host",
                "192.0.2.10",
                "--rpc-allow",
                "198.51.100.1,198.51.100.0/24",
                "--rpc-allow",
                "203.0.113.5",
            ])
            .expect("init parses");
        let (_, init) = parsed.subcommand().expect("a verb");
        let allowed: Vec<&String> = init.get_many("rpc-allow").expect("rpc-allow").collect();
        assert_eq!(allowed, ["198.51.100.1", "198.51.100.0/24", "203.0.113.5"]);
        let logs = command(Role::Rpc, Chain::Arc)
            .try_get_matches_from(["erpc rpc", "logs", "--layer", "consensus", "-f"])
            .expect("logs parses");
        let (_, logs) = logs.subcommand().expect("a verb");
        assert_eq!(logs.get_one::<u32>("lines"), Some(&100));
        assert!(logs.get_flag("follow"));
        command(Role::Rpc, Chain::Arc)
            .try_get_matches_from([
                "erpc rpc",
                "plan",
                "--change",
                "update-config",
                "--rpc-allow",
                "198.51.100.1",
            ])
            .expect("plan takes the lists update-config would be given");
        let init = command(Role::Rpc, Chain::Arc)
            .try_get_matches_from([
                "erpc rpc",
                "init",
                "--type",
                "archive",
                "--debug-api",
                "--name",
                "arc1",
            ])
            .expect("init takes a type");
        let (_, init) = init.subcommand().expect("a verb");
        let kind = super::arc_kind(init);
        assert_eq!(kind.rpc_type.as_deref(), Some("archive"));
        assert_eq!(kind.debug_api, Some(true));
        let off = command(Role::Rpc, Chain::Arc)
            .try_get_matches_from(["erpc rpc", "update-config", "--debug-api", "false"])
            .expect("debug-api takes false");
        assert!(
            command(Role::Rpc, Chain::Arc)
                .try_get_matches_from(["erpc rpc", "destroy", "--forget"])
                .is_err(),
            "forget needs purge-data"
        );
        assert_eq!(
            super::arc_kind(off.subcommand().expect("a verb").1).debug_api,
            Some(false)
        );
        assert!(
            command(Role::Rpc, Chain::Arc)
                .try_get_matches_from(["erpc rpc", "update-config", "--type", "archive"])
                .is_err(),
            "the type is fixed at init"
        );
    }

    #[test]
    fn solana_rpc_has_every_verb_with_its_flags() {
        let rpc = command(Role::Rpc, Chain::Solana);
        let verbs: Vec<&str> = rpc.get_subcommands().map(clap::Command::get_name).collect();
        for verb in erpc_core::chain::COMMON_VERBS {
            assert!(verbs.contains(&verb.name), "{}", verb.name);
        }
        let parsed = command(Role::Rpc, Chain::Solana)
            .try_get_matches_from([
                "erpc rpc",
                "init",
                "-n",
                "mainnet",
                "--name",
                "rpc1",
                "--host",
                "192.0.2.10",
                "--client",
                "agave",
                "--type",
                "index",
                "--rpc-allow",
                "198.51.100.0/24,203.0.113.5",
            ])
            .expect("init parses");
        let (_, init) = parsed.subcommand().expect("a verb");
        assert_eq!(
            init.get_one::<String>("type").map(String::as_str),
            Some("index")
        );
        let allowed: Vec<&String> = init.get_many("rpc-allow").expect("rpc-allow").collect();
        assert_eq!(allowed, ["198.51.100.0/24", "203.0.113.5"]);
        // No client given means the stored one, or jito for a new node.
        let parsed = command(Role::Rpc, Chain::Solana)
            .try_get_matches_from(["erpc rpc", "init", "--type", "send-tx"])
            .expect("parses");
        assert!(
            parsed
                .subcommand()
                .expect("verb")
                .1
                .get_one::<String>("client")
                .is_none()
        );
        for bad in [
            vec!["erpc rpc", "init", "--type", "Index RPC"],
            vec!["erpc rpc", "init", "--client", "allnodes-jito"],
            vec!["erpc rpc", "logs", "--source", "other"],
            vec!["erpc rpc", "status", "-y"],
        ] {
            assert!(
                command(Role::Rpc, Chain::Solana)
                    .try_get_matches_from(&bad)
                    .is_err(),
                "{bad:?}"
            );
        }
        let restart = command(Role::Rpc, Chain::Solana)
            .try_get_matches_from(["erpc rpc", "restart", "--service", "faithful", "-y"])
            .expect("restart parses");
        assert!(restart.subcommand().expect("verb").1.get_flag("yes"));
    }

    #[test]
    fn arc_reads_ask_nothing_and_arc_has_no_devnet() {
        for verb in ["status", "logs", "plan"] {
            let read =
                command(Role::Rpc, Chain::Arc).try_get_matches_from(["erpc rpc", verb, "-y"]);
            assert!(read.is_err(), "{verb} takes no --yes");
        }
        let devnet = command(Role::Rpc, Chain::Arc)
            .try_get_matches_from(["erpc rpc", "status", "-n", "devnet"]);
        assert!(devnet.is_err());
    }

    #[test]
    fn a_bare_role_shows_its_verbs_or_how_to_pick_a_chain() {
        let parsed = super::command(Role::Validator, Chain::Solana)
            .try_get_matches_from(["erpc validator"])
            .expect("no verb is not an error");
        assert!(parsed.subcommand().is_none());
        let text = super::overview_text(Role::Rpc, &[Chain::Solana, Chain::Arc]);
        assert!(text.contains("erpc rpc --chain arc --help"), "{text}");
    }
}
