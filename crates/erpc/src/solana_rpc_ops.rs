// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc r --chain solana list`, `status`, `logs`, `start`, `stop` and
//! `restart`: reading and running a Solana RPC node.

use std::fmt::Write as _;

use erpc_chain::inventory::SolanaRpc;
use erpc_chain_solana::rpc;
use erpc_ssh::arc::Action;
use erpc_ssh::solana_rpc::{LogSource, Service};
use erpc_ssh::{RemoteCommand, Session, Stream};
use serde_json::{Value, json};

use crate::arc_rpc::Login;
use crate::commands::Outcome;
use crate::error::CliError;
use crate::node_common::{Say, go_ahead};
use crate::solana_rpc::{Status, find_ready, list_or_nobody, open, read_status, target};

/// What one of these verbs is asked about.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// The network.
    pub network: String,
    /// The node.
    pub name: String,
    /// How to log in.
    pub login: Login,
}

/// Runs `erpc r --chain solana list`, for every network with a vault.
pub fn list(network: Option<&str>, json_out: bool) -> Outcome {
    let say = Say { quiet: true };
    let keyless = match crate::keyless::path().and_then(|p| crate::keyless::load(&p)) {
        Ok(k) => k,
        Err(e) => return Outcome::Failed(e),
    };
    let networks: Vec<&str> = rpc::NETWORKS
        .into_iter()
        .filter(|n| network.is_none_or(|w| w == *n))
        .filter(|n| keyless.networks.contains_key(*n))
        .collect();
    let mut all = Vec::new();
    for n in networks {
        match open(n, None, &say) {
            Ok(opened) => all.push((n.to_owned(), opened.nodes)),
            Err(e) => return Outcome::Failed(format!("{n}: {e}")),
        }
    }
    if json_out {
        let nodes: Vec<Value> = all
            .iter()
            .flat_map(|(network, nodes)| {
                nodes.iter().map(move |n| {
                    json!({
                        "network": network,
                        "name": n.name,
                        "address": n.address,
                        "client": n.client,
                        "type": n.rpc_type,
                        "version": n.version,
                        "identity": n.identity_account,
                        "rpc_allow": n.rpc_allow,
                        "last_result": n.last_result,
                    })
                })
            })
            .collect();
        crate::print_json(&json!({ "nodes": nodes }));
        return Outcome::Done(String::new());
    }
    Outcome::Done(render_list(&all))
}

fn render_list(all: &[(String, Vec<SolanaRpc>)]) -> String {
    if all.iter().all(|(_, nodes)| nodes.is_empty()) {
        return "no Solana RPC nodes yet: create one with `erpc r --chain solana init -n mainnet \
                --name <name> --host <address> --type <type> --ssh-key <pub>`"
            .to_owned();
    }
    let mut out = String::new();
    for (network, nodes) in all {
        for n in nodes {
            let version = &n.version;
            let _ = writeln!(
                out,
                "{network}  {:<16} {:<16} {:<10} {:<10} {:<16} {}",
                n.name,
                n.address,
                n.client,
                n.rpc_type,
                version,
                if n.last_result.is_empty() {
                    "not set up"
                } else {
                    &n.last_result
                }
            );
        }
    }
    out.trim_end().to_owned()
}

fn kb(v: Option<u64>) -> String {
    v.map_or_else(|| "-".to_owned(), |k| format!("{} GB", k / 1_000_000))
}

pub(crate) fn render_status(node: &SolanaRpc, s: &Status, problems: &[String]) -> String {
    let mut out = format!(
        "{} ({} {})  validator {}  health {}  slot {}\n  \
         running   {}{}\n  \
         pinned    {}\n  \
         identity  {}\n  \
         ledger    {} used, {} free; accounts {} free\n  \
         firewall  {} (rpc {}, metrics {})",
        node.name,
        node.client,
        node.rpc_type,
        s.validator,
        if s.health.is_empty() { "-" } else { &s.health },
        s.slot.map_or_else(|| "-".to_owned(), |v| v.to_string()),
        if s.version.is_empty() {
            "-"
        } else {
            &s.version
        },
        if s.since.is_empty() {
            String::new()
        } else {
            format!(" since {} ({} restarts)", s.since, s.restarts)
        },
        crate::solana_rpc::pins(node),
        if s.identity.is_empty() {
            "-"
        } else {
            &s.identity
        },
        kb(s.ledger_used_kb),
        kb(s.ledger_free_kb),
        kb(s.accounts_free_kb),
        if s.firewall_table {
            "loaded"
        } else {
            "missing"
        },
        list_or_nobody(&node.rpc_allow),
        list_or_nobody(&node.monitoring_allow),
    );
    if rpc::RpcType::parse(&node.rpc_type).is_some_and(rpc::RpcType::faithful) {
        let _ = write!(
            out,
            "\n  faithful  {} ({}; index sync {})",
            s.faithful, s.faithful_version, s.of1_sync
        );
    }
    if rpc::RpcType::parse(&node.rpc_type).is_some_and(rpc::RpcType::geyser) {
        let _ = write!(
            out,
            "\n  grpc      {} (yellowstone {})",
            if s.grpc_listen {
                "listening on 10000"
            } else {
                "not listening"
            },
            if s.geyser_version.is_empty() {
                "-"
            } else {
                &s.geyser_version
            }
        );
    }
    if !s.healthy() && s.validator == "active" {
        let _ = write!(
            out,
            "\n  the node is not caught up yet; it loads a snapshot and catches up after a start"
        );
    }
    for p in problems {
        let _ = write!(out, "\n  ! {p}");
    }
    out
}

pub(crate) fn status_json(node: &SolanaRpc, s: &Status, problems: &[String]) -> Value {
    json!({
        "name": node.name,
        "client": node.client,
        "type": node.rpc_type,
        "validator": s.validator,
        "faithful": s.faithful,
        "health": s.health,
        "healthy": s.healthy(),
        "slot": s.slot,
        "running": s.version,
        "identity": s.identity,
        "grpc_listen": s.grpc_listen,
        "geyser_version": s.geyser_version,
        "firewall": s.firewall_table,
        "firewall_unconfirmed": s.firewall_armed,
        "firewall_startup_revoked": s.firewall_revoked,
        "ledger_free_kb": s.ledger_free_kb,
        "problems": problems,
    })
}

/// Runs `erpc r --chain solana status`.
pub fn status(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: true };
    let result = (|| {
        let opened = open(&args.network, None, &say)?;
        let node = find_ready(&opened.nodes, &args.name, &args.network)?.clone();
        let session = Session::open(&target(&node, &args.login)?).map_err(|e| e.to_string())?;
        let s = read_status(&session)?;
        let problems = s.problems(&node);
        Ok::<_, String>((node, s, problems))
    })();
    match result {
        Err(e) => Outcome::Failed(e),
        Ok((node, s, problems)) => {
            if json_out {
                crate::print_json(&status_json(&node, &s, &problems));
                return if problems.is_empty() {
                    Outcome::Done(String::new())
                } else {
                    Outcome::Problems(String::new())
                };
            }
            let text = render_status(&node, &s, &problems);
            if problems.is_empty() {
                Outcome::Done(text)
            } else {
                Outcome::Problems(text)
            }
        }
    }
}

/// Runs `erpc r --chain solana logs`.
pub fn logs(args: &Args, source: &str, lines: u32, follow: bool) -> Outcome {
    let say = Say { quiet: true };
    let result = (|| {
        let opened = open(&args.network, None, &say)?;
        let node = find_ready(&opened.nodes, &args.name, &args.network)?.clone();
        let source = LogSource::parse(source).ok_or_else(|| {
            format!("--source {source} is not validator, journal, faithful or firewall")
        })?;
        let session = Session::open(&target(&node, &args.login)?).map_err(|e| e.to_string())?;
        session
            .stream(
                &RemoteCommand::SolanaRpcLogs {
                    source,
                    lines,
                    follow,
                },
                &mut |stream, line| match stream {
                    Stream::Stdout => crate::print_line(line),
                    Stream::Stderr => eprintln!("{line}"),
                },
            )
            .map_err(|e| e.to_string())
    })();
    match result {
        Ok(()) => Outcome::Done(String::new()),
        Err(e) => Outcome::Failed(e),
    }
}

/// Runs `erpc r --chain solana start|stop|restart`, then reads the node's
/// state.
pub fn service(args: &Args, action: Action, which: &str, yes: bool, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let verb = match action {
        Action::Start => "start",
        Action::Stop => "stop",
        Action::Restart => "restart",
    };
    let result = (|| -> Result<_, CliError> {
        let opened = open(&args.network, None, &say)?;
        let node = find_ready(&opened.nodes, &args.name, &args.network)?.clone();
        let service = match which {
            "validator" => Service::Validator,
            "faithful" => Service::Faithful,
            other => return Err(format!("--service {other} is not validator or faithful").into()),
        };
        let session = Session::open(&target(&node, &args.login)?).map_err(|e| e.to_string())?;
        if action != Action::Start {
            say.line(&format!(
                "plan       {verb} {} on {} ({}); RPC clients lose {} while it is down{}",
                if which == "faithful" {
                    "Old Faithful"
                } else {
                    "the validator"
                },
                node.name,
                args.network,
                if which == "faithful" {
                    "history"
                } else {
                    "the node"
                },
                if which == "faithful" {
                    ""
                } else {
                    ", and it loads its snapshot again on the way up"
                }
            ));
            go_ahead(yes, "nothing was changed")?;
        }
        say.line(&format!("service    {verb}…"));
        session
            .run(&RemoteCommand::SolanaRpcService { action, service }, None)
            .map_err(|e| e.to_string())?;
        let s = read_status(&session)?;
        Ok::<_, CliError>((node, s))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, s)) if action == Action::Stop => {
            if json_out {
                crate::print_json(
                    &json!({ "name": node.name, "validator": s.validator, "faithful": s.faithful }),
                );
                return Outcome::Done(String::new());
            }
            Outcome::Done(format!(
                "{}: validator {}, faithful {}. It starts again at boot; `erpc r --chain solana start` starts it now.",
                node.name,
                s.validator,
                if s.faithful.is_empty() {
                    "-"
                } else {
                    &s.faithful
                }
            ))
        }
        Ok((node, s)) => {
            // A validator that was just started is loading its snapshot: the
            // states are what a start can promise.
            let problems = s.problems(&node);
            if json_out {
                crate::print_json(&status_json(&node, &s, &problems));
                return if problems.is_empty() {
                    Outcome::Done(String::new())
                } else {
                    Outcome::Problems(String::new())
                };
            }
            let text = render_status(&node, &s, &problems);
            if problems.is_empty() {
                Outcome::Done(text)
            } else {
                Outcome::Problems(text)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::SolanaRpc;

    use super::render_list;

    #[test]
    fn the_list_shows_each_node_or_how_to_make_one() {
        assert!(
            render_list(&[("mainnet".to_owned(), Vec::new())])
                .contains("erpc r --chain solana init")
        );
        let nodes = vec![
            SolanaRpc {
                name: "rpc1".to_owned(),
                address: "192.0.2.10".to_owned(),
                client: "jito".to_owned(),
                rpc_type: "index".to_owned(),
                version: "v4.3.2-jito".to_owned(),
                last_result: "deploy ok".to_owned(),
                ..SolanaRpc::default()
            },
            SolanaRpc {
                name: "rpc2".to_owned(),
                address: "192.0.2.11".to_owned(),
                client: "agave".to_owned(),
                rpc_type: "send-tx".to_owned(),
                version: "v4.3.2".to_owned(),
                ..SolanaRpc::default()
            },
        ];
        let text = render_list(&[("mainnet".to_owned(), nodes)]);
        assert!(
            text.contains("rpc1") && text.contains("deploy ok"),
            "{text}"
        );
        assert!(
            text.contains("v4.3.2 ") && text.contains("not set up"),
            "{text}"
        );
    }
}
