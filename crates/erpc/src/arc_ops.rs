// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc r --chain arc list`, `status`, `logs`, `start`, `stop` and
//! `restart`: reading and running an Arc RPC node.

use std::fmt::Write as _;

use erpc_chain::inventory::RpcNode;
use erpc_ssh::arc::{Action, Layer, PublicRpc};
use erpc_ssh::{RemoteCommand, Session, Stream};
use serde_json::{Value, json};

use crate::arc_rpc::{Login, find, open, target};
use crate::commands::Outcome;
use crate::error::CliError;
use crate::node_common::{Say, go_ahead};

/// The networks Arc has, in the order they are listed.
const NETWORKS: [&str; 2] = ["mainnet", "testnet"];
/// How far behind the public endpoint a node may be and still count as
/// caught up, in blocks.
pub(crate) const CAUGHT_UP_BLOCKS: u64 = 10;

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

/// Runs `erpc r --chain arc list`, for one network or every network with a
/// vault.
pub fn list(network: Option<&str>, json_out: bool) -> Outcome {
    let say = Say { quiet: true };
    let keyless = match crate::keyless::path().and_then(|p| crate::keyless::load(&p)) {
        Ok(k) => k,
        Err(e) => return Outcome::Failed(e),
    };
    let networks: Vec<&str> = NETWORKS
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
                        "type": n.rpc_type,
                        "debug_api": n.debug_api,
                        "address": n.address,
                        "version": n.version,
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

fn render_list(all: &[(String, Vec<RpcNode>)]) -> String {
    if all.iter().all(|(_, nodes)| nodes.is_empty()) {
        return "no Arc RPC nodes yet: create one with `erpc r --chain arc init -n testnet --name <name> --host <address>`"
            .to_owned();
    }
    let mut out = String::new();
    for (network, nodes) in all {
        for n in nodes {
            let _ = writeln!(
                out,
                "{network}  {:<16} {:<8} {:<16} {:<8} {}",
                n.name,
                n.rpc_type,
                n.address,
                n.version,
                if n.last_result.is_empty() {
                    "not deployed"
                } else {
                    &n.last_result
                }
            );
        }
    }
    out.trim_end().to_owned()
}

/// Less free space than this for the chain data is a problem: an archive
/// node only grows, and a full one still needs room to compact.
const LOW_DISK_KB: u64 = 100_000_000;

/// An Arc node's state, from [`RemoteCommand::ArcStatus`].
// A report read from the node, one field per line it prints.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) execution: String,
    pub(crate) consensus: String,
    pub(crate) snapshots: String,
    pub(crate) firewall_unit: String,
    pub(crate) current: String,
    pub(crate) running: String,
    pub(crate) chain_id: Option<u64>,
    pub(crate) head: Option<u64>,
    pub(crate) syncing: String,
    pub(crate) public_head: Option<u64>,
    pub(crate) data_used_kb: Option<u64>,
    pub(crate) data_free_kb: Option<u64>,
    pub(crate) mem_execution: Option<u64>,
    pub(crate) mem_consensus: Option<u64>,
    pub(crate) restarts_execution: String,
    pub(crate) restarts_consensus: String,
    pub(crate) since_execution: String,
    pub(crate) firewall_table: bool,
    pub(crate) firewall_armed: bool,
    pub(crate) firewall_revoked: bool,
    pub(crate) credential: bool,
    pub(crate) snapshot_done: bool,
}

/// The `result` of a JSON-RPC answer.
fn rpc_result(text: &str) -> Option<Value> {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v.get("result").cloned())
}

/// A quantity a JSON-RPC answer gives as hex.
fn rpc_quantity(text: &str) -> Option<u64> {
    rpc_result(text)
        .as_ref()
        .and_then(Value::as_str)
        .and_then(|h| h.strip_prefix("0x"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

impl Status {
    pub(crate) fn parse(text: &str) -> Self {
        let mut s = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            let number = || value.parse::<u64>().ok();
            match key {
                "unit_arc-execution" => value.clone_into(&mut s.execution),
                "unit_arc-consensus" => value.clone_into(&mut s.consensus),
                "unit_arc-snapshots" => value.clone_into(&mut s.snapshots),
                "unit_erpc-arc-firewall" => value.clone_into(&mut s.firewall_unit),
                "current" => value.clone_into(&mut s.current),
                "running" => value.clone_into(&mut s.running),
                "chain_id" => s.chain_id = rpc_quantity(value),
                "head" => s.head = rpc_quantity(value),
                "syncing" => {
                    s.syncing = match rpc_result(value) {
                        Some(Value::Bool(false)) => "no".to_owned(),
                        Some(Value::Null) | None => "unknown".to_owned(),
                        Some(_) => "yes".to_owned(),
                    };
                }
                "public_head" => s.public_head = rpc_quantity(value),
                "data_used_kb" => s.data_used_kb = number(),
                "data_free_kb" => s.data_free_kb = number(),
                "mem_execution" => s.mem_execution = number(),
                "mem_consensus" => s.mem_consensus = number(),
                "restarts_execution" => value.clone_into(&mut s.restarts_execution),
                "restarts_consensus" => value.clone_into(&mut s.restarts_consensus),
                "since_execution" => value.clone_into(&mut s.since_execution),
                "firewall_table" => s.firewall_table = value == "yes",
                "firewall_armed" => s.firewall_armed = value == "yes",
                "firewall_revoked" => s.firewall_revoked = value == "yes",
                "credential" => s.credential = value == "yes",
                "snapshot" => s.snapshot_done = value == "done",
                _ => {}
            }
        }
        s
    }

    /// Blocks behind the public endpoint, when both heads were read.
    pub(crate) fn lag(&self) -> Option<u64> {
        Some(self.public_head?.saturating_sub(self.head?))
    }

    /// What is wrong with a deployed node, if anything.
    pub(crate) fn problems(&self, node: &RpcNode, chain_id: u64) -> Vec<String> {
        let mut out = Vec::new();
        for (unit, state) in [
            ("arc-execution", &self.execution),
            ("arc-consensus", &self.consensus),
        ] {
            if state != "active" {
                out.push(format!(
                    "{unit} is {}",
                    if state.is_empty() { "unknown" } else { state }
                ));
            }
        }
        if !self.current.ends_with(&format!("/{}", node.version)) {
            out.push(format!(
                "the node runs {}, not the pinned {}",
                if self.current.is_empty() {
                    "nothing"
                } else {
                    &self.current
                },
                node.version
            ));
        }
        // What the running process serves, against the pin: an update
        // that installed a release but never restarted onto it shows here.
        let pinned = format!(
            "{} ({})",
            node.version,
            &node.commit[..node.commit.len().min(8)]
        );
        if !self.running.is_empty() && self.running != pinned {
            out.push(format!(
                "the running node serves {}, not the pinned {pinned}",
                self.running
            ));
        }
        match self.chain_id {
            Some(id) if id != chain_id => {
                out.push(format!("the node answers chain id {id}, not {chain_id}"));
            }
            None => out.push("the node does not answer JSON-RPC".to_owned()),
            Some(_) => {}
        }
        if let Some(lag) = self.lag()
            && lag > CAUGHT_UP_BLOCKS
        {
            out.push(format!("{lag} blocks behind the public endpoint"));
        }
        if let Some(free) = self.data_free_kb
            && free < LOW_DISK_KB
        {
            out.push(format!(
                "only {} free for the chain data",
                crate::arc_rpc::gb(free)
            ));
        }
        if self.firewall_revoked {
            out.push("firewall rollback revoked startup; retry deployment after correcting access ranges".to_owned());
        }
        if self.firewall_armed {
            out.push("a firewall change is waiting to be confirmed or rolled back".to_owned());
        }
        if !self.firewall_table {
            out.push("the firewall table is not loaded".to_owned());
        }
        out
    }
}

/// Reads the node's state.
pub(crate) fn read_status(session: &Session, public_rpc: &str) -> Result<Status, String> {
    let public = PublicRpc::new(public_rpc).map_err(|e| e.to_string())?;
    let out = session
        .run(&RemoteCommand::ArcStatus(public), None)
        .map_err(|e| e.to_string())?;
    Ok(Status::parse(&String::from_utf8_lossy(&out.stdout)))
}

fn mb(bytes: Option<u64>) -> String {
    bytes.map_or_else(|| "-".to_owned(), |b| format!("{} MB", b / 1_000_000))
}

fn render_status(node: &RpcNode, network: &str, s: &Status, problems: &[String]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} ({network}, {}, {}{})",
        node.name,
        node.rpc_type,
        node.address,
        if node.debug_api {
            ", debug and trace"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "  execution  {:<10} restarts {}  since {}  memory {}",
        s.execution,
        s.restarts_execution,
        s.since_execution,
        mb(s.mem_execution)
    );
    let _ = writeln!(
        out,
        "  consensus  {:<10} restarts {}  memory {}",
        s.consensus,
        s.restarts_consensus,
        mb(s.mem_consensus)
    );
    let _ = writeln!(
        out,
        "  release    {} (pinned {})",
        if s.running.is_empty() {
            "-"
        } else {
            &s.running
        },
        node.version
    );
    let _ = writeln!(
        out,
        "  head       {}  public {}  behind {}  syncing {}",
        s.head.map_or_else(|| "-".to_owned(), |h| h.to_string()),
        s.public_head
            .map_or_else(|| "-".to_owned(), |h| h.to_string()),
        s.lag().map_or_else(|| "-".to_owned(), |l| l.to_string()),
        s.syncing
    );
    let _ = writeln!(
        out,
        "  data       {} used, {} free",
        crate::arc_rpc::gb(s.data_used_kb.unwrap_or(0)),
        crate::arc_rpc::gb(s.data_free_kb.unwrap_or(0))
    );
    let _ = writeln!(
        out,
        "  firewall   {}{}  key {}",
        if s.firewall_table {
            "loaded"
        } else {
            "not loaded"
        },
        if s.firewall_armed {
            " (unconfirmed)"
        } else {
            ""
        },
        if s.credential { "in place" } else { "missing" }
    );
    if problems.is_empty() {
        let _ = write!(out, "ok");
    } else {
        let _ = write!(out, "problems: {}", problems.join("; "));
    }
    out
}

fn status_json(node: &RpcNode, network: &str, s: &Status, problems: &[String]) -> Value {
    json!({
        "network": network,
        "name": node.name,
        "type": node.rpc_type,
        "debug_api": node.debug_api,
        "execution": s.execution,
        "consensus": s.consensus,
        "running": s.running,
        "pinned": node.version,
        "chain_id": s.chain_id,
        "head": s.head,
        "public_head": s.public_head,
        "behind": s.lag(),
        "syncing": s.syncing,
        "data_used_kb": s.data_used_kb,
        "data_free_kb": s.data_free_kb,
        "firewall_loaded": s.firewall_table,
        "firewall_unconfirmed": s.firewall_armed,
        "firewall_startup_revoked": s.firewall_revoked,
        "key_in_place": s.credential,
        "problems": problems,
    })
}

/// Runs `erpc r --chain arc status`.
pub fn status(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: true };
    let result = (|| {
        let opened = open(&args.network, None, &say)?;
        let node = find(&opened.nodes, &args.name, &args.network)?.clone();
        let session = Session::open(&target(&node, &args.login)?).map_err(|e| e.to_string())?;
        let s = read_status(&session, &opened.network.public_rpc)?;
        let problems = s.problems(&node, opened.network.chain_id);
        Ok::<_, String>((node, s, problems))
    })();
    match result {
        Err(e) => Outcome::Failed(e),
        Ok((node, s, problems)) => {
            if json_out {
                crate::print_json(&status_json(&node, &args.network, &s, &problems));
                return if problems.is_empty() {
                    Outcome::Done(String::new())
                } else {
                    Outcome::Problems(String::new())
                };
            }
            let text = render_status(&node, &args.network, &s, &problems);
            if problems.is_empty() {
                Outcome::Done(text)
            } else {
                Outcome::Problems(text)
            }
        }
    }
}

/// Runs `erpc r --chain arc logs`.
pub fn logs(args: &Args, layer: &str, lines: u32, follow: bool) -> Outcome {
    let say = Say { quiet: true };
    let Some(layer) = Layer::parse(layer) else {
        return Outcome::Usage(format!(
            "--layer {layer} is not execution, consensus or both"
        ));
    };
    let result = (|| {
        let opened = open(&args.network, None, &say)?;
        let node = find(&opened.nodes, &args.name, &args.network)?.clone();
        let session = Session::open(&target(&node, &args.login)?).map_err(|e| e.to_string())?;
        session
            .stream(
                &RemoteCommand::ArcLogs {
                    layer,
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

/// The problems a start or restart of `layer` answers for. A layer that was
/// just started answers before it has moved, so the lag is left out; and
/// starting the execution layer alone leaves the consensus layer as it was.
fn after_start(problems: Vec<String>, layer: Layer) -> Vec<String> {
    problems
        .into_iter()
        .filter(|p| !p.contains("behind"))
        .filter(|p| layer != Layer::Execution || !p.starts_with("arc-consensus "))
        .collect()
}

/// Runs `erpc r --chain arc start|stop|restart`, then reads the node's state.
pub fn service(args: &Args, action: Action, layer: &str, yes: bool, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let Some(layer) = Layer::parse(layer) else {
        return Outcome::Usage(format!(
            "--layer {layer} is not execution, consensus or both"
        ));
    };
    let verb = match action {
        Action::Start => "start",
        Action::Stop => "stop",
        Action::Restart => "restart",
    };
    let result = (|| {
        let opened = open(&args.network, None, &say)?;
        let node = find(&opened.nodes, &args.name, &args.network)?.clone();
        let session = Session::open(&target(&node, &args.login)?).map_err(|e| e.to_string())?;
        if action != Action::Start {
            say.line(&format!(
                "plan       {verb} {} of {} on {}; RPC clients lose the node while it is down",
                match layer {
                    Layer::Execution =>
                        "the execution layer (and the consensus layer, which needs it)",
                    Layer::Consensus => "the consensus layer",
                    Layer::Both => "both layers",
                },
                node.name,
                args.network
            ));
            go_ahead(yes, "nothing was changed")?;
        }
        say.line(&format!("service    {verb}…"));
        session
            .run(&RemoteCommand::ArcService { action, layer }, None)
            .map_err(|e| e.to_string())?;
        let s = read_status(&session, &opened.network.public_rpc)?;
        Ok::<_, CliError>((node, s, opened.network.chain_id))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, s, _)) if action == Action::Stop => {
            let text = format!(
                "{}: execution {}, consensus {}. It starts again at boot; `erpc r --chain arc start` starts it now.",
                node.name, s.execution, s.consensus
            );
            if json_out {
                crate::print_json(
                    &json!({ "name": node.name, "execution": s.execution, "consensus": s.consensus }),
                );
                return Outcome::Done(String::new());
            }
            Outcome::Done(text)
        }
        Ok((node, s, chain_id)) => {
            let problems = after_start(s.problems(&node, chain_id), layer);
            if json_out {
                crate::print_json(&status_json(&node, &args.network, &s, &problems));
                return if problems.is_empty() {
                    Outcome::Done(String::new())
                } else {
                    Outcome::Problems(String::new())
                };
            }
            let text = render_status(&node, &args.network, &s, &problems);
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
    use erpc_chain::inventory::RpcNode;

    use erpc_ssh::arc::Layer;

    use super::{Status, after_start, render_list};

    #[test]
    fn a_start_answers_for_the_layers_it_started() {
        let problems = || {
            vec![
                "arc-consensus is inactive".to_owned(),
                "40 blocks behind the public endpoint".to_owned(),
                "the firewall table is not loaded".to_owned(),
            ]
        };
        assert_eq!(
            after_start(problems(), Layer::Execution),
            ["the firewall table is not loaded"]
        );
        assert_eq!(
            after_start(problems(), Layer::Both),
            [
                "arc-consensus is inactive",
                "the firewall table is not loaded"
            ]
        );
    }

    const SAMPLE: &str = "unit_arc-execution=active\nunit_arc-consensus=active\nunit_arc-snapshots=inactive\n\
        unit_erpc-arc-firewall=active\ncurrent=/opt/arc/v0.8.1\nrunning=v0.8.1 (ab09dbfd)\n\
        chain_id={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x4cef52\"}\n\
        head={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x100\"}\n\
        syncing={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":false}\n\
        public_head={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x104\"}\n\
        data_used_kb=120000000\ndata_free_kb=1700000000\nmem_execution=12000000000\nmem_consensus=\n\
        restarts_execution=0\nrestarts_consensus=1\nsince_execution=Fri 2026-10-23 10:00:00 UTC\n\
        firewall_table=yes\nfirewall_armed=no\ncredential=yes\nsnapshot=done\n";

    fn node() -> RpcNode {
        RpcNode {
            name: "arc1".to_owned(),
            address: "192.0.2.10".to_owned(),
            version: "v0.8.1".to_owned(),
            commit: "ab09dbfd9553a7ad48f9c134ec5e808c36512c74".to_owned(),
            ..RpcNode::default()
        }
    }

    #[test]
    fn a_node_still_serving_the_old_release_says_so() {
        let s = Status::parse(
            &SAMPLE.replace("running=v0.8.1 (ab09dbfd)", "running=v0.8.0 (66ad2d5a)"),
        );
        let problems = s.problems(&node(), 5_042_002);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("v0.8.0 (66ad2d5a)"));
    }

    #[test]
    fn the_status_reads_and_a_healthy_node_has_no_problems() {
        let s = Status::parse(SAMPLE);
        assert_eq!(s.chain_id, Some(5_042_002));
        assert_eq!(s.head, Some(256));
        assert_eq!(s.lag(), Some(4));
        assert_eq!(s.syncing, "no");
        assert_eq!(s.mem_consensus, None);
        assert!(s.snapshot_done && s.credential && s.firewall_table);
        assert!(
            s.problems(&node(), 5_042_002).is_empty(),
            "{:?}",
            s.problems(&node(), 5_042_002)
        );
    }

    #[test]
    fn a_stopped_lagging_or_wrong_node_says_why() {
        let s = Status::parse(
            &SAMPLE
                .replace("unit_arc-consensus=active", "unit_arc-consensus=failed")
                .replace("0x104", "0x200")
                .replace("current=/opt/arc/v0.8.1", "current=/opt/arc/v0.8.0")
                .replace("firewall_armed=no", "firewall_armed=yes"),
        );
        let problems = s.problems(&node(), 5_042_002);
        assert_eq!(problems.len(), 4, "{problems:?}");
        assert_eq!(s.problems(&node(), 5042).len(), 5);
        let dead = Status::parse("unit_arc-execution=inactive\n");
        assert!(
            dead.problems(&node(), 5042)
                .iter()
                .any(|p| p.contains("does not answer"))
        );
    }

    #[test]
    fn the_list_shows_each_node_or_how_to_make_one() {
        assert!(
            render_list(&[("testnet".to_owned(), Vec::new())]).contains("erpc r --chain arc init")
        );
        let shown = render_list(&[("testnet".to_owned(), vec![node()])]);
        assert!(shown.starts_with("testnet  arc1"), "{shown}");
        assert!(shown.ends_with("not deployed"), "{shown}");
    }
}
