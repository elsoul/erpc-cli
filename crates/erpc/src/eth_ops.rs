// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc r --chain eth list`, `status`, `logs`, `start`, `stop` and
//! `restart`: reading and running an Ethereum RPC node.
//!
//! The node is judged by its own two layers: Reth's head against the block
//! Lighthouse's head carries, both layers done syncing, and Lighthouse
//! reaching Reth over the engine API. No public endpoint is asked.

use std::fmt::Write as _;

use erpc_chain::inventory::EthRpc;
use erpc_ssh::arc::{Action, Layer};
use erpc_ssh::{RemoteCommand, Session, Stream};
use serde_json::{Value, json};

use crate::arc_rpc::gb;
use crate::commands::Outcome;
use crate::error::CliError;
use crate::eth_rpc::{Login, find, open, target};
use crate::node_common::{Say, go_ahead};

/// The networks erpc runs Ethereum RPC nodes on, in the order they are listed.
const NETWORKS: [&str; 1] = ["mainnet"];
/// How far Reth's head may trail the block Lighthouse's head carries and
/// still count as caught up.
pub(crate) const CAUGHT_UP_BLOCKS: u64 = 2;
/// Less free space than this for the chain data is a problem.
const LOW_DISK_KB: u64 = 200_000_000;

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

/// Runs `erpc r --chain eth list`, for one network or every network with a
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
                        "address": n.address,
                        "reth_version": n.reth_version,
                        "lighthouse_version": n.lighthouse_version,
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

fn render_list(all: &[(String, Vec<EthRpc>)]) -> String {
    if all.iter().all(|(_, nodes)| nodes.is_empty()) {
        return "no Ethereum RPC nodes yet: create one with `erpc r --chain eth init -n mainnet --name <name> --host <address> --type full|archive`"
            .to_owned();
    }
    let mut out = String::new();
    for (network, nodes) in all {
        for n in nodes {
            let _ = writeln!(
                out,
                "{network}  {:<16} {:<8} {:<16} reth {:<8} lighthouse {:<8} {}",
                n.name,
                n.rpc_type,
                n.address,
                n.reth_version,
                n.lighthouse_version,
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

/// An Ethereum node's state, from [`RemoteCommand::EthStatus`].
// A report read from the node, one field per line it prints.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) execution: String,
    pub(crate) consensus: String,
    pub(crate) snapshot_unit: String,
    pub(crate) current: String,
    pub(crate) client_version: String,
    pub(crate) chain_id: Option<u64>,
    pub(crate) head: Option<u64>,
    pub(crate) syncing: String,
    pub(crate) peers: Option<u64>,
    /// Lighthouse: still syncing, `None` when it did not answer.
    pub(crate) cl_syncing: Option<bool>,
    pub(crate) cl_optimistic: bool,
    pub(crate) cl_el_offline: bool,
    pub(crate) cl_head_slot: Option<u64>,
    pub(crate) cl_peers: Option<u64>,
    /// The execution block Lighthouse's head carries.
    pub(crate) cl_head_block: Option<u64>,
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
    pub(crate) jwt: bool,
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

/// A field of a beacon API answer's `data`: numbers come as strings.
fn beacon_data(text: &str) -> Option<Value> {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v.get("data").cloned())
}

fn beacon_number(data: Option<&Value>, key: &str) -> Option<u64> {
    data?.get(key)?.as_str()?.parse().ok()
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
                "unit_reth" => value.clone_into(&mut s.execution),
                "unit_lighthouse" => value.clone_into(&mut s.consensus),
                "unit_reth-snapshot" => value.clone_into(&mut s.snapshot_unit),
                "current" => value.clone_into(&mut s.current),
                "client_version" => {
                    s.client_version = rpc_result(value)
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default();
                }
                "chain_id" => s.chain_id = rpc_quantity(value),
                "head" => s.head = rpc_quantity(value),
                "syncing" => {
                    s.syncing = match rpc_result(value) {
                        Some(Value::Bool(false)) => "no".to_owned(),
                        Some(Value::Null) | None => "unknown".to_owned(),
                        Some(_) => "yes".to_owned(),
                    };
                }
                "peers" => s.peers = rpc_quantity(value),
                "cl_syncing" => {
                    let data = beacon_data(value);
                    let flag = |k: &str| data.as_ref().and_then(|d| d.get(k)?.as_bool());
                    s.cl_syncing = flag("is_syncing");
                    s.cl_optimistic = flag("is_optimistic").unwrap_or(false);
                    s.cl_el_offline = flag("el_offline").unwrap_or(false);
                    s.cl_head_slot = beacon_number(data.as_ref(), "head_slot");
                }
                "cl_peers" => s.cl_peers = beacon_number(beacon_data(value).as_ref(), "connected"),
                "cl_head_block" => s.cl_head_block = number(),
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
                "jwt" => s.jwt = value == "yes",
                "snapshot" => s.snapshot_done = value == "done",
                _ => {}
            }
        }
        s
    }

    /// Blocks Reth's head trails the block Lighthouse's head carries.
    pub(crate) fn lag(&self) -> Option<u64> {
        Some(self.cl_head_block?.saturating_sub(self.head?))
    }

    /// Both layers done syncing and Reth at Lighthouse's head.
    pub(crate) fn caught_up(&self) -> bool {
        self.syncing == "no"
            && self.cl_syncing == Some(false)
            && self.lag().is_some_and(|l| l <= CAUGHT_UP_BLOCKS)
    }

    /// What is wrong with a deployed node, if anything. Still syncing is not
    /// a problem; a layer that cannot reach the other is.
    pub(crate) fn problems(&self, node: &EthRpc, chain_id: u64) -> Vec<String> {
        let mut out = Vec::new();
        for (unit, state) in [("reth", &self.execution), ("lighthouse", &self.consensus)] {
            if state != "active" {
                out.push(format!(
                    "{unit} is {}",
                    if state.is_empty() { "unknown" } else { state }
                ));
            }
        }
        let pair = format!(
            "reth-{}--lighthouse-{}",
            node.reth_version, node.lighthouse_version
        );
        if !self.current.ends_with(&format!("/{pair}")) {
            out.push(format!(
                "the node runs {}, not the pinned {pair}",
                if self.current.is_empty() {
                    "nothing"
                } else {
                    &self.current
                }
            ));
        }
        // What the running process serves, against the pin: an update that
        // installed a pair but never restarted onto it shows here.
        if !self.client_version.is_empty()
            && !self
                .client_version
                .contains(&format!("/{}-", node.reth_version))
        {
            out.push(format!(
                "Reth serves {}, not the pinned {}",
                self.client_version, node.reth_version
            ));
        }
        match self.chain_id {
            Some(id) if id != chain_id => {
                out.push(format!("the node answers chain id {id}, not {chain_id}"));
            }
            None => out.push("Reth does not answer JSON-RPC".to_owned()),
            Some(_) => {}
        }
        if self.cl_syncing.is_none() {
            out.push("Lighthouse does not answer its beacon API".to_owned());
        }
        if self.cl_el_offline {
            out.push("Lighthouse cannot reach Reth over the engine API".to_owned());
        }
        // A layer still syncing is behind by design: after the snapshot,
        // Reth catches up from the snapshot's block.
        if self.cl_syncing == Some(false)
            && self.syncing == "no"
            && let Some(lag) = self.lag()
            && lag > CAUGHT_UP_BLOCKS
        {
            out.push(format!("Reth is {lag} blocks behind Lighthouse's head"));
        }
        if let Some(free) = self.data_free_kb
            && free < LOW_DISK_KB
        {
            out.push(format!("only {} free for the chain data", gb(free)));
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
pub(crate) fn read_status(session: &Session) -> Result<Status, String> {
    let out = session
        .run(&RemoteCommand::EthStatus, None)
        .map_err(|e| e.to_string())?;
    Ok(Status::parse(&String::from_utf8_lossy(&out.stdout)))
}

fn mb(bytes: Option<u64>) -> String {
    bytes.map_or_else(|| "-".to_owned(), |b| format!("{} MB", b / 1_000_000))
}

fn number(n: Option<u64>) -> String {
    n.map_or_else(|| "-".to_owned(), |n| n.to_string())
}

/// The heads in a line: Reth's, the block Lighthouse's head carries, and
/// whether the node is caught up.
pub(crate) fn head_line(s: &Status) -> String {
    format!(
        "head {} (Lighthouse's {}{})",
        number(s.head),
        number(s.cl_head_block),
        if s.caught_up() {
            ", caught up".to_owned()
        } else if s.syncing == "yes" || s.cl_syncing == Some(true) {
            ", syncing".to_owned()
        } else {
            s.lag()
                .map_or_else(String::new, |l| format!(", {l} behind"))
        }
    )
}

fn render_status(node: &EthRpc, network: &str, s: &Status, problems: &[String]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} ({network}, {}, {})",
        node.name, node.rpc_type, node.address
    );
    let _ = writeln!(
        out,
        "  reth        {:<10} restarts {}  since {}  memory {}  peers {}",
        s.execution,
        s.restarts_execution,
        s.since_execution,
        mb(s.mem_execution),
        number(s.peers)
    );
    let _ = writeln!(
        out,
        "  lighthouse  {:<10} restarts {}  memory {}  peers {}",
        s.consensus,
        s.restarts_consensus,
        mb(s.mem_consensus),
        number(s.cl_peers)
    );
    let _ = writeln!(
        out,
        "  release     {} (pinned reth {}, lighthouse {})",
        if s.client_version.is_empty() {
            "-"
        } else {
            &s.client_version
        },
        node.reth_version,
        node.lighthouse_version
    );
    let _ = writeln!(
        out,
        "  sync        {}  reth syncing {}  lighthouse syncing {}  slot {}",
        head_line(s),
        s.syncing,
        s.cl_syncing.map_or_else(
            || "-".to_owned(),
            |b| if b { "yes" } else { "no" }.to_owned()
        ),
        number(s.cl_head_slot)
    );
    let _ = writeln!(
        out,
        "  data        {} used, {} free",
        gb(s.data_used_kb.unwrap_or(0)),
        gb(s.data_free_kb.unwrap_or(0))
    );
    let _ = writeln!(
        out,
        "  firewall    {}{}  snapshot {}",
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
        if s.snapshot_done {
            "in place"
        } else if s.snapshot_unit == "activating" || s.snapshot_unit == "active" {
            "downloading"
        } else {
            "missing"
        }
    );
    if problems.is_empty() {
        let _ = write!(out, "ok");
    } else {
        let _ = write!(out, "problems: {}", problems.join("; "));
    }
    out
}

fn status_json(node: &EthRpc, network: &str, s: &Status, problems: &[String]) -> Value {
    json!({
        "network": network,
        "name": node.name,
        "type": node.rpc_type,
        "reth": s.execution,
        "lighthouse": s.consensus,
        "client_version": s.client_version,
        "pinned": { "reth": node.reth_version, "lighthouse": node.lighthouse_version },
        "chain_id": s.chain_id,
        "head": s.head,
        "lighthouse_head_block": s.cl_head_block,
        "lighthouse_head_slot": s.cl_head_slot,
        "behind": s.lag(),
        "syncing": s.syncing,
        "lighthouse_syncing": s.cl_syncing,
        "caught_up": s.caught_up(),
        "peers": s.peers,
        "lighthouse_peers": s.cl_peers,
        "data_used_kb": s.data_used_kb,
        "data_free_kb": s.data_free_kb,
        "firewall_loaded": s.firewall_table,
        "firewall_unconfirmed": s.firewall_armed,
        "firewall_startup_revoked": s.firewall_revoked,
        "snapshot_in_place": s.snapshot_done,
        "problems": problems,
    })
}

fn report(
    node: &EthRpc,
    network: &str,
    s: &Status,
    problems: &[String],
    json_out: bool,
) -> Outcome {
    if json_out {
        crate::print_json(&status_json(node, network, s, problems));
        return if problems.is_empty() {
            Outcome::Done(String::new())
        } else {
            Outcome::Problems(String::new())
        };
    }
    let text = render_status(node, network, s, problems);
    if problems.is_empty() {
        Outcome::Done(text)
    } else {
        Outcome::Problems(text)
    }
}

/// Runs `erpc r --chain eth status`.
pub fn status(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: true };
    let result = (|| {
        let opened = open(&args.network, None, &say)?;
        let node = find(&opened.nodes, &args.name, &args.network)?.clone();
        let session = Session::open(&target(&node, &args.login)?).map_err(|e| e.to_string())?;
        let s = read_status(&session)?;
        let problems = s.problems(&node, opened.network.chain_id);
        Ok::<_, String>((node, s, problems))
    })();
    match result {
        Err(e) => Outcome::Failed(e),
        Ok((node, s, problems)) => report(&node, &args.network, &s, &problems, json_out),
    }
}

/// Runs `erpc r --chain eth logs`.
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
                &RemoteCommand::EthLogs {
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

/// The problems a start or restart of `layer` answers for: a layer just
/// started has not caught up yet, and starting Reth alone leaves
/// Lighthouse as it was.
fn after_start(problems: Vec<String>, layer: Layer) -> Vec<String> {
    problems
        .into_iter()
        .filter(|p| !p.contains("behind") && !p.contains("beacon API"))
        .filter(|p| layer != Layer::Execution || !p.starts_with("lighthouse "))
        .collect()
}

/// Runs `erpc r --chain eth start|stop|restart`, then reads the node's state.
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
                    Layer::Execution => "Reth (and Lighthouse, which needs it)",
                    Layer::Consensus => "Lighthouse",
                    Layer::Both => "both layers",
                },
                node.name,
                args.network
            ));
            go_ahead(yes, "nothing was changed")?;
        }
        say.line(&format!("service    {verb}…"));
        session
            .run(&RemoteCommand::EthService { action, layer }, None)
            .map_err(|e| e.to_string())?;
        let s = read_status(&session)?;
        Ok::<_, CliError>((node, s, opened.network.chain_id))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, s, _)) if action == Action::Stop => {
            if json_out {
                crate::print_json(
                    &json!({ "name": node.name, "reth": s.execution, "lighthouse": s.consensus }),
                );
                return Outcome::Done(String::new());
            }
            Outcome::Done(format!(
                "{}: reth {}, lighthouse {}. It starts again at boot; `erpc r --chain eth start` starts it now.",
                node.name, s.execution, s.consensus
            ))
        }
        Ok((node, s, chain_id)) => {
            let problems = after_start(s.problems(&node, chain_id), layer);
            report(&node, &args.network, &s, &problems, json_out)
        }
    }
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::EthRpc;
    use erpc_ssh::arc::Layer;

    use super::{Status, after_start, render_list};

    const SAMPLE: &str = "unit_reth=active\nunit_lighthouse=active\nunit_reth-snapshot=inactive\n\
        unit_erpc-eth-firewall=active\ncurrent=/opt/ethereum/reth-v2.8.1--lighthouse-v8.3.2\n\
        client_version={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"reth/v2.8.1-d763342/x86_64-unknown-linux-gnu\"}\n\
        chain_id={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}\n\
        head={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x190a4fd\"}\n\
        syncing={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":false}\n\
        peers={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x32\"}\n\
        cl_syncing={\"data\":{\"head_slot\":\"13000000\",\"sync_distance\":\"0\",\"is_syncing\":false,\"is_optimistic\":false,\"el_offline\":false}}\n\
        cl_peers={\"data\":{\"disconnected\":\"10\",\"connecting\":\"0\",\"connected\":\"80\",\"disconnecting\":\"0\"}}\n\
        cl_head_block=26256638\n\
        data_used_kb=1000000000\ndata_free_kb=900000000\nmem_execution=20000000000\nmem_consensus=\n\
        restarts_execution=0\nrestarts_consensus=0\nsince_execution=Sat 2026-10-24 10:00:00 UTC\n\
        firewall_table=yes\nfirewall_armed=no\njwt=yes\nsnapshot=done\n";

    fn node() -> EthRpc {
        EthRpc {
            name: "eth1".to_owned(),
            address: "192.0.2.10".to_owned(),
            rpc_type: "full".to_owned(),
            reth_version: "v2.8.1".to_owned(),
            lighthouse_version: "v8.3.2".to_owned(),
            ..EthRpc::default()
        }
    }

    #[test]
    fn the_status_reads_and_a_healthy_node_has_no_problems() {
        let s = Status::parse(SAMPLE);
        assert_eq!(s.chain_id, Some(1));
        assert_eq!(s.head, Some(26_256_637));
        assert_eq!(s.lag(), Some(1));
        assert_eq!((s.peers, s.cl_peers), (Some(50), Some(80)));
        assert_eq!(s.cl_head_slot, Some(13_000_000));
        assert!(s.caught_up());
        assert!(
            s.problems(&node(), 1).is_empty(),
            "{:?}",
            s.problems(&node(), 1)
        );
    }

    #[test]
    fn a_syncing_node_is_not_a_problem_but_a_cut_engine_is() {
        let syncing = Status::parse(
            &SAMPLE
                .replace("\"is_syncing\":false", "\"is_syncing\":true")
                .replace("cl_head_block=26256638", "cl_head_block=26256900"),
        );
        assert!(!syncing.caught_up());
        assert!(syncing.problems(&node(), 1).is_empty());
        let cut = Status::parse(&SAMPLE.replace("\"el_offline\":false", "\"el_offline\":true"));
        assert_eq!(cut.problems(&node(), 1).len(), 1);
        let lagging =
            Status::parse(&SAMPLE.replace("cl_head_block=26256638", "cl_head_block=26256700"));
        assert!(lagging.problems(&node(), 1)[0].contains("behind"));
        // Reth catching up from its snapshot while Lighthouse is synced, as a
        // new node does (eth1 on 2026-10-24).
        let catching_up = Status::parse(
            &SAMPLE
                .replace("cl_head_block=26256638", "cl_head_block=26263157")
                .replace(
                    "\"result\":false}\npeers",
                    "\"result\":{\"currentBlock\":\"0x190a3fd\"}}\npeers",
                ),
        );
        assert_eq!(catching_up.syncing, "yes");
        assert!(
            catching_up.problems(&node(), 1).is_empty(),
            "{:?}",
            catching_up.problems(&node(), 1)
        );
    }

    #[test]
    fn a_node_on_another_release_or_chain_says_so() {
        let s = Status::parse(
            &SAMPLE
                .replace("reth/v2.8.1-", "reth/v2.8.0-")
                .replace("lighthouse-v8.3.2\n", "lighthouse-v8.3.1\n")
                .replace("\"0x1\"", "\"0xaa36a7\"")
                .replace("firewall_armed=no", "firewall_armed=yes"),
        );
        assert_eq!(
            s.problems(&node(), 1).len(),
            4,
            "{:?}",
            s.problems(&node(), 1)
        );
        let dead = Status::parse("unit_reth=inactive\n");
        assert!(
            dead.problems(&node(), 1)
                .iter()
                .any(|p| p.contains("does not answer"))
        );
    }

    #[test]
    fn a_start_answers_for_the_layers_it_started() {
        let problems = vec![
            "lighthouse is inactive".to_owned(),
            "Reth is 40 blocks behind Lighthouse's head".to_owned(),
            "the firewall table is not loaded".to_owned(),
        ];
        assert_eq!(
            after_start(problems.clone(), Layer::Execution),
            ["the firewall table is not loaded"]
        );
        assert_eq!(after_start(problems, Layer::Both).len(), 2);
    }

    #[test]
    fn the_list_shows_each_node_or_how_to_make_one() {
        assert!(
            render_list(&[("mainnet".to_owned(), Vec::new())]).contains("erpc r --chain eth init")
        );
        let shown = render_list(&[("mainnet".to_owned(), vec![node()])]);
        assert!(shown.starts_with("mainnet  eth1"), "{shown}");
        assert!(shown.ends_with("not deployed"), "{shown}");
    }
}
