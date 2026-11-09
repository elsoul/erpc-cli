// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc r --chain arc list`, `status`, `logs`, `start`, `stop` and
//! `restart`: reading and running an Arc RPC node.

use std::fmt::Write as _;

use erpc_chain::inventory::RpcNode;
use erpc_ssh::arc::{Action, Layer};
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

/// An Arc node's state from its original authority controller.
// A report read from the node, one field per line it prints.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) execution: String,
    pub(crate) consensus: String,
    pub(crate) snapshots: String,
    pub(crate) firewall_unit: String,
    pub(crate) current: String,
    pub(crate) source_archive: String,
    pub(crate) source_platform: String,
    pub(crate) running: String,
    pub(crate) running_commit: Option<String>,
    pub(crate) chain_id: Option<u64>,
    pub(crate) head: Option<u64>,
    pub(crate) head_hash: Option<String>,
    pub(crate) head_timestamp: Option<u64>,
    pub(crate) observed_unix: Option<u64>,
    pub(crate) genesis_hash: Option<String>,
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
    pub(crate) execution_authority: bool,
    pub(crate) consensus_authority: bool,
    pub(crate) original_authority: bool,
    pub(crate) credential: bool,
    pub(crate) snapshot_done: bool,
}

/// The `result` of a JSON-RPC answer.
fn rpc_result(text: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(text).ok()?;
    if value["jsonrpc"] != "2.0" || value["id"] != 1 || value.get("error").is_some() {
        return None;
    }
    value.get("result").cloned()
}

/// A quantity a JSON-RPC answer gives as hex.
fn rpc_quantity(text: &str) -> Option<u64> {
    rpc_result(text)
        .as_ref()
        .and_then(Value::as_str)
        .and_then(|h| h.strip_prefix("0x"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

fn hex_quantity(value: &Value) -> Option<u64> {
    value
        .as_str()?
        .strip_prefix("0x")
        .and_then(|text| u64::from_str_radix(text, 16).ok())
}

fn block_hash(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let raw = text.strip_prefix("0x")?;
    (raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| text.to_ascii_lowercase())
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
                "source_archive" => value.clone_into(&mut s.source_archive),
                "source_platform" => value.clone_into(&mut s.source_platform),
                "current" => value.clone_into(&mut s.current),
                "running" => value.clone_into(&mut s.running),
                "version_info" => {
                    if let Some(info) = rpc_result(value) {
                        info["cargo_version"]
                            .as_str()
                            .unwrap_or_default()
                            .clone_into(&mut s.running);
                        s.running_commit = info["git_commit"].as_str().map(str::to_owned);
                    }
                }
                "chain_id" => s.chain_id = rpc_quantity(value),
                "head" => s.head = rpc_quantity(value),
                "genesis" => {
                    s.genesis_hash = rpc_result(value).and_then(|block| block_hash(&block["hash"]));
                }
                "latest_block" => {
                    if let Some(block) = rpc_result(value) {
                        s.head = hex_quantity(&block["number"]);
                        s.head_timestamp = hex_quantity(&block["timestamp"]);
                        s.head_hash = block_hash(&block["hash"]);
                    }
                }
                "observed_unix" => s.observed_unix = number(),
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
                "execution_authority" => s.execution_authority = value == "yes",
                "consensus_authority" => s.consensus_authority = value == "yes",
                "original_authority" => s.original_authority = value == "yes",
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

    /// A missing public comparison is unknown, not evidence of local failure.
    pub(crate) fn readiness(&self, problems: &[String]) -> Option<bool> {
        if problems.is_empty() {
            self.public_head.map(|_| true)
        } else {
            Some(false)
        }
    }

    pub(crate) fn release_matches(
        &self,
        node: &RpcNode,
        network: &erpc_chain_arc::network::Network,
    ) -> bool {
        crate::arc_authority::directory(node, &self.source_platform).as_deref()
            == Some(self.current.as_str())
            && self.source_archive == node.archive_sha256
            && self.running
                == format!(
                    "{} ({})",
                    node.version,
                    &node.commit[..node.commit.len().min(8)]
                )
            && self.running_commit.as_deref() == Some(node.commit.as_str())
            && self.chain_id == Some(network.chain_id)
            && self.genesis_hash.as_deref() == Some(network.genesis_hash.as_str())
    }

    fn chain_problems(&self, chain_id: u64) -> Vec<String> {
        let mut out = Vec::new();
        match self.chain_id {
            Some(id) if id != chain_id => {
                out.push(format!("the node answers chain id {id}, not {chain_id}"));
            }
            None => out.push("the node does not answer JSON-RPC".to_owned()),
            Some(_) => {}
        }
        let expected_genesis = NETWORKS
            .into_iter()
            .filter_map(erpc_chain_arc::network::get)
            .find(|network| network.chain_id == chain_id)
            .map(|network| network.genesis_hash);
        if expected_genesis.is_none() || self.genesis_hash != expected_genesis {
            out.push(
                "the local genesis hash is unavailable or differs from the network pin".to_owned(),
            );
        }
        if self.head_hash.is_none()
            || !matches!((self.observed_unix, self.head_timestamp),
            (Some(now), Some(timestamp)) if timestamp <= now.saturating_add(120) && now.saturating_sub(timestamp) <= 300)
        {
            out.push(
                "the local latest block is missing, stale or outside the clock tolerance"
                    .to_owned(),
            );
        }
        if self.head.is_none() {
            out.push("the local block height is unavailable".to_owned());
        }
        if self.syncing != "no" {
            out.push(if self.syncing == "yes" {
                "the execution layer is syncing".to_owned()
            } else {
                "the execution synchronization state is unavailable".to_owned()
            });
        }
        out
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
        if crate::arc_authority::directory(node, &self.source_platform).as_deref()
            != Some(self.current.as_str())
            || self.source_archive != node.archive_sha256
        {
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
        if self.running != pinned || self.running_commit.as_deref() != Some(&node.commit) {
            out.push(format!(
                "the running node version/source is {}, expected {pinned} at {}",
                if self.running.is_empty() {
                    "unavailable"
                } else {
                    &self.running
                },
                node.commit
            ));
        }
        out.extend(self.chain_problems(chain_id));
        if !self.original_authority {
            out.push("the original native process/listener authority was not verified".to_owned());
        }
        if !self.credential {
            out.push("the established consensus credential is missing".to_owned());
        }
        if !self.snapshot_done {
            out.push("snapshot completion has not been recorded".to_owned());
        }
        if self.firewall_unit != "active" {
            out.push("the firewall boot service is not active".to_owned());
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
pub(crate) fn read_status(
    session: &Session,
    node: &RpcNode,
    network: &erpc_chain_arc::network::Network,
) -> Result<Status, String> {
    let reply = crate::arc_authority::invoke(session, node, network, "status", json!({}))?;
    let observation = reply
        .get("observation")
        .and_then(Value::as_str)
        .ok_or("invalid original Arc status")?;
    Ok(Status::parse(observation))
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
        let _ = write!(
            out,
            "{}",
            if s.public_head.is_some() {
                "ok"
            } else {
                "local checks passed; network catch-up unknown (public reference unavailable)"
            }
        );
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
        "running_commit": s.running_commit,
        "ready": s.readiness(problems),
        "catchup": if s.public_head.is_none() { "unknown" } else if s.lag().is_some_and(|lag| lag <= CAUGHT_UP_BLOCKS) { "within_reference_threshold" } else { "behind" },
        "pinned": node.version,
        "chain_id": s.chain_id,
        "head": s.head,
        "head_hash": s.head_hash,
        "head_timestamp": s.head_timestamp,
        "observed_unix": s.observed_unix,
        "genesis_hash": s.genesis_hash,
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
        let s = read_status(&session, &node, &opened.network)?;
        let problems = s.problems(&node, opened.network.chain_id);
        Ok::<_, String>((node, s, problems))
    })();
    match result {
        Err(e) => Outcome::Failed(e),
        Ok((node, s, problems)) => {
            if json_out {
                crate::print_json(&status_json(&node, &args.network, &s, &problems));
                return if s.readiness(&problems) == Some(true) {
                    Outcome::Done(String::new())
                } else {
                    Outcome::Problems(String::new())
                };
            }
            let text = render_status(&node, &args.network, &s, &problems);
            if s.readiness(&problems) == Some(true) {
                Outcome::Done(text)
            } else {
                Outcome::Problems(text)
            }
        }
    }
}

fn journal_output(
    json_out: bool,
    stream: impl FnOnce(&mut dyn FnMut(Stream, &str)) -> Result<(), String>,
    mut stdout: impl FnMut(&str),
    mut stderr: impl FnMut(&str),
) -> Result<(), String> {
    stream(&mut |stream, line| {
        if json_out {
            stdout(&json!({"journal":line}).to_string());
        } else {
            match stream {
                Stream::Stdout => stdout(line),
                Stream::Stderr => stderr(line),
            }
        }
    })
}

/// Runs `erpc r --chain arc logs`.
pub fn logs(args: &Args, layer: &str, lines: u32, follow: bool, json_out: bool) -> Outcome {
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
        journal_output(
            json_out,
            |sink| {
                session
                    .stream(
                        &RemoteCommand::ArcLogs {
                            layer,
                            lines,
                            follow,
                        },
                        sink,
                    )
                    .map_err(|e| e.to_string())
            },
            crate::print_line,
            crate::interrupt::say,
        )
    })();
    match result {
        Ok(()) => {
            if json_out {
                crate::print_json(&json!({"logs":"complete"}));
            }
            Outcome::Done(String::new())
        }
        Err(e) => Outcome::Failed(e),
    }
}

/// Report an applied service operation without weakening full-node readiness.
fn started_result(
    node: &RpcNode,
    args: &Args,
    state: &Status,
    chain_id: u64,
    operation: (Action, Layer),
    json_out: bool,
    mut emit: impl FnMut(&Value),
) -> Outcome {
    let (action, layer) = operation;
    let action = match action {
        Action::Start => "start",
        Action::Restart => "restart",
        Action::Stop => "stop",
    };
    let layer = match layer {
        Layer::Execution => "execution",
        Layer::Consensus => "consensus",
        Layer::Both => "both",
    };
    let problems = state.problems(node, chain_id);
    let ready = state.readiness(&problems);
    let message = if json_out {
        let mut report = status_json(node, &args.network, state, &problems);
        report["operation"] = json!({"action":action,"layer":layer,"startup_requested":true,
            "native_started": if layer == "execution" && action == "start" {state.execution_authority} else {state.original_authority}});
        emit(&report);
        String::new()
    } else {
        format!(
            "Requested {action} for {layer}; native readiness follows.\n{}",
            render_status(node, &args.network, state, &problems)
        )
    };
    if ready == Some(true) {
        Outcome::Done(message)
    } else {
        Outcome::Problems(message)
    }
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
        let layer_name = match layer {
            Layer::Execution => "execution",
            Layer::Consensus => "consensus",
            Layer::Both => "both",
        };
        crate::arc_authority::invoke(
            &session,
            &node,
            &opened.network,
            verb,
            json!({"layer":layer_name}),
        )?;
        let s = read_status(&session, &node, &opened.network)?;
        Ok::<_, CliError>((node, s, opened.network.chain_id))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, s, _)) if action == Action::Stop => {
            let text = format!(
                "{}: execution {}, consensus {}. The selected layers remain fenced at boot until an explicit start or deployment.",
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
        Ok((node, s, chain_id)) => started_result(
            &node,
            args,
            &s,
            chain_id,
            (action, layer),
            json_out,
            crate::print_json,
        ),
    }
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::RpcNode;

    use erpc_ssh::arc::Layer;

    use super::{Status, render_list};

    const SAMPLE: &str = "unit_arc-execution=active\nunit_arc-consensus=active\nunit_arc-snapshots=inactive\n\
        unit_erpc-arc-firewall=active\ncurrent=/opt/arc/releases/da4633f5ab1551cdcc683816afd4815e4218588c1d37301dcb8db2403ad1f000\nsource_archive=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsource_platform=x86_64-unknown-linux-gnu\nrunning=v0.8.1 (ab09dbfd)\nversion_info={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"cargo_version\":\"v0.8.1 (ab09dbfd)\",\"git_commit\":\"ab09dbfd9553a7ad48f9c134ec5e808c36512c74\"}}\n\
        chain_id={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x4cef52\"}\n\
        head={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x100\"}\n\
        genesis={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"hash\":\"0xe20e653af4441e8c6088e172b129d56420139824400477287b46e7101ae2bb1f\"}}\n\
        latest_block={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"number\":\"0x100\",\"timestamp\":\"0x7d0\",\"hash\":\"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}\n\
        observed_unix=2000\n\
        syncing={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":false}\n\
        public_head={\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x104\"}\n\
        data_used_kb=120000000\ndata_free_kb=1700000000\nmem_execution=12000000000\nmem_consensus=\n\
        restarts_execution=0\nrestarts_consensus=1\nsince_execution=Fri 2026-10-23 10:00:00 UTC\n\
        firewall_table=yes\nfirewall_armed=no\noriginal_authority=yes\ncredential=yes\nsnapshot=done\n";

    fn node() -> RpcNode {
        RpcNode {
            name: "arc1".to_owned(),
            address: "192.0.2.10".to_owned(),
            version: "v0.8.1".to_owned(),
            commit: "ab09dbfd9553a7ad48f9c134ec5e808c36512c74".to_owned(),
            archive_sha256: "a".repeat(64),
            ..RpcNode::default()
        }
    }

    #[test]
    fn a_node_still_serving_the_old_release_says_so() {
        let s = Status::parse(&SAMPLE.replace("v0.8.1 (ab09dbfd)", "v0.8.0 (66ad2d5a)"));
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
                .replace("source_archive=aaaaaaaa", "source_archive=bbbbbbbb")
                .replace("firewall_armed=no", "firewall_armed=yes"),
        );
        let problems = s.problems(&node(), 5_042_002);
        assert_eq!(problems.len(), 4, "{problems:?}");
        assert!(
            s.problems(&node(), 5042)
                .iter()
                .any(|problem| problem.contains("genesis"))
        );
        let dead = Status::parse("unit_arc-execution=inactive\n");
        assert!(
            dead.problems(&node(), 5042)
                .iter()
                .any(|p| p.contains("does not answer"))
        );
    }

    #[test]
    fn applied_start_and_restart_preserve_full_observation_in_formatter_and_outcome() {
        use erpc_ssh::arc::Action;
        type Case = (&'static str, Layer, Option<bool>, fn(&mut Status));
        let cases: [Case; 4] = [
            ("lag", Layer::Both, Some(false), |state| {
                state.public_head = Some(267);
            }),
            ("partial", Layer::Execution, Some(false), |state| {
                state.consensus = "inactive".into();
            }),
            ("unknown", Layer::Both, None, |state| {
                state.public_head = None;
            }),
            ("healthy", Layer::Both, Some(true), |_| {}),
        ];
        let args = super::Args {
            network: "testnet".into(),
            name: "arc1".into(),
            ..Default::default()
        };
        for action in [Action::Start, Action::Restart] {
            for (name, layer, expected, change) in cases {
                for json_out in [false, true] {
                    let mut state = Status::parse(SAMPLE);
                    change(&mut state);
                    let full_problems = state.problems(&node(), 5_042_002);
                    let mut records = Vec::new();
                    let outcome = super::started_result(
                        &node(),
                        &args,
                        &state,
                        5_042_002,
                        (action, layer),
                        json_out,
                        |body| {
                            crate::emit_json_record(body, |line| records.push(line.to_owned()))
                                .unwrap();
                        },
                    );
                    assert_eq!(
                        matches!(outcome, crate::commands::Outcome::Done(_)),
                        expected == Some(true),
                        "{name}"
                    );
                    if expected != Some(true) {
                        assert!(matches!(outcome, crate::commands::Outcome::Problems(_)));
                    }
                    if json_out {
                        assert_eq!(records.len(), 1);
                        assert_eq!(records[0].lines().count(), 1);
                        let report: serde_json::Value = serde_json::from_str(&records[0]).unwrap();
                        assert_eq!(report["ready"], serde_json::json!(expected), "{name}");
                        assert_eq!(report["problems"], serde_json::json!(full_problems));
                        assert_eq!(report["operation"]["startup_requested"], true);
                        assert_eq!(
                            report["operation"]["action"],
                            if action == Action::Start {
                                "start"
                            } else {
                                "restart"
                            }
                        );
                        if name == "lag" {
                            assert_eq!(report["catchup"], "behind");
                        }
                        if name == "partial" {
                            assert_eq!(report["consensus"], "inactive");
                        }
                        if name == "unknown" {
                            assert_eq!(report["catchup"], "unknown");
                        }
                    } else {
                        assert!(records.is_empty());
                        let (crate::commands::Outcome::Done(message)
                        | crate::commands::Outcome::Problems(message)) = outcome
                        else {
                            unreachable!()
                        };
                        assert!(message.starts_with("Requested "));
                        for problem in full_problems {
                            assert!(message.contains(&problem));
                        }
                        if name == "unknown" {
                            assert!(message.contains("catch-up unknown"));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn required_local_observations_never_report_ready_when_missing_or_wrong() {
        type Change = fn(&mut Status);
        let changes: [Change; 10] = [
            |state| state.running_commit = None,
            |state| state.running_commit = Some("b".repeat(40)),
            |state| state.syncing = "yes".into(),
            |state| state.syncing = "unknown".into(),
            |state| state.head = None,
            |state| state.genesis_hash = Some("0x".to_owned() + &"b".repeat(64)),
            |state| state.head_timestamp = Some(1699),
            |state| state.head_timestamp = Some(2121),
            |state| state.credential = false,
            |state| state.snapshot_done = false,
        ];
        for change in changes {
            let mut state = Status::parse(SAMPLE);
            change(&mut state);
            let problems = state.problems(&node(), 5_042_002);
            assert!(!problems.is_empty());
            assert_eq!(state.readiness(&problems), Some(false));
        }
        let wrong_envelope = SAMPLE.replace("\"jsonrpc\":\"2.0\"", "\"jsonrpc\":\"1.0\"");
        let state = Status::parse(&wrong_envelope);
        assert!(
            state.head.is_none() && state.genesis_hash.is_none() && state.running_commit.is_none()
        );
        assert!(!state.problems(&node(), 5_042_002).is_empty());
    }

    #[test]
    fn public_reference_outage_is_explicit_unknown_without_inventing_local_failure() {
        let mut state = Status::parse(SAMPLE);
        state.public_head = None;
        let problems = state.problems(&node(), 5_042_002);
        assert!(problems.is_empty());
        assert_eq!(state.readiness(&problems), None);
        let report = super::status_json(&node(), "testnet", &state, &problems);
        assert!(report["ready"].is_null());
        assert_eq!(report["catchup"], "unknown");
        assert!(
            super::render_status(&node(), "testnet", &state, &problems)
                .contains("catch-up unknown")
        );
        let network = erpc_chain_arc::network::get("testnet").unwrap();
        assert!(state.release_matches(&node(), &network));
        let genesis = state.genesis_hash.take();
        assert!(!state.release_matches(&node(), &network));
        state.genesis_hash = genesis;
        state.current = "/unowned/v0.8.1".into();
        assert!(!state.release_matches(&node(), &network));
    }

    #[test]
    fn logs_keep_machine_ndjson_and_existing_human_streams_separate() {
        use erpc_ssh::Stream;
        let messages = [
            (Stream::Stdout, "native \"log\"\nsecond line"),
            (Stream::Stderr, "diagnostic\r\n\t"),
        ];
        for json in [false, true] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            super::journal_output(
                json,
                |sink| {
                    for (stream, line) in messages {
                        sink(stream, line);
                    }
                    Ok(())
                },
                |line| out.push(line.to_owned()),
                |line| err.push(line.to_owned()),
            )
            .unwrap();
            if json {
                assert!(err.is_empty());
                crate::emit_json_record(&serde_json::json!({"logs":"complete"}), |line| {
                    out.push(line.to_owned());
                })
                .unwrap();
                assert_eq!(out.len(), 3);
                for line in &out {
                    assert_eq!(line.lines().count(), 1);
                    assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
                }
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&out[0]).unwrap()["journal"],
                    messages[0].1
                );
            } else {
                assert_eq!(out, [messages[0].1]);
                assert_eq!(err, [messages[1].1]);
            }
        }
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
