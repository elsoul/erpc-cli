// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc r --chain eth deploy`, `update-config`, `update`, `plan` and
//! `destroy`: the changes to an Ethereum RPC node that run a play on it.
//!
//! - **deploy** runs `deploy.yml`, confirms the firewall from a fresh
//!   connection and reads the node's state back.
//! - **update-config** stores new allow lists, if given, and runs the same
//!   play for the units and the firewall alone.
//! - **update** pins another Reth and Lighthouse pair, runs `update.yml`,
//!   and stores the new pins only once the node runs them.
//! - **plan** says what each of those would do, and changes nothing.
//! - **destroy** runs `destroy.yml`; the 1Password item stays unless
//!   `--forget`.

use std::fmt::Write as _;

use erpc_chain::inventory::EthRpc;
use erpc_chain_eth::plays;
use erpc_chain_eth::releases::Client;
use erpc_ssh::Session;
use serde_json::{Map, Value, json};

use crate::arc_rpc::allow_list;
use crate::commands::Outcome;
use crate::error::CliError;
use crate::eth_ops::{Status, head_line, read_status};
use crate::eth_rpc::{
    Facts, Login, Opened, RunVars, facts, find, lockout_warning, open, run_play, target,
};
use crate::node_common::{Say, go_ahead};

/// What a change to a node was asked to do.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// The network.
    pub network: String,
    /// The node.
    pub name: String,
    /// How to log in.
    pub login: Login,
    /// Do not ask.
    pub yes: bool,
    /// `update` and `plan`: the Reth release to move to.
    pub reth_version: Option<String>,
    /// `update` and `plan`: the Lighthouse release to move to.
    pub lighthouse_version: Option<String>,
    /// `update-config`: who may reach RPC; `None` keeps what is stored.
    pub rpc_allow: Option<Vec<String>>,
    /// `update-config`: who may reach SSH besides erpc.
    pub management_allow: Option<Vec<String>>,
    /// `update-config`: who may scrape metrics.
    pub monitoring_allow: Option<Vec<String>>,
    /// `destroy`: delete the chain data too.
    pub purge_data: bool,
    /// `destroy`: then remove the node's item from the inventory.
    pub forget: bool,
    /// `plan`: `deploy`, `update` or `update-config`.
    pub change: String,
}

/// A node opened for a change: its vault, the node, a session to it, its
/// facts and its state.
struct Reached {
    opened: Opened,
    node: EthRpc,
    target: erpc_ssh::Target,
    session: Session,
    facts: Facts,
    status: Status,
}

fn reach(args: &Args, say: &Say) -> Result<Reached, String> {
    let opened = open(&args.network, None, say)?;
    let node = find(&opened.nodes, &args.name, &args.network)?.clone();
    // Init records its result only once the host is prepared.
    if node.last_result.is_empty() {
        return Err(format!(
            "{} has not finished init; run `erpc r --chain eth init -n {} --name {}` again",
            node.name, args.network, node.name
        ));
    }
    let target = target(&node, &args.login)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let facts = facts(&session)?;
    let refusals = facts.refusals();
    if !refusals.is_empty() {
        return Err(format!("{}: {}", node.name, refusals.join("; ")));
    }
    let status = read_status(&session)?;
    Ok(Reached {
        opened,
        node,
        target,
        session,
        facts,
        status,
    })
}

fn vars<'a>(r: &'a Reached, node: &'a EthRpc, phase: &str) -> RunVars<'a> {
    let mut extra = Map::new();
    extra.insert("eth_phase".to_owned(), json!(phase));
    RunVars {
        node,
        network: &r.opened.network,
        facts: &r.facts,
        extra,
    }
}

/// Records how a run ended in the node's item; a 1Password prompt that has
/// timed out after a long run is a warning, not a failure.
fn record(r: &Reached, node: EthRpc, run: &str, result: &str, say: &Say) -> EthRpc {
    match r.opened.store.update_eth_rpc(&EthRpc {
        last_run: run.to_owned(),
        last_result: result.to_owned(),
        ..node.clone()
    }) {
        Ok(stored) => stored,
        Err(e) => {
            say.line(&format!(
                "warning    the run is not recorded in 1Password: {e}"
            ));
            node
        }
    }
}

fn done(text: String, json_out: bool, body: &Value) -> Outcome {
    if json_out {
        crate::print_json(body);
        Outcome::Done(String::new())
    } else {
        Outcome::Done(text)
    }
}

fn list_or_nobody(list: &[String]) -> String {
    if list.is_empty() {
        "nobody".to_owned()
    } else {
        list.join(",")
    }
}

fn pair(node: &EthRpc) -> String {
    format!(
        "reth {} + lighthouse {}",
        node.reth_version, node.lighthouse_version
    )
}

/// Runs `erpc r --chain eth deploy`.
pub fn deploy(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let result = (|| {
        let r = reach(args, &say)?;
        say.line(&format!(
            "plan       {} on {}: {}{}, {}, firewall (rpc {}, metrics {})",
            r.node.name,
            args.network,
            pair(&r.node),
            if r.status.current.is_empty() {
                " (new)"
            } else {
                ""
            },
            if r.status.snapshot_done {
                "data in place".to_owned()
            } else {
                format!(
                    "Reth's {} snapshot fetched first ({})",
                    r.node.rpc_type,
                    if r.node.rpc_type == "archive" {
                        "about 1.8 TB: hours"
                    } else {
                        "about 730 GB: an hour or more"
                    }
                )
            },
            list_or_nobody(&r.node.rpc_allow),
            list_or_nobody(&r.node.monitoring_allow)
        ));
        if let Some(warning) = lockout_warning(&r.node.management_allow, &r.facts) {
            say.line(&warning);
        }
        go_ahead(args.yes, "nothing was changed")?;
        let run = run_play(
            &r.session,
            &r.target,
            &vars(&r, &r.node, "deploy"),
            plays::DEPLOY,
            "Run deploy again to see how it ended",
            &say,
        )?;
        let fresh = Session::open(&r.target).map_err(|e| e.to_string())?;
        let status = read_status(&fresh)?;
        let node = record(&r, r.node.clone(), &run, "deploy ok", &say);
        Ok::<_, CliError>((node, run, status))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, run, s)) => done(
            format!(
                "{} runs {}: {}.\nNext: erpc r --chain eth status -n {} --name {}",
                node.name,
                pair(&node),
                head_line(&s),
                args.network,
                node.name
            ),
            json_out,
            &json!({ "status": "ok", "name": node.name, "reth_version": node.reth_version,
                    "lighthouse_version": node.lighthouse_version, "run": run, "head": s.head,
                    "lighthouse_head_block": s.cl_head_block, "caught_up": s.caught_up() }),
        ),
    }
}

/// The node with the allow lists the flags give, and what changes.
fn with_lists(node: &EthRpc, args: &Args) -> Result<(EthRpc, Vec<String>), String> {
    let mut next = node.clone();
    let mut changes = Vec::new();
    for (flag, what, open_ok, field) in [
        (&args.rpc_allow, "--rpc-allow", true, 0),
        (&args.management_allow, "--management-allow", false, 1),
        (&args.monitoring_allow, "--monitoring-allow", false, 2),
    ] {
        let Some(items) = flag else { continue };
        let list = allow_list(what, items, open_ok)?;
        let slot = match field {
            0 => &mut next.rpc_allow,
            1 => &mut next.management_allow,
            _ => &mut next.monitoring_allow,
        };
        if *slot != list {
            changes.push(format!(
                "{}: {} -> {}",
                what.trim_start_matches("--"),
                list_or_nobody(slot),
                list_or_nobody(&list)
            ));
            *slot = list;
        }
    }
    Ok((next, changes))
}

/// Runs `erpc r --chain eth update-config`.
pub fn update_config(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let result = (|| {
        let r = reach(args, &say)?;
        let (next, changes) = with_lists(&r.node, args)?;
        say.line(&format!(
            "plan       {} on {}: {}; units and firewall written again, layers restarted only if their units change",
            r.node.name,
            args.network,
            if changes.is_empty() {
                "nothing stored changes".to_owned()
            } else {
                changes.join("; ")
            }
        ));
        if let Some(warning) = lockout_warning(&next.management_allow, &r.facts) {
            say.line(&warning);
        }
        go_ahead(args.yes, "nothing was changed")?;
        let node = if changes.is_empty() {
            next
        } else {
            r.opened
                .store
                .update_eth_rpc(&next)
                .map_err(|e| e.to_string())?
        };
        let run = run_play(
            &r.session,
            &r.target,
            &vars(&r, &node, "config"),
            plays::DEPLOY,
            "Run update-config again to see how it ended",
            &say,
        )?;
        let node = record(&r, node, &run, "deploy ok (config)", &say);
        Ok::<_, CliError>((node, run, changes))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, run, changes)) => done(
            format!(
                "{} is configured as stored{}.",
                node.name,
                if changes.is_empty() {
                    ""
                } else {
                    ", with the changes"
                }
            ),
            json_out,
            &json!({ "status": "ok", "name": node.name, "run": run, "changes": changes }),
        ),
    }
}

/// The pair `update` would move to: each client's release asked for, or
/// its newest at or above the floor.
async fn next_pair(node: &EthRpc, facts: &Facts, args: &Args) -> Result<EthRpc, String> {
    let say = Say { quiet: true };
    let (reth_version, reth_commit, reth_sha256) =
        crate::eth_init::pin(Client::Reth, args.reth_version.as_deref(), facts, &say).await?;
    let (lighthouse_version, lighthouse_commit, lighthouse_sha256) = crate::eth_init::pin(
        Client::Lighthouse,
        args.lighthouse_version.as_deref(),
        facts,
        &say,
    )
    .await?;
    Ok(EthRpc {
        reth_version,
        reth_commit,
        reth_sha256,
        lighthouse_version,
        lighthouse_commit,
        lighthouse_sha256,
        ..node.clone()
    })
}

fn same_pair(a: &EthRpc, b: &EthRpc) -> bool {
    a.reth_version == b.reth_version && a.lighthouse_version == b.lighthouse_version
}

/// Runs `erpc r --chain eth update`.
pub async fn update(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let result = async {
        let r = reach(args, &say)?;
        let next = next_pair(&r.node, &r.facts, args).await?;
        if same_pair(&next, &r.node) {
            return Ok::<_, CliError>((r.node.clone(), String::new(), None));
        }
        say.line(&format!(
            "plan       {} on {}: {} -> {}; installed beside the running pair, then both layers \
             restart on it (RPC is down meanwhile); back to the running pair if it does not come up",
            r.node.name,
            args.network,
            pair(&r.node),
            pair(&next)
        ));
        go_ahead(args.yes, "nothing was changed")?;
        let run = match run_play(
            &r.session,
            &r.target,
            &vars(&r, &next, "update"),
            plays::UPDATE,
            "Run update again to see how it ended",
            &say,
        ) {
            Ok(run) => run,
            Err(e) => {
                record(&r, r.node.clone(), "", &format!("update to {} failed", pair(&next)), &say);
                return Err(e.into());
            }
        };
        // The node runs the new pair: only now is it the pin.
        let mut stored = r.opened.store.update_eth_rpc(&next).map_err(|e| {
            format!(
                "the node runs {} but 1Password still pins {}: {e}",
                pair(&next),
                pair(&r.node)
            )
        })?;
        stored = record(&r, stored, &run, &format!("update to {} ok", pair(&next)), &say);
        let status = read_status(&r.session)?;
        Ok((stored, run, Some(status)))
    }
    .await;
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, _, None)) => done(
            format!("{} runs {} already; nothing to do.", node.name, pair(&node)),
            json_out,
            &json!({ "status": "ok", "name": node.name, "changed": false }),
        ),
        Ok((node, run, Some(s))) => done(
            format!("{} runs {}: {}.", node.name, pair(&node), head_line(&s)),
            json_out,
            &json!({ "status": "ok", "name": node.name, "reth_version": node.reth_version,
                    "lighthouse_version": node.lighthouse_version, "changed": true, "run": run }),
        ),
    }
}

/// Runs `erpc r --chain eth plan`.
pub async fn plan(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: true };
    let result = async {
        let r = reach(args, &say)?;
        let mut lines: Vec<String> = Vec::new();
        match args.change.as_str() {
            "update" => {
                let next = next_pair(&r.node, &r.facts, args).await?;
                if same_pair(&next, &r.node) {
                    lines.push(format!(
                        "update: {} is the newest pair; nothing to do",
                        pair(&r.node)
                    ));
                } else {
                    lines.push(format!("update: {} -> {}", pair(&r.node), pair(&next)));
                }
            }
            "update-config" => {
                let (_, changes) = with_lists(&r.node, args)?;
                if changes.is_empty() {
                    lines.push(
                        "update-config: nothing stored changes; units and firewall written again"
                            .to_owned(),
                    );
                }
                lines.extend(changes.into_iter().map(|c| format!("update-config: {c}")));
            }
            _ => {
                let s = &r.status;
                let wanted = format!(
                    "reth-{}--lighthouse-{}",
                    r.node.reth_version, r.node.lighthouse_version
                );
                lines.push(format!(
                    "deploy: {} {}",
                    pair(&r.node),
                    if s.current.ends_with(&format!("/{wanted}")) {
                        "in place"
                    } else {
                        "installed, each archive checked against its digest and signature"
                    }
                ));
                lines.push(format!(
                    "deploy: Reth's {} snapshot {}",
                    r.node.rpc_type,
                    if s.snapshot_done {
                        "in place"
                    } else {
                        "fetched"
                    }
                ));
                lines.push(format!(
                    "deploy: engine JWT {}",
                    if s.jwt {
                        "in place"
                    } else {
                        "made on the node"
                    }
                ));
                lines.push(format!(
                    "deploy: firewall rpc {}, metrics {}, ssh {} and erpc",
                    list_or_nobody(&r.node.rpc_allow),
                    list_or_nobody(&r.node.monitoring_allow),
                    list_or_nobody(&r.node.management_allow)
                ));
                lines.push(format!(
                    "deploy: layers {}",
                    if s.execution == "active" && s.consensus == "active" {
                        "restarted only if their units change"
                    } else {
                        "started"
                    }
                ));
            }
        }
        Ok::<_, String>(lines)
    }
    .await;
    match result {
        Err(e) => Outcome::Failed(e),
        Ok(lines) => {
            if json_out {
                crate::print_json(&json!({ "change": args.change, "plan": lines }));
                return Outcome::Done(String::new());
            }
            let mut out = String::new();
            for l in &lines {
                let _ = writeln!(out, "{l}");
            }
            let _ = write!(out, "Nothing was changed.");
            Outcome::Done(out)
        }
    }
}

/// Runs `erpc r --chain eth destroy`.
pub fn destroy(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let result = (|| -> Result<_, CliError> {
        // Data left behind would be taken for the next node's, whatever its type.
        if args.forget && !args.purge_data {
            return Err(
                "--forget needs --purge-data: the next node set up on this server must not \
                 start from this one's data"
                    .to_owned()
                    .into(),
            );
        }
        let opened = open(&args.network, None, &say)?;
        let node = find(&opened.nodes, &args.name, &args.network)?.clone();
        let target = target(&node, &args.login)?;
        let session = Session::open(&target).map_err(|e| e.to_string())?;
        let facts = facts(&session)?;
        say.line(&format!(
            "plan       {} on {}: stop both layers and remove units, releases, firewall and the JWT{}; {}",
            node.name,
            args.network,
            if args.purge_data {
                ", AND DELETE THE CHAIN DATA"
            } else {
                "; the chain data stays"
            },
            if args.forget {
                "then remove the node's 1Password item"
            } else {
                "the 1Password item stays"
            }
        ));
        go_ahead(args.yes, "nothing was changed")?;
        let mut extra = Map::new();
        extra.insert("eth_phase".to_owned(), json!("destroy"));
        extra.insert("eth_purge_data".to_owned(), json!(args.purge_data));
        let run = run_play(
            &session,
            &target,
            &RunVars {
                node: &node,
                network: &opened.network,
                facts: &facts,
                extra,
            },
            plays::DESTROY,
            "Run destroy again to see how it ended",
            &say,
        )?;
        if args.forget {
            let id = node.id.clone().ok_or("the node's item has no id")?;
            opened.store.remove(&id).map_err(|e| {
                format!(
                    "{} is destroyed, but its item is still in 1Password: {e}",
                    node.name
                )
            })?;
            return Ok::<_, CliError>((node, run));
        }
        let result = if args.purge_data {
            "destroyed (data deleted)"
        } else {
            "destroyed"
        };
        if let Err(e) = opened.store.update_eth_rpc(&EthRpc {
            last_run: run.clone(),
            last_result: result.to_owned(),
            ..node.clone()
        }) {
            say.line(&format!(
                "warning    the run is not recorded in 1Password: {e}"
            ));
        }
        Ok::<_, CliError>((node, run))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, run)) => done(
            if args.forget {
                format!(
                    "{} no longer runs Ethereum and is out of the inventory; `erpc r --chain eth init` sets the server up again, as either type.",
                    node.name
                )
            } else {
                format!(
                    "{} no longer runs Ethereum. Its 1Password item stays; `erpc r --chain eth deploy` sets it up again.",
                    node.name
                )
            },
            json_out,
            &json!({ "status": "ok", "name": node.name, "run": run, "purged": args.purge_data, "forgotten": args.forget }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::EthRpc;

    use super::{Args, same_pair, with_lists};

    #[test]
    fn update_config_changes_only_the_lists_it_is_given() {
        let node = EthRpc {
            rpc_allow: vec!["198.51.100.0/24".to_owned()],
            monitoring_allow: vec!["192.0.2.50".to_owned()],
            ..EthRpc::default()
        };
        let (same, unchanged) = with_lists(&node, &Args::default()).expect("same");
        assert_eq!(same, node);
        assert!(unchanged.is_empty());
        let args = Args {
            rpc_allow: Some(vec!["198.51.100.0/24".to_owned(), "203.0.113.9".to_owned()]),
            monitoring_allow: Some(vec!["192.0.2.50".to_owned()]),
            ..Args::default()
        };
        let (next, changes) = with_lists(&node, &args).expect("changed");
        assert_eq!(next.rpc_allow, ["198.51.100.0/24", "203.0.113.9"]);
        assert_eq!(changes.len(), 1, "{changes:?}");
        let bad = Args {
            management_allow: Some(vec!["0.0.0.0/0".to_owned()]),
            ..Args::default()
        };
        assert!(with_lists(&node, &bad).is_err());
    }

    #[test]
    fn a_pair_is_the_same_only_when_both_releases_are() {
        let a = EthRpc {
            reth_version: "v2.8.1".to_owned(),
            lighthouse_version: "v8.3.2".to_owned(),
            ..EthRpc::default()
        };
        assert!(same_pair(&a, &a.clone()));
        let b = EthRpc {
            lighthouse_version: "v8.3.3".to_owned(),
            ..a.clone()
        };
        assert!(!same_pair(&a, &b));
    }
}
