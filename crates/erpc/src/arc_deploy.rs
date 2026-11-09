// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc r --chain arc deploy`, `update-config`, `update`, `plan` and
//! `destroy`: the changes to an Arc RPC node that run a play on it.
//!
//! - **deploy** puts the consensus key in place when the node has none (from
//!   1Password, over SSH standard input, into `systemd-creds`), runs
//!   `deploy.yml`, confirms the firewall from a fresh connection and reads
//!   the node's state back.
//! - **update-config** stores new allow lists, `debug` and `trace` or a
//!   provider's peers, if given, and runs the same play for the units and
//!   the firewall alone.
//! - **update** pins another release, refuses a move that needs a migration,
//!   runs `update.yml`, and stores the new pin only once the node runs it.
//! - **plan** says what each of those would do, and changes nothing.
//! - **destroy** runs `destroy.yml`; the 1Password items stay.

use std::fmt::Write as _;

use erpc_chain::inventory::RpcNode;
use erpc_chain_arc::{key, plays, releases};
use erpc_ssh::Session;
use serde_json::{Map, Value, json};

use crate::arc_ops::{CAUGHT_UP_BLOCKS, Status, read_status};
use crate::arc_rpc::{
    Facts, KindFlags, Login, Opened, RunVars, allow_list, facts, find, open, run_play, target,
    with_kind,
};
use crate::commands::Outcome;
use crate::error::CliError;
use crate::node_common::{Say, go_ahead};

/// What a change to a node was asked to do.
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)] // Independent CLI switches, not persisted lifecycle state.
pub struct Args {
    /// The network.
    pub network: String,
    /// The node.
    pub name: String,
    /// How to log in.
    pub login: Login,
    /// Do not ask.
    pub yes: bool,
    /// `update` and `plan`: the release to move to.
    pub version: Option<String>,
    /// `update-config`: who may reach RPC; `None` keeps what is stored.
    pub rpc_allow: Option<Vec<String>>,
    /// `update-config`: who may reach SSH besides erpc.
    pub management_allow: Option<Vec<String>>,
    /// `update-config`: who may scrape metrics.
    pub monitoring_allow: Option<Vec<String>>,
    /// `update-config`: `debug` and `trace`, and a provider's peers; the
    /// type itself is fixed at init.
    pub kind: KindFlags,
    /// `destroy`: delete the chain data too.
    pub purge_data: bool,
    /// `destroy`: then remove the node's item from the inventory, so the
    /// name and the server can be set up again, as another type too. The
    /// consensus key's item stays.
    pub forget: bool,
    /// `plan`: `deploy`, `update` or `update-config`.
    pub change: String,
    /// Explicitly rewrap the same original key, then continue deployment.
    pub restore_custody: bool,
    /// Quarantine an incomplete initial bootstrap; active history is never reset.
    pub reset_bootstrap: bool,
}

/// A node opened for a change: its vault, the node, a session to it, its
/// facts and its state.
struct Reached {
    opened: Opened,
    node: RpcNode,
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
            "{} has not finished init; run `erpc r --chain arc init -n {} --name {}` again",
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
    let status = read_status(&session, &node, &opened.network)?;
    Ok(Reached {
        opened,
        node,
        target,
        session,
        facts,
        status,
    })
}

/// Puts the consensus key in place when the node has none: read from
/// 1Password into memory, sent on standard input to `systemd-creds`.
fn put_key(r: &Reached, node: &RpcNode, say: &Say, restore: bool) -> Result<(), String> {
    if r.status.credential && !restore {
        return Ok(());
    }
    let stored = key::StoredKey {
        public_key: node.consensus_public_key.clone(),
        reference: r
            .opened
            .store
            .arc_key_reference(node)
            .map_err(|e| e.to_string())?
            .ok_or("original Arc key reservation is incomplete; resume init")?
            .to_string(),
    };
    let owner = key::Owner {
        vault: &r.opened.vault,
        network: r
            .opened
            .network
            .chain
            .strip_prefix("arc-")
            .ok_or("unknown Arc network")?,
        name: &node.name,
        item: node.id.as_deref().ok_or("original Arc item is missing")?,
    };
    let consensus = key::read(&r.opened.runner, &owner, &stored).map_err(|e| e.to_string())?;
    crate::arc_authority::import_key(&r.session, node, &r.opened.network, &consensus, restore)?;
    say.line("key        original encrypted identity verified");
    Ok(())
}

fn vars<'a>(
    r: &'a Reached,
    node: &'a RpcNode,
    phase: &str,
    extra: Map<String, Value>,
) -> RunVars<'a> {
    let mut extra = extra;
    extra.insert("arc_phase".to_owned(), json!(phase));
    RunVars {
        node,
        network: &r.opened.network,
        facts: &r.facts,
        extra,
    }
}

/// Records how a run ended in the node's item; a 1Password prompt that has
/// timed out after a long run is a warning, not a failure.
fn record(r: &Reached, node: RpcNode, run: &str, result: &str, say: &Say) -> RpcNode {
    match r.opened.store.update_rpc_node(&RpcNode {
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

/// A completed play and an observed healthy node are separate results.
fn observed_done(
    node: &RpcNode,
    network: &str,
    state: &Status,
    action: &str,
    json_out: bool,
    mut body: Value,
) -> Outcome {
    let Some(network) = erpc_chain_arc::network::get(network) else {
        return Outcome::Usage("unsupported Arc network".to_owned());
    };
    let problems = state.problems(node, network.chain_id);
    let readiness = state.readiness(&problems);
    body["status"] = json!(match readiness {
        Some(true) => "ready",
        Some(false) => "not_ready",
        None => "unknown",
    });
    body["ready"] = json!(readiness);
    body["catchup"] = json!(if state.public_head.is_none() {
        "unknown"
    } else if state.lag().is_some_and(|lag| lag <= CAUGHT_UP_BLOCKS) {
        "within_reference_threshold"
    } else {
        "behind"
    });
    body["genesis_hash"] = json!(state.genesis_hash);
    body["head_timestamp"] = json!(state.head_timestamp);
    body["problems"] = json!(problems);
    body["head"] = json!(state.head);
    body["public_head"] = json!(state.public_head);
    body["behind"] = json!(state.lag());
    body["running"] = json!(state.running);
    body["running_commit"] = json!(state.running_commit);
    let message = if json_out {
        crate::print_json(&body);
        String::new()
    } else {
        format!(
            "{}: {action} finished; {}",
            node.name,
            if problems.is_empty() {
                if readiness.is_some() {
                    "observed node checks passed".to_owned()
                } else {
                    "local checks passed, network catch-up unknown (public reference unavailable)"
                        .to_owned()
                }
            } else {
                format!("readiness problems: {}", problems.join("; "))
            }
        )
    };
    if readiness == Some(true) {
        Outcome::Done(message)
    } else {
        Outcome::Problems(message)
    }
}

/// What a failed update left: the play rolls back to the release the node
/// ran, so when the node serves that release again, say so instead of the
/// generic advice to run the same command again.
fn failed_update(old: &RpcNode, next: &RpcNode, now: Option<&Status>, error: String) -> String {
    match now {
        Some(s) if s.running.starts_with(&format!("{} ", old.version)) => format!(
            "{} did not complete: the previous release is still observed on {} ({}, {}). No automatic database rollback was attempted. 1Password still pins {}; \
             the logs are in `erpc r --chain arc logs`",
            next.version,
            old.name,
            old.version,
            head_line(s),
            old.version
        ),
        _ => error,
    }
}

fn head_line(s: &Status) -> String {
    format!(
        "head {} (public {}{})",
        s.head.map_or_else(|| "-".to_owned(), |h| h.to_string()),
        s.public_head
            .map_or_else(|| "-".to_owned(), |h| h.to_string()),
        s.lag().map_or_else(String::new, |l| {
            if l <= CAUGHT_UP_BLOCKS {
                ", caught up".to_owned()
            } else {
                format!(", {l} behind and catching up")
            }
        })
    )
}

/// Runs `erpc r --chain arc deploy`.
pub fn deploy(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let result = (|| {
        let r = reach(args, &say)?;
        say.line(&format!(
            "plan       {} on {}: arc-node {}{}, {}, firewall (rpc {}, metrics {})",
            r.node.name,
            args.network,
            r.node.version,
            if r.status.current.is_empty() {
                " (new)"
            } else {
                ""
            },
            if r.status.snapshot_done {
                "data in place"
            } else {
                "snapshots fetched first (tens of minutes)"
            },
            list_or_nobody(&r.node.rpc_allow),
            list_or_nobody(&r.node.monitoring_allow)
        ));
        if let Some(warning) = crate::arc_rpc::lockout_warning(&r.node.management_allow, &r.facts) {
            say.line(&warning);
        }
        go_ahead(args.yes, "nothing was changed")?;
        if args.reset_bootstrap {
            let observed = crate::arc_authority::invoke(
                &r.session,
                &r.node,
                &r.opened.network,
                "status",
                json!({}),
            )?;
            let intent = observed
                .get("bootstrap_intent")
                .and_then(Value::as_str)
                .ok_or("no incomplete original Arc bootstrap is recorded")?;
            crate::arc_authority::invoke(
                &r.session,
                &r.node,
                &r.opened.network,
                "reset-bootstrap",
                json!({"intent":intent}),
            )?;
        }
        put_key(&r, &r.node, &say, args.restore_custody)?;
        let run = run_play(
            &r.session,
            &r.target,
            &vars(&r, &r.node, "deploy", Map::new()),
            plays::DEPLOY,
            "Run deploy again to see how it ended",
            &say,
        )?;
        let fresh = Session::open(&r.target).map_err(|e| e.to_string())?;
        let status = read_status(&fresh, &r.node, &r.opened.network)?;
        let node = record(
            &r,
            r.node.clone(),
            &run,
            "deploy applied; readiness observed separately",
            &say,
        );
        Ok::<_, CliError>((node, run, status))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, run, s)) => observed_done(
            &node,
            &args.network,
            &s,
            "deploy",
            json_out,
            json!({ "name": node.name, "version": node.version, "run": run }),
        ),
    }
}

fn list_or_nobody(list: &[String]) -> String {
    if list.is_empty() {
        "nobody".to_owned()
    } else {
        list.join(",")
    }
}

/// The node with the allow lists, `debug` and `trace` and the peers the
/// flags give, and what changes.
fn with_lists(node: &RpcNode, args: &Args) -> Result<(RpcNode, Vec<String>), String> {
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
    let kinded = with_kind(&next, true, &args.kind)?;
    if kinded.debug_api != next.debug_api {
        changes.push(format!(
            "debug and trace: {}",
            if kinded.debug_api { "on" } else { "off" }
        ));
    }
    for (what, before, after) in [
        ("trusted-peers", &next.trusted_peers, &kinded.trusted_peers),
        ("sentry-peers", &next.sentry_peers, &kinded.sentry_peers),
    ] {
        if before != after {
            changes.push(format!("{what}: {} -> {}", before.len(), after.len()));
        }
    }
    Ok((kinded, changes))
}

/// Runs `erpc r --chain arc update-config`.
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
        if let Some(warning) = crate::arc_rpc::lockout_warning(&next.management_allow, &r.facts) {
            say.line(&warning);
        }
        go_ahead(args.yes, "nothing was changed")?;
        let (node, run) = crate::arc_custody::configure(
            &r.opened.store,
            &r.node,
            &next,
            |saved| put_key(&r, saved, &say, false),
            |saved| {
                run_play(
                    &r.session,
                    &r.target,
                    &vars(&r, saved, "config", Map::new()),
                    plays::DEPLOY,
                    "Run update-config again to see how it ended",
                    &say,
                )
            },
        )?;
        let status = read_status(&r.session, &r.node, &r.opened.network)?;
        let node = record(
            &r,
            node,
            &run,
            "configuration applied; readiness observed separately",
            &say,
        );
        Ok::<_, CliError>((node, run, changes, status))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, run, changes, s)) => observed_done(
            &node,
            &args.network,
            &s,
            "update-config",
            json_out,
            json!({ "name": node.name, "run": run, "changes": changes }),
        ),
    }
}

/// The release `update` would move to, and what stands in the way.
async fn next_release(
    node: &RpcNode,
    facts: &Facts,
    wanted: Option<&str>,
) -> Result<(releases::Release, Vec<releases::Migration>), String> {
    let platform = facts.platform()?;
    let github = releases::Github::new().map_err(|e| e.to_string())?;
    let (release, _) = releases::pin(
        &github,
        Some(wanted.unwrap_or(erpc_chain_arc::authority::VERSION)),
        platform,
    )
    .await
    .map_err(|e| e.to_string())?;
    erpc_chain_arc::authority::qualify_source(
        &release.tag,
        &release.commit,
        release
            .digest(platform)
            .ok_or("qualified Arc archive is unavailable")?,
        platform,
    )?;
    let migrations = releases::migrations_between(&node.version, &release.tag);
    Ok((release, migrations))
}

/// Runs `erpc r --chain arc update`.
pub async fn update(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let result = async {
        let r = reach(args, &say)?;
        let (release, migrations) = next_release(&r.node, &r.facts, args.version.as_deref()).await?;
        if release.tag == r.node.version {
            return Ok::<_, CliError>((r.node.clone(), String::new(), r.status));
        }
        if !migrations.is_empty() {
            return Err(format!(
                "moving {} from {} to {} needs a step erpc does not take on its own: {}. Nothing was changed",
                r.node.name,
                r.node.version,
                release.tag,
                migrations.iter().map(|m| format!("{} ({})", m.at, m.step)).collect::<Vec<_>>().join("; ")
            ).into());
        }
        let platform = r.facts.platform()?;
        let next = RpcNode {
            version: release.tag.clone(),
            commit: release.commit.clone(),
            archive_sha256: release
                .digest(platform)
                .ok_or("the release has no digest for this platform")?
                .to_owned(),
            ..r.node.clone()
        };
        say.line(&format!(
            "plan       {} on {}: arc-node {} -> {} @ {}; installed beside the running release, \
             then both layers restart on it (RPC is down meanwhile); failures remain fenced without a database downgrade",
            r.node.name,
            args.network,
            r.node.version,
            next.version,
            &next.commit[..12]
        ));
        go_ahead(args.yes, "nothing was changed")?;
        let run = run_play(
            &r.session,
            &r.target,
            &vars(&r, &next, "update", Map::new()),
            plays::UPDATE,
            "Run update again to see how it ended",
            &say,
        );
        let run = match run {
            Ok(run) => run,
            Err(e) => {
                record(&r, r.node.clone(), "", &format!("update to {} failed", next.version), &say);
                let now = read_status(&r.session, &r.node, &r.opened.network).ok();
                return Err(failed_update(&r.node, &next, now.as_ref(), e).into());
            }
        };
        let status = read_status(&r.session, &r.node, &r.opened.network)?;
        if !status.release_matches(&next, &r.opened.network) {
            return Err("update play completed but the expected running release/source/network was not observed; inventory pin was retained".into());
        }
        // Only the observed source-qualified release becomes the inventory pin.
        let mut stored = r
            .opened
            .store
            .update_rpc_node(&next)
            .map_err(|e| format!("the node runs {} but 1Password still pins {}: {e}", next.version, r.node.version))?;
        stored = record(&r, stored, &run, &format!("update to {} applied; readiness observed separately", next.version), &say);
        Ok((stored, run, status))
    }
    .await;
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, run, s)) => observed_done(
            &node,
            &args.network,
            &s,
            "update",
            json_out,
            json!({ "name": node.name, "version": node.version, "changed": !run.is_empty(), "run": run }),
        ),
    }
}

/// Runs `erpc r --chain arc plan`.
pub async fn plan(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: true };
    let result = async {
        let r = reach(args, &say)?;
        let mut lines: Vec<String> = Vec::new();
        match args.change.as_str() {
            "update" => {
                let (release, migrations) =
                    next_release(&r.node, &r.facts, args.version.as_deref()).await?;
                if release.tag == r.node.version {
                    lines.push(format!(
                        "update: {} is the qualified release; nothing to do",
                        r.node.version
                    ));
                } else {
                    lines.push(format!(
                        "update: arc-node {} -> {} @ {}",
                        r.node.version,
                        release.tag,
                        &release.commit[..12]
                    ));
                    for m in migrations {
                        lines.push(format!(
                            "  refused until done by hand: {} ({})",
                            m.at, m.step
                        ));
                    }
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
                lines.push(format!(
                    "deploy: release {}",
                    if s.release_matches(&r.node, &r.opened.network) {
                        format!("{} in place", r.node.version)
                    } else {
                        format!("{} installed", r.node.version)
                    }
                ));
                lines.push(format!(
                    "deploy: snapshots {}",
                    if s.snapshot_done {
                        "in place"
                    } else {
                        "fetched"
                    }
                ));
                lines.push(format!(
                    "deploy: consensus key {}",
                    if s.credential {
                        "in place"
                    } else {
                        "put in place from 1Password"
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
                        "fenced and restarted through the original authority"
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

/// Runs `erpc r --chain arc destroy`.
pub fn destroy(args: &Args, json_out: bool) -> Outcome {
    if args.forget || args.purge_data {
        return Outcome::Usage("Arc original inventory, key and data history must be retained; --forget and --purge-data are not supported".into());
    }
    let say = Say { quiet: json_out };
    let result = (|| -> Result<_, CliError> {
        let opened = open(&args.network, None, &say)?;
        let node = find(&opened.nodes, &args.name, &args.network)?.clone();
        let session = Session::open(&target(&node, &args.login)?).map_err(|e| e.to_string())?;
        say.line("plan       stop and durably retire original Arc services; preserve identity, data and filtering");
        go_ahead(args.yes, "nothing was changed")?;
        crate::arc_authority::invoke(
            &session,
            &node,
            &opened.network,
            "destroy",
            json!({"layer":"both"}),
        )?;
        let recorded = opened
            .store
            .update_rpc_node(&RpcNode {
                last_result: "retired; original data and custody retained".into(),
                ..node.clone()
            })
            .is_ok();
        Ok((node, recorded))
    })();
    match result {
        Err(error) => Outcome::from(error),
        Ok((node, recorded)) => done(
            format!(
                "{} is retired and fenced at boot. Original identity and chain data remain. Inventory receipt: {}.",
                node.name,
                if recorded {
                    "saved"
                } else {
                    "not saved; reload inventory before retrying"
                }
            ),
            json_out,
            &json!({"retired":true,"name":node.name,"data_preserved":true,"key_preserved":true,"inventory_recorded":recorded}),
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn completed_play_cannot_be_reported_as_healthy_without_native_evidence() {
        let node = erpc_chain::inventory::RpcNode {
            name: "fixture".into(),
            version: "v0.8.1".into(),
            commit: "ab09dbfd9553a7ad48f9c134ec5e808c36512c74".into(),
            ..Default::default()
        };
        let missing = crate::arc_ops::Status::default();
        for operation in ["deploy", "update-config", "update"] {
            assert!(matches!(
                super::observed_done(
                    &node,
                    "testnet",
                    &missing,
                    operation,
                    false,
                    serde_json::json!({})
                ),
                crate::commands::Outcome::Problems(_)
            ));
        }
    }

    use erpc_chain::inventory::RpcNode;

    use super::{Args, KindFlags, failed_update, with_lists};
    use crate::arc_ops::Status;

    #[test]
    fn a_failed_update_does_not_invent_an_automatic_database_rollback() {
        let old = RpcNode {
            name: "arc1".to_owned(),
            version: "v0.8.0".to_owned(),
            ..RpcNode::default()
        };
        let next = RpcNode {
            version: "v0.8.1".to_owned(),
            ..old.clone()
        };
        let back = Status::parse("running=v0.8.0 (66ad2d5a)\nhead=0x10\npublic_head=0x10\n");
        let said = failed_update(&old, &next, Some(&back), "play failed".to_owned());
        assert!(
            said.starts_with(
                "v0.8.1 did not complete: the previous release is still observed on arc1"
            ),
            "{said}"
        );
        let stuck = Status::parse("running=\n");
        assert_eq!(
            failed_update(&old, &next, Some(&stuck), "play failed".to_owned()),
            "play failed"
        );
        assert_eq!(
            failed_update(&old, &next, None, "play failed".to_owned()),
            "play failed"
        );
    }

    #[test]
    fn update_config_changes_only_the_lists_it_is_given() {
        let node = RpcNode {
            rpc_allow: vec!["198.51.100.0/24".to_owned()],
            monitoring_allow: vec!["192.0.2.50".to_owned()],
            rpc_type: "full".to_owned(),
            ..RpcNode::default()
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
        assert!(changes[0].starts_with("rpc-allow:"));
        let bad = Args {
            management_allow: Some(vec!["0.0.0.0/0".to_owned()]),
            ..Args::default()
        };
        assert!(with_lists(&node, &bad).is_err());
        let debug = Args {
            kind: KindFlags {
                debug_api: Some(true),
                ..KindFlags::default()
            },
            ..Args::default()
        };
        let (next, changes) = with_lists(&node, &debug).expect("debug on");
        assert!(next.debug_api);
        assert_eq!(changes, ["debug and trace: on"]);
    }
}
