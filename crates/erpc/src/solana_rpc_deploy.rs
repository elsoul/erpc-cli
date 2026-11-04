// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc r --chain solana deploy`, `update-config`, `update`, `plan` and
//! `destroy`: the changes to a Solana RPC node that run a play on it.
//!
//! - **deploy** shows the free disks and what becomes of them, runs
//!   `deploy.yml` (SLV's `slv rpc deploy`), confirms the firewall from a
//!   fresh connection, and records the identity the node made.
//! - **update-config** stores new allow lists, if given, and runs
//!   `config.yml`: the startup and the firewall written again, the service
//!   restarted only when its startup changed.
//! - **update** pins another client release (and the Yellowstone plugin built
//!   for it), runs `update.yml`, and stores the new pins only once the node
//!   was restarted on them.
//! - **plan** says what each of those would do, and changes nothing.
//! - **destroy** runs `destroy.yml`; the item stays.

use std::fmt::Write as _;

use erpc_chain::inventory::SolanaRpc;
use erpc_chain_solana::plays;
use erpc_chain_solana::rpc::{self, Client, RpcType};
use erpc_ssh::{Session, Target};
use serde_json::{Map, Value, json};

use crate::arc_rpc::{Facts, Login, allow_list, facts};
use crate::commands::Outcome;
use crate::error::CliError;
use crate::node_common::{Say, check_ubuntu, free_disks, go_ahead, public_key_line};
use crate::solana_rpc::{
    Opened, RunVars, Status, find_ready, list_or_nobody, lockout_warning, memory_warning, open,
    pins, read_status, record, refusals, run_play, target,
};
use crate::solana_rpc_init::{Pins, Wanted, pin};

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
    /// `update` and `plan`: the client release to move to.
    pub version: Option<String>,
    /// `update` and `plan`: the Yellowstone release to move to.
    pub geyser_version: Option<String>,
    /// `update-config`: who may reach RPC; `None` keeps what is stored.
    pub rpc_allow: Option<Vec<String>>,
    /// `update-config`: who may reach SSH besides erpc.
    pub management_allow: Option<Vec<String>>,
    /// `update-config`: who may scrape metrics.
    pub monitoring_allow: Option<Vec<String>>,
    /// `destroy`: delete the ledger, accounts and snapshots too.
    pub purge_data: bool,
    /// `plan`: `deploy`, `update` or `update-config`.
    pub change: String,
}

/// A node opened for a change: its vault, the node, a session to it, its
/// facts and state, and the operator's key line.
struct Reached {
    network: String,
    opened: Opened,
    node: SolanaRpc,
    target: Target,
    session: Session,
    facts: Facts,
    status: Status,
    authorized: String,
}

fn reach(args: &Args, say: &Say) -> Result<Reached, String> {
    let opened = open(&args.network, None, say)?;
    let node = find_ready(&opened.nodes, &args.name, &args.network)?.clone();
    // The pins, before anything runs.
    rpc::versions_yml(&args.network, &node).map_err(|e| e.to_string())?;
    let authorized = public_key_line(
        args.login
            .ssh_key
            .as_deref()
            .ok_or("pass --ssh-key <path to the .pub of the key that logs in>")?,
    )?;
    let target = target(&node, &args.login)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let os = check_ubuntu(&session)?;
    let facts = facts(&session)?;
    let refused = refusals(&facts);
    if !refused.is_empty() {
        return Err(format!("{}: {}", node.name, refused.join("; ")));
    }
    let status = read_status(&session)?;
    say.line(&format!("server     {} as solv: {os}", node.name));
    Ok(Reached {
        network: args.network.clone(),
        opened,
        node,
        target,
        session,
        facts,
        status,
        authorized,
    })
}

fn vars<'a>(r: &'a Reached, node: &'a SolanaRpc, extra: Map<String, Value>) -> RunVars<'a> {
    RunVars {
        network: &r.network,
        node,
        facts: &r.facts,
        authorized: &r.authorized,
        extra,
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

/// The free disks and what deploy makes of them, with the variable the
/// deploy play reads.
fn disks(r: &Reached) -> Result<(Vec<String>, Value), String> {
    let found = free_disks(&r.session)?;
    let lines = crate::validator_deploy::disk_plan(&found);
    let chosen = Value::Array(
        found
            .iter()
            .take(crate::validator_deploy::MOUNT_TARGETS.len())
            .map(|d| json!({ "name": d.name, "wipe": d.wipe }))
            .collect(),
    );
    Ok((lines, chosen))
}

fn firewall_line(node: &SolanaRpc) -> String {
    format!(
        "firewall rpc {}, metrics {}, ssh {} and erpc",
        list_or_nobody(&node.rpc_allow),
        list_or_nobody(&node.monitoring_allow),
        list_or_nobody(&node.management_allow)
    )
}

/// Runs `erpc r --chain solana deploy`.
pub fn deploy(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let result = (|| -> Result<_, CliError> {
        let r = reach(args, &say)?;
        say.line(&format!(
            "plan       {} on {}: {} {}; {}",
            r.node.name,
            args.network,
            r.node.rpc_type,
            pins(&r.node),
            firewall_line(&r.node)
        ));
        say.line(
            "           the base system, the client built from source, the identity made on the node, \
             a snapshot into an empty ledger, the services, then the firewall",
        );
        if r.status.validator == "active" {
            say.line("           the validator runs: it is left running (update-config restarts it on a new startup)");
        }
        let (disk_lines, chosen) = disks(&r)?;
        for line in disk_lines {
            say.line(&format!("disks      {line}"));
        }
        if let Some(w) = memory_warning(&r.facts, &r.node.rpc_type) {
            say.line(&w);
        }
        if let Some(w) = lockout_warning(&r.node, &r.facts) {
            say.line(&w);
        }
        go_ahead(args.yes, "nothing was run")?;
        let mut extra = Map::new();
        extra.insert("erpc_disks".to_owned(), chosen);
        say.line("deploy     starting on the node (the build and the snapshot take a while)…");
        let run = run_play(
            &r.session,
            &r.target,
            &vars(&r, &r.node, extra),
            plays::MAINNET_RPC_DEPLOY,
            &[],
            "Run deploy again to see how it ended",
            &say,
        );
        let run = match run {
            Ok(run) => run,
            Err(e) => {
                record(&r.opened.store, r.node.clone(), "", "deploy failed", &say);
                return Err(e.into());
            }
        };
        let fresh = Session::open(&r.target).map_err(|e| e.to_string())?;
        let status = read_status(&fresh)?;
        let mut node = r.node.clone();
        if !status.identity.is_empty() && status.identity != node.identity_account {
            say.line(&format!(
                "identity   {} (made on the node)",
                status.identity
            ));
            status.identity.clone_into(&mut node.identity_account);
        }
        let problems = status.problems(&node);
        if !problems.is_empty() {
            record(
                &r.opened.store,
                node.clone(),
                &run,
                "deploy ran; checks failed",
                &say,
            );
            return Err(
                format!("the deploy ran, but {}: {}", node.name, problems.join("; ")).into(),
            );
        }
        let node = record(&r.opened.store, node, &run, "deploy ok", &say);
        Ok::<_, CliError>((node, run, status))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, run, s)) => done(
            format!(
                "{} runs {} as {}; health {}.\n\
                 It loads its snapshot and catches up next. Check with:\n  \
                 erpc r --chain solana status -n {} --name {} --ssh-key <pub>",
                node.name,
                pins(&node),
                node.identity_account,
                if s.health.is_empty() { "-" } else { &s.health },
                args.network,
                node.name
            ),
            json_out,
            &json!({ "status": "ok", "name": node.name, "run": run, "identity": node.identity_account,
                    "health": s.health, "slot": s.slot }),
        ),
    }
}

/// The node with the allow lists the flags give, and what changes.
fn with_lists(node: &SolanaRpc, args: &Args) -> Result<(SolanaRpc, Vec<String>), String> {
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

/// Runs `erpc r --chain solana update-config`.
pub fn update_config(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let result = (|| {
        let r = reach(args, &say)?;
        let (next, changes) = with_lists(&r.node, args)?;
        say.line(&format!(
            "plan       {} on {}: {}; the startup and the firewall written again, the validator \
             restarted only if its startup changes",
            r.node.name,
            args.network,
            if changes.is_empty() {
                "allow lists unchanged".to_owned()
            } else {
                changes.join("; ")
            }
        ));
        if let Some(w) = lockout_warning(&next, &r.facts) {
            say.line(&w);
        }
        go_ahead(args.yes, "nothing was changed")?;
        let node = if changes.is_empty() {
            next
        } else {
            r.opened
                .store
                .update_solana_rpc(&next)
                .map_err(|e| e.to_string())?
        };
        let run = run_play(
            &r.session,
            &r.target,
            &vars(&r, &node, Map::new()),
            plays::MAINNET_RPC_CONFIG,
            &[],
            "Run update-config again to see how it ended",
            &say,
        )?;
        let node = record(&r.opened.store, node, &run, "deploy ok (config)", &say);
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
                    ", with the new allow lists"
                }
            ),
            json_out,
            &json!({ "status": "ok", "name": node.name, "run": run, "changes": changes }),
        ),
    }
}

/// The pins `update` would move the node to.
async fn next_pins(node: &SolanaRpc, args: &Args, say: &Say) -> Result<Pins, String> {
    let client = Client::parse(&node.client).ok_or("the node's client is not one erpc runs")?;
    let rpc_type = RpcType::parse(&node.rpc_type).ok_or("the node's type is not one erpc runs")?;
    pin(
        &Wanted {
            network: &args.network,
            client,
            rpc_type,
            version: args.version.as_deref(),
            geyser_version: args.geyser_version.as_deref(),
            of1: rpc_type
                .faithful()
                .then(|| (node.of1_version.clone(), node.of1_sha256.clone())),
        },
        say,
    )
    .await
}

/// Runs `erpc r --chain solana update`.
pub async fn update(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let result = async {
        let r = reach(args, &say)?;
        let wanted = next_pins(&r.node, args, &say).await?;
        if wanted == Pins::of(&r.node) {
            return Ok::<_, CliError>((r.node.clone(), String::new(), None));
        }
        let next = wanted.apply(&r.node);
        say.line(&format!(
            "plan       {} on {}: {} -> {}; built beside the running one, then the validator \
             restarts on it (RPC is down while it loads its snapshot)",
            r.node.name,
            args.network,
            pins(&r.node),
            pins(&next)
        ));
        go_ahead(args.yes, "nothing was changed")?;
        let run = run_play(
            &r.session,
            &r.target,
            &vars(&r, &next, Map::new()),
            plays::MAINNET_RPC_UPDATE,
            &[],
            "Run update again to see how it ended",
            &say,
        );
        let run = match run {
            Ok(run) => run,
            Err(e) => {
                record(
                    &r.opened.store,
                    r.node.clone(),
                    "",
                    &format!("update to {} failed", next.version),
                    &say,
                );
                return Err(e.into());
            }
        };
        // The node was restarted on the new build: only now is it the pin.
        let stored = r.opened.store.update_solana_rpc(&next).map_err(|e| {
            format!(
                "the node runs {} but 1Password still pins {}: {e}",
                pins(&next),
                pins(&r.node)
            )
        })?;
        let stored = record(
            &r.opened.store,
            stored,
            &run,
            &format!("update to {} ok", next.version),
            &say,
        );
        let status = read_status(&r.session)?;
        Ok((stored, run, Some(status)))
    }
    .await;
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, _, None)) => done(
            format!("{} runs {} already; nothing to do.", node.name, pins(&node)),
            json_out,
            &json!({ "status": "ok", "name": node.name, "version": node.version, "changed": false }),
        ),
        Ok((node, run, Some(s))) => done(
            format!(
                "{} was restarted on {}; validator {}, health {}.",
                node.name,
                pins(&node),
                s.validator,
                if s.health.is_empty() { "-" } else { &s.health }
            ),
            json_out,
            &json!({ "status": "ok", "name": node.name, "version": node.version, "changed": true, "run": run }),
        ),
    }
}

/// Runs `erpc r --chain solana plan`.
pub async fn plan(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: true };
    let result = async {
        let r = reach(args, &say)?;
        let mut lines: Vec<String> = Vec::new();
        match args.change.as_str() {
            "update" => {
                let wanted = next_pins(&r.node, args, &say).await?;
                if wanted == Pins::of(&r.node) {
                    lines.push(format!("update: {} is current; nothing to do", pins(&r.node)));
                } else {
                    lines.push(format!(
                        "update: {} -> {}",
                        pins(&r.node),
                        pins(&wanted.apply(&r.node))
                    ));
                    lines.push("update: built on the node, then the validator restarts".to_owned());
                }
            }
            "update-config" => {
                let (_, changes) = with_lists(&r.node, args)?;
                if changes.is_empty() {
                    lines.push(
                        "update-config: allow lists unchanged; the startup and firewall written again"
                            .to_owned(),
                    );
                }
                lines.extend(changes.into_iter().map(|c| format!("update-config: {c}")));
            }
            _ => {
                lines.push(format!("deploy: {} {}", r.node.rpc_type, pins(&r.node)));
                let (disk_lines, _) = disks(&r)?;
                lines.extend(disk_lines.into_iter().map(|l| format!("deploy: {l}")));
                lines.push(format!(
                    "deploy: identity {}",
                    if r.status.identity.is_empty() {
                        "made on the node".to_owned()
                    } else {
                        format!("{} kept", r.status.identity)
                    }
                ));
                lines.push(format!("deploy: {}", firewall_line(&r.node)));
                lines.push(format!(
                    "deploy: validator {}",
                    if r.status.validator == "active" {
                        "left running"
                    } else {
                        "started, after a snapshot if the ledger is empty"
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

/// Runs `erpc r --chain solana destroy`.
pub fn destroy(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    let result = (|| {
        let r = reach(args, &say)?;
        say.line(&format!(
            "plan       {} on {}: stop the validator and Old Faithful, remove their units and the firewall{}; \
             the identity, the builds and the 1Password item stay",
            r.node.name,
            args.network,
            if args.purge_data {
                ", AND DELETE THE LEDGER, ACCOUNTS AND SNAPSHOTS"
            } else {
                "; the ledger stays"
            }
        ));
        go_ahead(args.yes, "nothing was changed")?;
        let mut extra = Map::new();
        extra.insert("erpc_purge_data".to_owned(), json!(args.purge_data));
        let run = run_play(
            &r.session,
            &r.target,
            &vars(&r, &r.node, extra),
            plays::MAINNET_RPC_DESTROY,
            &[],
            "Run destroy again to see how it ended",
            &say,
        )?;
        let node = record(
            &r.opened.store,
            r.node.clone(),
            &run,
            if args.purge_data {
                "destroyed (data deleted)"
            } else {
                "destroyed"
            },
            &say,
        );
        Ok::<_, CliError>((node, run))
    })();
    match result {
        Err(e) => Outcome::from(e),
        Ok((node, run)) => done(
            format!(
                "{} no longer runs Solana RPC. Its 1Password item stays; `erpc r --chain solana deploy` sets it up again.",
                node.name
            ),
            json_out,
            &json!({ "status": "ok", "name": node.name, "run": run, "purged": args.purge_data }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::SolanaRpc;

    use super::{Args, with_lists};

    #[test]
    fn update_config_changes_only_the_lists_it_is_given() {
        let node = SolanaRpc {
            rpc_allow: vec!["198.51.100.0/24".to_owned()],
            monitoring_allow: vec!["192.0.2.50".to_owned()],
            ..SolanaRpc::default()
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
}
