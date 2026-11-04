// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! `erpc v deploy` and `erpc v status`: a host `erpc v init` set up gets
//! the base system, the pinned client and its service (`solv`, or
//! `firedancer` for the full Firedancer), sync-only, from the network's
//! carried deploy play run on the node; and its state is read back.
//!
//! Before anything runs, the host's Jito endpoints are compared with the
//! region table and the pin with the floor. The run itself carries on on
//! the node if the connection drops; erpc follows it again.

use std::fmt::Write as _;
use std::path::PathBuf;

use erpc_chain::inventory::{Host, Inventory, Role, Validator};
use erpc_chain_solana::{plays, regions, versions};
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use serde_json::json;

use crate::commands::Outcome;
use crate::node_common::{
    FreeDisk, Say, agent_socket, check_ubuntu, confirm, free_disks, public_key_line,
};
use crate::validator_init::{bundle, inventory_json, open_vault};

/// The RPC port the startup script binds to 127.0.0.1.
const RPC_PORT: u16 = 7211;

/// What `erpc v deploy` and `erpc v status` were asked about.
#[derive(Debug, Clone)]
pub struct Args {
    /// The network.
    pub network: String,
    /// The validator.
    pub name: String,
    /// One of its hosts, by inventory name; needed when it has more than one.
    pub host: Option<String>,
    /// The `.pub` file of the key that logs in as `solv`.
    pub ssh_key: Option<PathBuf>,
    /// The SSH agent holding it.
    pub ssh_agent: Option<PathBuf>,
    /// Do not ask before running.
    pub yes: bool,
}

/// The host to act on: the one named, or the validator's only one.
fn pick<'a>(
    inventory: &'a Inventory,
    name: &str,
    host: Option<&str>,
) -> Result<(&'a Validator, &'a Host), String> {
    let validator = inventory
        .validators
        .iter()
        .find(|v| v.name == name)
        .ok_or_else(|| format!("there is no validator {name}; `erpc v list` shows them"))?;
    let hosts = inventory.hosts_of(name);
    let found = match host {
        Some(h) => hosts.iter().find(|x| x.name == h).copied().ok_or_else(|| {
            format!(
                "{name} has no host {h}; it has {}",
                hosts
                    .iter()
                    .map(|x| x.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?,
        None => match hosts.as_slice() {
            [only] => *only,
            [] => return Err(format!("{name} has no host yet; run `erpc v init` first")),
            _ => {
                return Err(format!(
                    "{name} has {} hosts: pass --host {}",
                    hosts.len(),
                    hosts
                        .iter()
                        .map(|x| x.name.as_str())
                        .collect::<Vec<_>>()
                        .join(" or --host ")
                ));
            }
        },
    };
    if found.ssh_user != "solv" {
        return Err(format!(
            "{} has no solv user yet: run `erpc v init -n <network> --name {name}` again to finish it",
            found.name
        ));
    }
    Ok((validator, found))
}

/// The target that logs in to `host` as `solv`, with its pinned key.
fn target(host: &Host, args: &Args) -> Result<Target, String> {
    let ssh_key = args
        .ssh_key
        .clone()
        .ok_or("pass --ssh-key <path to the .pub of the key that logs in>")?;
    Ok(Target {
        host: host.address.clone(),
        port: host.ssh_port,
        user: host.ssh_user.clone(),
        host_key: HostKey::parse(&host.host_key).map_err(|e| e.to_string())?,
        identity: Identity::Agent {
            socket: agent_socket(args.ssh_agent.as_deref())?,
            public_key: ssh_key,
        },
    })
}

/// The validator's state on the node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Status {
    service: String,
    identity_link: String,
    identity: String,
    health: String,
    slot: String,
    /// What the running validator was started with: `--vote-account <key>`
    /// or `--no-voting`.
    running_vote: String,
}

impl Status {
    fn parse(text: &str) -> Self {
        let mut s = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().to_owned();
            match key {
                "service" => s.service = value,
                "identity_link" => s.identity_link = value,
                "identity" => s.identity = value,
                "health" => s.health = rpc_result(&value),
                "slot" => s.slot = rpc_result(&value),
                "running_vote" => s.running_vote = value,
                _ => {}
            }
        }
        s
    }
}

/// The `result` of a JSON-RPC answer, or its error's message, or what came
/// back when it is neither.
fn rpc_result(text: &str) -> String {
    if text.is_empty() {
        return "no answer".to_owned();
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return text.chars().take(120).collect();
    };
    if let Some(r) = v.get("result") {
        return r.as_str().map_or_else(|| r.to_string(), str::to_owned);
    }
    v["error"]["message"]
        .as_str()
        .map_or_else(|| text.chars().take(120).collect(), str::to_owned)
}

fn read_status(session: &Session, validator: &Validator) -> Result<Status, String> {
    let command = RemoteCommand::ValidatorStatus {
        rpc_port: RPC_PORT,
        firedancer: validator.client == "firedancer",
    };
    let out = session.run(&command, None).map_err(|e| e.to_string())?;
    Ok(Status::parse(&String::from_utf8_lossy(&out.stdout)))
}

/// Where a status falls short of a sync-only validator with this identity
/// unstaked: the service runs, and the node's identity is the unstaked key,
/// not the validator's.
fn problems(status: &Status, validator: &Validator) -> Vec<String> {
    let mut out = Vec::new();
    if status.service != "active" {
        out.push(format!(
            "the {} service is {:?}, not active",
            unit(validator),
            status.service
        ));
    }
    if !status.identity_link.ends_with("/unstaked-identity.json") {
        out.push(format!(
            "identity.json leads to {:?}, not the unstaked key",
            status.identity_link
        ));
    }
    if status.identity.is_empty() || status.identity == validator.identity_account {
        out.push(format!(
            "the node runs as {:?}, which is not an unstaked identity",
            status.identity
        ));
    }
    out
}

/// The systemd unit that runs the validator.
fn unit(validator: &Validator) -> &'static str {
    if validator.client == "firedancer" {
        "firedancer"
    } else {
        "solv"
    }
}

/// Runs `erpc v status`.
pub fn status(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: true };
    let result = (|| {
        let (_, _, _, inventory) = open_vault(&args.network, None, &say)?;
        let (validator, host) = pick(&inventory, &args.name, args.host.as_deref())?;
        let session = Session::open(&target(host, args)?).map_err(|e| e.to_string())?;
        let status = read_status(&session, validator)?;
        Ok::<_, String>((validator.clone(), host.clone(), status))
    })();
    let (validator, host, status) = match result {
        Ok(found) => found,
        Err(e) => return Outcome::Failed(e),
    };
    let problems = problems(&status, &validator);
    if json_out {
        crate::print_json(&json!({
            "validator": validator.name,
            "host": host.name,
            "service": status.service,
            "identity": status.identity,
            "unstaked": status.identity_link.ends_with("/unstaked-identity.json"),
            "health": status.health,
            "slot": status.slot,
            "started_with": status.running_vote.trim(),
            "problems": problems,
        }));
        return Outcome::Done(String::new());
    }
    let mut text = format!(
        "{} ({})  service {}  health {}  slot {}\n  started  {}\n  identity {} ({})",
        host.name,
        validator.name,
        status.service,
        status.health,
        status.slot,
        if status.running_vote.trim().is_empty() {
            "-"
        } else {
            status.running_vote.trim()
        },
        status.identity,
        if status.identity_link.ends_with("/unstaked-identity.json") {
            "unstaked"
        } else {
            "not the unstaked key"
        }
    );
    for p in &problems {
        let _ = write!(text, "\n  ! {p}");
    }
    Outcome::Done(text)
}

/// Runs `erpc v deploy`.
pub fn deploy(args: &Args, json_out: bool) -> Outcome {
    let say = Say { quiet: json_out };
    match run(args, &say) {
        Ok((host, run, status)) => {
            if json_out {
                crate::print_json(&json!({
                    "status": "ok",
                    "host": host.name,
                    "run": run,
                    "service": status.service,
                    "identity": status.identity,
                    "health": status.health,
                    "slot": status.slot,
                }));
                return Outcome::Done(String::new());
            }
            Outcome::Done(format!(
                "{} runs sync-only as {} (unstaked); RPC health {}.\n\
                 It downloads a snapshot and catches up next. Check with:\n  \
                 erpc v status -n {} --name {}",
                host.name, status.identity, status.health, args.network, args.name
            ))
        }
        Err(e) => Outcome::Failed(e),
    }
}

/// Where `mount_disks.yml` mounts the free disks, largest first.
pub(crate) const MOUNT_TARGETS: [&str; 4] =
    ["/mnt/ledger", "/mnt/accounts", "/mnt/snapshot", "/mnt"];

/// What the deploy does with each free disk, for the operator to agree to.
pub(crate) fn disk_plan(disks: &[FreeDisk]) -> Vec<String> {
    if disks.is_empty() {
        return vec![
            "no free disk: the ledger, accounts and snapshots stay on the root disk".to_owned(),
        ];
    }
    let mut out: Vec<String> = disks
        .iter()
        .zip(MOUNT_TARGETS)
        .map(|(d, path)| {
            #[allow(clippy::cast_precision_loss)]
            let tb = d.bytes as f64 / 1e12;
            let wipe = if d.wipe {
                format!(", after removing its empty partitions ({})", d.partitions)
            } else {
                String::new()
            };
            format!("/dev/{} ({tb:.1} TB) is formatted as {path}{wipe}", d.name)
        })
        .collect();
    out.push(
        "a validator that runs already stops while its data moves onto the new disk, and starts again at the end"
            .to_owned(),
    );
    out
}

/// The host with its Jito endpoints as the region table has them now,
/// asking before it changes the item.
fn refresh_jito(
    store: &erpc_chain::inventory::Store<erpc_auth::store::one_password::OpCli>,
    network: &str,
    host: Host,
    yes: bool,
    say: &Say,
) -> Result<Host, String> {
    let stale = regions::stale(network, &host.jito);
    if stale.is_empty() {
        return Ok(host);
    }
    say.line(&format!(
        "jito       {}'s {} endpoints differ from the region table ({}):",
        host.name,
        host.jito.region,
        regions::table().read
    ));
    for change in &stale {
        say.line(&format!("           {change}"));
    }
    let refreshed = regions::jito_for(
        network,
        &host.jito.region,
        host.jito.latency_ms.parse().ok(),
        &host.jito.measured_at,
    )
    .ok_or("the host's region is no longer in the table; run `erpc v init` for a new host")?;
    let agreed = yes || (crate::session::has_terminal() && confirm("Use the table's endpoints?")?);
    if !agreed {
        return Err("nothing was run: the host's Jito endpoints are out of date".to_owned());
    }
    store
        .update_host(&Host {
            jito: refreshed,
            ..host
        })
        .map_err(|e| e.to_string())
}

/// The deploy's bundle: the pin, and the free disks the operator agreed to.
fn deploy_bundle(
    network: &str,
    validator: &Validator,
    host: &Host,
    authorized: &str,
    disks: &[FreeDisk],
    voting: bool,
) -> Result<erpc_ops::bundle::Built, String> {
    let pinned = versions::versions_yml(
        network,
        &validator.client,
        &validator.version,
        &validator.commit,
    )
    .map_err(|e| e.to_string())?;
    let mut extra = serde_json::Map::new();
    extra.insert(
        "erpc_disks".to_owned(),
        serde_json::Value::Array(
            disks
                .iter()
                .take(MOUNT_TARGETS.len())
                .map(|d| json!({ "name": d.name, "wipe": d.wipe }))
                .collect(),
        ),
    );
    bundle(
        &inventory_json(validator, host, authorized, voting, extra),
        &[("vars/versions.yml", pinned)],
    )
}

/// Whether the startup script names the vote account: only when it is on
/// chain, votes for this identity, is withdrawn by the authority, and has its
/// BLS key (without one, Alpenglow counts it as unstaked). A validator with
/// no vote account stays sync-only.
fn voting_ready(network: &str, validator: &Validator, say: &Say) -> Result<bool, String> {
    if validator.vote_account.is_empty() {
        return Ok(false);
    }
    let again = format!("erpc v vote-account -n {network} --name {}", validator.name);
    // erpc checks vote accounts through its own cluster RPC, which it has
    // for testnet only: elsewhere the node stays sync-only.
    let Some(url) = erpc_chain_solana::cli::rpc_url(network) else {
        say.line(&format!(
            "vote       sync-only: erpc does not check vote accounts on {network} yet"
        ));
        return Ok(false);
    };
    let cli = erpc_chain_solana::cli::SolanaCli::find().map_err(|e| e.to_string())?;
    let dir = crate::session::state_dir()?;
    let account = erpc_chain_solana::vote::read(&cli, url, &validator.vote_account, &dir)
        .map_err(|e| e.to_string())?;
    let decision = voting_decision(account.as_ref(), validator)?;
    match (&decision, account) {
        (Ok(()), Some(account)) => say.line(&format!(
            "vote       {} on chain, for {}, BLS key registered",
            validator.vote_account, account.identity
        )),
        (Err(why), _) => say.line(&format!(
            "vote       sync-only: {why}; `{again}` makes it ready"
        )),
        (Ok(()), None) => {}
    }
    Ok(decision.is_ok())
}

/// Whether the validator votes, given its vote account as the chain has it:
/// only when the account exists, is this validator's, and has its BLS key.
/// A missing account or key leaves the node sync-only (the reason inside);
/// an account that belongs to someone else stops the deploy.
fn voting_decision(
    account: Option<&erpc_chain_solana::vote::VoteAccount>,
    validator: &Validator,
) -> Result<Result<(), String>, String> {
    let Some(account) = account else {
        return Ok(Err(format!(
            "the vote account {} is not on chain yet",
            validator.vote_account
        )));
    };
    if let Some(why) = account.mismatch(&validator.identity_account, &validator.authority_account) {
        return Err(format!(
            "the vote account {} is not this validator's: {why}. Nothing was run",
            validator.vote_account
        ));
    }
    if account.bls.is_none() {
        return Ok(Err(format!(
            "the vote account {} has no BLS key, so it would count as unstaked",
            validator.vote_account
        )));
    }
    Ok(Ok(()))
}

/// A node that runs unstaked on an older startup script is restarted onto
/// the new one: deploy's `systemctl start` leaves a running service as it
/// is. A node that runs the staked identity is never restarted here, since a
/// restart would drop it back to the unstaked key.
fn restart_if_stale(
    target: &Target,
    validator: &Validator,
    voting: bool,
    status: Status,
    say: &Say,
) -> Result<Status, String> {
    let wanted = if voting {
        format!("--vote-account {}", validator.vote_account)
    } else {
        "--no-voting".to_owned()
    };
    if status.running_vote.trim().is_empty() || status.running_vote.contains(&wanted) {
        return Ok(status);
    }
    if status.identity == validator.identity_account
        || !status.identity_link.ends_with("/unstaked-identity.json")
    {
        say.line(&format!(
            "warning    the validator still runs with {}; it runs the staked identity, so it is not restarted",
            status.running_vote.trim()
        ));
        return Ok(status);
    }
    say.line(&format!(
        "restart    the validator runs with {}; restarting it onto the new startup script ({wanted})",
        status.running_vote.trim()
    ));
    let session = Session::open(target).map_err(|e| e.to_string())?;
    session
        .run(&RemoteCommand::RestartSolv, None)
        .map_err(|e| format!("could not restart solv: {e}"))?;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let now = read_status(&session, validator)?;
        if now.service == "active" && now.running_vote.contains(&wanted) {
            return Ok(now);
        }
    }
    Err("solv did not come back on the new startup script within a minute".to_owned())
}

/// The play that deploys a validator on `network`.
fn deploy_play(network: &str) -> Result<&'static str, String> {
    match network {
        "testnet" => Ok(plays::TESTNET_VALIDATOR_DEPLOY),
        "mainnet" => Ok(plays::MAINNET_VALIDATOR_DEPLOY),
        other => Err(format!(
            "erpc deploys validators on testnet and mainnet, not {other}"
        )),
    }
}

/// The deploy's plan, for the operator to agree to.
fn show_plan(host: &Host, validator: &Validator, voting: bool, say: &Say) {
    say.line(&format!(
        "plan       {} {} of {}: {} {} @ {}, Jito {}, {}",
        host.role.map_or("host", Role::as_str),
        host.name,
        validator.name,
        validator.client,
        validator.version,
        &validator.commit[..12],
        host.jito.region,
        if voting {
            format!(
                "vote account {}, started with the unstaked identity (it votes once the identity is put on it)",
                validator.vote_account
            )
        } else {
            "sync-only with an unstaked identity".to_owned()
        }
    ));
}

fn run(args: &Args, say: &Say) -> Result<(Host, String, Status), String> {
    let (_, _, store, inventory) = open_vault(&args.network, None, say)?;
    let (validator, host) = pick(&inventory, &args.name, args.host.as_deref())?;
    let (validator, host) = (validator.clone(), host.clone());

    // The pin and the region, before anything runs.
    versions::check_client_floor(&args.network, &validator.client, &validator.version)
        .map_err(|e| e.to_string())?;
    versions::check_commit(&validator.commit).map_err(|e| e.to_string())?;
    let host = refresh_jito(&store, &args.network, host, args.yes, say)?;
    let voting = voting_ready(&args.network, &validator, say)?;

    let authorized = public_key_line(
        args.ssh_key
            .as_deref()
            .ok_or("pass --ssh-key <path to the .pub of the key that logs in>")?,
    )?;
    let target = target(&host, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let os = check_ubuntu(&session)?;
    say.line(&format!("server     {} as solv: {os}", host.name));
    show_plan(&host, &validator, voting, say);
    say.line(&format!(
        "           the base system, the client built from source, and the {} service",
        unit(&validator)
    ));
    let disks = free_disks(&session)?;
    for line in disk_plan(&disks) {
        say.line(&format!("disks      {line}"));
    }
    if !args.yes {
        if !crate::session::has_terminal() {
            return Err("nothing was run: pass --yes to go ahead without a terminal".to_owned());
        }
        if !confirm("Deploy?")? {
            return Err("nothing was run".to_owned());
        }
    }

    let built = deploy_bundle(
        &args.network,
        &validator,
        &host,
        &authorized,
        &disks,
        voting,
    )?;
    say.line("deploy     starting on the node (the build takes a while)…");
    let play = deploy_play(&args.network)?;
    let run = erpc_ops::run::start(&session, &built, play).map_err(|e| e.to_string())?;
    say.line(&format!("           run {}", run.as_str()));
    drop(session);
    let result =
        crate::node_common::follow(&target, &run, "Run deploy again to see how it ended", say)?;

    // The run is recorded in the host item last, and a failure to record it
    // does not undo what ran: 1Password may ask again after a long build.
    let record = |host: Host, outcome: &str| {
        let name = host.name.clone();
        store
            .update_host(&Host {
                last_run: run.as_str().to_owned(),
                last_result: outcome.to_owned(),
                ..host
            })
            .unwrap_or_else(|e| {
                say.line(&format!(
                    "warning    the run is not recorded in {name}'s 1Password item: {e}"
                ));
                Host {
                    last_run: run.as_str().to_owned(),
                    last_result: outcome.to_owned(),
                    ..Host::default()
                }
            })
    };
    if !result.ok() {
        let name = host.name.clone();
        record(host, "deploy failed");
        return Err(format!(
            "the deploy failed on {name} (run {}, exit {}): {}. Fix it and run deploy again; \
             what is done is not redone",
            run.as_str(),
            result.exit_code,
            result.message
        ));
    }

    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let status = read_status(&session, &validator)?;
    drop(session);
    let status = restart_if_stale(&target, &validator, voting, status, say)?;
    let problems = problems(&status, &validator);
    if !problems.is_empty() {
        let name = host.name.clone();
        record(host, "deploy ran; checks failed");
        return Err(format!(
            "the deploy ran, but {name}: {}",
            problems.join("; ")
        ));
    }
    let name = host.name.clone();
    let mut recorded = record(host, "deploy ok");
    recorded.name = name;
    Ok((recorded, run.as_str().to_owned(), status))
}

#[cfg(test)]
mod tests {
    use erpc_chain::inventory::{Host, Inventory, Validator};

    use super::{Status, disk_plan, pick, problems, rpc_result, voting_decision};
    use crate::node_common::parse_free_disks;

    fn inventory(hosts: &[(&str, &str)]) -> Inventory {
        Inventory {
            validators: vec![Validator {
                name: "tv1".to_owned(),
                identity_account: "Staked111".to_owned(),
                ..Validator::default()
            }],
            hosts: hosts
                .iter()
                .map(|(name, user)| Host {
                    name: (*name).to_owned(),
                    validator: "tv1".to_owned(),
                    ssh_user: (*user).to_owned(),
                    ..Host::default()
                })
                .collect(),
        }
    }

    #[test]
    fn the_only_host_is_picked_and_two_need_a_name() {
        let one = inventory(&[("tv1-1", "solv")]);
        assert_eq!(pick(&one, "tv1", None).expect("one").1.name, "tv1-1");
        let two = inventory(&[("tv1-1", "solv"), ("tv1-2", "solv")]);
        assert!(pick(&two, "tv1", None).is_err());
        assert_eq!(
            pick(&two, "tv1", Some("tv1-2")).expect("named").1.name,
            "tv1-2"
        );
        assert!(pick(&two, "tv2", None).is_err());
    }

    #[test]
    fn free_disks_are_read_largest_first_and_only_empty_partitions_are_wiped() {
        let text = "skip nvme0n1 mounted\n\
                    free nvme2n1 960197124096 clean\n\
                    free nvme1n1 1920383410176 empty-partitions nvme1n1p1\n\
                    skip nvme3n1 nvme3n1p1 holds ext4\n";
        let disks = parse_free_disks(text);
        assert_eq!(
            disks
                .iter()
                .map(|d| (d.name.as_str(), d.wipe))
                .collect::<Vec<_>>(),
            [("nvme1n1", true), ("nvme2n1", false)]
        );
        let plan = disk_plan(&disks);
        assert!(
            plan[0].contains("/dev/nvme1n1")
                && plan[0].contains("/mnt/ledger")
                && plan[0].contains("nvme1n1p1")
        );
        assert!(
            plan[1].contains("/dev/nvme2n1")
                && plan[1].contains("/mnt/accounts")
                && !plan[1].contains("removing")
        );
        assert!(disk_plan(&[])[0].contains("root disk"));
    }

    #[test]
    fn a_host_without_solv_is_sent_back_to_init() {
        let pending = inventory(&[("tv1-1", "ubuntu")]);
        assert!(
            pick(&pending, "tv1", None)
                .unwrap_err()
                .contains("erpc v init")
        );
    }

    #[test]
    fn a_vote_account_not_ready_leaves_the_node_sync_only() {
        let validator = Validator {
            identity_account: "Staked111".to_owned(),
            authority_account: "Auth111".to_owned(),
            vote_account: "Vote111".to_owned(),
            ..Validator::default()
        };
        let account = |identity: &str, bls: Option<&str>| erpc_chain_solana::vote::VoteAccount {
            identity: identity.to_owned(),
            withdrawer: "Auth111".to_owned(),
            voter: identity.to_owned(),
            bls: bls.map(str::to_owned),
            commission: 0,
        };
        // A fresh init's vote key, not on chain: deploy goes on, sync-only
        // (tvj on 2026-10-24 stopped here before).
        assert!(matches!(voting_decision(None, &validator), Ok(Err(_))));
        assert!(matches!(
            voting_decision(Some(&account("Staked111", None)), &validator),
            Ok(Err(_))
        ));
        assert_eq!(
            voting_decision(Some(&account("Staked111", Some("bls"))), &validator),
            Ok(Ok(()))
        );
        // Someone else's account stops the deploy.
        assert!(voting_decision(Some(&account("Other111", Some("bls"))), &validator).is_err());
    }

    #[test]
    fn the_status_reads_and_a_staked_identity_is_a_problem() {
        let text = "service=active\nidentity_link=/home/solv/unstaked-identity.json\nidentity=Unstaked222\n\
                    health={\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":1}\n\
                    slot={\"jsonrpc\":\"2.0\",\"result\":4242,\"id\":1}\n";
        let status = Status::parse(text);
        assert_eq!(status.health, "ok");
        assert_eq!(status.slot, "4242");
        let validator = Validator {
            identity_account: "Staked111".to_owned(),
            ..Validator::default()
        };
        assert!(problems(&status, &validator).is_empty());
        let staked = Status {
            identity: "Staked111".to_owned(),
            identity_link: "/home/solv/testnet-validator-keypair.json".to_owned(),
            ..status
        };
        assert_eq!(problems(&staked, &validator).len(), 2);
        let stopped = Status {
            service: "failed".to_owned(),
            ..staked.clone()
        };
        let firedancer = Validator {
            client: "firedancer".to_owned(),
            ..validator.clone()
        };
        assert!(problems(&stopped, &firedancer)[0].starts_with("the firedancer service"));
        assert_eq!(rpc_result(""), "no answer");
        assert_eq!(
            rpc_result("{\"error\":{\"code\":-32005,\"message\":\"Node is behind\"}}"),
            "Node is behind"
        );
    }
}
