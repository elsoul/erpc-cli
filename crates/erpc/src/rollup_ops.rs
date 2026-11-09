// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Qualified follower lifecycle over scoped inventory, pinned SSH and confirmed policy.
use crate::{
    commands::Outcome,
    node_common::{self, Say},
    rollup_bundle as bundle,
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, rollup::RollupRpc};
use erpc_chain_op::{
    access,
    release::{self, Architecture},
    snapshot::{self, Prepared},
};
use erpc_chain_rollup::profile::{self, Family, Profile};
use erpc_secret::OpRef;
use erpc_ssh::rollup::Command as NodeCommand;
use erpc_ssh::{HostKey, Identity, RemoteCommand, RunId, Session, Target};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

fn one<'a>(args: &'a ArgMatches, key: &str) -> Option<&'a str> {
    args.try_get_one::<String>(key)
        .ok()
        .flatten()
        .map(String::as_str)
}
fn flag(args: &ArgMatches, key: &str) -> bool {
    args.try_get_one::<bool>(key)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
fn store(profile: Profile, args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        profile.network,
        one(args, "vault"),
        "initialize this follower with --vault <vault>",
    )?;
    Ok((
        node_common::store(
            &node_common::op_runner()?,
            &vault,
            profile.family.name(),
            profile.network,
        )?,
        vault,
    ))
}
fn find(store: &Store<OpCli>, args: &ArgMatches) -> Result<RollupRpc, String> {
    let name = one(args, "name").ok_or("follower operation requires --name")?;
    store
        .rollup_rpcs()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|node| node.name == name)
        .ok_or_else(|| "follower is not initialized in this chain/network scope".into())
}
fn settings(node: &mut RollupRpc, args: &ArgMatches) -> Result<(), String> {
    if let Some(ip) = one(args, "advertise-ip") {
        node.advertise_ip = ip.into();
    }
    node.advertise_ip = access::advertise(&node.advertise_ip)?;
    if let Some(reference) = one(args, "l1-upstreams") {
        node.upstream_ref = reference.into();
    }
    OpRef::parse(&node.upstream_ref).map_err(
        |_| "pass --l1-upstreams with an identifier-only secret reference and unique field label",
    )?;
    for (name, open, list) in [
        ("rpc-allow", true, &mut node.rpc_allow),
        ("management-allow", false, &mut node.management_allow),
        ("monitoring-allow", false, &mut node.monitoring_allow),
    ] {
        if let Some(values) = args.try_get_many::<String>(name).ok().flatten() {
            *list = values.cloned().collect();
        }
        *list = access::list(list, open)?;
    }
    Ok(())
}
fn target(node: &RollupRpc, args: &ArgMatches) -> Result<Target, String> {
    Ok(Target {
        host: node.address.clone(),
        port: node.ssh_port,
        user: node.ssh_user.clone(),
        host_key: HostKey::parse(&node.host_key).map_err(|e| e.to_string())?,
        identity: Identity::Agent {
            socket: node_common::agent_socket(
                args.try_get_one::<std::path::PathBuf>("ssh-agent")
                    .ok()
                    .flatten()
                    .map(std::path::PathBuf::as_path),
            )?,
            public_key: args
                .try_get_one::<std::path::PathBuf>("ssh-key")
                .ok()
                .flatten()
                .cloned()
                .ok_or("pass --ssh-key <operator public key file>")?,
        },
    })
}
fn facts(session: &Session) -> Result<(crate::eth_rpc::Facts, Architecture), String> {
    let facts = crate::eth_rpc::facts(session)?;
    if !["ubuntu 24.04", "ubuntu 26.04"].contains(&facts.os.as_str())
        || !facts.sudo
        || facts.mem_kb < 63_000_000
        || facts.cpus < 16
        || facts.root_free_kb < 20_000_000
    {
        return Err("follower hosts require Ubuntu 24.04/26.04, passwordless sudo, 64 GB RAM, 16 logical CPUs and 20 GB free system space".into());
    }
    let architecture =
        Architecture::parse(&facts.machine).ok_or("unsupported follower host architecture")?;
    if architecture == Architecture::Amd64 && facts.x86_64_v3 != 4 {
        return Err("AMD64 follower policy requires AVX2, BMI2, FMA and MOVBE".into());
    }
    Ok((facts, architecture))
}
fn preflight(session: &Session, node: &RollupRpc) -> Result<Value, String> {
    let body = bundle::contract(node)?.to_string();
    let out = session
        .run(
            &RemoteCommand::Rollup(NodeCommand::Preflight),
            Some(body.as_bytes()),
        )
        .map_err(|_| "follower remote ownership preflight refused")?;
    serde_json::from_slice(&out.stdout).map_err(|_| "invalid follower ownership response".into())
}
fn control_intent(
    session: &Session,
    node: &RollupRpc,
    action: &str,
    intent: Option<&str>,
) -> Result<Value, String> {
    let mut request = bundle::request(node, action)?;
    if let Some(intent) = intent {
        request["intent"] = json!(intent);
    }
    let body = request.to_string();
    let out = session
        .run(
            &RemoteCommand::Rollup(NodeCommand::Control),
            Some(body.as_bytes()),
        )
        .map_err(|_| "follower operation refused or failed; inspect its owned journal")?;
    serde_json::from_slice(&out.stdout).map_err(|_| "invalid follower control response".into())
}
fn control(session: &Session, node: &RollupRpc, action: &str) -> Result<Value, String> {
    control_intent(session, node, action, None)
}
fn follow(
    session: &Session,
    target: &Target,
    built: &erpc_ops::bundle::Built,
    play: &str,
    say: &Say,
) -> Result<RunId, String> {
    let run = erpc_ops::run::start(session, built, play).map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Resume the stored follower target with deploy; bootstrap uses start to resume",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "follower operation failed; data preserved (run {})",
            run.as_str()
        ));
    }
    Ok(run)
}
fn firewall(
    node: &RollupRpc,
    profile: Profile,
    facts: &crate::eth_rpc::Facts,
    session: &Session,
    target: &Target,
    say: &Say,
    intent: &str,
) -> Result<(RunId, String), String> {
    let built = bundle::build(node, profile, facts, None, None, Some(intent))?;
    let run = follow(session, target, &built, "ansible/op/firewall.yml", say)?;
    let token = erpc_ssh::firewall::FirewallToken::new(run.clone(), &built.sha256)?;
    let family = erpc_ssh::rollup::Family::parse(profile.family.name())
        .ok_or("invalid follower namespace")?;
    // A fresh connection proves the new SSH policy admits the caller. The
    // controller separately verifies run identity, live filter and deadline.
    let fresh = Session::open(target).map_err(|_| "fresh SSH firewall confirmation failed")?;
    fresh
        .run(
            &RemoteCommand::Rollup(NodeCommand::FirewallConfirm { family, token }),
            None,
        )
        .map_err(|_| "follower firewall confirmation expired, changed or failed")?;
    Ok((run, built.sha256))
}
fn provision_upstreams(
    session: &Session,
    node: &RollupRpc,
    receipt: (&RunId, &str),
    intent: &str,
) -> Result<(), String> {
    let reference =
        OpRef::parse(&node.upstream_ref).map_err(|_| "invalid concealed upstream reference")?;
    let credential = crate::rollup_credentials::read(&node_common::op_runner()?, &reference)?;
    let public = json!({"contract": bundle::contract(node)?, "action":"upstreams", "intent":intent, "firewall":{"run":receipt.0.as_str(),"bundle":receipt.1}}).to_string();
    let header = public
        .strip_suffix('}')
        .ok_or("cannot encode credential ownership")?;
    let secret = SecretString::from(format!(
        "{header},\"upstreams\":{}}}",
        credential.secret().expose_secret()
    ));
    session
        .run(
            &RemoteCommand::Rollup(NodeCommand::Control),
            Some(secret.expose_secret().as_bytes()),
        )
        .map_err(|_| "concealed upstream provisioning failed")?;
    Ok(())
}

async fn init(profile: Profile, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let (store, vault) = store(profile, args)?;
    let name = one(args, "name").ok_or("init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    let existing = store
        .rollup_rpcs()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|node| node.name == name);
    let mut node = if let Some(node) = existing {
        if one(args, "host").is_some_and(|v| v != node.address)
            || one(args, "type").is_some_and(|v| v != node.history)
            || one(args, "l1-upstreams").is_some_and(|v| v != node.upstream_ref)
            || one(args, "advertise-ip").is_some_and(|v| v != node.advertise_ip)
        {
            return Err(
                "init cannot retarget an existing follower; use update-config for mutable settings"
                    .into(),
            );
        }
        node
    } else {
        let address = one(args, "host").ok_or("new follower requires --host")?;
        let port = args.get_one::<u16>("port").copied().unwrap_or(22);
        let key = node_common::host_key(address, port, None, one(args, "fingerprint"), say)?;
        RollupRpc {
            name: name.into(),
            address: address.into(),
            ssh_user: one(args, "user").unwrap_or("ubuntu").into(),
            ssh_port: port,
            host_key: key.to_openssh(),
            family: profile.family.name().into(),
            network: profile.network.into(),
            history: one(args, "type").unwrap_or("full").into(),
            ..RollupRpc::default()
        }
    };
    let original = node.clone();
    settings(&mut node, args)?;
    if node.id.is_some() && original != node {
        return Err("init cannot change follower settings; use update-config".into());
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let before = preflight(&session, &node)?; // A failed other-network init cannot reserve authority.
    if node.id.is_some()
        && ["installed", "installing", "bootstrapping"]
            .contains(&before["phase"].as_str().unwrap_or_default())
    {
        return Ok(
            json!({"name":node.name,"family":node.family,"network":node.network,"phase":before["phase"],"unchanged":true}),
        );
    }
    let (facts, architecture) = facts(&session)?;
    if node.id.is_some() && bundle::architecture(&node)? != architecture {
        return Err("stored host architecture changed".into());
    }
    let prepared = if node.id.is_none() {
        snapshot::prepare(profile, node.history == "archive").await?
    } else {
        Prepared {
            pin: serde_json::from_value(node.bootstrap.clone())
                .map_err(|_| "invalid bootstrap pin")?,
            manifest: None,
        }
    };
    if node.id.is_none() {
        node.pair = serde_json::to_value(release::recommended(profile.family, architecture))
            .map_err(|_| "cannot encode reviewed pair")?;
        node.bootstrap =
            serde_json::to_value(&prepared.pin).map_err(|_| "cannot encode bootstrap pin")?;
    }
    node_common::go_ahead(flag(args, "yes"), "no follower host changed")
        .map_err(|e| e.to_string())?;
    if node.id.is_none() {
        node = store.add_rollup_rpc(&node).map_err(|e| e.to_string())?;
    }
    node_common::save_vault(profile.network, &vault)?;
    let built = bundle::build(&node, profile, &facts, None, None, None)?;
    let run = follow(&session, &target, &built, "ansible/op/init.yml", say)?;
    node.last_run = run.as_str().into();
    node.last_result = "init ok".into();
    store.update_rollup_rpc(&node).map_err(|e| e.to_string())?;
    Ok(
        json!({"name":node.name,"family":node.family,"network":node.network,"phase":if before["owned"] == true { before["phase"].clone() } else { json!("prepared") },"services_started_by_init":false}),
    )
}

fn no_downgrade(wanted: &Value, previous: &Value) -> Result<(), String> {
    fn version(value: &Value) -> Result<Vec<u16>, String> {
        let text = value.as_str().ok_or("stored client version missing")?;
        let numbers: Vec<u16> = text
            .split('.')
            .map(|p| {
                p.parse::<u16>()
                    .map_err(|_| "invalid client version".to_owned())
            })
            .collect::<Result<_, _>>()?;
        if numbers.len() != 3 {
            return Err("client version must have three numeric components".into());
        }
        Ok(numbers)
    }
    for role in ["execution", "consensus"] {
        if version(&wanted[role]["version"])? < version(&previous[role]["version"])? {
            return Err(
                "client/database downgrade refused before inventory or host changes".into(),
            );
        }
    }
    Ok(())
}

async fn desired(
    verb: &str,
    profile: Profile,
    args: &ArgMatches,
    node: &RollupRpc,
    before: &Value,
    architecture: Architecture,
) -> Result<(RollupRpc, Option<Prepared>), String> {
    let mut wanted = node.clone();
    if verb == "update-config" {
        settings(&mut wanted, args)?;
    }
    if verb == "update" {
        wanted.pair = serde_json::to_value(release::recommended(profile.family, architecture))
            .map_err(|_| "cannot encode reviewed pair")?;
    }
    let prepared: Option<Prepared> = if before["phase"] == "prepared"
        || (before["phase"] == "retired" && before["pair"].is_null())
    {
        Some(snapshot::prepare(profile, wanted.history == "archive").await?)
    } else if before["bootstrap_done"] != true {
        Some(
            snapshot::resume(
                profile,
                wanted.history == "archive",
                serde_json::from_value(wanted.bootstrap.clone())
                    .map_err(|_| "invalid bootstrap pin")?,
            )
            .await?,
        )
    } else {
        None
    };
    if let Some(prepared) = &prepared {
        wanted.bootstrap =
            serde_json::to_value(&prepared.pin).map_err(|_| "cannot encode bootstrap source")?;
    }
    no_downgrade(&wanted.pair, &node.pair)?;
    if !before["pair"].is_null() {
        no_downgrade(&wanted.pair, &before["pair"])?;
    }
    if verb == "update-config" && !before["pair"].is_null() && wanted.pair != before["pair"] {
        return Err("resume the desired client pair with deploy before changing settings".into());
    }
    Ok((wanted, prepared))
}

fn deployment_intent() -> Result<RunId, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "cannot create deployment intent")?;
    RunId::new(&format!("r-{:032x}", u128::from_be_bytes(bytes)))
        .map_err(|_| "cannot encode deployment intent".into())
}

async fn deploy(
    verb: &str,
    profile: Profile,
    args: &ArgMatches,
    node: &mut RollupRpc,
    store: &Store<OpCli>,
    say: &Say,
) -> Result<Value, String> {
    let target = target(node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    preflight(&session, node)?;
    let mut before = control(&session, node, "status")?;
    if flag(args, "reset-bootstrap") {
        if before["bootstrap_done"] == true {
            return Err("completed databases cannot be reset by bootstrap recovery".into());
        }
        node_common::go_ahead(
            flag(args, "yes"),
            "incomplete bootstrap data was not quarantined",
        )
        .map_err(|e| e.to_string())?;
        let recovery = control(&session, node, "reset-bootstrap")?;
        say.line(&format!(
            "Incomplete bootstrap data retained at {}",
            recovery["quarantine"]
        ));
        before = control(&session, node, "status")?;
    }
    if before["phase"] == "resetting" {
        return Err("resume interrupted recovery with deploy --reset-bootstrap".into());
    }
    if before["phase"] == "bootstrapping" {
        if verb != "deploy" {
            return Err("resume the current bootstrap with start/deploy before changing clients or settings".into());
        }
        node_common::go_ahead(flag(args, "yes"), "bootstrap was not resumed")
            .map_err(|e| e.to_string())?;
        return control(&session, node, "start");
    }
    if before["phase"] == "installing" && verb != "deploy" {
        return Err("resume the stored installation with deploy before another change".into());
    }
    let (facts, architecture) = facts(&session)?;
    if architecture != bundle::architecture(node)? {
        return Err("host architecture differs from its inventory".into());
    }
    let (mut wanted, prepared) = desired(verb, profile, args, node, &before, architecture).await?;
    bundle::vars(
        &wanted,
        profile,
        &facts,
        prepared.as_ref().is_some_and(|p| p.manifest.is_some()),
    )?;
    node_common::go_ahead(flag(args, "yes"), "no follower configuration changed")
        .map_err(|e| e.to_string())?;
    wanted.last_result = format!("{verb} pending; desired pair may not be installed yet");
    *node = store
        .update_rollup_rpc(&wanted)
        .map_err(|e| e.to_string())?;
    let intent = deployment_intent()?;
    control_intent(&session, node, "authorize-deploy", Some(intent.as_str()))?;
    let receipt = firewall(
        node,
        profile,
        &facts,
        &session,
        &target,
        say,
        intent.as_str(),
    )?;
    provision_upstreams(&session, node, (&receipt.0, &receipt.1), intent.as_str())?;
    let built = bundle::build(
        node,
        profile,
        &facts,
        prepared.as_ref(),
        Some((&receipt.0, &receipt.1)),
        Some(intent.as_str()),
    )?;
    let run = follow(&session, &target, &built, "ansible/op/deploy.yml", say)?;
    node.last_run = run.as_str().into();
    node.last_result = format!("{verb} submitted; inspect readiness");
    *node = store.update_rollup_rpc(node).map_err(|e| e.to_string())?;
    control(&session, node, "status")
}

async fn operation(
    verb: &str,
    profile: Profile,
    args: &ArgMatches,
    say: &Say,
    json_out: bool,
) -> Result<Value, String> {
    if verb == "init" {
        return init(profile, args, say).await;
    }
    let (store, _) = store(profile, args)?;
    if verb == "list" {
        return Ok(json!({"nodes": store.rollup_rpcs().map_err(|e| e.to_string())?}));
    }
    let mut node = find(&store, args)?;
    settings(&mut node, args)?; // Revalidate public records before any interpolation or secret read.
    if verb == "plan" {
        let change = one(args, "change").unwrap_or("deploy");
        let pair = if change == "update" {
            serde_json::to_value(release::recommended(
                profile.family,
                bundle::architecture(&node)?,
            ))
            .map_err(|_| "cannot encode reviewed pair")?
        } else {
            node.pair.clone()
        };
        return Ok(
            json!({"name":node.name,"family":node.family,"network":node.network,"change":change,"pair":pair,"history":node.history,
            "rpc_allow":node.rpc_allow,"monitoring_allow":node.monitoring_allow,"bootstrap":node.bootstrap,
            "provider_credentials":"concealed field; encrypted host credential","automatic_database_rollback":false,"destroy_preserves_data":true}),
        );
    }
    if ["deploy", "update", "update-config"].contains(&verb) {
        return deploy(verb, profile, args, &mut node, &store, say).await;
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    preflight(&session, &node)?;
    if verb == "status" {
        return control(&session, &node, "status");
    }
    if verb == "logs" {
        let family =
            erpc_ssh::rollup::Family::parse(&node.family).ok_or("invalid follower family")?;
        session.stream(&RemoteCommand::Rollup(NodeCommand::Logs { family, lines: args.get_one::<u32>("lines").copied().unwrap_or(100), follow: flag(args, "follow") }),
            &mut |stream, line| { if json_out { crate::print_json(&json!({"journal":line,"stream":match stream {erpc_ssh::Stream::Stdout=>"stdout",erpc_ssh::Stream::Stderr=>"stderr"}})); } else { say.line(line); } })
            .map_err(|_| "follower journal read failed")?;
        return Ok(json!({"logs":"complete"}));
    }
    if ["start", "stop", "restart", "destroy"].contains(&verb) {
        node_common::go_ahead(flag(args, "yes"), "no follower service changed")
            .map_err(|e| e.to_string())?;
        let result = control(&session, &node, verb)?;
        node.last_result = format!("{verb} ok; data retained");
        store.update_rollup_rpc(&node).map_err(|e| e.to_string())?;
        return Ok(result);
    }
    Err("unsupported follower operation".into())
}

pub(crate) fn report_status(
    result: Result<Value, String>,
    json_out: bool,
    output: &mut dyn FnMut(&str),
) -> Outcome {
    crate::node_report::status(result, "/readiness/ready", json_out, output)
}

pub(crate) async fn run(
    chain: erpc_core::chain::Chain,
    verb: &str,
    args: &ArgMatches,
    network: Option<&str>,
    json_out: bool,
) -> Outcome {
    let family = match chain {
        erpc_core::chain::Chain::Optimism => Family::Optimism,
        erpc_core::chain::Chain::Base => Family::Base,
        erpc_core::chain::Chain::Soneium => Family::Soneium,
        _ => return Outcome::Usage("unsupported follower family".into()),
    };
    let Some(profile) = network.and_then(|network| profile::get(family, network)) else {
        return Outcome::Usage("select an explicit supported follower network".into());
    };
    let say = Say { quiet: json_out };
    let result = operation(verb, profile, args, &say, json_out).await;
    if verb == "status" {
        return report_status(result, json_out, &mut crate::print_line);
    }
    match result {
        Ok(value) => {
            if json_out {
                crate::print_json(&value);
            } else {
                say.line(&serde_json::to_string_pretty(&value).unwrap_or_default());
            }
            Outcome::Done(String::new())
        }
        Err(error) => Outcome::Failed(error),
    }
}
