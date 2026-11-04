// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Avalanche lifecycle with pinned host/identity, in-memory custody and external staking.
use crate::{
    error::CliError,
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, avax::AvaxNode};
use erpc_chain_avax::{
    Network,
    registration::Registration,
    release::{self, Pin},
    status,
};
use erpc_core::chain::Role;
use erpc_ssh::{
    HostKey, Identity, RemoteCommand, Session, Target, arc::Action, avax::IdentityAction,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::path::PathBuf;

fn contract(node: &AvaxNode) -> Result<erpc_ssh::avax::Contract, String> {
    let network = Network::parse(&node.network).ok_or("invalid stored network")?;
    if !["full", "archive"].contains(&node.rpc_type.as_str()) {
        return Err("invalid stored history policy".into());
    }
    Ok(erpc_ssh::avax::Contract {
        mainnet: network == Network::Mainnet,
        validator: node.validator,
        archive: node.rpc_type == "archive",
    })
}
fn verify_contract(session: &Session, node: &AvaxNode, allow_missing: bool) -> Result<(), String> {
    session
        .run(
            &RemoteCommand::AvaxCheckContract {
                contract: contract(node)?,
                allow_missing,
            },
            None,
        )
        .map_err(|_| "remote network/role/history contract mismatch or missing".to_owned())?;
    Ok(())
}
fn mutator_preflight(
    node: &AvaxNode,
    verb: &str,
    verify: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if [
        "logs",
        "status",
        "plan",
        "prepare-registration",
        "validate-registration",
    ]
    .contains(&verb)
    {
        return Ok(());
    }
    if node.last_result.is_empty() {
        return Err("init did not finish; retry init before changing this host".into());
    }
    verify()
}
fn json_journal(line: &str, stream: erpc_ssh::Stream) -> Value {
    json!({"journal": line, "stream": match stream { erpc_ssh::Stream::Stdout => "stdout", erpc_ssh::Stream::Stderr => "stderr" }})
}
fn one(sub: &ArgMatches, id: &str) -> Option<String> {
    sub.try_get_one::<String>(id).ok().flatten().cloned()
}
fn flag(sub: &ArgMatches, id: &str) -> bool {
    sub.try_get_one::<bool>(id)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
fn target(node: &AvaxNode, sub: &ArgMatches) -> Result<Target, String> {
    Ok(Target {
        host: node.address.clone(),
        port: node.ssh_port,
        user: node.ssh_user.clone(),
        host_key: HostKey::parse(&node.host_key).map_err(|e| e.to_string())?,
        identity: Identity::Agent {
            socket: node_common::agent_socket(
                sub.try_get_one::<PathBuf>("ssh-agent")
                    .ok()
                    .flatten()
                    .map(PathBuf::as_path),
            )?,
            public_key: sub
                .try_get_one::<PathBuf>("ssh-key")
                .ok()
                .flatten()
                .cloned()
                .ok_or("pass --ssh-key <public key file>")?,
        },
    })
}
fn checked_output(session: &Session, cmd: &RemoteCommand) -> Result<Value, String> {
    let out = session.run(cmd, None).map_err(|e| e.to_string())?;
    serde_json::from_slice(&out.stdout).map_err(|_| "unreadable Avalanche node response".into())
}
fn pin(node: &AvaxNode) -> Pin {
    Pin {
        version: node.version.clone(),
        commit: node.commit.clone(),
        arch: node.arch.clone(),
        sha256: node.archive_sha256.clone(),
    }
}
fn set_pin(node: &mut AvaxNode, p: Pin) {
    node.version = p.version;
    node.commit = p.commit;
    node.arch = p.arch;
    node.archive_sha256 = p.sha256;
}
fn allow_lists(node: &mut AvaxNode, sub: &ArgMatches) -> Result<(), String> {
    for (name, public, list) in [
        ("rpc-allow", true, &mut node.rpc_allow),
        ("management-allow", false, &mut node.management_allow),
        ("monitoring-allow", false, &mut node.monitoring_allow),
    ] {
        if let Some(items) = sub.try_get_many::<String>(name).ok().flatten() {
            *list = crate::arc_rpc::allow_list(name, &items.cloned().collect::<Vec<_>>(), public)?;
        }
        // Revalidate values read from inventory, too.
        *list = crate::arc_rpc::allow_list(name, list, public)?;
    }
    Ok(())
}
fn facts(session: &Session) -> Result<crate::eth_rpc::Facts, String> {
    let f = crate::eth_rpc::facts(session)?;
    if !f.os.starts_with("ubuntu 24.") && !f.os.starts_with("ubuntu 26.") {
        return Err("Avalanche backend requires Ubuntu 24.04 or 26.04".into());
    }
    if !f.sudo || f.mem_kb < 15_000_000 || f.cpus < 8 {
        return Err("Avalanche requires passwordless sudo, 16 GB RAM and 8 logical CPUs".into());
    }
    Ok(f)
}
fn vars(
    node: &AvaxNode,
    f: &crate::eth_rpc::Facts,
    phase: &str,
    purge: bool,
) -> Result<Value, String> {
    release::validate(&pin(node))?;
    let mut v4 = node.management_allow.clone();
    let mut v6 = Vec::new();
    match f.controller_ip()? {
        std::net::IpAddr::V4(ip) => v4.push(ip.to_string()),
        std::net::IpAddr::V6(ip) => v6.push(ip.to_string()),
    }
    Ok(json!({"all":{"hosts":{node.name.clone():{
        "ansible_connection":"local","avax_network":node.network,"avax_type":node.rpc_type,"avax_validator":node.validator,
        "avax_version":node.version,"avax_commit":node.commit,"avax_sha256":node.archive_sha256,"avax_url":release::archive_url(&node.version,&node.arch)?,"avax_fingerprint":release::FINGERPRINT,
        "avax_rpc_allow":node.rpc_allow,"avax_monitoring_allow":node.monitoring_allow,"avax_fw_management_v4":v4,"avax_fw_management_v6":v6,"avax_ssh_port":node.ssh_port,
        "avax_new_identity":node.node_id.is_empty(),"avax_phase":phase,"avax_purge_data":purge
    }}}}))
}
fn play(
    session: &Session,
    target: &Target,
    node: &AvaxNode,
    f: &crate::eth_rpc::Facts,
    phase: &str,
    purge: bool,
    say: &Say,
) -> Result<String, String> {
    let mut bundle = erpc_ops::bundle::Bundle::new();
    for (path, bytes) in erpc_chain_avax::files() {
        bundle
            .add(path, bytes.to_vec())
            .map_err(|e| e.to_string())?;
    }
    bundle
        .add(
            "inventory.yml",
            vars(node, f, phase, purge)?.to_string().into_bytes(),
        )
        .map_err(|e| e.to_string())?;
    let built = bundle.finish().map_err(|e| e.to_string())?;
    let path = match phase {
        "init" => "ansible/avax/init.yml",
        "destroy" => "ansible/avax/destroy.yml",
        _ => "ansible/avax/deploy.yml",
    };
    let run = erpc_ops::run::start(session, &built, path).map_err(|e| e.to_string())?;
    let firewall_token = erpc_ssh::avax::FirewallToken::new(run.clone(), &built.sha256)?;
    let result = node_common::follow(
        target,
        &run,
        "Run the same command again to recover an interrupted operation",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "Avalanche {phase} failed (run {}); no database rollback was attempted",
            run.as_str()
        ));
    }
    if ["deploy", "config", "update"].contains(&phase) {
        Session::open(target)
            .map_err(|e| e.to_string())?
            .run(
                &RemoteCommand::AvaxFirewallConfirm {
                    token: firewall_token,
                    contract: contract(node)?,
                },
                None,
            )
            .map_err(|e| e.to_string())?;
    }
    Ok(run.as_str().into())
}
fn identity(session: &Session, node: &mut AvaxNode, s: &Value) -> Result<(), String> {
    let id = s["identity"]["result"]["nodeID"]
        .as_str()
        .ok_or("node did not report its identity")?;
    if !erpc_chain_avax::registration::node_id_valid(id) {
        return Err("invalid NodeID reported".into());
    }
    let hashes = checked_output(
        session,
        &RemoteCommand::AvaxIdentity {
            action: IdentityAction::Hashes,
            contract: contract(node)?,
        },
    )?;
    let pop = s["identity"]["result"]["nodePOP"].clone();
    if !node.node_id.is_empty()
        && (node.node_id != id || node.identity_hashes != hashes || node.node_pop != pop)
    {
        return Err("live staking identity differs from inventory; refused".into());
    }
    node.node_id = id.into();
    node.node_pop = pop;
    node.identity_hashes = hashes;
    Ok(())
}
#[derive(serde::Deserialize)]
struct BackupHeader {
    hashes: Value,
}

fn backup(session: &Session, store: &Store<OpCli>, node: &AvaxNode) -> Result<AvaxNode, String> {
    let out = session
        .run(
            &RemoteCommand::AvaxIdentity {
                action: IdentityAction::Backup,
                contract: contract(node)?,
            },
            None,
        )
        .map_err(|_| "could not export sealed identity")?;
    let secret =
        SecretString::from(String::from_utf8(out.stdout).map_err(|_| "invalid identity bundle")?);
    let header: BackupHeader = serde_json::from_str(secret.expose_secret())
        .map_err(|_| "invalid identity backup metadata")?;
    if header.hashes != node.identity_hashes {
        return Err("backup identity differs from pinned inventory".into());
    }
    // This payload never enters the run bundle, stdout to the user, logs or argv.
    store
        .backup_avax_identity(node, &secret)
        .map_err(|_| "could not save/verify identity backup in 1Password".into())
}
fn observation(node: &AvaxNode, net: Network, s: &Value) -> Value {
    json!({"name":node.name,"network":net.name(),"identity_matches":s["identity"]["result"]["nodeID"]==node.node_id,"ready":status::ready(s,net) && s["identity"]["result"]["nodeID"]==node.node_id,"validator_state":if node.validator{status::validator_state(s,&node.node_id,None,0)}else{"not a validator inventory role"},"reward_eligibility":"peer-measured uptime is observational; final reward is not guaranteed","observations":s})
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn run(
    role: Role,
    verb: &str,
    sub: &ArgMatches,
    network: Option<&str>,
    name: Option<&str>,
    json_out: bool,
) -> Result<Value, CliError> {
    let net = Network::parse(network.ok_or("pass --network mainnet or fuji")?)
        .ok_or("unsupported Avalanche network")?;
    let say = Say { quiet: json_out };
    let vault = node_common::vault_for(
        net.name(),
        one(sub, "vault").as_deref(),
        "erpc r --chain avax init --network fuji --vault <vault>",
    )?;
    let runner = node_common::op_runner()?;
    let store = node_common::store(&runner, &vault, "avax", net.name())?;
    let nodes = store.avax_nodes().map_err(|e| e.to_string())?;
    let validator = role == Role::Validator;
    if verb == "list" {
        return Ok(
            json!({"network":net.name(),"nodes":nodes.iter().filter(|n|n.validator==validator).map(|n|json!({"name":n.name,"type":n.rpc_type,"validator":n.validator,"version":n.version,"node_id":n.node_id,"last_result":n.last_result})).collect::<Vec<_>>()}),
        );
    }
    let name = name.ok_or("pass --name <inventory node>")?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    if verb == "init" {
        return init(&store, &nodes, &vault, net, name, validator, sub, &say).await;
    }
    let mut node = nodes
        .into_iter()
        .find(|n| n.name == name)
        .ok_or("node not found; run init first")?;
    if node.validator != validator {
        return Err("role mismatch: use the role recorded at init; RPC/node are aliases".into());
    }
    allow_lists(&mut node, sub)?;
    release::validate(&pin(&node))?;
    let target = target(&node, sub)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    mutator_preflight(&node, verb, || verify_contract(&session, &node, false))?;
    if verb == "logs" {
        let command = RemoteCommand::AvaxLogs {
            lines: sub.get_one::<u32>("lines").copied().unwrap_or(100),
            follow: flag(sub, "follow"),
        };
        session
            .stream(&command, &mut |stream, line| {
                if json_out {
                    crate::print_json(&json_journal(line, stream));
                } else {
                    println!("{line}");
                }
            })
            .map_err(|e| e.to_string())?;
        return Ok(json!({"status":"logs ended"}));
    }
    if verb == "identity-restore" {
        if node.node_id.is_empty() {
            return Err("no pinned identity to restore".into());
        }
        say.line("Restore the pinned identity on this host only; AvalancheGo must already be stopped. Existing different identity files will not be overwritten.");
        node_common::go_ahead(flag(sub, "yes"), "identity was not restored")?;
        let secret = store
            .avax_identity_backup(&node)
            .map_err(|_| "identity backup unavailable")?;
        let input = SecretString::from(format!(
            "{{\"expected_hashes\":{},\"bundle\":{}}}",
            node.identity_hashes,
            secret.expose_secret()
        ));
        session
            .run(
                &RemoteCommand::AvaxIdentity {
                    action: IdentityAction::Restore,
                    contract: contract(&node)?,
                },
                Some(input.expose_secret().as_bytes()),
            )
            .map_err(|_| "identity recovery refused; host must be stopped and backup must match")?;
        return Ok(
            json!({"status":"identity restored","service":"stopped","node_id":node.node_id}),
        );
    }
    let s = checked_output(&session, &RemoteCommand::AvaxStatus)?;
    if verb == "status" {
        let mut report = observation(&node, net, &s);
        if let Some(path) = sub.try_get_one::<PathBuf>("registration").ok().flatten() {
            let prepared = read_registration(path)?;
            if prepared.network != net
                || prepared.node_id != node.node_id
                || prepared.node_pop != node.node_pop
            {
                return Err("registration file does not match this node".into());
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "system clock invalid")?
                .as_secs();
            report["validator_state"] = json!(status::validator_state(
                &s,
                &node.node_id,
                Some(prepared.end),
                now
            ));
            report["intended_end"] = json!(prepared.end);
            report["seconds_to_intended_end"] = json!(prepared.end.saturating_sub(now));
        }
        return Ok(report);
    }
    if ["prepare-registration", "validate-registration"].contains(&verb) {
        return registration(&session, &mut node, net, &s, sub, verb);
    }
    if verb == "identity-backup" {
        identity(&session, &mut node, &s)?;
        node_common::go_ahead(flag(sub, "yes"), "identity not backed up")?;
        backup(&session, &store, &node)?;
        return Ok(json!({"status":"identity backed up and read back","node_id":node.node_id}));
    }
    if ["start", "stop", "restart"].contains(&verb) {
        say.line(&format!("{verb} AvalancheGo and its gateway on {} ({}); validator state: {}. Interrupting an active validator can reduce rewards.",node.name,net.name(),status::validator_state(&s,&node.node_id,None,0)));
        node_common::go_ahead(flag(sub, "yes"), "services unchanged")?;
        let action = match verb {
            "start" => Action::Start,
            "stop" => Action::Stop,
            _ => Action::Restart,
        };
        session
            .run(
                &RemoteCommand::AvaxService {
                    action,
                    contract: contract(&node)?,
                },
                None,
            )
            .map_err(|e| e.to_string())?;
        return Ok(
            json!({"status":"service command completed","action":verb,"registration_changed":false}),
        );
    }
    let f = facts(&session)?;
    let phase = if verb == "plan" {
        one(sub, "change").unwrap_or_else(|| "deploy".into())
    } else {
        verb.into()
    };
    if phase == "update" {
        let tag = one(sub, "version")
            .ok_or("update requires --version; upgrades never follow latest automatically")?;
        let candidate = release::resolve(&tag, &node.arch).await?;
        release::update_allowed(&pin(&node), &candidate)?;
        set_pin(&mut node, candidate);
    }
    if verb == "plan" {
        return Ok(
            json!({"change":phase,"node":node.name,"network":node.network,"release":pin(&node),"history":node.rpc_type,"rpc_allow":node.rpc_allow,"monitoring_allow":node.monitoring_allow,"identity":if node.node_id.is_empty(){"generate once on first deploy"}else{"verify and preserve"},"registration":"external; not submitted","current":s,"changed":false}),
        );
    }
    say.line(&format!(
        "{verb} {} on {} using {}; identity preserved, RPC allowed {:?}, metrics allowed {:?}{}",
        node.name,
        net.name(),
        node.version,
        node.rpc_allow,
        node.monitoring_allow,
        if flag(sub, "purge-data") {
            "; DELETE chain database and logs"
        } else {
            ""
        }
    ));
    if node.management_allow.is_empty() {
        say.line("SSH will be admitted only from the current controller; use a stable --management-allow range before its address changes.");
    }
    node_common::go_ahead(flag(sub, "yes"), "nothing changed")?;
    let phase = if verb == "update-config" {
        "config"
    } else {
        verb
    };
    let run = play(
        &session,
        &target,
        &node,
        &f,
        phase,
        flag(sub, "purge-data"),
        &say,
    )?;
    if verb != "destroy" {
        let s = checked_output(&session, &RemoteCommand::AvaxStatus)?;
        identity(&session, &mut node, &s)?;
    }
    node.last_run = run;
    node.last_result = if verb == "destroy" {
        "destroyed; identity preserved"
    } else {
        "service installed; bootstrap/validation observed separately"
    }
    .into();
    node = store.update_avax_node(&node).map_err(|e| e.to_string())?;
    if verb != "destroy" {
        node = backup(&session, &store, &node)?;
    }
    Ok(
        json!({"status":"ok","name":node.name,"node_id":node.node_id,"run":node.last_run,"result":node.last_result,"registration_submitted":false}),
    )
}

#[allow(clippy::too_many_arguments)]
async fn init(
    store: &Store<OpCli>,
    nodes: &[AvaxNode],
    vault: &str,
    net: Network,
    name: &str,
    validator: bool,
    sub: &ArgMatches,
    say: &Say,
) -> Result<Value, CliError> {
    let existing = nodes.iter().find(|n| n.name == name);
    let mut node = existing.cloned().unwrap_or_else(|| AvaxNode {
        name: name.into(),
        network: net.name().into(),
        validator,
        rpc_type: one(sub, "type").unwrap_or_else(|| "full".into()),
        address: one(sub, "host").unwrap_or_default(),
        ssh_user: one(sub, "user").unwrap_or_else(|| "ubuntu".into()),
        ssh_port: sub.get_one::<u16>("port").copied().unwrap_or(22),
        ..AvaxNode::default()
    });
    if node.validator != validator
        || one(sub, "host").is_some_and(|h| h != node.address)
        || one(sub, "type").is_some_and(|t| t != node.rpc_type)
    {
        return Err("init cannot change existing role, host or history policy".into());
    }
    if node.address.is_empty()
        || nodes
            .iter()
            .any(|n| n.name != name && n.address == node.address)
    {
        return Err("pass an unused --host for the new node".into());
    }
    erpc_ssh::config::check_host(&node.address).map_err(|e| e.to_string())?;
    let seen = node_common::host_key(
        &node.address,
        node.ssh_port,
        existing.map(|n| n.host_key.as_str()),
        one(sub, "fingerprint").as_deref(),
        say,
    )?;
    node.host_key = seen.to_openssh();
    let target = target(&node, sub)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    verify_contract(&session, &node, true)?;
    node_common::check_ubuntu(&session)?;
    let f = facts(&session)?;
    let arch = match f.machine.as_str() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => return Err("unsupported Avalanche CPU architecture".into()),
    };
    if existing.is_none() {
        set_pin(
            &mut node,
            release::resolve(
                one(sub, "version")
                    .as_deref()
                    .unwrap_or(release::RECOMMENDED),
                arch,
            )
            .await?,
        );
    } else if one(sub, "version").is_some_and(|v| v != node.version) {
        return Err("use update to change a stored release".into());
    }
    allow_lists(&mut node, sub)?;
    say.line("Avalanche init prepares an unprivileged service user and persistent directories. Mount local NVMe at /var/lib/avalanchego; no disk will be formatted. Deploy generates the identity once and backs it up to 1Password.");
    node_common::go_ahead(flag(sub, "yes"), "nothing changed")?;
    node = if existing.is_none() {
        store.add_avax_node(&node)
    } else {
        store.update_avax_node(&node)
    }
    .map_err(|e| e.to_string())?;
    node_common::save_vault(net.name(), vault)?;
    node.last_run = play(&session, &target, &node, &f, "init", false, say)?;
    node.last_result = "initialized".into();
    store.update_avax_node(&node).map_err(|e| e.to_string())?;
    Ok(
        json!({"status":"initialized","name":node.name,"network":node.network,"version":node.version,"next":"deploy","validator_registration":"not submitted"}),
    )
}
fn registration(
    session: &Session,
    node: &mut AvaxNode,
    net: Network,
    s: &Value,
    sub: &ArgMatches,
    verb: &str,
) -> Result<Value, CliError> {
    if node.node_id.is_empty() || !node.validator || !status::ready(s, net) {
        return Err("registration needs a fully bootstrapped healthy validator-intent node on the expected network".into());
    }
    identity(session, node, s)?;
    if status::validator_state(s, &node.node_id, None, 0) != "not active" {
        return Err(
            "node is active, or its current validator state is unknown; inspect externally submitted transactions separately".into(),
        );
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is invalid")?
        .as_secs();
    let registration = if verb == "prepare-registration" {
        Registration {
            network: net,
            node_id: node.node_id.clone(),
            node_pop: node.node_pop.clone(),
            stake_navax: *sub.get_one::<u64>("stake-navax").ok_or("stake required")?,
            prepared_at: now,
            end: *sub.get_one::<u64>("end").ok_or("end required")?,
            rewards_address: one(sub, "rewards-address").ok_or("rewards address required")?,
            delegation_fee_bps: sub
                .get_one::<u16>("delegation-fee-bps")
                .copied()
                .unwrap_or(200),
        }
    } else {
        let path = sub.get_one::<PathBuf>("file").ok_or("file required")?;
        read_registration(path)?
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is invalid")?
        .as_secs();
    registration.validate(net, &node.node_id, &node.node_pop, now)?;
    Ok(registration.review())
}

fn read_registration(path: &std::path::Path) -> Result<Registration, CliError> {
    if std::fs::metadata(path).map_err(|e| e.to_string())?.len() > 16384 {
        return Err("registration file too large".into());
    }
    let value: Value = serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|_| "invalid registration JSON")?;
    serde_json::from_value(value.get("registration").unwrap_or(&value).clone())
        .map_err(|_| "invalid registration fields".into())
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    #[test]
    fn failed_initialization_and_cross_scope_reject_all_mutators() {
        let failed = AvaxNode {
            network: "fuji".into(),
            rpc_type: "full".into(),
            ..AvaxNode::default()
        };
        for verb in [
            "deploy",
            "start",
            "stop",
            "restart",
            "update",
            "update-config",
            "destroy",
            "identity-backup",
            "identity-restore",
        ] {
            assert!(
                mutator_preflight(&failed, verb, || panic!("failed init must not dispatch"))
                    .is_err()
            );
            let initialized = AvaxNode {
                last_result: "initialized".into(),
                ..failed.clone()
            };
            assert!(
                mutator_preflight(&initialized, verb, || Err("remote is mainnet".into())).is_err()
            );
            assert!(mutator_preflight(&initialized, verb, || Ok(())).is_ok());
        }
    }
    #[test]
    fn json_logs_escape_arbitrary_journal_data_and_identify_stream() {
        let line = "quotes \" and newline\n control \u{1b}";
        let value = json_journal(line, erpc_ssh::Stream::Stderr);
        let encoded = serde_json::to_string(&value).unwrap();
        assert_eq!(encoded.lines().count(), 1);
        let parsed: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(parsed["journal"], line);
        assert_eq!(parsed["stream"], "stderr");
    }
}
