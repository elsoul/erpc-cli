// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Sui orchestration using the existing pinned SSH, remote runs and 1Password store.
use crate::{
    commands::Outcome,
    error::CliError,
    eth_rpc::{Facts, Login},
    node_common::{self, Say},
};
use erpc_chain::inventory::sui::SuiNode;
use erpc_chain_sui::validator::{self, Metadata};
use erpc_chain_sui::{
    network::{self, Network},
    status::Status,
};
use erpc_ops::bundle::Bundle;
use erpc_ssh::sui::{Command, Confirmation, Contract};
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use zeroize::Zeroizing;

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // Independent CLI switches, not persistent state.
pub(crate) struct Args {
    pub(crate) validator: bool,
    pub(crate) restore_keys: bool,
    pub(crate) validator_info: Option<std::path::PathBuf>,
    pub(crate) keys_unhosted: bool,
    pub(crate) key_references: [Option<String>; 3],
    pub(crate) registration_action: Option<String>,
    pub(crate) network: String,
    pub(crate) name: String,
    pub(crate) host: Option<String>,
    pub(crate) user: String,
    pub(crate) port: u16,
    pub(crate) fingerprint: Option<String>,
    pub(crate) vault: Option<String>,
    pub(crate) login: Login,
    pub(crate) yes: bool,
    pub(crate) rpc_allow: Option<Vec<String>>,
    pub(crate) management_allow: Option<Vec<String>>,
    pub(crate) monitoring_allow: Option<Vec<String>>,
    pub(crate) lines: u32,
    pub(crate) follow: bool,
    pub(crate) recover_bootstrap: bool,
}

fn target(node: &SuiNode, login: &Login) -> Result<Target, String> {
    Ok(Target {
        host: node.address.clone(),
        port: node.ssh_port,
        user: node.ssh_user.clone(),
        host_key: HostKey::parse(&node.host_key).map_err(|e| e.to_string())?,
        identity: Identity::Agent {
            socket: node_common::agent_socket(login.ssh_agent.as_deref())?,
            public_key: login
                .ssh_key
                .clone()
                .ok_or("pass --ssh-key with the login public key")?,
        },
    })
}
fn facts(session: &Session) -> Result<Facts, String> {
    let out = session
        .run(&RemoteCommand::Sui(Command::Facts), None)
        .map_err(|e| e.to_string())?;
    Ok(Facts::parse(&String::from_utf8_lossy(&out.stdout)))
}
fn preflight(f: &Facts, fresh: bool, validator: bool) -> Result<(), String> {
    if f.os != "ubuntu 24.04"
        || !f.sudo
        || f.mem_kb < 120_000_000
        || f.cpus < if validator { 48 } else { 16 }
    {
        return Err("Sui requires the reviewed Ubuntu 24.04 profile, passwordless sudo, 128 GB RAM and 16 logical CPUs (48 for validators)".to_owned());
    }
    if fresh && f.data_free_kb.unwrap_or(f.root_free_kb) < 3_500_000_000 {
        return Err("Sui needs a mounted 4 TB NVMe data volume at /var/lib/sui with at least 3.5 TB free; init never formats disks".to_owned());
    }
    f.controller_ip()?;
    Ok(())
}
fn allow_lists(node: &mut SuiNode, args: &Args) -> Result<(), String> {
    for (flag, field, name) in [
        (&args.rpc_allow, &mut node.rpc_allow, "--rpc-allow"),
        (
            &args.management_allow,
            &mut node.management_allow,
            "--management-allow",
        ),
        (
            &args.monitoring_allow,
            &mut node.monitoring_allow,
            "--monitoring-allow",
        ),
    ] {
        if let Some(values) = flag {
            *field = crate::arc_rpc::allow_list(name, values, false)?;
        }
    }
    Ok(())
}
fn pin(node: &mut SuiNode, net: Network) -> Result<(), String> {
    net.version.clone_into(&mut node.version);
    net.commit.clone_into(&mut node.commit);
    node.archive_sha256 = net.archive(&node.architecture)?.1.to_owned();
    Ok(())
}
fn vars(node: &SuiNode, net: Network, facts: &Facts, phase: &str) -> Result<Value, String> {
    net.validate_pin(
        &node.version,
        &node.commit,
        &node.archive_sha256,
        &node.architecture,
    )?;
    for (name, list) in [
        ("stored RPC ranges", &node.rpc_allow),
        ("stored management ranges", &node.management_allow),
        ("stored monitoring ranges", &node.monitoring_allow),
    ] {
        crate::arc_rpc::allow_list(name, list, false)?;
    }

    if node.role == "validator" {
        metadata(node)?;
        if !node.rpc_allow.is_empty() {
            return Err("validator RPC must remain private".to_owned());
        }
    } else if node.validator_metadata.is_some() {
        return Err("full nodes cannot carry validator metadata".to_owned());
    }
    let mut management = node.management_allow.clone();
    let mut v6 = Vec::new();
    match facts.controller_ip()? {
        std::net::IpAddr::V4(ip) => management.push(ip.to_string()),
        std::net::IpAddr::V6(ip) => v6.push(ip.to_string()),
    }
    management.sort();
    management.dedup();
    Ok(json!({"all":{"hosts":{node.name.clone():{
        "ansible_connection":"local", "sui_network":net.name,"sui_role":node.role,
        "sui_version":node.version,"sui_commit":node.commit,"sui_archive_sha256":node.archive_sha256,
        "sui_archive_url":net.archive(&node.architecture)?.0,
        "sui_genesis_url":net.genesis_url(),"sui_genesis_sha256":net.genesis_sha256,
        "sui_validator_metadata":node.validator_metadata,"sui_rpc_allow":node.rpc_allow,"sui_monitoring_allow":node.monitoring_allow,
        "sui_fw_management_v4":management,"sui_fw_management_v6":v6,"sui_ssh_port":node.ssh_port,"sui_phase":phase
    }}}}))
}
fn run_play(
    session: &Session,
    target: &Target,
    node: &SuiNode,
    net: Network,
    facts: &Facts,
    phase: &str,
    say: &Say,
) -> Result<String, String> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "could not make a unique Sui deployment intent")?;
    let confirmation = Confirmation::new(nonce);
    let mut bundle = Bundle::new();
    for file in erpc_chain_sui::files() {
        bundle
            .add(
                file,
                erpc_chain_sui::file(file)
                    .ok_or("missing template")?
                    .to_vec(),
            )
            .map_err(|e| e.to_string())?;
    }
    bundle
        .add(
            "inventory.yml",
            serde_json::to_vec(&{
                let mut inventory = vars(node, net, facts, phase)?;
                inventory["all"]["hosts"][&node.name]["sui_confirmation_id"] =
                    json!(confirmation.text());
                inventory
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let play = match phase {
        "init" => "init",
        "destroy" => "destroy",
        _ => "deploy",
    };
    let run = erpc_ops::run::start(
        session,
        &bundle.finish().map_err(|e| e.to_string())?,
        &format!("ansible/sui-node/{play}.yml"),
    )
    .map_err(|e| e.to_string())?;
    say.line(&format!("run        {}", run.as_str()));
    let result = node_common::follow(
        target,
        &run,
        "Inspect this run before retrying the operation",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "Sui {phase} failed (run {}, exit {}); data and identity were retained",
            run.as_str(),
            result.exit_code
        ));
    }
    if !["init", "destroy", "prepare-validator"].contains(&phase) {
        Session::open(target)
            .map_err(|e| e.to_string())?
            .run(
                &RemoteCommand::Sui(Command::ConfirmFirewall(contract(node, net)?, confirmation)),
                None,
            )
            .map_err(|e| {
                format!(
                    "firewall confirmation failed; deployment was rolled back or superseded: {e}"
                )
            })?;
        Session::open(target)
            .map_err(|e| e.to_string())?
            .run(
                &RemoteCommand::Sui(Command::StartConfirmed(contract(node, net)?, confirmation)),
                None,
            )
            .map_err(|e| e.to_string())?;
    }
    Ok(run.as_str().to_owned())
}
fn public(node: &SuiNode, net: Network) -> Value {
    json!({"name":node.name,"role":node.role,"network":net.name,"version":node.version,"commit":node.commit,"archive_sha256":node.archive_sha256,"genesis_sha256":net.genesis_sha256,"last_run":node.last_run,"last_result":node.last_result})
}

fn contract(node: &SuiNode, net: Network) -> Result<Contract, String> {
    Contract::new(
        net.name,
        if node.role == "validator" {
            "validator"
        } else {
            "fullnode"
        },
        net.genesis_sha256,
    )
}
fn metadata(node: &SuiNode) -> Result<Metadata, String> {
    let value = node
        .validator_metadata
        .as_ref()
        .ok_or("validator metadata is missing")?;
    Metadata::parse(&value.to_string())
}
fn initialize_validator(node: &mut SuiNode, stored: bool, args: &Args) -> Result<(), String> {
    let supplied = if let Some(path) = &args.validator_info {
        if std::fs::metadata(path)
            .map_err(|_| "could not read validator metadata")?
            .len()
            > 32768
        {
            return Err("validator metadata exceeds 32 KiB".to_owned());
        }
        Some(Metadata::parse(
            &std::fs::read_to_string(path).map_err(|_| "could not read validator metadata")?,
        )?)
    } else {
        None
    };
    if stored {
        let previous = metadata(node)?;
        if supplied.as_ref().is_some_and(|s| s != &previous)
            || args
                .key_references
                .iter()
                .zip(&node.key_references)
                .any(|(new, old)| new.as_ref().is_some_and(|v| v != old))
        {
            return Err(
                "validator keys and metadata are immutable; do not repurpose an existing signer"
                    .to_owned(),
            );
        }
        return Ok(());
    }
    if !args.keys_unhosted {
        return Err(
            "new validator imports require --keys-unhosted; live signer migration is refused"
                .to_owned(),
        );
    }
    let info = supplied
        .ok_or("new validators require --validator-info with public official metadata JSON")?;
    for (flag, stored) in args.key_references.iter().zip(&mut node.key_references) {
        let field = flag
            .as_deref()
            .ok_or("all three protocol/network/worker 1Password references are required")?;
        validator::reference(field)?;
        field.clone_into(stored);
    }
    node.validator_metadata =
        Some(serde_json::to_value(info).map_err(|_| "could not encode public metadata")?);
    Ok(())
}
fn import_validator(
    session: &Session,
    node: &SuiNode,
    net: Network,
    restore: bool,
) -> Result<(), String> {
    metadata(node)?;
    let expected = contract(node, net)?;
    if !restore
        && session
            .run(&RemoteCommand::Sui(Command::ValidatorCheck(expected)), None)
            .is_ok()
    {
        // Redeployment never needs to re-read healthy private material.
        return Ok(());
    }
    let runner = node_common::op_runner()?;
    let mut payload = Zeroizing::new(String::from("{"));
    for (index, (name, reference)) in ["protocol", "network", "worker"]
        .iter()
        .zip(&node.key_references)
        .enumerate()
    {
        let secret = validator::read_key(&runner, reference)?;
        let value = secret.expose_secret().trim();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return Err("1Password key field is not a base64 Sui key file".to_owned());
        }
        if index > 0 {
            payload.push(',');
        }
        payload.push('"');
        payload.push_str(name);
        payload.push_str("\":\"");
        payload.push_str(value);
        payload.push('"');
    }
    payload.push('}');
    session
        .run(
            &RemoteCommand::Sui(if restore {
                Command::ValidatorRestore(expected)
            } else {
                Command::ValidatorImport(expected)
            }),
            Some(payload.as_bytes()),
        )
        .map_err(
            |_| "validator key import failed; no owner key or on-chain transaction was used",
        )?;
    Ok(())
}
fn registration(
    session: &Session,
    node: &SuiNode,
    net: Network,
    action: &str,
) -> Result<Value, String> {
    let meta = metadata(node)?;
    let expected = contract(node, net)?;
    if action == "validate" {
        session
            .run(&RemoteCommand::Sui(Command::ValidatorCheck(expected)), None)
            .map_err(|_| "stored validator keys could not be verified")?;
    }
    let out = session
        .run(
            &RemoteCommand::Sui(Command::ValidatorStatus(expected)),
            None,
        )
        .map_err(|_| "validator network status is unavailable; admission is unknown")?;
    let observed: Value = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| serde_json::from_str(line).ok())
        .ok_or("unreadable validator observation")?;
    if observed["membership"] == "active" && observed["keys_match"] != true {
        return Err(
            "the active validator's public keys differ from this host's reserved metadata"
                .to_owned(),
        );
    }
    Ok(
        json!({"observation":observed,"key_binding_checked":action=="validate","official_detail_command":["sui","validator","--client.env",net.name,"display-metadata",meta.info.account_address,"--json","true"],"transaction_submission":"external official tooling only"}),
    )
}

#[allow(clippy::too_many_lines)]
fn execute(verb: &str, args: &Args, say: &Say) -> Result<Value, CliError> {
    let net = network::get(&args.network).ok_or("Sui supports mainnet and testnet")?;
    let vault = node_common::vault_for(
        &args.network,
        args.vault.as_deref(),
        if args.validator {
            "erpc v --chain sui init --vault <vault ID>"
        } else {
            "erpc r --chain sui init --vault <vault ID>"
        },
    )?;
    let store = node_common::store(&node_common::op_runner()?, &vault, "sui", &args.network)?;
    let role = if args.validator {
        "validator"
    } else {
        "fullnode"
    };
    let nodes = store.sui_nodes(role).map_err(|e| e.to_string())?;
    if verb == "list" {
        return Ok(json!({"nodes":nodes.iter().map(|n|public(n,net)).collect::<Vec<_>>()}));
    }
    erpc_chain::inventory::check_name(&args.name).map_err(|e| e.to_string())?;
    let existing = nodes.iter().find(|n| n.name == args.name);
    if verb == "init" {
        let mut node = if let Some(n) = existing {
            if args.host.as_ref().is_some_and(|h| h != &n.address) {
                return Err("stored Sui host is immutable".into());
            }
            n.clone()
        } else {
            SuiNode {
                name: args.name.clone(),
                address: args.host.clone().ok_or("new Sui nodes need --host")?,
                ssh_user: args.user.clone(),
                ssh_port: args.port,
                role: role.to_owned(),
                ..SuiNode::default()
            }
        };
        if args.validator {
            initialize_validator(&mut node, existing.is_some(), args)?;
        }
        allow_lists(&mut node, args)?;
        let key = node_common::host_key(
            &node.address,
            node.ssh_port,
            existing.map(|n| n.host_key.as_str()),
            args.fingerprint.as_deref(),
            say,
        )?;
        node.host_key = key.to_openssh();
        let target = target(&node, &args.login)?;
        let session = Session::open(&target).map_err(|e| e.to_string())?;
        let facts = facts(&session)?;
        preflight(&facts, existing.is_none(), args.validator)?;
        if existing.is_some() && node.architecture != facts.machine {
            return Err("Sui host architecture changed".into());
        }
        node.architecture.clone_from(&facts.machine);
        if existing.is_none() {
            pin(&mut node, net)?;
        }
        say.line("plan       reserve the host and prepare Sui directories; preserve disks and existing identities");
        node_common::go_ahead(args.yes, "Sui init was not started")?;
        node = if existing.is_none() {
            store.add_sui_node(&node)
        } else {
            store.update_sui_node(&node)
        }
        .map_err(|e| e.to_string())?;
        node_common::save_vault(&args.network, &vault)?;
        node.last_run = run_play(&session, &target, &node, net, &facts, "init", say)?;
        "init ok".clone_into(&mut node.last_result);
        let stored = store.update_sui_node(&node).map_err(|e| e.to_string())?;
        return Ok(public(&stored, net));
    }
    let mut node = existing
        .ok_or("no stored Sui node; run init first")?
        .clone();
    if verb == "plan" {
        return Ok(
            json!({"node":public(&node,net),"changes":["verify release archive and network genesis","preserve host-bound P2P identity","restore verified formal snapshot once",if args.validator { "retain original validator identities and private unindexed gRPC" } else { "enable indexed gRPC with 14 epoch retention" },"restrict access and confirm firewall through fresh SSH"],"live_acceptance":"deferred; no host contacted"}),
        );
    }
    if args.validator
        && verb == "registration"
        && args.registration_action.as_deref() == Some("prepare")
    {
        return Ok(metadata(&node)?.preparation(net.name));
    }
    let target = target(&node, &args.login)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if args.validator && verb == "registration" {
        return registration(
            &session,
            &node,
            net,
            args.registration_action.as_deref().unwrap_or("status"),
        )
        .map_err(Into::into);
    }
    if verb == "status" {
        let out = session
            .run(&RemoteCommand::Sui(Command::Status), None)
            .map_err(|e| e.to_string())?;
        let s = Status::parse(&String::from_utf8_lossy(&out.stdout));
        if args.validator {
            return Ok(
                json!({"node":public(&node,net),"local":s,"registration":registration(&session,&node,net,"status")?,"consensus_duties":"not inferred from service liveness"}),
            );
        }
        return Ok(json!({"node":public(&node,net),"ready":s.ready(net.chain_id),"observation":s}));
    }
    if verb == "logs" {
        session
            .stream(
                &RemoteCommand::Sui(Command::Logs {
                    lines: args.lines,
                    follow: args.follow,
                }),
                &mut |_, line| {
                    if say.quiet {
                        crate::print_json(&json!({"journal":line}));
                    } else {
                        say.line(line);
                    }
                },
            )
            .map_err(|e| e.to_string())?;
        return Ok(json!({"status":"journal complete"}));
    }
    if node.last_result.is_empty() {
        return Err("init has not completed; retry init first".into());
    }
    if args.recover_bootstrap {
        say.line("recovery   stop incomplete bootstrap, retain its database in quarantine, then restore a fresh verified snapshot (3.5 TB additional free space required)");
    }
    node_common::go_ahead(args.yes, "Sui operation was not started")?;
    if ["start", "stop", "restart"].contains(&verb) {
        let action = match verb {
            "start" => erpc_ssh::arc::Action::Start,
            "stop" => erpc_ssh::arc::Action::Stop,
            _ => erpc_ssh::arc::Action::Restart,
        };
        session
            .run(
                &RemoteCommand::Sui(Command::Service(action, contract(&node, net)?)),
                None,
            )
            .map_err(|e| e.to_string())?;
        return Ok(
            json!({"operation":verb,"name":node.name,"activation":"not inferred from process state"}),
        );
    }
    if node.last_result.is_empty() {
        return Err("init has not completed; retry init first".into());
    }
    let f = facts(&session)?;
    preflight(&f, false, args.validator)?;
    if verb == "update" {
        pin(&mut node, net)?;
    }
    if verb == "update-config" {
        allow_lists(&mut node, args)?;
    }
    if !["deploy", "update", "update-config", "destroy"].contains(&verb) {
        return Err("unsupported Sui operation".into());
    }
    if args.recover_bootstrap {
        if verb != "deploy" {
            return Err("bootstrap recovery is only available with deploy".into());
        }
        session
            .run(
                &RemoteCommand::Sui(Command::RecoverBootstrap(contract(&node, net)?)),
                None,
            )
            .map_err(|e| e.to_string())?;
    }
    if args.validator && verb == "deploy" {
        // Prepare binaries/helpers with listeners stopped; no private material in the run bundle.
        run_play(&session, &target, &node, net, &f, "prepare-validator", say)?;
        import_validator(&session, &node, net, args.restore_keys)?;
    }
    node.last_run = run_play(&session, &target, &node, net, &f, verb, say)?;
    node.last_result = format!("{verb} ok");
    let node = store.update_sui_node(&node).map_err(|e| {
        format!(
            "host operation finished, but inventory update failed: {e}; inspect run before retrying"
        )
    })?;
    Ok(
        json!({"node":public(&node,net),"readiness":"check status; bootstrap completion and activation are not implied by deploy success"}),
    )
}

pub(crate) fn run(verb: &str, args: &Args, json_out: bool) -> Outcome {
    match execute(verb, args, &Say { quiet: json_out }) {
        Ok(result) => {
            if json_out {
                crate::print_json(&result);
                Outcome::Done(String::new())
            } else {
                Outcome::Done(serde_json::to_string_pretty(&result).unwrap_or_default())
            }
        }
        Err(error) => Outcome::from(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preflight_refuses_small_hosts_and_cross_network_bundle_pins() {
        assert!(preflight(&Facts::default(), true, false).is_err());
        let net = network::get("testnet").expect("testnet");
        let mut node = SuiNode {
            name: "sui1".to_owned(),
            role: "fullnode".to_owned(),
            architecture: "x86_64".to_owned(),
            ..SuiNode::default()
        };
        pin(&mut node, net).expect("pin");
        let f = Facts {
            controller: "192.0.2.1".to_owned(),
            ..Facts::default()
        };
        assert!(
            vars(
                &node,
                network::get("mainnet").expect("mainnet"),
                &f,
                "deploy"
            )
            .is_err()
        );
        assert!(
            !vars(&node, net, &f, "deploy")
                .expect("vars")
                .to_string()
                .contains("host_key")
        );
        assert!(
            allow_lists(
                &mut node,
                &Args {
                    rpc_allow: Some(vec!["0.0.0.0/0".to_owned()]),
                    ..Args::default()
                }
            )
            .is_err()
        );
    }
}
