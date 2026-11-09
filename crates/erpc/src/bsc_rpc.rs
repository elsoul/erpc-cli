// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated BSC RPC nodes with fixed network/retention and official snapshot bootstrap.

use crate::bsc_owned::{self, Node};
use crate::{
    commands::Outcome,
    eth_rpc::Facts,
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, bsc::BscRpc};
use erpc_chain_bsc::Network;
use erpc_ops::bundle::{Built, Bundle};
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn one<'a>(args: &'a ArgMatches, name: &str) -> Option<&'a str> {
    args.try_get_one::<String>(name)
        .ok()
        .flatten()
        .map(String::as_str)
}
fn yes(args: &ArgMatches) -> bool {
    args.try_get_one::<bool>("yes")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
fn owner(node: &Node) -> Result<&str, String> {
    node.id
        .as_deref()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 80
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        .ok_or_else(|| "invalid BSC inventory owner".into())
}
pub(crate) fn request(node: &Node, network: Network, action: &str) -> Result<Value, String> {
    let qualified = network.qualify(&node.version)?;
    if Some(node.commit.as_str()) != qualified["commit"].as_str()
        || !["amd64", "arm64"].contains(&node.platform.as_str())
    {
        return Err("stored BSC release is not in the network catalog".into());
    }
    let identity = serde_json::to_vec(&(&node.management_allow, node.ssh_port))
        .map_err(|_| "cannot encode BSC configuration identity")?;
    Ok(
        json!({"owner":owner(node)?,"network":network.name(),"role":if node.is_validator() { "validator" } else { "rpc" },"operator":node.operator(),"version":node.version,"commit":node.commit,"platform":node.platform,"storage":node.storage,"snapshot":node.snapshot,"action":action,"config_id":format!("{:x}",Sha256::digest(identity))}),
    )
}

pub(crate) fn control(
    session: &Session,
    node: &Node,
    network: Network,
    action: &str,
) -> Result<Value, String> {
    control_request(session, &request(node, network, action)?)
}
pub(crate) fn control_request(session: &Session, request: &Value) -> Result<Value, String> {
    let body = request.to_string();
    let output = session
        .run(
            &RemoteCommand::BscControl(erpc_ssh::bsc::Control::new()?),
            Some(body.as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid BSC controller response".into())
}
fn target(node: &Node, args: &ArgMatches) -> Result<Target, String> {
    let public_key = args
        .try_get_one::<std::path::PathBuf>("ssh-key")
        .ok()
        .flatten()
        .ok_or("pass --ssh-key with the operator public key file")?
        .clone();
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
            public_key,
        },
    })
}
fn host_check(facts: &Facts, validator: bool, network: Network) -> Result<&'static str, String> {
    let ubuntu = facts
        .os
        .strip_prefix("ubuntu ")
        .and_then(|v| v.split_once('.'))
        .and_then(|(a, b)| Some((a.parse::<u32>().ok()?, b.parse::<u32>().ok()?)))
        .is_some_and(|v| v >= (24, 4));
    if !ubuntu
        || !facts.sudo
        || facts.mem_kb
            < if validator {
                if network == Network::Mainnet {
                    120_000_000
                } else {
                    15_000_000
                }
            } else {
                60_000_000
            }
        || facts.cpus < 16
    {
        return Err(
            "BSC hosts require Ubuntu 24.04+, passwordless sudo, sixteen cores and role/network-qualified RAM (RPC 64 GB; mainnet validator 128 GB; Chapel validator 16 GB)"
                .into(),
        );
    }
    match facts.machine.as_str() {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        _ => Err("BSC binaries support Linux x86-64 or ARM64".into()),
    }
}
fn open(network: Network, args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        network.name(),
        one(args, "vault"),
        "erpc r --chain bsc init --network <network> --vault <vault>",
    )?;
    Ok((
        node_common::store(&node_common::op_runner()?, &vault, "bsc", network.name())?,
        vault,
    ))
}
fn find(store: &Store<OpCli>, args: &ArgMatches, validator: bool) -> Result<Node, String> {
    let name = one(args, "name").ok_or("BSC operation requires --name")?;
    bsc_owned::list(store, validator)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name)
        .ok_or_else(|| "BSC node is not initialized in this network".into())
}
fn management(args: &ArgMatches, old: &[String]) -> Result<Vec<String>, String> {
    let values = args
        .try_get_many::<String>("management-allow")
        .ok()
        .flatten()
        .map_or_else(|| old.to_vec(), |v| v.cloned().collect());
    crate::arc_rpc::allow_list("management", &values, false)
}
fn helper_sha() -> Result<String, String> {
    let mut hash = Sha256::new();
    for path in ["node/control.py", "node/bootstrap.py", "node/validator.py"] {
        hash.update(
            erpc_chain_bsc::TEMPLATES
                .get_file(path)
                .ok_or("missing BSC helper")?
                .contents(),
        );
    }
    hash.update(erpc_chain_bsc::CATALOG_BYTES);
    Ok(format!("{:x}", hash.finalize()))
}
fn systemd_control() -> Result<String, String> {
    erpc_ssh::python::systemd_command(&format!(
        "/usr/local/lib/erpc/bsc/releases/{}/control.py",
        helper_sha()?
    ))
}

fn variables(node: &Node, network: Network, facts: &Facts) -> Result<Value, String> {
    let platform = host_check(facts, node.is_validator(), network)?;
    if platform != node.platform {
        return Err("host platform differs from immutable BSC inventory".into());
    }
    if facts.ssh_port == 0 {
        return Err("cannot establish the host SSH listener port".into());
    }
    let mut v4 = crate::arc_rpc::allow_list("management", &node.management_allow, false)?;
    let mut v6 = Vec::new();
    match facts.controller_ip()? {
        std::net::IpAddr::V4(ip) => {
            let ip = ip.to_string();
            if !v4.contains(&ip) {
                v4.push(ip);
            }
        }
        std::net::IpAddr::V6(ip) => v6.push(ip.to_string()),
    }
    Ok(
        json!({"ansible_connection":"local","bsc_request":request(node,network,"prepare")?,"bsc_prepare_action":"prepare","bsc_helper_sha":helper_sha()?,"bsc_systemd_control":systemd_control()?,"bsc_management_v4":v4,"bsc_management_v6":v6,"bsc_ssh_port":facts.ssh_port}),
    )
}

fn add_templates(dir: &include_dir::Dir<'_>, bundle: &mut Bundle) -> Result<(), String> {
    for file in dir.files() {
        bundle
            .add(
                file.path().to_str().ok_or("invalid carried path")?,
                if file
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "service")
                {
                    file.contents_utf8()
                        .ok_or("invalid BSC unit")?
                        .replace("@ERPC_BSC_CONTROL@", &systemd_control()?)
                        .into_bytes()
                } else {
                    file.contents().to_vec()
                },
            )
            .map_err(|e| e.to_string())?;
    }
    for child in dir.dirs() {
        add_templates(child, bundle)?;
    }
    Ok(())
}
fn bundle(inventory: &str) -> Result<Built, String> {
    let mut bundle = Bundle::new();
    add_templates(&erpc_chain_bsc::TEMPLATES, &mut bundle)?;
    bundle
        .add("inventory.yml", inventory.as_bytes().to_vec())
        .map_err(|e| e.to_string())?;
    bundle
        .add("node/catalog.json", erpc_chain_bsc::CATALOG_BYTES.to_vec())
        .map_err(|e| e.to_string())?;
    bundle
        .add("rpc-firewall.py", erpc_ops::RPC_FIREWALL.to_vec())
        .map_err(|e| e.to_string())?;
    bundle.finish().map_err(|e| e.to_string())
}
fn play(
    session: &Session,
    target: &Target,
    inventory: &str,
    play: &str,
    say: &Say,
) -> Result<String, String> {
    let built = bundle(inventory)?;
    let run = erpc_ops::run::start(session, &built, play).map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Resume BSC deployment using its stored owner and release",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "BSC play failed; data and ownership retained (run {})",
            run.as_str()
        ));
    }
    Ok(run.as_str().into())
}
fn deploy(
    session: &Session,
    target: &Target,
    node: &Node,
    network: Network,
    inventory: &str,
    say: &Say,
) -> Result<String, String> {
    // Short policy application completes before confirmation. No slow image/snapshot
    // work holds the run lock while its rollback timer is awaiting confirmation.
    let preparation = bundle(inventory)?;
    let prepared = erpc_ops::run::start(session, &preparation, "node/firewall.yml")
        .map_err(|e| e.to_string())?;
    let result = node_common::follow(target, &prepared, "Retry BSC firewall preparation", say)?;
    if !result.ok() {
        return Err("BSC firewall preparation failed; deployment did not start".into());
    }
    let fresh = Session::open(target).map_err(|e| e.to_string())?;
    // A new connection also verifies that the same immutable node owns this host.
    control(&fresh, node, network, "status")?;
    fresh
        .run(
            &RemoteCommand::BscFirewallConfirm {
                control: erpc_ssh::bsc::Control::new()?,
                token: erpc_ssh::firewall::FirewallToken::new(
                    prepared.clone(),
                    &preparation.sha256,
                )?,
            },
            None,
        )
        .map_err(|_| "BSC firewall confirmation failed; await rollback before retrying")?;
    let confirmed = erpc_ops::firewall_inventory(inventory, &prepared, &preparation.sha256)?;
    play(session, target, &confirmed, "node/deploy.yml", say)
}

fn init(network: Network, args: &ArgMatches, say: &Say, validator: bool) -> Result<Value, String> {
    let (store, vault) = open(network, args)?;
    let name = one(args, "name").ok_or("init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    let existing = bsc_owned::list(&store, validator)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name);
    let mut node = if let Some(node) = existing {
        if one(args, "host").is_some_and(|v| v != node.address)
            || one(args, "storage").is_some_and(|v| v != node.storage)
            || one(args, "version").is_some_and(|v| v != node.version)
        {
            return Err(
                "init cannot retarget an owned node; host and retention are immutable".into(),
            );
        }
        node
    } else {
        let version = one(args, "version").unwrap_or(network.recommended());
        let qualified = network.qualify(version)?;
        let storage = one(args, "storage").unwrap_or("full");
        let snapshot = network.catalog()["recommended_snapshots"][storage]
            .as_str()
            .ok_or("invalid BSC storage mode")?;
        let host = one(args, "host").ok_or("new node requires --host")?;
        let port = args.get_one::<u16>("port").copied().unwrap_or(22);
        let host_key = node_common::host_key(host, port, None, one(args, "fingerprint"), say)?;
        let common = BscRpc {
            name: name.into(),
            address: host.into(),
            ssh_user: one(args, "user").unwrap_or("ubuntu").into(),
            ssh_port: port,
            host_key: host_key.to_openssh(),
            version: version.into(),
            commit: qualified["commit"]
                .as_str()
                .ok_or("missing source pin")?
                .into(),
            storage: storage.into(),
            snapshot: snapshot.into(),
            management_allow: management(args, &[])?,
            ..BscRpc::default()
        };
        if validator {
            Node::Validator(erpc_chain::inventory::bsc_validator::BscValidator {
                node: common,
                operator: erpc_chain_bsc::validator::address(
                    one(args, "operator")
                        .ok_or("new validator requires its external --operator address")?,
                )?,
                custody: "unprovisioned".into(),
                ..erpc_chain::inventory::bsc_validator::BscValidator::default()
            })
        } else {
            Node::Rpc(common)
        }
    };
    if let Some(value) = one(args, "operator") {
        let canonical = erpc_chain_bsc::validator::address(value)?;
        if Some(canonical.as_str()) != node.operator() {
            return Err("BSC operator address is immutable".into());
        }
    }
    network.qualify(&node.version)?;
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let facts = crate::eth_rpc::facts(&session)?;
    let platform = host_check(&facts, node.is_validator(), network)?;
    if node.id.is_some() && node.platform != platform {
        return Err("stored BSC platform differs from host".into());
    }
    node.platform = platform.into();
    node_common::go_ahead(yes(args), "no BSC host changed").map_err(|e| e.to_string())?;
    if node.id.is_none() {
        node = bsc_owned::add(&store, &node).map_err(|e| e.to_string())?;
    }
    let vars = variables(&node, network, &facts)?;
    let inventory = json!({"all":{"hosts":{node.name.clone():vars}}}).to_string();
    node.last_run = play(&session, &target, &inventory, "node/prepare.yml", say)?;
    let status = control(&session, &node, network, "status")?;
    node.last_result = "prepared; deploy required".into();
    bsc_owned::save(&store, &mut node).map_err(|e| e.to_string())?;
    node_common::save_vault(network.name(), &vault)?;
    Ok(json!({"name":node.name,"family":"bsc","network":network.name(),"state":status["phase"]}))
}
fn authorize_deploy(session: &Session, node: &Node, network: Network) -> Result<String, String> {
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy).map_err(|_| "cannot create BSC deployment intent")?;
    let intent = format!("{:032x}", u128::from_be_bytes(entropy));
    let mut authorization = request(node, network, "authorize-deploy")?;
    authorization["intent"] = json!(intent);
    control_request(session, &authorization)?;
    Ok(intent)
}
fn emit_log(
    stream: erpc_ssh::Stream,
    line: &str,
    json_out: bool,
    stdout: &mut impl FnMut(&str),
    stderr: &mut impl FnMut(&str),
) {
    if json_out {
        stdout(
            &json!({"journal":line,"stream":match stream { erpc_ssh::Stream::Stdout=>"stdout", erpc_ssh::Stream::Stderr=>"stderr" }}).to_string(),
        );
    } else {
        stderr(line);
    }
}
fn logs(session: &Session, args: &ArgMatches, json_out: bool) -> Result<Value, String> {
    let output = Say { quiet: false };
    session
        .stream(
            &RemoteCommand::BscLogs {
                lines: args.get_one::<u32>("lines").copied().unwrap_or(100),
                follow: args.get_flag("follow"),
            },
            &mut |stream, line| {
                emit_log(
                    stream,
                    line,
                    json_out,
                    &mut crate::print_line,
                    &mut |text| output.line(text),
                );
            },
        )
        .map_err(|e| e.to_string())?;
    Ok(json!({"logs":"complete"}))
}
fn plan(node: &Node, network: Network, args: &ArgMatches) -> Result<Value, String> {
    if one(args, "change") == Some("register") {
        let target = target(node, args)?;
        let session = Session::open(&target).map_err(|e| e.to_string())?;
        return crate::bsc_signer::registration(&session, node, network);
    }
    let wanted = one(args, "version").unwrap_or(&node.version);
    network.qualify(wanted)?;
    let snapshot = &network.catalog()["snapshots"][&node.snapshot];
    let initial_free = snapshot["files"]
        .as_array()
        .ok_or("stored snapshot is outside the catalog")?
        .iter()
        .try_fold(200_000_000_000u64, |sum, file| {
            file["estimated_bytes"]
                .as_u64()
                .and_then(|size| size.checked_add(32_000_000))
                .and_then(|size| size.checked_mul(2))
                .and_then(|size| sum.checked_add(size))
                .ok_or("snapshot capacity metadata is invalid")
        })?;
    Ok(
        json!({"name":node.name,"family":"bsc","network":network.name(),"change":one(args,"change").unwrap_or("deploy"),"current_version":node.version,"version":wanted,"recommended_version":network.recommended(),"network_upgrade":network.catalog()["network_upgrade"],"storage":node.storage,"snapshot":node.snapshot,"initial_free_bytes_before_allocated_data":initial_free,"rpc":if node.is_validator(){"disabled; private IPC only"}else{"loopback HTTP/WS"},"validator":node.is_validator(),"destroy_preserves_data":true,"financial_transactions":"external tools only"}),
    )
}
fn operation(
    verb: &str,
    network: Network,
    args: &ArgMatches,
    say: &Say,
    json_out: bool,
    validator: bool,
) -> Result<Value, String> {
    if verb == "init" {
        return init(network, args, say, validator);
    }
    let (store, vault) = open(network, args)?;
    if verb == "list" {
        let nodes = bsc_owned::list(&store, validator)
            .map_err(|e| e.to_string())?
            .iter()
            .map(Node::public)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(json!({"nodes":nodes}));
    }
    let mut node = find(&store, args, validator)?;
    if verb == "plan" {
        return plan(&node, network, args);
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let before = control(&session, &node, network, "status")?;
    if verb == "status" {
        return Ok(before);
    }
    if verb == "logs" {
        return logs(&session, args, json_out);
    }
    if args
        .try_get_one::<bool>("restore-custody")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
    {
        node_common::go_ahead(yes(args), "no signer material changed")
            .map_err(|e| e.to_string())?;
        return crate::bsc_signer::restore(&session, &node, network);
    }
    if before["phase"] == "installing" && !["deploy", "stop", "destroy"].contains(&verb) {
        return Err("resume deploy at the stored target before another operation".into());
    }
    node_common::go_ahead(yes(args), "no BSC host changed").map_err(|e| e.to_string())?;
    match verb {
        "deploy" | "update" | "update-config" => {
            let facts = crate::eth_rpc::facts(&session)?;
            host_check(&facts, node.is_validator(), network)?;
            if verb == "update" {
                let wanted = one(args, "version").ok_or("update requires --version")?;
                let qualified = network.qualify(wanted)?;
                let numbers = |value: &str| {
                    value
                        .split('.')
                        .map(str::parse::<u16>)
                        .collect::<Result<Vec<_>, _>>()
                };
                if numbers(wanted).map_err(|_| "invalid wanted version")?
                    < numbers(&node.version).map_err(|_| "invalid current version")?
                {
                    return Err("BSC database downgrades are refused".into());
                }
                node.version = wanted.into();
                node.commit = qualified["commit"]
                    .as_str()
                    .ok_or("missing source pin")?
                    .into();
            }
            node.management_allow = management(args, &node.management_allow)?;
            bsc_owned::save(&store, &mut node).map_err(|e| e.to_string())?;
            let mut vars = variables(&node, network, &facts)?;
            let intent = authorize_deploy(&session, &node, network)?;
            vars["bsc_request"]["intent"] = json!(intent);
            vars["bsc_prepare_action"] = json!("begin-install");
            let inventory = json!({"all":{"hosts":{node.name.clone():vars}}}).to_string();
            // The carried controller understands this CLI's release catalog. It
            // fences/stops the old owner before replacing the installed helper.
            play(&session, &target, &inventory, "node/prepare.yml", say)?;
            node.last_run = deploy(&session, &target, &node, network, &inventory, say)?;
            node.last_result = format!("{verb} complete; synchronization observed separately");
            bsc_owned::save(&store, &mut node).map_err(|e| e.to_string())?;
            crate::bsc_signer::finish(&session, &mut node, network, &store, &vault)
        }
        "start" | "stop" | "restart" | "destroy" => {
            let result = control(&session, &node, network, verb)?;
            node.last_result = format!("{verb} complete; data retained");
            bsc_owned::save(&store, &mut node).map_err(|e| e.to_string())?;
            Ok(result)
        }
        _ => Err("unsupported BSC operation".into()),
    }
}
pub(crate) fn report_status(
    result: Result<Value, String>,
    json_out: bool,
    output: &mut dyn FnMut(&str),
) -> Outcome {
    crate::node_report::status(result, "/ready", json_out, output)
}

pub(crate) fn run_role(
    verb: &str,
    args: &ArgMatches,
    network: Option<&str>,
    json_out: bool,
    validator: bool,
) -> Outcome {
    let Some(network) = network.and_then(Network::parse) else {
        return Outcome::Usage("BSC requires an explicit mainnet or chapel network".into());
    };
    let say = Say { quiet: json_out };
    let result = operation(verb, network, args, &say, json_out, validator);
    if verb == "status" {
        return report_status(result, json_out, &mut crate::print_line);
    }
    match result {
        Ok(value) => {
            if json_out {
                if verb == "logs" {
                    crate::print_line(&value.to_string());
                } else {
                    crate::print_json(&value);
                }
            } else {
                say.line(&serde_json::to_string_pretty(&value).unwrap_or_default());
            }
            Outcome::Done(String::new())
        }
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parsed_upgrade_plan_exposes_network_deadline_without_rewriting_original_inventory() {
        use erpc_core::chain::{Chain, Role};
        for role in [Role::Rpc, Role::Validator] {
            for (network, original, target) in [
                (Network::Mainnet, "1.7.8", "1.8.2"),
                (Network::Chapel, "1.8.1", "1.8.1"),
            ] {
                let matches = crate::tree::command(role, Chain::Bsc)
                    .try_get_matches_from([
                        "node",
                        "plan",
                        "--network",
                        network.name(),
                        "--version",
                        target,
                    ])
                    .unwrap();
                let profile = network.catalog();
                let inventory = BscRpc {
                    name: "fixture".into(),
                    version: original.into(),
                    commit: profile["releases"][original]["commit"]
                        .as_str()
                        .unwrap()
                        .into(),
                    snapshot: profile["recommended_snapshots"]["full"]
                        .as_str()
                        .unwrap()
                        .into(),
                    storage: "full".into(),
                    ..Default::default()
                };
                let node = if role == Role::Validator {
                    Node::Validator(erpc_chain::inventory::bsc_validator::BscValidator {
                        node: inventory,
                        ..Default::default()
                    })
                } else {
                    Node::Rpc(inventory)
                };
                let before = node.public().unwrap();
                let report =
                    plan(&node, network, matches.subcommand_matches("plan").unwrap()).unwrap();
                assert_eq!(report["current_version"], original);
                assert_eq!(report["version"], target);
                assert_eq!(report["recommended_version"], target);
                assert_eq!(report["validator"], role == Role::Validator);
                if network == Network::Mainnet {
                    assert_eq!(
                        report["network_upgrade"]["activation_unix"],
                        1_796_697_000u64
                    );
                    assert_eq!(report["network_upgrade"]["minimum_version"], "1.8.2");
                } else {
                    assert!(report["network_upgrade"].is_null());
                }
                assert_eq!(node.public().unwrap(), before);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn rendered_startup_authenticates_paths_before_interpreting_helper_bytes() {
        use std::io::Write;
        let built = bundle("all: {hosts: {fixture: {ansible_connection: local}}}").unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-bsc/tests/entrypoints.py");
        let mut child = std::process::Command::new("python3")
            .arg("-I")
            .arg("-B")
            .arg(script)
            .arg(systemd_control().unwrap())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&built.bytes).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["rendered_entries"], 4);
        assert_eq!(report["inert_execution_scenarios"], 28);
    }

    #[test]
    fn json_journal_lines_use_stdout_and_text_uses_the_diagnostic_sink() {
        let message = "first\nsecond\"\t";
        for (stream, name) in [
            (erpc_ssh::Stream::Stdout, "stdout"),
            (erpc_ssh::Stream::Stderr, "stderr"),
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            emit_log(
                stream,
                message,
                true,
                &mut |v| stdout.push(v.to_string()),
                &mut |text| stderr.push(text.to_owned()),
            );
            assert!(stderr.is_empty());
            assert_eq!(stdout.len(), 1);
            assert_eq!(stdout[0].lines().count(), 1);
            let parsed: Value = serde_json::from_str(&stdout[0]).expect("NDJSON record");
            assert_eq!(parsed, json!({"journal":message,"stream":name}));
        }
        let mut stderr = Vec::new();
        emit_log(
            erpc_ssh::Stream::Stdout,
            message,
            false,
            &mut |_| panic!("text must not reach the JSON sink"),
            &mut |text| stderr.push(text.to_owned()),
        );
        assert_eq!(stderr, [message]);
    }
    #[test]
    fn candidate_uses_observed_ssh_listener_and_refuses_missing_or_invalid_port() {
        let profile = Network::Mainnet.catalog();
        let node = BscRpc {
            id: Some("fixtureowner".into()),
            version: Network::Mainnet.recommended().into(),
            commit: profile["releases"][Network::Mainnet.recommended()]["commit"]
                .as_str()
                .unwrap()
                .into(),
            platform: "amd64".into(),
            storage: "full".into(),
            snapshot: profile["recommended_snapshots"]["full"]
                .as_str()
                .unwrap()
                .into(),
            ssh_port: 2222,
            ..BscRpc::default()
        };
        let nodes = [
            Node::Rpc(node.clone()),
            Node::Validator(erpc_chain::inventory::bsc_validator::BscValidator {
                node,
                operator: format!("0x{}", "2".repeat(40)),
                ..Default::default()
            }),
        ];
        for node in nodes {
            let observed = "os=ubuntu 24.04\nmachine=x86_64\nmem_kb=128000000\ncpus=16\nsudo=yes\ncontroller=192.0.2.1\n";
            let facts = Facts::parse(&format!("{observed}ssh_port=22\n"));
            let candidate = variables(&node, Network::Mainnet, &facts).unwrap();
            assert_eq!(candidate["bsc_ssh_port"], 22);
            assert_eq!(node.ssh_port, 2222);
            for value in ["", "0", "invalid", "65536"] {
                let facts = Facts::parse(&format!("{observed}ssh_port={value}\n"));
                assert!(
                    variables(&node, Network::Mainnet, &facts)
                        .unwrap_err()
                        .contains("SSH listener")
                );
            }
            assert!(variables(&node, Network::Mainnet, &Facts::parse(observed)).is_err());
        }
    }

    #[test]
    fn public_request_binds_snapshot_retention_and_configuration() {
        let profile = Network::Mainnet.catalog();
        let mut node = Node::Rpc(BscRpc {
            id: Some("fixtureowner".into()),
            version: Network::Mainnet.recommended().into(),
            commit: profile["releases"][Network::Mainnet.recommended()]["commit"]
                .as_str()
                .expect("compiled field")
                .into(),
            platform: "amd64".into(),
            storage: "full".into(),
            snapshot: profile["recommended_snapshots"]["full"]
                .as_str()
                .expect("compiled field")
                .into(),
            ..BscRpc::default()
        });
        let before = request(&node, Network::Mainnet, "status").expect("public request");
        node.management_allow.push("192.0.2.1".into());
        assert_ne!(
            before["config_id"],
            request(&node, Network::Mainnet, "status").expect("changed request")["config_id"]
        );
        assert!(request(&node, Network::Chapel, "status").is_err());
    }
}
