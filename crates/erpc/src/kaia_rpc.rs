// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated Kaia RPC nodes with fixed network/retention and official snapshot bootstrap.

use crate::{
    commands::Outcome,
    eth_rpc::Facts,
    kaia_owned::{self, Node},
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, kaia::KaiaRpc};
use erpc_chain_kaia::Network;
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
pub(crate) fn owner(node: &Node) -> Result<&str, String> {
    node.id
        .as_deref()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 80
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        .ok_or_else(|| "invalid Kaia inventory owner".into())
}
pub(crate) fn request(node: &Node, network: Network, action: &str) -> Result<Value, String> {
    if node.network != network.name()
        || node.genesis != network.genesis()
        || node.platform != "amd64"
    {
        return Err("stored Kaia network/platform contract differs".into());
    }
    let identity = serde_json::to_vec(&(&node.management_allow, node.ssh_port))
        .map_err(|_| "cannot encode Kaia configuration identity")?;
    let mut value = json!({"owner":owner(node)?,"network":network.name(),"role":"rpc","version":node.version,"commit":node.commit,"platform":node.platform,"storage":node.storage,"snapshot":node.snapshot,"genesis":node.genesis,"image":node.image,"action":action,"config_id":format!("{:x}",Sha256::digest(identity))});
    if let Node::Validator(cell) = node {
        value["role"] = json!("validator");
        for (key, field) in [
            ("node_kind", json!(cell.node_kind)),
            ("advertise", json!(cell.advertise)),
            ("peers", json!(cell.peers)),
            ("reward_address", json!(cell.reward_address)),
            ("manager_address", json!(cell.manager_address)),
            ("staking_address", json!(cell.staking_address)),
            ("gc_id", json!(cell.gc_id)),
        ] {
            value[key] = field;
        }
        value["config_id"] = json!(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
                    &node.management_allow,
                    node.ssh_port,
                    &cell.peers,
                    &cell.reward_address,
                    &cell.manager_address,
                    &cell.staking_address,
                    &cell.gc_id
                ))
                .map_err(|_| "cannot bind core-cell configuration")?
            )
        ));
    }
    Ok(value)
}

fn reviewed(node: &Node, network: Network) -> Result<(), String> {
    network.qualify(&node.version)?;
    if node.commit != erpc_chain_kaia::release::COMMIT
        || node.image != erpc_chain_kaia::release::IMAGE
    {
        return Err("Kaia source/image differs from the reviewed catalog".into());
    }
    network.initial_capacity(&node.storage, &node.snapshot)?;
    Ok(())
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
            &RemoteCommand::KaiaControl(erpc_ssh::kaia::Control::new()?),
            Some(body.as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid Kaia controller response".into())
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
fn host_check(facts: &Facts) -> Result<&'static str, String> {
    let ubuntu = facts
        .os
        .strip_prefix("ubuntu ")
        .and_then(|v| v.split_once('.'))
        .and_then(|(a, b)| Some((a.parse::<u32>().ok()?, b.parse::<u32>().ok()?)))
        .is_some_and(|v| v >= (24, 4));
    if !ubuntu || !facts.sudo || facts.mem_kb < 60_000_000 || facts.cpus < 8 {
        return Err(
            "Kaia hosts require Ubuntu 24.04+, passwordless sudo, 64 GB RAM and eight CPU cores"
                .into(),
        );
    }
    match facts.machine.as_str() {
        "x86_64" => Ok("amd64"),
        _ => Err("The reviewed Kaia OCI image supports Linux x86-64 only".into()),
    }
}
fn open(network: Network, args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        network.name(),
        one(args, "vault"),
        "erpc r --chain kaia init --network <network> --vault <vault>",
    )?;
    Ok((
        node_common::store(&node_common::op_runner()?, &vault, "kaia", network.name())?,
        vault,
    ))
}
fn find(store: &Store<OpCli>, args: &ArgMatches, validator: bool) -> Result<Node, String> {
    let name = one(args, "name").ok_or("Kaia operation requires --name")?;
    kaia_owned::list(store, validator)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name)
        .ok_or_else(|| "Kaia node is not initialized in this network".into())
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
    for path in [
        "node/control.py",
        "node/bootstrap.py",
        "node/custody.py",
        "node/corecell.py",
        "node/coreaccount.py",
    ] {
        hash.update(
            erpc_chain_kaia::TEMPLATES
                .get_file(path)
                .ok_or("missing Kaia helper")?
                .contents(),
        );
    }
    hash.update(erpc_chain_kaia::CATALOG_BYTES);
    Ok(format!("{:x}", hash.finalize()))
}
fn systemd_control() -> Result<String, String> {
    erpc_ssh::python::systemd_command(&format!(
        "/usr/local/lib/erpc/kaia/releases/{}/control.py",
        helper_sha()?
    ))
}

fn variables(node: &Node, network: Network, facts: &Facts) -> Result<Value, String> {
    reviewed(node, network)?;
    let platform = host_check(facts)?;
    if let Node::Validator(cell) = node {
        let kind = erpc_chain_kaia::corecell::Kind::parse(&cell.node_kind)
            .ok_or("invalid core-cell kind")?;
        if facts.cpus < kind.threads() || facts.mem_kb < kind.memory_kib() {
            return Err(
                "host does not meet the documented CN/PN CPU and memory recommendation".into(),
            );
        }
    }
    if platform != node.platform {
        return Err("host platform differs from immutable Kaia inventory".into());
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
        json!({"ansible_connection":"local","kaia_request":request(node,network,"prepare")?,"kaia_prepare_action":"prepare","kaia_helper_sha":helper_sha()?,"kaia_systemd_control":systemd_control()?,"kaia_management_v4":v4,"kaia_management_v6":v6,"kaia_ssh_port":facts.ssh_port}),
    )
}

fn add_templates(dir: &include_dir::Dir<'_>, bundle: &mut Bundle) -> Result<(), String> {
    for file in dir.files() {
        bundle
            .add(
                file.path().to_str().ok_or("invalid carried path")?,
                if file.path().to_string_lossy() == "node/erpc-kaia.service" {
                    file.contents_utf8()
                        .ok_or("invalid Kaia unit")?
                        .replace("@ERPC_KAIA_CONTROL@", &systemd_control()?)
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
    add_templates(&erpc_chain_kaia::TEMPLATES, &mut bundle)?;
    bundle
        .add("inventory.yml", inventory.as_bytes().to_vec())
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
        "Resume Kaia deployment using its stored owner and release",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "Kaia play failed; data and ownership retained (run {})",
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
    let result = node_common::follow(target, &prepared, "Retry Kaia firewall preparation", say)?;
    if !result.ok() {
        return Err("Kaia firewall preparation failed; deployment did not start".into());
    }
    let fresh = Session::open(target).map_err(|e| e.to_string())?;
    // A new connection also verifies that the same immutable node owns this host.
    control(&fresh, node, network, "status")?;
    fresh
        .run(
            &RemoteCommand::KaiaFirewallConfirm {
                control: erpc_ssh::kaia::Control::new()?,
                token: erpc_ssh::firewall::FirewallToken::new(
                    prepared.clone(),
                    &preparation.sha256,
                )?,
            },
            None,
        )
        .map_err(|_| "Kaia firewall confirmation failed; await rollback before retrying")?;
    let confirmed = erpc_ops::firewall_inventory(inventory, &prepared, &preparation.sha256)?;
    play(session, target, &confirmed, "node/deploy.yml", say)
}

fn init(network: Network, args: &ArgMatches, say: &Say, validator: bool) -> Result<Value, String> {
    let (store, vault) = open(network, args)?;
    let name = one(args, "name").ok_or("init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    let existing = kaia_owned::list(&store, validator)
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
        crate::kaia_signer::check_init(&node, args)?;
        node
    } else {
        let version = one(args, "version").unwrap_or(network.recommended());
        let qualified = network.qualify(version)?;
        let storage =
            one(args, "storage").unwrap_or(if validator && one(args, "node-kind") == Some("cn") {
                "full"
            } else {
                "pruned"
            });
        let snapshot = if storage == "full" {
            "genesis"
        } else {
            network.catalog()["recommended_snapshot"]
                .as_str()
                .ok_or("missing reviewed Kaia snapshot")?
        };
        let host = one(args, "host").ok_or("new node requires --host")?;
        let port = args.get_one::<u16>("port").copied().unwrap_or(22);
        let host_key = node_common::host_key(host, port, None, one(args, "fingerprint"), say)?;
        let base = KaiaRpc {
            name: name.into(),
            network: network.name().into(),
            genesis: network.genesis().into(),
            image: erpc_chain_kaia::release::IMAGE.into(),
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
            ..KaiaRpc::default()
        };
        if validator {
            Node::validator(crate::kaia_signer::fresh(base, args)?)
        } else {
            Node::rpc(base)
        }
    };
    network.qualify(&node.version)?;
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let facts = crate::eth_rpc::facts(&session)?;
    let platform = host_check(&facts)?;
    if node.id.is_some() && node.platform != platform {
        return Err("stored Kaia platform differs from host".into());
    }
    node.platform = platform.into();
    node_common::go_ahead(yes(args), "no Kaia host changed").map_err(|e| e.to_string())?;
    if node.id.is_none() {
        node = kaia_owned::add(&store, &node).map_err(|e| e.to_string())?;
    }
    let vars = variables(&node, network, &facts)?;
    let inventory = json!({"all":{"hosts":{node.name.clone():vars}}}).to_string();
    node.last_run = play(&session, &target, &inventory, "node/prepare.yml", say)?;
    if node.is_validator() {
        crate::kaia_signer::finish(&session, &mut node, network, &store, &vault)?;
    }
    let status = control(&session, &node, network, "status")?;
    node.last_result = "prepared; deploy required".into();
    kaia_owned::save(&store, &mut node).map_err(|e| e.to_string())?;
    node_common::save_vault(network.name(), &vault)?;
    Ok(
        json!({"name":node.name,"family":"kaia","network":network.name(),"state":status["phase"],"registration":crate::kaia_signer::registration(&node)}),
    )
}
fn authorize_deploy(session: &Session, node: &Node, network: Network) -> Result<String, String> {
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy).map_err(|_| "cannot create Kaia deployment intent")?;
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
            &RemoteCommand::KaiaLogs {
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
trait DeploymentOperations {
    fn is_validator(&self) -> bool;
    fn restore(&mut self) -> Result<(), String>;
    fn configure(&mut self, verb: &str, args: &ArgMatches) -> Result<(), String>;
    fn authorize_and_prepare(&mut self) -> Result<(), String>;
    fn deploy(&mut self) -> Result<(), String>;
    fn finish(&mut self, verb: &str) -> Result<Value, String>;
}

fn run_deployment(
    verb: &str,
    args: &ArgMatches,
    operations: &mut impl DeploymentOperations,
) -> Result<Value, String> {
    if !["deploy", "update", "update-config"].contains(&verb) {
        return Err("unsupported Kaia deployment operation".into());
    }
    if operations.is_validator()
        && args.try_get_one::<bool>("restore-custody").ok().flatten() == Some(&true)
    {
        operations.restore()?;
    }
    operations.configure(verb, args)?;
    operations.authorize_and_prepare()?;
    operations.deploy()?;
    operations.finish(verb)
}

struct HostDeployment<'a> {
    store: &'a Store<OpCli>,
    node: &'a mut Node,
    session: &'a Session,
    target: &'a Target,
    network: Network,
    say: &'a Say,
    variables: Option<Value>,
    inventory: Option<String>,
}

impl DeploymentOperations for HostDeployment<'_> {
    fn is_validator(&self) -> bool {
        self.node.is_validator()
    }
    fn restore(&mut self) -> Result<(), String> {
        crate::kaia_signer::restore(self.session, self.node, self.network).map(|_| ())
    }
    fn configure(&mut self, verb: &str, args: &ArgMatches) -> Result<(), String> {
        let facts = crate::eth_rpc::facts(self.session)?;
        host_check(&facts)?;
        if verb == "update" {
            let wanted = one(args, "version").ok_or("update requires --version")?;
            let qualified = self.network.qualify(wanted)?;
            let numbers = |value: &str| {
                value
                    .split('.')
                    .map(str::parse::<u16>)
                    .collect::<Result<Vec<_>, _>>()
            };
            if numbers(wanted).map_err(|_| "invalid wanted version")?
                < numbers(&self.node.version).map_err(|_| "invalid current version")?
            {
                return Err("Kaia database downgrades are refused".into());
            }
            self.node.version = wanted.into();
            self.node.commit = qualified["commit"]
                .as_str()
                .ok_or("missing source pin")?
                .into();
            self.node.image = erpc_chain_kaia::release::IMAGE.into();
        }
        reviewed(self.node, self.network)?;
        crate::kaia_signer::configure(self.node, args)?;
        self.node.management_allow = management(args, &self.node.management_allow)?;
        kaia_owned::save(self.store, self.node).map_err(|e| e.to_string())?;
        self.variables = Some(variables(self.node, self.network, &facts)?);
        Ok(())
    }
    fn authorize_and_prepare(&mut self) -> Result<(), String> {
        let mut vars = self
            .variables
            .take()
            .ok_or("deployment configuration unavailable")?;
        let intent = authorize_deploy(self.session, self.node, self.network)?;
        vars["kaia_request"]["intent"] = json!(intent);
        vars["kaia_prepare_action"] = json!("begin-install");
        let inventory = json!({"all":{"hosts":{self.node.name.clone():vars}}}).to_string();
        // The carried controller fences/stops the old owner before replacing code.
        play(
            self.session,
            self.target,
            &inventory,
            "node/prepare.yml",
            self.say,
        )?;
        self.inventory = Some(inventory);
        Ok(())
    }
    fn deploy(&mut self) -> Result<(), String> {
        let inventory = self
            .inventory
            .as_deref()
            .ok_or("deployment preparation unavailable")?;
        self.node.last_run = deploy(
            self.session,
            self.target,
            self.node,
            self.network,
            inventory,
            self.say,
        )?;
        Ok(())
    }
    fn finish(&mut self, verb: &str) -> Result<Value, String> {
        self.node.last_result = format!("{verb} complete; synchronization observed separately");
        kaia_owned::save(self.store, self.node).map_err(|e| e.to_string())?;
        control(self.session, self.node, self.network, "status")
    }
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
    let (store, _) = open(network, args)?;
    if verb == "list" {
        return Ok(
            json!({"nodes":kaia_owned::list(&store,validator).map_err(|e|e.to_string())?.iter().map(Node::public).collect::<Result<Vec<_>,_>>()?}),
        );
    }
    let mut node = find(&store, args, validator)?;
    if verb == "plan" {
        let wanted = one(args, "version").unwrap_or(&node.version);
        network.qualify(wanted)?;
        let initial_free = network.initial_capacity(&node.storage, &node.snapshot)?;
        return Ok(
            json!({"name":node.name,"family":"kaia","network":network.name(),"change":one(args,"change").unwrap_or("deploy"),"current_version":node.version,"version":wanted,"storage":node.storage,"snapshot":node.snapshot,"initial_free_bytes_before_allocated_data":initial_free,"rpc":"loopback HTTP/WS","validator":validator,"destroy_preserves_data":true,"financial_transactions":"external tools only","registration":crate::kaia_signer::registration(&node)}),
        );
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
    if before["phase"] == "installing" && !["deploy", "stop", "destroy"].contains(&verb) {
        return Err("resume deploy at the stored target before another operation".into());
    }
    node_common::go_ahead(yes(args), "no Kaia host changed").map_err(|e| e.to_string())?;
    match verb {
        "deploy" | "update" | "update-config" => run_deployment(
            verb,
            args,
            &mut HostDeployment {
                store: &store,
                node: &mut node,
                session: &session,
                target: &target,
                network,
                say,
                variables: None,
                inventory: None,
            },
        ),
        "start" | "stop" | "restart" | "destroy" => {
            let result = control(&session, &node, network, verb)?;
            node.last_result = format!("{verb} complete; data retained");
            kaia_owned::save(&store, &mut node).map_err(|e| e.to_string())?;
            Ok(result)
        }
        _ => Err("unsupported Kaia operation".into()),
    }
}
pub(crate) fn report_status(
    result: Result<Value, String>,
    json_out: bool,
    output: &mut dyn FnMut(&str),
) -> Outcome {
    crate::node_report::status(result, "/ready", json_out, output)
}

pub(crate) fn run(
    verb: &str,
    args: &ArgMatches,
    network: Option<&str>,
    json_out: bool,
    validator: bool,
) -> Outcome {
    let Some(network) = network.and_then(Network::parse) else {
        return Outcome::Usage("Kaia requires an explicit mainnet or kairos network".into());
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
    struct InertOperations {
        events: Vec<&'static str>,
        fail: Option<&'static str>,
        started: bool,
    }
    impl InertOperations {
        fn step(&mut self, name: &'static str) -> Result<(), String> {
            self.events.push(name);
            if self.fail == Some(name) {
                Err("inert remote failure".into())
            } else {
                Ok(())
            }
        }
    }
    impl DeploymentOperations for InertOperations {
        fn is_validator(&self) -> bool {
            true
        }
        fn restore(&mut self) -> Result<(), String> {
            assert!(!self.started);
            self.step("custody-restore")
        }
        fn configure(&mut self, verb: &str, _args: &ArgMatches) -> Result<(), String> {
            assert_eq!(verb, "deploy");
            self.step("configure")
        }
        fn authorize_and_prepare(&mut self) -> Result<(), String> {
            self.step("authorize-and-prepare")
        }
        fn deploy(&mut self) -> Result<(), String> {
            self.step("deploy")?;
            self.started = true;
            Ok(())
        }
        fn finish(&mut self, verb: &str) -> Result<Value, String> {
            assert_eq!(verb, "deploy");
            self.step("finish")?;
            Ok(json!({"startup_requested":self.started}))
        }
    }

    #[test]
    fn parsed_restore_deploy_runs_the_real_orchestrator_and_stops_after_restore_errors() {
        let spec = erpc_core::chain::Verb {
            name: "deploy",
            about: "fixture",
            read_only: false,
        };
        let command = crate::kaia_tree::args(clap::Command::new("deploy"), &spec, true);
        let restored = command
            .clone()
            .try_get_matches_from(["deploy", "--restore-custody", "--yes"])
            .unwrap();
        for fail in [Some("custody-restore"), Some("configure"), None] {
            let mut operations = InertOperations {
                events: Vec::new(),
                fail,
                started: false,
            };
            let result = run_deployment("deploy", &restored, &mut operations);
            match fail {
                Some("custody-restore") => assert_eq!(operations.events, ["custody-restore"]),
                Some("configure") => {
                    assert_eq!(operations.events, ["custody-restore", "configure"]);
                }
                None => assert_eq!(
                    operations.events,
                    [
                        "custody-restore",
                        "configure",
                        "authorize-and-prepare",
                        "deploy",
                        "finish"
                    ]
                ),
                _ => unreachable!(),
            }
            assert_eq!(result.is_ok(), fail.is_none());
            assert_eq!(operations.started, fail.is_none());
        }
        let normal = command.try_get_matches_from(["deploy", "--yes"]).unwrap();
        let mut operations = InertOperations {
            events: Vec::new(),
            fail: None,
            started: false,
        };
        run_deployment("deploy", &normal, &mut operations).unwrap();
        assert_eq!(
            operations.events,
            ["configure", "authorize-and-prepare", "deploy", "finish"]
        );
        let rpc = crate::kaia_tree::args(clap::Command::new("deploy"), &spec, false);
        assert!(
            rpc.try_get_matches_from(["deploy", "--restore-custody"])
                .is_err()
        );
        for verb in ["start", "stop", "destroy", "update"] {
            let spec = erpc_core::chain::Verb {
                name: verb,
                about: "fixture",
                read_only: false,
            };
            assert!(
                crate::kaia_tree::args(clap::Command::new(verb), &spec, true)
                    .try_get_matches_from([verb, "--restore-custody"])
                    .is_err()
            );
        }
    }

    #[test]
    fn candidate_uses_observed_ssh_listener_and_refuses_unknown_port() {
        let node = Node::rpc(KaiaRpc {
            id: Some("fixtureowner".into()),
            network: "kairos".into(),
            genesis: Network::Kairos.genesis().into(),
            image: erpc_chain_kaia::release::IMAGE.into(),
            version: Network::Kairos.recommended().into(),
            commit: erpc_chain_kaia::release::COMMIT.into(),
            platform: "amd64".into(),
            storage: "full".into(),
            snapshot: "genesis".into(),
            ssh_port: 2222,
            ..KaiaRpc::default()
        });
        let observed = "os=ubuntu 24.04\nmachine=x86_64\nmem_kb=64000000\ncpus=8\nsudo=yes\ncontroller=192.0.2.1\n";
        let candidate = variables(
            &node,
            Network::Kairos,
            &Facts::parse(&format!("{observed}ssh_port=22\n")),
        )
        .unwrap();
        assert_eq!(candidate["kaia_ssh_port"], 22);
        assert_eq!(node.ssh_port, 2222);
        for value in ["", "0", "invalid", "65536"] {
            let facts = Facts::parse(&format!("{observed}ssh_port={value}\n"));
            assert!(
                variables(&node, Network::Kairos, &facts)
                    .unwrap_err()
                    .contains("SSH listener")
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rendered_startup_authenticates_paths_before_interpreting_helper_bytes() {
        use std::io::Write;
        let built = bundle("all: {hosts: {fixture: {ansible_connection: local}}}").unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-kaia/tests/entrypoints.py");
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

    use super::*;
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
    fn public_request_binds_snapshot_retention_and_configuration() {
        let mut node = Node::rpc(KaiaRpc {
            id: Some("fixtureowner".into()),
            network: "mainnet".into(),
            genesis: Network::Mainnet.genesis().into(),
            version: erpc_chain_kaia::release::VERSION.into(),
            commit: erpc_chain_kaia::release::COMMIT.into(),
            image: erpc_chain_kaia::release::IMAGE.into(),
            platform: "amd64".into(),
            storage: "full".into(),
            snapshot: "genesis".into(),
            ..KaiaRpc::default()
        });
        let before = request(&node, Network::Mainnet, "status").expect("public request");
        node.management_allow.push("192.0.2.1".into());
        assert_ne!(
            before["config_id"],
            request(&node, Network::Mainnet, "status").expect("changed request")["config_id"]
        );
        assert!(request(&node, Network::Kairos, "status").is_err());
    }
}
