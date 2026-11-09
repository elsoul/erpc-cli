// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! RPC ownership and shared public supervisor orchestration.
use crate::{
    commands::Outcome,
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, hyperliquid::HyperliquidNode};
use erpc_chain_hyperliquid::{Network, contract::Contract};
use erpc_ssh::{
    HostKey, Identity, RemoteCommand, Session, Target,
    hyperliquid::{Command as HostCommand, Owner},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub(crate) fn one<'a>(args: &'a ArgMatches, key: &str) -> Option<&'a str> {
    args.try_get_one::<String>(key)
        .ok()
        .flatten()
        .map(String::as_str)
}
pub(crate) fn flag(args: &ArgMatches, key: &str) -> bool {
    args.try_get_one::<bool>(key)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
pub(crate) fn nonce() -> Result<String, String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| "cannot create public operation identity")?;
    let alphabet = b"0123456789abcdef";
    let mut result = String::with_capacity(32);
    for byte in bytes {
        result.push(char::from(alphabet[usize::from(byte >> 4)]));
        result.push(char::from(alphabet[usize::from(byte & 15)]));
    }
    Ok(result)
}
pub(crate) fn open(network: Network, args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        network.name(),
        one(args, "vault"),
        "pass --vault <network inventory vault>",
    )?;
    Ok((
        node_common::store(
            &node_common::op_runner()?,
            &vault,
            "hyperliquid",
            network.name(),
        )?,
        vault,
    ))
}
fn canonical(values: &[String], public: bool) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    for value in erpc_chain_op::access::list(values, public)? {
        let address = value
            .split('/')
            .next()
            .ok_or("missing access address")?
            .parse::<std::net::IpAddr>()
            .map_err(|_| "invalid access address")?;
        if matches!(address,std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()) {
            return Err(
                "IPv4-mapped IPv6 ranges are ambiguous; use the canonical IPv4 range".into(),
            );
        }
        result.push(if value.contains('/') {
            value
        } else {
            format!("{value}/{}", if address.is_ipv4() { 32 } else { 128 })
        });
    }
    result.sort_unstable();
    result.dedup();
    Ok(result)
}
pub(crate) fn settings(node: &mut HyperliquidNode, args: &ArgMatches) -> Result<(), String> {
    for (name, public, list) in [
        ("rpc-allow", true, &mut node.rpc_allow),
        ("management-allow", false, &mut node.management_allow),
    ] {
        if let Some(values) = args.try_get_many::<String>(name).ok().flatten() {
            *list = values.cloned().collect();
        }
        *list = canonical(list, public)?;
    }
    Ok(())
}
pub(crate) fn target(node: &HyperliquidNode, args: &ArgMatches) -> Result<Target, String> {
    Ok(Target {
        host: node.address.clone(),
        port: node.ssh_port,
        user: node.ssh_user.clone(),
        host_key: HostKey::parse(&node.host_key).map_err(|e| e.to_string())?,
        identity: Identity::Agent {
            socket: node_common::agent_socket(
                args.try_get_one::<PathBuf>("ssh-agent")
                    .ok()
                    .flatten()
                    .map(PathBuf::as_path),
            )?,
            public_key: args
                .try_get_one::<PathBuf>("ssh-key")
                .ok()
                .flatten()
                .cloned()
                .ok_or("pass --ssh-key <operator public key>")?,
        },
    })
}
pub(crate) fn request(node: &HyperliquidNode, action: &str, intent: &str) -> Result<Value, String> {
    let profile = node.contract.network.profile()?;
    let policy = json!({"rpc_allow":node.rpc_allow,"management_allow":node.management_allow});
    let mut helper = Sha256::new();
    for name in erpc_ssh::hyperliquid::RUNTIME_FILES {
        helper.update(
            erpc_chain_hyperliquid::file(&format!("node/{name}"))
                .ok_or("missing compiled native helper")?,
        );
    }
    Ok(
        json!({"action":action,"contract":node.contract,"policy":policy,"intent":intent,"target":{
        "id":profile["supervisor"]["id"],"sha256":profile["supervisor"]["sha256"],"signed_at":profile["supervisor"]["signed_at"],
        "helper_sha":format!("{:x}",helper.finalize()),"config_id":format!("{:x}",Sha256::digest(policy.to_string().as_bytes()))}}),
    )
}
pub(crate) fn control(session: &Session, value: &Value) -> Result<Value, String> {
    let output = session
        .run(
            &RemoteCommand::Hyperliquid(HostCommand::Control),
            Some(value.to_string().as_bytes()),
        )
        .map_err(|_| "Hyperliquid control refused; original data and ownership remain retained")?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid public Hyperliquid response".into())
}
pub(crate) fn facts(session: &Session) -> Result<crate::eth_rpc::Facts, String> {
    let facts = crate::eth_rpc::facts(session)?;
    if facts.os != "ubuntu 24.04"
        || facts.machine != "x86_64"
        || !facts.sudo
        || facts.cpus < 16
        || facts.mem_kb < 120_000_000
        || facts.ssh_port == 0
    {
        return Err("Hyperliquid RPC requires Ubuntu24.04 x86-64, sixteen CPU cores,128GB RAM, passwordless sudo and an observable SSH server port; native preflight checks its500GB-class data volume".into());
    }
    Ok(facts)
}
pub(crate) fn inventory(
    node: &HyperliquidNode,
    facts: &crate::eth_rpc::Facts,
    intent: &str,
) -> Result<String, String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for address in &node.management_allow {
        if address.contains(':') {
            v6.push(address.clone());
        } else {
            v4.push(address.clone());
        }
    }
    match facts.controller_ip()? {
        std::net::IpAddr::V4(ip) => v4.push(ip.to_string()),
        std::net::IpAddr::V6(ip) => v6.push(ip.to_string()),
    }
    if facts.ssh_port == 0 {
        return Err("cannot identify the actual host SSH listener".into());
    }
    Ok(json!({"all":{"hosts":{node.name.clone():{"ansible_connection":"local","hyperliquid_request":request(node,"prepare",intent)?,
        "hyperliquid_management_v4":v4,"hyperliquid_management_v6":v6,"hyperliquid_ssh_port":facts.ssh_port}}}}).to_string())
}
pub(crate) fn play(
    session: &Session,
    target: &Target,
    inventory: &str,
    phase: &str,
    say: &Say,
) -> Result<(erpc_ssh::RunId, String), String> {
    if ![
        "preflight",
        "initialize",
        "prepare",
        "firewall",
        "activate",
        "recover-private-filesystem",
    ]
    .contains(&phase)
    {
        return Err("unknown Hyperliquid deployment phase".into());
    }
    let mut bundle = erpc_ops::bundle::Bundle::new();
    for name in erpc_chain_hyperliquid::files() {
        bundle
            .add(
                name,
                erpc_chain_hyperliquid::file(name)
                    .ok_or("missing embedded resource")?
                    .to_vec(),
            )
            .map_err(|e| e.to_string())?;
    }
    bundle
        .add("rpc-firewall.py", erpc_ops::RPC_FIREWALL.to_vec())
        .map_err(|e| e.to_string())?;
    bundle
        .add("inventory.yml", inventory.as_bytes().to_vec())
        .map_err(|e| e.to_string())?;
    let built = bundle.finish().map_err(|e| e.to_string())?;
    let run = erpc_ops::run::start(session, &built, &format!("ansible/hyperliquid/{phase}.yml"))
        .map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Retry the same qualified target after repairing the reported host condition; retained native data is preserved",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "Hyperliquid {phase} failed in {}; retained state remains fenced",
            run.as_str()
        ));
    }
    Ok((run, built.sha256))
}
fn init(network: Network, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let name = one(args, "name").ok_or("pass --name <inventory host>")?;
    let (store, vault) = open(network, args)?;
    let previous = store
        .hyperliquid_nodes()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|node| node.name == name);
    let profile = network.profile()?;
    let mut node = if let Some(node) = previous.as_ref() {
        for (flag, stored) in [
            ("host", node.address.as_str()),
            ("user", node.ssh_user.as_str()),
            ("public-ip", node.contract.public_ip.as_str()),
        ] {
            if one(args, flag).is_some_and(|value| value != stored) {
                return Err(
                    "original Hyperliquid host and peer advertisement cannot change".into(),
                );
            }
        }
        if args
            .try_get_one::<u16>("port")
            .ok()
            .flatten()
            .is_some_and(|port| *port != node.ssh_port)
        {
            return Err("original SSH port cannot change".into());
        }
        node.clone()
    } else {
        HyperliquidNode {
            id: None,
            item_version: 0,
            name: name.into(),
            address: one(args, "host").ok_or("pass --host <server>")?.into(),
            ssh_user: one(args, "user").unwrap_or("ubuntu").into(),
            ssh_port: args
                .try_get_one::<u16>("port")
                .ok()
                .flatten()
                .copied()
                .unwrap_or(22),
            host_key: String::new(),
            contract: Contract {
                owner: nonce()?,
                network,
                role: "rpc".into(),
                validator: None,
                public_ip: one(args, "public-ip")
                    .ok_or("pass --public-ip <native public IPv4>")?
                    .into(),
            },
            supervisor_sha256: profile["supervisor"]["sha256"]
                .as_str()
                .ok_or("invalid compiled supervisor")?
                .into(),
            signed_at: profile["supervisor"]["signed_at"]
                .as_u64()
                .ok_or("invalid signature timestamp")?,
            rpc_allow: vec![],
            management_allow: vec![],
            last_run: String::new(),
            last_result: String::new(),
        }
    };
    node.contract.validate()?;
    settings(&mut node, args)?;
    erpc_ssh::config::check_host(&node.address).map_err(|e| e.to_string())?;
    node.host_key = node_common::host_key(
        &node.address,
        node.ssh_port,
        previous.as_ref().map(|n| n.host_key.as_str()),
        one(args, "fingerprint"),
        say,
    )?
    .to_openssh();
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let facts = facts(&session)?;
    say.line("Reserve a dedicated non-validator host and persistent numeric service identities. Native wallet funding and validator signing are not part of this RPC operation.");
    node_common::go_ahead(flag(args, "yes"), "Hyperliquid host unchanged")
        .map_err(|e| e.to_string())?;
    let vars = inventory(&node, &facts, &nonce()?)?;
    play(&session, &target, &vars, "preflight", say)?;
    node = if previous.is_some() {
        store.update_hyperliquid_node(&node)
    } else {
        store.add_hyperliquid_node(&node)
    }
    .map_err(|e| e.to_string())?;
    let (run, _) = play(&session, &target, &vars, "initialize", say)?;
    node.last_run = run.as_str().into();
    node.last_result = "initialized".into();
    store
        .update_hyperliquid_node(&node)
        .map_err(|e| e.to_string())?;
    node_common::save_vault(network.name(), &vault)?;
    Ok(
        json!({"name":name,"network":network.name(),"role":"rpc","phase":"initialized","started":false}),
    )
}
fn operation(
    verb: &str,
    network: Network,
    args: &ArgMatches,
    json_out: bool,
) -> Result<Value, String> {
    let say = Say { quiet: json_out };
    if verb == "init" {
        return init(network, args, &say);
    }
    if verb == "plan" && one(args, "name").is_none() {
        return Ok(
            json!({"network":network.name(),"role":"rpc","qualified_profile":network.profile()?,"child_update_policy":"vendor-managed","changed":false}),
        );
    }
    let (store, _) = open(network, args)?;
    let nodes = store.hyperliquid_nodes().map_err(|e| e.to_string())?;
    if verb == "list" {
        return Ok(
            json!({"nodes":nodes.iter().map(|n|json!({"name":n.name,"network":network.name(),"supervisor_sha256":n.supervisor_sha256,"last_result":n.last_result})).collect::<Vec<_>>()}),
        );
    }
    let name = one(args, "name").ok_or("pass --name <inventory host>")?;
    let mut node = nodes
        .into_iter()
        .find(|n| n.name == name)
        .ok_or("Hyperliquid host is not initialized in this network")?;
    node.contract.validate()?;
    settings(&mut node, args)?;
    if verb == "plan" {
        return Ok(
            json!({"contract":node.contract,"current_supervisor_sha256":node.supervisor_sha256,"qualified_profile":network.profile()?,"rpc_allow":node.rpc_allow,"management_allow":node.management_allow,"changed":false}),
        );
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if verb == "logs" {
        session.stream(&RemoteCommand::Hyperliquid(HostCommand::Logs{owner:Owner::new(&node.contract.owner)?,lines:args.get_one::<u32>("lines").copied().unwrap_or(100),follow:flag(args,"follow")}),&mut|stream,line|{
            if json_out{crate::print_line(&json!({"journal":line,"stream":match stream{erpc_ssh::Stream::Stdout=>"stdout",erpc_ssh::Stream::Stderr=>"stderr"}}).to_string());}else{say.line(line);}
        }).map_err(|e|e.to_string())?;
        return Ok(json!({"journal":"ended"}));
    }
    if verb == "status" {
        return control(
            &session,
            &json!({"action":"status","contract":node.contract}),
        );
    }
    node_common::go_ahead(flag(args, "yes"), "Hyperliquid host unchanged")
        .map_err(|e| e.to_string())?;
    if ["start", "stop", "restart", "destroy"].contains(&verb) {
        let action = if verb == "destroy" { "retire" } else { verb };
        return control(&session, &json!({"action":action,"contract":node.contract}));
    }
    if !["deploy", "update", "update-config"].contains(&verb) {
        return Err("unsupported Hyperliquid RPC operation".into());
    }
    let profile = network.profile()?;
    let sha = profile["supervisor"]["sha256"]
        .as_str()
        .ok_or("invalid qualified supervisor")?;
    let signed_at = profile["supervisor"]["signed_at"]
        .as_u64()
        .ok_or("invalid qualified signature time")?;
    if signed_at < node.signed_at {
        return Err("supervisor signature-time downgrade is refused".into());
    }
    if node.supervisor_sha256 != sha && verb != "update" {
        return Err(
            "qualified supervisor changed; inspect plan then select update explicitly".into(),
        );
    }
    let facts = facts(&session)?;
    let intent = nonce()?;
    if flag(args, "recover-preparation") {
        control(
            &session,
            &json!({"action":"recover-preparation","contract":node.contract}),
        )?;
    }
    control(&session, &request(&node, "authorize", &intent)?)?;
    let vars = inventory(&node, &facts, &intent)?;
    play(&session, &target, &vars, "prepare", &say)?;
    let (firewall_run, firewall_sha) = play(&session, &target, &vars, "firewall", &say)?;
    let mut confirm = request(&node, "firewall-confirm", &intent)?;
    confirm["firewall"] = json!({"run":firewall_run.as_str(),"bundle":firewall_sha});
    // A new SSH connection proves the just-applied management policy still
    // permits the caller before its exact candidate can become durable.
    let fresh = Session::open(&target)
        .map_err(|_| "fresh SSH confirmation failed; operation rollback remains armed")?;
    control(&fresh, &confirm)?;
    let activated = erpc_ops::firewall_inventory(&vars, &firewall_run, &firewall_sha)?;
    let (run, _) = play(&fresh, &target, &activated, "activate", &say)?;
    node.supervisor_sha256 = sha.into();
    node.signed_at = signed_at;
    node.last_run = run.as_str().into();
    node.last_result = "started; synchronization observation pending".into();
    store
        .update_hyperliquid_node(&node)
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"name":node.name,"network":network.name(),"supervisor_sha256":sha,"started":true,"child_update_policy":"vendor-managed","ready":"inspect status after synchronization"}),
    )
}

pub(crate) fn run(verb: &str, args: &ArgMatches, network: Option<&str>, json_out: bool) -> Outcome {
    let Some(network) = network.and_then(Network::parse) else {
        return Outcome::Usage("Hyperliquid RPC requires --network mainnet or testnet".into());
    };
    if !["list", "plan"].contains(&verb) && one(args, "name").is_none() {
        return Outcome::Usage("pass --name <inventory host>".into());
    }
    match operation(verb, network, args, json_out) {
        Ok(value) => {
            let unready = verb == "status" && value["ready"] != true;
            let text = if json_out {
                crate::print_line(&value.to_string());
                String::new()
            } else {
                serde_json::to_string_pretty(&value).unwrap_or_default()
            };
            if unready {
                Outcome::Problems(text)
            } else {
                Outcome::Done(text)
            }
        }
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node() -> HyperliquidNode {
        let pin = Network::Testnet.profile().unwrap();
        HyperliquidNode {
            id: None,
            item_version: 0,
            name: "fixture".into(),
            address: "192.0.2.10".into(),
            ssh_user: "operator".into(),
            ssh_port: 2222,
            host_key: String::new(),
            contract: Contract {
                owner: "a".repeat(32),
                network: Network::Testnet,
                role: "rpc".into(),
                validator: None,
                public_ip: "8.8.8.8".into(),
            },
            supervisor_sha256: pin["supervisor"]["sha256"].as_str().unwrap().into(),
            signed_at: pin["supervisor"]["signed_at"].as_u64().unwrap(),
            rpc_allow: vec![],
            management_allow: vec![],
            last_run: String::new(),
            last_result: String::new(),
        }
    }
    #[test]
    fn firewall_uses_observed_server_port_and_refuses_unknown_listener() {
        let node = node();
        let mut facts = crate::eth_rpc::Facts {
            controller: "192.0.2.20".into(),
            ssh_port: 22,
            ..Default::default()
        };
        let values: Value =
            serde_json::from_str(&inventory(&node, &facts, &"b".repeat(32)).unwrap()).unwrap();
        let host = &values["all"]["hosts"]["fixture"];
        assert_eq!(host["hyperliquid_ssh_port"], 22);
        assert_eq!(host["hyperliquid_management_v4"], json!(["192.0.2.20"]));
        facts.ssh_port = 0;
        assert!(inventory(&node, &facts, &"b".repeat(32)).is_err());
        facts.ssh_port = 22;
        facts.controller = "$(inert)".into();
        assert!(inventory(&node, &facts, &"b".repeat(32)).is_err());
    }
    #[test]
    fn all_twelve_verbs_parse_and_recovery_is_explicitly_scoped() {
        use erpc_core::chain::{COMMON_VERBS, Chain, Role};
        for verb in COMMON_VERBS {
            let parsed = crate::tree::command(Role::Rpc, Chain::Hyperliquid)
                .try_get_matches_from(["rpc", "--network", "testnet", verb.name])
                .unwrap();
            assert_eq!(parsed.subcommand_name(), Some(verb.name));
            if !["list", "plan"].contains(&verb.name) {
                let sub = parsed.subcommand_matches(verb.name).unwrap();
                assert!(matches!(
                    run(verb.name, sub, Some("testnet"), false),
                    Outcome::Usage(_)
                ));
            }
            let recovery = crate::tree::command(Role::Rpc, Chain::Hyperliquid)
                .try_get_matches_from(["rpc", verb.name, "--recover-preparation"]);
            assert_eq!(
                recovery.is_ok(),
                ["deploy", "update", "update-config"].contains(&verb.name)
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn actual_carried_qualification_accepts_controller_policy_and_runtime_digests() {
        let mut node = node();
        node.rpc_allow = canonical(&["192.0.2.20".into(), "192.0.2.20/32".into()], true).unwrap();
        node.management_allow = canonical(&["2001:db8::20".into()], false).unwrap();
        assert_eq!(node.rpc_allow, vec!["192.0.2.20/32"]);
        assert!(canonical(&["::ffff:192.0.2.20".into()], false).is_err());
        let payload = request(&node, "prepare", &"b".repeat(32)).unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-hyperliquid/templates/node");
        let program = "import os,sys,json\nsys.dont_write_bytecode=True\nsys.path.insert(0,sys.argv[1])\nimport erpc_hl_host as h,erpc_hl_common as c\nh.read=lambda p:c.read(p,owner=os.getuid())\nh.qualified(json.load(sys.stdin))\n";
        let mut child = std::process::Command::new("python3")
            .args(["-I", "-c", program])
            .arg(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(
            &mut child.stdin.take().unwrap(),
            payload.to_string().as_bytes(),
        )
        .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
