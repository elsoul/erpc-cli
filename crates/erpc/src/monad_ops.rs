// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Native Monad orchestration with exact ownership and external financial signing.
use crate::{
    commands::Outcome,
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, monad::MonadNode};
use erpc_chain_monad::{contract::Contract, registration::Registration};
use erpc_core::chain::Role;
use erpc_secret::OpRef;
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target, monad::Command as HostCommand};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use std::path::PathBuf;

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
fn catalog() -> Result<Value, String> {
    serde_json::from_slice(
        erpc_chain_monad::file("node/catalog.json").ok_or("compiled Monad catalog is missing")?,
    )
    .map_err(|_| "invalid compiled Monad catalog".into())
}
fn pin() -> Result<Value, String> {
    let c = catalog()?;
    Ok(
        json!({"version":c["version"],"consensus_commit":c["consensus_commit"],"execution_commit":c["execution_commit"]}),
    )
}
fn open(network: &str, args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        network,
        one(args, "vault"),
        "initialize with --vault <network vault>",
    )?;
    Ok((
        node_common::store(&node_common::op_runner()?, &vault, "monad", network)?,
        vault,
    ))
}
fn target(node: &MonadNode, args: &ArgMatches) -> Result<Target, String> {
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
                .ok_or("pass --ssh-key <operator public key file>")?,
        },
    })
}
fn request(node: &MonadNode, operation: &str) -> Value {
    json!({"contract":node.contract,"operation":operation})
}
fn control(session: &Session, request: &Value) -> Result<Value, String> {
    let output = session
        .run(
            &RemoteCommand::Monad(HostCommand::Control),
            Some(request.to_string().as_bytes()),
        )
        .map_err(|_| "Monad control operation refused; inspect the owned state before retrying")?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid public Monad response".into())
}
fn settings(node: &mut MonadNode, args: &ArgMatches) -> Result<(), String> {
    for (name, public, list) in [
        ("rpc-allow", true, &mut node.rpc_allow),
        ("management-allow", false, &mut node.management_allow),
        ("monitoring-allow", false, &mut node.monitoring_allow),
    ] {
        if let Some(values) = args.try_get_many::<String>(name).ok().flatten() {
            *list = values.cloned().collect();
        }
        *list = erpc_chain_op::access::list(list, public)?;
    }
    Ok(())
}
fn facts(session: &Session) -> Result<crate::eth_rpc::Facts, String> {
    let f = crate::eth_rpc::facts(session)?;
    if f.os != "ubuntu 24.04"
        || f.machine != "x86_64"
        || !f.sudo
        || f.mem_kb < 30_000_000
        || f.cpus < 16
        || f.root_free_kb < 12_000_000
    {
        return Err("Monad requires Ubuntu 24.04 x86-64, passwordless sudo, 32 GB RAM, 16 physical CPUs and 12 GB free system space; host preflight also checks bare metal and disabled SMT".into());
    }
    Ok(f)
}
fn inventory(
    node: &MonadNode,
    f: &crate::eth_rpc::Facts,
    intent: &str,
    initial: bool,
    initialize_device: bool,
) -> Result<String, String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for range in &node.management_allow {
        if range.contains(':') {
            v6.push(range.clone());
        } else {
            v4.push(range.clone());
        }
    }
    match f.controller_ip()? {
        std::net::IpAddr::V4(ip) => v4.push(ip.to_string()),
        std::net::IpAddr::V6(ip) => v6.push(ip.to_string()),
    }
    Ok(json!({"all":{"hosts":{node.name.clone():{"ansible_connection":"local","monad_initial":initial,
 "monad_request":{"contract":node.contract,"target":pin()?,"intent":intent},"monad_initialize_device":initialize_device,
 "monad_ssh_port":node.ssh_port,"monad_management_v4":v4,"monad_management_v6":v6,
 "monad_rpc_allow":node.rpc_allow,"monad_monitoring_allow":node.monitoring_allow}}}}).to_string())
}
fn recovery_inventory(
    name: &str,
    contract: &impl serde::Serialize,
    original_uuid: &str,
) -> Result<String, String> {
    let parts: Vec<_> = original_uuid.split('-').collect();
    if parts.iter().map(|value| value.len()).collect::<Vec<_>>() != [8, 4, 4, 4, 12]
        || !parts.iter().all(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        || original_uuid.bytes().all(|byte| b"0-".contains(&byte))
    {
        return Err("pass the independently recorded original lowercase filesystem UUID, not the raw execution PARTUUID".into());
    }
    Ok(json!({"all":{"hosts":{name:{"ansible_connection":"local",
        "monad_request":{"contract":contract,"original_uuid":original_uuid}}}}})
    .to_string())
}
fn bundle(inventory: &str) -> Result<erpc_ops::bundle::Built, String> {
    let mut bundle = erpc_ops::bundle::Bundle::new();
    for path in erpc_chain_monad::files() {
        bundle
            .add(
                path,
                erpc_chain_monad::file(path)
                    .ok_or("missing embedded Monad file")?
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
    bundle.finish().map_err(|e| e.to_string())
}
fn play(
    session: &Session,
    target: &Target,
    inventory: &str,
    phase: &str,
    say: &Say,
) -> Result<(erpc_ssh::RunId, String), String> {
    let built = bundle(inventory)?;
    let entry = match phase {
        "preflight" => "ansible/monad/preflight.yml",
        "prepare" => "ansible/monad/prepare.yml",
        "firewall" => "ansible/monad/firewall.yml",
        "activate" => "ansible/monad/activate.yml",
        "recover-data-filesystem" => "ansible/monad/recover-data-filesystem.yml",
        _ => return Err("unknown Monad phase".into()),
    };
    let run = erpc_ops::run::start(session, &built, entry).map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Retry the same target to recover; raw device initialization never repeats automatically",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "Monad {phase} failed in {}; retained data and identity were preserved",
            run.as_str()
        ));
    }
    Ok((run, built.sha256))
}
fn new_intent() -> Result<String, String> {
    let mut value = [0; 16];
    getrandom::fill(&mut value).map_err(|_| "cannot create operation identity")?;
    Ok(erpc_chain_monad::contract::hex(&value))
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeKey {
    public_key: String,
    keystore_base64: SecretString,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeBundle {
    schema: u8,
    secp: NativeKey,
    bls: NativeKey,
}
fn material(node: &MonadNode) -> Result<SecretString, String> {
    let reference =
        OpRef::parse(&node.keys_ref).map_err(|_| "invalid original native key reference")?;
    let secret = crate::rollup_credentials::read_concealed(&node_common::op_runner()?, &reference)?;
    if secret.expose_secret().len() > 32768 {
        return Err("native identity bundle exceeds 32 KiB".into());
    }
    let parsed: NativeBundle = serde_json::from_str(secret.expose_secret())
        .map_err(|_| "invalid concealed native key bundle")?;
    if parsed.schema != 1
        || parsed.secp.public_key != node.contract.secp
        || parsed.bls.public_key != node.contract.bls
        || [parsed.secp.keystore_base64, parsed.bls.keystore_base64]
            .iter()
            .any(|v| v.expose_secret().is_empty() || v.expose_secret().len() > 8192)
    {
        return Err("original native identity bundle differs from reserved public keys".into());
    }
    Ok(secret)
}
fn import(
    session: &Session,
    node: &MonadNode,
    secret: &SecretString,
    intent: &str,
    restore: bool,
) -> Result<Value, String> {
    let mut public = request(
        node,
        if restore {
            "restore-identity"
        } else {
            "import-identity"
        },
    );
    public["intent"] = json!(intent);
    let public = public.to_string();
    let encoded = SecretString::from(format!(
        "{},\"identity\":{}}}",
        public
            .strip_suffix('}')
            .ok_or("invalid public import request")?,
        secret.expose_secret()
    ));
    let output = session
        .run(
            &RemoteCommand::Monad(HostCommand::Control),
            Some(encoded.expose_secret().as_bytes()),
        )
        .map_err(|_| "native identity import/restore refused; no replacement key was generated")?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid public identity response".into())
}
#[allow(clippy::too_many_lines)]
fn init(network: &str, role: &str, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let (store, vault) = open(network, args)?;
    let name = one(args, "name").ok_or("init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    let existing = store
        .monad_nodes(role)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name);
    let c = catalog()?;
    let mut node = if let Some(old) = existing.clone() {
        for (field, stored) in [
            ("host", old.address.as_str()),
            ("device-partuuid", old.contract.partuuid.as_str()),
            ("public-ip", old.contract.public_ip.as_str()),
            ("secp-public-key", old.contract.secp.as_str()),
            ("bls-public-key", old.contract.bls.as_str()),
            ("keys-ref", old.keys_ref.as_str()),
            ("beneficiary", old.contract.beneficiary.as_str()),
            ("auth-address", old.contract.auth_address.as_str()),
        ] {
            if one(args, field).is_some_and(|v| v != stored) {
                return Err("init cannot replace immutable host/device/identity fields".into());
            }
        }
        old
    } else {
        if !flag(args, "exclusive-identity") {
            return Err("initial reservation requires --exclusive-identity for dedicated unhosted consensus keys; financial keys stay external".into());
        }
        let value = |key| {
            one(args, key)
                .map(str::to_owned)
                .ok_or_else(|| format!("init requires --{key}"))
        };
        let zero = format!("0x{}", "0".repeat(40));
        MonadNode {
            id: None,
            item_version: 0,
            name: name.into(),
            address: value("host")?,
            ssh_user: one(args, "user").unwrap_or("ubuntu").into(),
            ssh_port: args.get_one::<u16>("port").copied().unwrap_or(22),
            host_key: String::new(),
            contract: Contract {
                owner: new_intent()?,
                network: network.into(),
                role: role.into(),
                partuuid: value("device-partuuid")?,
                public_ip: value("public-ip")?,
                name_record_sequence: *args
                    .get_one::<u64>("name-record-sequence")
                    .ok_or("init requires explicit --name-record-sequence")?,
                secp: value("secp-public-key")?,
                bls: value("bls-public-key")?,
                beneficiary: if role == "validator" {
                    value("beneficiary")?
                } else {
                    zero.clone()
                },
                auth_address: if role == "validator" {
                    value("auth-address")?
                } else {
                    zero
                },
            },
            keys_ref: value("keys-ref")?,
            version: c["version"].as_str().ok_or("invalid catalog")?.into(),
            consensus_commit: c["consensus_commit"]
                .as_str()
                .ok_or("invalid catalog")?
                .into(),
            execution_commit: c["execution_commit"]
                .as_str()
                .ok_or("invalid catalog")?
                .into(),
            rpc_allow: vec![],
            management_allow: vec![],
            monitoring_allow: vec![],
            last_run: String::new(),
            last_result: String::new(),
        }
    };
    node.contract.validate()?;
    OpRef::parse(&node.keys_ref).map_err(|_| "use an identifier-only concealed key reference")?;
    settings(&mut node, args)?;
    erpc_ssh::config::check_host(&node.address).map_err(|e| e.to_string())?;
    let key = node_common::host_key(
        &node.address,
        node.ssh_port,
        existing.as_ref().map(|n| n.host_key.as_str()),
        one(args, "fingerprint"),
        say,
    )?;
    node.host_key = key.to_openssh();
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    session
        .run(
            &RemoteCommand::Monad(HostCommand::Probe),
            Some(json!({"contract":node.contract}).to_string().as_bytes()),
        )
        .map_err(
            |_| "remote ownership mismatch or unowned artifacts; no inventory reservation made",
        )?;
    let f = facts(&session)?;
    say.line("Reserve the dedicated Monad host and specified raw partition, install the authenticated native package and persistent permissions. Initializing TrieDB requires a separate deploy --initialize-device.");
    node_common::go_ahead(flag(args, "yes"), "Monad host unchanged").map_err(|e| e.to_string())?;
    // Check the selected concealed bundle's public labels locally before any
    // immutable reservation. No native private material is sent during init.
    drop(material(&node)?);
    // A mistyped/missing partition or foreign native account must not leave an
    // immutable but unusable inventory reservation behind. This carried phase
    // checks hardware/device/ownership before storing the node or native state.
    let vars = inventory(&node, &f, &new_intent()?, true, false)?;
    play(&session, &target, &vars, "preflight", say)?;
    node = if existing.is_some() {
        store.update_monad_node(&node)
    } else {
        store.add_monad_node(&node)
    }
    .map_err(|e| e.to_string())?;
    let (run, _) = play(&session, &target, &vars, "prepare", say)?;
    node.last_run = run.as_str().into();
    node.last_result = "initialized; device not initialized".into();
    store.update_monad_node(&node).map_err(|e| e.to_string())?;
    node_common::save_vault(network, &vault)?;
    Ok(
        json!({"name":node.name,"network":network,"role":role,"state":"initialized","version":node.version,"raw_device_written":false}),
    )
}
#[allow(clippy::too_many_lines)]
fn operation(
    verb: &str,
    network: &str,
    role: &str,
    args: &ArgMatches,
    json_out: bool,
) -> Result<Value, String> {
    let say = Say { quiet: json_out };
    if verb == "init" {
        return init(network, role, args, &say);
    }
    let (store, _) = open(network, args)?;
    let nodes = store.monad_nodes(role).map_err(|e| e.to_string())?;
    if verb == "list" {
        return Ok(
            json!({"nodes":nodes.iter().map(|n|json!({"name":n.name,"network":network,"role":role,"version":n.version,"public_keys":{"secp":n.contract.secp,"bls":n.contract.bls},"last_result":n.last_result})).collect::<Vec<_>>()}),
        );
    }
    let name = one(args, "name").ok_or("pass --name <inventory node>")?;
    let mut node = nodes
        .into_iter()
        .find(|n| n.name == name)
        .ok_or("Monad node is not initialized in this network/role scope")?;
    node.contract.validate()?;
    settings(&mut node, args)?;
    let compiled = pin()?;
    if ["update", "plan"].contains(&verb)
        && one(args, "version").is_some_and(|v| Some(v) != compiled["version"].as_str())
    {
        return Err("version is not in this CLI's reviewed native catalog".into());
    }
    if verb == "plan" {
        return Ok(
            json!({"contract":node.contract,"current_version":node.version,"qualified_target":compiled,"change":one(args,"change").unwrap_or("deploy"),"device":"preserve; explicit first initialization only", "financial_signing":"external", "rpc_allow":node.rpc_allow,"monitoring_allow":node.monitoring_allow,"changed":false}),
        );
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if verb == "logs" {
        let command = RemoteCommand::Monad(HostCommand::Logs {
            owner: erpc_ssh::monad::Owner::new(&node.contract.owner)?,
            lines: args.get_one::<u32>("lines").copied().unwrap_or(100),
            follow: flag(args, "follow"),
        });
        session.stream(&command,&mut |stream,line|{if json_out {crate::print_line(&json!({"journal":line,"stream":match stream{erpc_ssh::Stream::Stdout=>"stdout",erpc_ssh::Stream::Stderr=>"stderr"}}).to_string());}else{say.line(line);}}).map_err(|e|e.to_string())?;
        return Ok(json!({"status":"journal ended"}));
    }
    if ["status", "check-identity", "registration-status"].contains(&verb) {
        let mut value = request(&node, verb);
        if verb == "registration-status" {
            value["validator_id"] = json!(
                *args
                    .get_one::<u64>("validator-id")
                    .ok_or("validator ID required")?
            );
        }
        return control(&session, &value);
    }
    if ["prepare-registration", "validate-registration"].contains(&verb) {
        if role != "validator" {
            return Err("registration requires validator role".into());
        }
        if control(&session, &request(&node, "status"))?["ready"] != true {
            return Err("registration preparation requires a fresh synchronized node on the reserved network".into());
        }
        control(&session, &request(&node, "check-identity"))?;
        if verb == "prepare-registration" {
            control(&session, &request(&node, "registration-preflight"))?;
        }
        let intent = if verb == "prepare-registration" {
            Registration {
                contract: node.contract.clone(),
                stake_wei: one(args, "stake-wei")
                    .ok_or("explicit stake wei required")?
                    .into(),
                commission: *args
                    .get_one::<u64>("commission")
                    .ok_or("explicit commission required")?,
            }
        } else {
            let path = args
                .get_one::<PathBuf>("file")
                .ok_or("registration file required")?;
            if std::fs::metadata(path)
                .map_err(|_| "cannot inspect registration file")?
                .len()
                > 16384
            {
                return Err("registration file exceeds limit".into());
            }
            let value: Value = serde_json::from_slice(
                &std::fs::read(path).map_err(|_| "cannot read registration file")?,
            )
            .map_err(|_| "invalid public registration file")?;
            Registration::parse_prepared(value)?
        };
        if intent.contract != node.contract {
            return Err("registration does not match this node/role/network".into());
        }
        return intent.review();
    }
    node_common::go_ahead(flag(args, "yes"), "Monad host unchanged").map_err(|e| e.to_string())?;
    if verb == "recover-data-filesystem" {
        let vars = recovery_inventory(
            &node.name,
            &node.contract,
            one(args, "original-uuid").ok_or("original filesystem UUID is required")?,
        )?;
        let (run, _) = play(&session, &target, &vars, "recover-data-filesystem", &say)?;
        return Ok(
            json!({"filesystem_identity_upgraded":true,"stopped":true,"history_preserved":true,"next_action":"resume original init if incomplete, otherwise deploy the qualified controller before starting","run":run.as_str()}),
        );
    }
    if ["start", "stop", "restart", "destroy", "recover-device"].contains(&verb) {
        return control(&session, &request(&node, verb));
    }
    if verb == "identity-restore" {
        let key = material(&node)?;
        return import(&session, &node, &key, "", true);
    }
    if !["deploy", "update", "update-config"].contains(&verb) {
        return Err("unsupported Monad operation".into());
    }
    let selected = compiled["version"].as_str().ok_or("invalid catalog")?;
    if node.version == selected
        && (node.consensus_commit != compiled["consensus_commit"]
            || node.execution_commit != compiled["execution_commit"])
    {
        return Err("same-version native source substitution is refused".into());
    }
    let version_parts = |value: &str| {
        value
            .split('.')
            .map(str::parse::<u16>)
            .collect::<Result<Vec<_>, _>>()
    };
    if version_parts(selected).map_err(|_| "invalid catalog version")?
        < version_parts(&node.version).map_err(|_| "invalid stored version")?
    {
        return Err("native downgrade is refused".into());
    }
    if verb != "update" && node.version != selected {
        return Err(
            "this CLI has a newer qualified release; choose update --version explicitly".into(),
        );
    }
    let f = facts(&session)?;
    let secret = material(&node)?;
    let intent = new_intent()?;
    let mut authorize = request(&node, "authorize");
    authorize["intent"] = json!(intent);
    authorize["target"] = compiled.clone();
    control(&session, &authorize)?;
    let vars = inventory(&node, &f, &intent, false, flag(args, "initialize-device"))?;
    play(&session, &target, &vars, "prepare", &say)?;
    import(&session, &node, &secret, &intent, false)?;
    let (fw, digest) = play(&session, &target, &vars, "firewall", &say)?;
    let fresh = Session::open(&target).map_err(|e| e.to_string())?;
    let mut confirm = request(&node, "firewall-confirm");
    confirm["intent"] = json!(intent);
    confirm["run"] = json!(fw.as_str());
    confirm["bundle"] = json!(digest);
    control(&fresh, &confirm)?;
    let confirmed = erpc_ops::firewall_inventory(&vars, &fw, &digest)?;
    let (run, _) = play(&fresh, &target, &confirmed, "activate", &say)?;
    node.version = compiled["version"]
        .as_str()
        .ok_or("invalid catalog")?
        .into();
    node.consensus_commit = compiled["consensus_commit"]
        .as_str()
        .ok_or("invalid catalog")?
        .into();
    node.execution_commit = compiled["execution_commit"]
        .as_str()
        .ok_or("invalid catalog")?
        .into();
    node.last_run = run.as_str().into();
    node.last_result = format!("{verb} completed; synchronization observed separately");
    store.update_monad_node(&node).map_err(|e| e.to_string())?;
    control(&fresh, &request(&node, "status"))
}
pub(crate) fn run(
    role: Role,
    verb: &str,
    args: &ArgMatches,
    network: Option<&str>,
    json_out: bool,
) -> Outcome {
    let Some(network) = network.filter(|n| ["mainnet", "testnet"].contains(n)) else {
        return Outcome::Usage("Monad requires explicit mainnet or testnet".into());
    };
    let role = if role == Role::Validator {
        "validator"
    } else {
        "rpc"
    };
    match operation(verb, network, role, args, json_out) {
        Ok(value) => {
            let text = if json_out {
                crate::print_line(&value.to_string());
                String::new()
            } else {
                serde_json::to_string_pretty(&value).unwrap_or_default()
            };
            if verb == "status" && value["ready"] != true {
                Outcome::Problems(text)
            } else {
                Outcome::Done(text)
            }
        }
        Err(message) => Outcome::Failed(message),
    }
}

#[cfg(test)]
mod filesystem_recovery_tests {
    use super::*;
    #[test]
    fn carried_recovery_inventory_contains_only_explicit_public_original_authority() {
        let contract = json!({"owner":"public-fixture","network":"testnet","role":"rpc"});
        let original = "00000000-0000-0000-0000-000000000001";
        let inventory = recovery_inventory("fixture", &contract, original).unwrap();
        let value: Value = serde_json::from_str(&inventory).unwrap();
        assert_eq!(
            value["all"]["hosts"]["fixture"]["monad_request"],
            json!({"contract":contract,"original_uuid":original})
        );
        assert!(!inventory.contains("initialize_device"));
        assert!(!inventory.contains("intent"));
        let built = bundle(&inventory).unwrap();
        assert!(!built.sha256.is_empty());
        let play = std::str::from_utf8(
            erpc_chain_monad::file("ansible/monad/recover-data-filesystem.yml").unwrap(),
        )
        .unwrap();
        assert!(play.contains("recover-data-filesystem"));
        assert!(!play.contains("publish-helpers"));
        for invalid in [
            "",
            "/dev/nvme0n1",
            "00000000-0000-0000-0000-000000000000",
            "abcd",
            "00000000-0000-0000-0000-00000000000G",
        ] {
            assert!(recovery_inventory("fixture", &contract, invalid).is_err());
        }
    }
}
