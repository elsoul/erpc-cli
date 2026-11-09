// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Owned Bor/Heimdall RPC lifecycle; parent credentials are carried only on stdin.
use crate::{
    commands::Outcome,
    eth_rpc::Facts,
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::{OpCli, OpRunner};
use erpc_chain::inventory::{
    Store,
    polygon::{PolygonNode, PolygonSentry, PolygonValidator},
};
use erpc_chain_polygon::network::Network;
use erpc_chain_rollup::upstreams::ExecutionCredential;
use erpc_ops::bundle::{Built, Bundle};
use erpc_secret::OpRef;
use erpc_ssh::{
    HostKey, Identity, RemoteCommand, Session, Target,
    polygon::{Command, Contract},
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn one<'a>(args: &'a ArgMatches, name: &str) -> Option<&'a str> {
    args.try_get_one::<String>(name)
        .ok()
        .flatten()
        .map(String::as_str)
}
fn flag(args: &ArgMatches, name: &str) -> bool {
    args.try_get_one::<bool>(name)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
fn owner(node: &PolygonNode) -> Result<&str, String> {
    node.id
        .as_deref()
        .filter(|id| {
            id.len() == 26
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        .ok_or_else(|| "Polygon requires a reserved stable inventory owner".into())
}
fn contract(node: &PolygonNode) -> Result<Value, String> {
    let profile = Network::get(&node.network)?;
    profile.platform(&node.architecture)?;
    let mut value = json!({"network":node.network,"owner":owner(node)?,"architecture":node.architecture,"role":node.role,
        "bor_genesis":profile.bor_genesis_hash,"heimdall_genesis":profile.heimdall_genesis.sha256});
    match node.role.as_str() {
        "fullnode" if node.validator.is_none() => {}
        "validator" => {
            let validator = node
                .validator
                .as_ref()
                .ok_or("Polygon validator authority is missing")?;
            if !validator.original_ready || validator.original_ref.is_empty() {
                return Err("original Polygon signer must read back from 1Password before any host ownership or key transfer".into());
            }
            value["signer"] = json!(validator.signer);
            value["stake_owner"] = json!(validator.stake_owner);
        }
        _ => return Err("unsupported Polygon inventory role".into()),
    }
    Ok(value)
}
fn reviewed(node: &PolygonNode) -> Result<Network, String> {
    let profile = Network::get(&node.network)?;
    if node.profile
        != serde_json::to_value(&profile).map_err(|_| "cannot encode Polygon profile")?
    {
        return Err("stored Polygon target differs from this CLI's reviewed catalog; use an appropriate CLI or explicit update".into());
    }
    profile.platform(&node.architecture)?;
    Ok(profile)
}
fn helpers() -> Result<String, String> {
    let mut digest = Sha256::new();
    for name in erpc_chain_polygon::HELPER_FILES {
        if *name == "upstreams.py" {
            digest.update(erpc_chain_rollup::UPSTREAM_PROXY.as_bytes());
        } else {
            digest.update(
                erpc_chain_polygon::TEMPLATES
                    .get_file(format!("scripts/{name}"))
                    .ok_or("missing compiled Polygon helper")?
                    .contents(),
            );
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn request(node: &PolygonNode, action: &str) -> Result<Value, String> {
    Ok(json!({"contract":contract(node)?,"action":action}))
}
fn control(session: &Session, body: &Value) -> Result<Value, String> {
    let output = session
        .run(
            &RemoteCommand::Polygon(Command::request()?),
            Some(body.to_string().as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid Polygon controller response".into())
}
fn credential<R: OpRunner>(runner: &R, reference: &str) -> Result<ExecutionCredential, String> {
    let reference = OpRef::parse(reference)
        .map_err(|_| "Polygon parent requires an identifier-only op reference")?;
    ExecutionCredential::parse(crate::rollup_credentials::read_concealed(
        runner, &reference,
    )?)
    .map_err(|_| "invalid concealed Polygon execution-parent configuration".to_string())
}
fn secret_request(base: &Value, secret: &ExecutionCredential) -> Result<SecretString, String> {
    if !base.is_object() {
        return Err("Polygon request must be a public object".into());
    }
    let encoded = base.to_string();
    let prefix = encoded
        .strip_suffix('}')
        .ok_or("cannot encode Polygon request")?;
    Ok(SecretString::from(format!(
        "{prefix},\"credential\":{}}}",
        secret.secret().expose_secret()
    )))
}
fn send_credential(
    session: &Session,
    base: &Value,
    secret: &ExecutionCredential,
) -> Result<(), String> {
    let mut request = base.clone();
    request["action"] = json!("credential");
    let encoded = secret_request(&request, secret)?;
    session
        .run(
            &RemoteCommand::Polygon(Command::request()?),
            Some(encoded.expose_secret().as_bytes()),
        )
        .map_err(|_| "Polygon parent credential import or chain identity verification failed")?;
    Ok(())
}
fn send_secret_action(
    session: &Session,
    base: &Value,
    secret: &ExecutionCredential,
) -> Result<(), String> {
    let encoded = secret_request(base, secret)?;
    session.run(&RemoteCommand::Polygon(Command::request()?), Some(encoded.expose_secret().as_bytes()))
        .map_err(|_| "Polygon original admission authorization failed; retain the observer and inspect external registration")?;
    Ok(())
}
fn signer_request(base: &Value, secret: &SecretString) -> Result<SecretString, String> {
    let scalar = secret
        .expose_secret()
        .strip_prefix("0x")
        .unwrap_or(secret.expose_secret());
    if !base.is_object()
        || scalar.len() != 64
        || !scalar.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid original Polygon signer transfer".into());
    }
    let address = erpc_wallet::evm::EvmKey::from_hex(scalar)
        .map_err(|_| "invalid original Polygon signer scalar")?
        .address()
        .to_string()
        .to_ascii_lowercase();
    if base["contract"]["role"] != "validator"
        || base["contract"]["signer"].as_str() != Some(address.as_str())
    {
        return Err("original Polygon signer differs from its immutable transfer scope".into());
    }
    let mut public = base.clone();
    public["action"] = json!("validator-key");
    let encoded = public.to_string();
    let prefix = encoded.strip_suffix('}').ok_or("invalid signer request")?;
    Ok(SecretString::from(format!(
        "{prefix},\"original_signer\":\"{scalar}\"}}"
    )))
}
fn send_signer(session: &Session, base: &Value, secret: &SecretString) -> Result<(), String> {
    let encoded = signer_request(base, secret)?;
    session
        .run(
            &RemoteCommand::Polygon(Command::request()?),
            Some(encoded.expose_secret().as_bytes()),
        )
        .map_err(|_| "Polygon original signer import failed; no new signer was generated")?;
    Ok(())
}
fn target(node: &PolygonNode, args: &ArgMatches) -> Result<Target, String> {
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
fn facts(session: &Session) -> Result<Facts, String> {
    let output = session
        .run(&RemoteCommand::Polygon(Command::facts()), None)
        .map_err(|e| e.to_string())?;
    Ok(Facts::parse(&String::from_utf8_lossy(&output.stdout)))
}
fn host_check(facts: &Facts, network: &str) -> Result<(), String> {
    let memory = if network == "mainnet" {
        60_000_000
    } else {
        15_000_000
    };
    if facts.os != "ubuntu 24.04" || !facts.sudo || facts.cpus < 16 || facts.mem_kb < memory {
        return Err("Polygon requires Ubuntu 24.04, passwordless sudo, 16 CPU cores and 64 GB RAM on Mainnet or 16 GB on Amoy".into());
    }
    Network::get(network)?.platform(&facts.machine)
}
fn open(network: &str, args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        network,
        one(args, "vault"),
        "erpc r --chain polygon init --network <mainnet|amoy> --vault <vault>",
    )?;
    Ok((
        node_common::store(&node_common::op_runner()?, &vault, "polygon", network)?,
        vault,
    ))
}
fn find(store: &Store<OpCli>, args: &ArgMatches, role: &str) -> Result<PolygonNode, String> {
    let name = one(args, "name").ok_or("Polygon operation requires --name")?;
    store
        .polygon_nodes(role)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name)
        .ok_or_else(|| "Polygon RPC node is not initialized in this network".into())
}
fn access(args: &ArgMatches, name: &str, old: &[String]) -> Result<Vec<String>, String> {
    let values = args
        .try_get_many::<String>(name)
        .ok()
        .flatten()
        .map_or_else(|| old.to_vec(), |v| v.cloned().collect());
    erpc_chain_op::access::list(&values, false)
}
fn advertise(value: &str) -> Result<String, String> {
    // Native configuration also applies the shared explicit IANA policy before use.
    value
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| "Polygon P2P advertisement requires a numeric public IP".into())
}
fn operation_profile(node: &PolygonNode) -> Value {
    let mut profile = node.profile.clone();
    if let Some(validator) = &node.validator {
        profile["validator"] = json!({"phase":validator.phase,"signer":validator.signer,"sentries":validator.sentries});
    }
    profile
}

fn variables(
    node: &PolygonNode,
    facts: Option<&Facts>,
    intent: &str,
    restore: bool,
) -> Result<Value, String> {
    let mut management = erpc_chain_op::access::list(&node.management_allow, false)?;
    if let Some(facts) = facts {
        host_check(facts, &node.network)?;
        if facts.machine != node.architecture {
            return Err("Polygon host architecture differs from its inventory".into());
        }
        let controller = facts.controller_ip()?.to_string();
        if !management.contains(&controller) {
            management.push(controller);
        }
    }
    let split = |values: Vec<String>| -> (Vec<String>, Vec<String>) {
        values.into_iter().partition(|v| !v.contains(':'))
    };
    let (management_v4, management_v6) = split(management);
    let (rpc_v4, rpc_v6) = split(erpc_chain_op::access::list(&node.rpc_allow, false)?);
    let (metrics_v4, metrics_v6) =
        split(erpc_chain_op::access::list(&node.monitoring_allow, false)?);
    Ok(
        json!({"ansible_connection":"local","polygon_network":node.network,"polygon_contract":contract(node)?,"polygon_profile":operation_profile(node),
        "polygon_helpers":helpers()?,"polygon_credential_condition":erpc_ssh::python::systemd_condition_command(&format!("/usr/local/lib/erpc/polygon/releases/{}/control.py",helpers()?))?,"polygon_service_guard":erpc_ssh::python::systemd_command(&format!("/usr/local/lib/erpc/polygon/releases/{}/control.py",helpers()?))?,"polygon_intent":intent,"polygon_advertise":advertise(&node.advertise_ip)?,"polygon_restore_keys":restore,
        "polygon_management_v4":management_v4,"polygon_management_v6":management_v6,"polygon_rpc_v4":rpc_v4,"polygon_rpc_v6":rpc_v6,
        "polygon_metrics_v4":metrics_v4,"polygon_metrics_v6":metrics_v6,"polygon_ssh_port":facts.map_or(node.ssh_port,|f|f.ssh_port)}),
    )
}
fn inventory(node: &PolygonNode, vars: &Value) -> String {
    json!({"all":{"hosts":{node.name.clone():vars}}}).to_string()
}
fn add_templates(dir: &include_dir::Dir<'_>, bundle: &mut Bundle) -> Result<(), String> {
    for file in dir.files() {
        bundle
            .add(
                file.path().to_str().ok_or("invalid template path")?,
                file.contents().to_vec(),
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
    add_templates(&erpc_chain_polygon::TEMPLATES, &mut bundle)?;
    for (name, bytes) in [
        ("inventory.yml", inventory.as_bytes()),
        (
            "scripts/upstreams.py",
            erpc_chain_rollup::UPSTREAM_PROXY.as_bytes(),
        ),
        ("rpc-firewall.py", erpc_ops::RPC_FIREWALL),
    ] {
        bundle
            .add(name, bytes.to_vec())
            .map_err(|e| e.to_string())?;
    }
    bundle.finish().map_err(|e| e.to_string())
}
fn play(
    session: &Session,
    target: &Target,
    built: &Built,
    play: &str,
    say: &Say,
) -> Result<erpc_ssh::RunId, String> {
    let run = erpc_ops::run::start(session, built, play).map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Retry the stored Polygon target; original identities and consensus history are retained",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "Polygon operation failed; ownership and data retained (run {})",
            run.as_str()
        ));
    }
    Ok(run)
}
fn intent() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "cannot generate a deployment intent")?;
    Ok(format!("{:032x}", u128::from_be_bytes(bytes)))
}
fn validator_sentries(
    args: &ArgMatches,
    previous: &[PolygonSentry],
) -> Result<Vec<PolygonSentry>, String> {
    let Some(values) = args.try_get_many::<String>("sentry").ok().flatten() else {
        return if previous.is_empty() {
            Err("a validator requires at least one explicit --sentry IP,BOR_NODE_ID,HEIMDALL_NODE_ID".into())
        } else {
            Ok(previous.to_vec())
        };
    };
    let mut peers = Vec::new();
    let mut addresses = std::collections::BTreeSet::new();
    for value in values {
        let fields: Vec<_> = value.split(',').collect();
        if fields.len() != 3 {
            return Err("expected --sentry IP,BOR_NODE_ID,HEIMDALL_NODE_ID".into());
        }
        let address = advertise(fields[0])?;
        let hex = |value: &str, size: usize| {
            value.len() == size && value.bytes().all(|b| b.is_ascii_hexdigit())
        };
        if !hex(fields[1], 128) || !hex(fields[2], 40) || !addresses.insert(address.clone()) {
            return Err("invalid or duplicate Polygon sentry identity".into());
        }
        peers.push(PolygonSentry {
            address,
            bor_node_id: fields[1].to_ascii_lowercase(),
            heimdall_node_id: fields[2].to_ascii_lowercase(),
        });
    }
    if peers.is_empty() || peers.len() > 8 {
        return Err("select between one and eight distinct Polygon sentries".into());
    }
    Ok(peers)
}
fn stake_owner(args: &ArgMatches) -> Result<String, String> {
    let value = one(args, "stake-owner")
        .ok_or("a fresh validator requires its external --stake-owner address")?;
    let parsed = erpc_wallet::evm::Address::parse(value)
        .map_err(|_| "invalid external Polygon stake-owner address")?;
    let normalized = parsed.to_string().to_ascii_lowercase();
    if normalized[2..].bytes().all(|b| b == b'0') {
        return Err("stake owner cannot be the zero address".into());
    }
    Ok(normalized)
}
fn original_signer<R: OpRunner>(
    op: &R,
    node: &PolygonNode,
    vault: &str,
    fresh: Option<&SecretString>,
) -> Result<crate::polygon_custody::Original, String> {
    let authority = node
        .validator
        .as_ref()
        .ok_or("Polygon validator authority is absent")?;
    let binding = crate::polygon_custody::Binding {
        vault,
        network: &node.network,
        owner: owner(node)?,
        creation: &authority.creation,
        address: &authority.signer,
    };
    let original = crate::polygon_custody::original(op, &binding, fresh)?;
    if authority.original_ready && authority.original_ref != original.reference {
        return Err("the original Polygon signer item cannot be reassigned".into());
    }
    Ok(original)
}

fn reserve_validator<R: OpRunner>(
    store: &Store<R>,
    op: &impl OpRunner,
    vault: &str,
    mut node: PolygonNode,
    fresh: Option<&SecretString>,
) -> Result<PolygonNode, String> {
    if node.role != "validator" || node.validator.is_none() {
        return Err("expected dedicated validator reservation".into());
    }
    if node.id.is_some() && fresh.is_some() {
        return Err("an existing validator can only recover its original key".into());
    }
    if node.id.is_none() {
        if fresh.is_none() {
            return Err("a new validator needs freshly generated original material".into());
        }
        node = store.add_polygon_node(&node).map_err(|e| e.to_string())?;
    }
    let original = original_signer(op, &node, vault, fresh)?;
    if !node
        .validator
        .as_ref()
        .ok_or("missing validator authority")?
        .original_ready
    {
        let authority = node
            .validator
            .as_mut()
            .ok_or("missing validator authority")?;
        authority.original_ref = original.reference;
        authority.original_ready = true;
        node = store
            .update_polygon_node(&node)
            .map_err(|e| e.to_string())?;
    }
    // contract() is also the host-transfer barrier: a public reservation alone
    // cannot authorize remote initialization or secret transfer.
    contract(&node)?;
    Ok(node)
}

fn initial_node(
    store: &Store<OpCli>,
    role: &str,
    network: &str,
    args: &ArgMatches,
    say: &Say,
) -> Result<PolygonNode, String> {
    let name = one(args, "name").ok_or("Polygon init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    let existing = store
        .polygon_nodes(role)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name);
    let node = if let Some(node) = existing {
        if one(args, "host").is_some_and(|v| v != node.address)
            || one(args, "l1-execution").is_some_and(|v| v != node.upstream_ref)
            || one(args, "advertise-ip").is_some_and(|v| v != node.advertise_ip)
        {
            return Err("init cannot retarget an owned Polygon host; use update-config for policy or credential rotation".into());
        }
        node
    } else {
        let host = one(args, "host").ok_or("new Polygon node requires --host")?;
        let port = args.get_one::<u16>("port").copied().unwrap_or(22);
        let key = node_common::host_key(host, port, None, one(args, "fingerprint"), say)?;
        PolygonNode {
            name: name.into(),
            address: host.into(),
            ssh_user: one(args, "user").unwrap_or("ubuntu").into(),
            ssh_port: port,
            host_key: key.to_openssh(),
            network: network.into(),
            role: role.into(),
            advertise_ip: advertise(
                one(args, "advertise-ip").ok_or("new Polygon node requires --advertise-ip")?,
            )?,
            upstream_ref: one(args, "l1-execution")
                .ok_or("new Polygon node requires --l1-execution")?
                .into(),
            profile: serde_json::to_value(Network::get(network)?)
                .map_err(|_| "cannot encode reviewed profile")?,
            rpc_allow: access(args, "rpc-allow", &[])?,
            management_allow: access(args, "management-allow", &[])?,
            monitoring_allow: access(args, "monitoring-allow", &[])?,
            ..PolygonNode::default()
        }
    };
    Ok(node)
}
fn init(role: &str, network: &str, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let (store, vault) = open(network, args)?;
    let mut node = initial_node(&store, role, network, args, say)?;
    let public_validator = if role == "validator" {
        if let Some(authority) = node.validator.as_ref() {
            if one(args, "stake-owner").is_some() && stake_owner(args)? != authority.stake_owner {
                return Err("the external Polygon stake owner is immutable".into());
            }
            if args
                .try_get_many::<String>("sentry")
                .ok()
                .flatten()
                .is_some()
                && validator_sentries(args, &authority.sentries)? != authority.sentries
            {
                return Err("init cannot change sentries; use update-config".into());
            }
            None
        } else {
            Some((stake_owner(args)?, validator_sentries(args, &[])?))
        }
    } else {
        None
    };
    // Validate concealed schema before reserving the host; init never imports or rotates it.
    let _secret = credential(&node_common::op_runner()?, &node.upstream_ref)?;
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let facts = facts(&session)?;
    host_check(&facts, network)?;
    if node.id.is_some() && node.architecture != facts.machine {
        return Err("stored Polygon architecture differs from host".into());
    }
    node.architecture.clone_from(&facts.machine);
    reviewed(&node)?;
    node_common::go_ahead(flag(args, "yes"), "no Polygon host changed")
        .map_err(|e| e.to_string())?;
    let mut fresh_key = None;
    if node.id.is_none() {
        if let Some((stake_owner, sentries)) = public_validator {
            let key = erpc_wallet::evm::EvmKey::generate()
                .map_err(|_| "cannot generate a fresh dedicated Polygon signer")?;
            let signer = key.address().to_string().to_ascii_lowercase();
            if signer == stake_owner {
                return Err("hot signer must differ from the external stake owner".into());
            }
            fresh_key = Some(SecretString::from(key.secret_hex().to_string()));
            node.validator = Some(PolygonValidator {
                phase: "observing".into(),
                stake_owner,
                signer,
                creation: intent()?,
                original_ref: String::new(),
                original_ready: false,
                sentries,
            });
        }
        if role == "fullnode" {
            node = store.add_polygon_node(&node).map_err(|e| e.to_string())?;
        }
    }
    if role == "validator" {
        // Public binding read-back precedes original secret creation, and the
        // ready transition follows exact concealed-key read-back.
        node = reserve_validator(
            &store,
            &node_common::op_runner()?,
            &vault,
            node,
            fresh_key.as_ref(),
        )?;
    }
    // The stable item ID exists before constructing any remote ownership contract.
    let vars = variables(&node, Some(&facts), &intent()?, false)?;
    node.last_run = play(
        &session,
        &target,
        &bundle(&inventory(&node, &vars))?,
        "ansible/polygon/init.yml",
        say,
    )?
    .as_str()
    .into();
    if node.last_result.is_empty() {
        node.last_result = "initialized; deploy required".into();
    }
    store
        .update_polygon_node(&node)
        .map_err(|e| e.to_string())?;
    node_common::save_vault(network, &vault)?;
    Ok(
        json!({"name":node.name,"network":network,"initialized":true,"deployment":"explicit deploy required"}),
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeploymentStep {
    Init,
    RestoreOriginal,
    AuthorizeActive,
    PersistTarget,
    Prepare,
    ImportParent,
    ImportSigner,
    FinalizeValidator,
    ApplyFirewall,
    ConfirmFirewall,
    Activate,
}
fn deployment_steps(
    phase: Option<&str>,
    restore: bool,
    mut step: impl FnMut(DeploymentStep) -> Result<String, String>,
) -> Result<String, String> {
    if phase.is_some_and(|value| !["observing", "active"].contains(&value)) {
        return Err("unsupported Polygon validator phase".into());
    }
    step(DeploymentStep::Init)?;
    if restore && phase == Some("active") {
        step(DeploymentStep::RestoreOriginal)?;
    }
    if phase == Some("active") {
        step(DeploymentStep::AuthorizeActive)?;
    }
    step(DeploymentStep::PersistTarget)?;
    step(DeploymentStep::Prepare)?;
    step(DeploymentStep::ImportParent)?;
    if phase.is_some() {
        step(DeploymentStep::ImportSigner)?;
        step(DeploymentStep::FinalizeValidator)?;
    }
    step(DeploymentStep::ApplyFirewall)?;
    step(DeploymentStep::ConfirmFirewall)?;
    step(DeploymentStep::Activate)
}
fn deploy(
    session: &Session,
    target: &Target,
    node: &mut PolygonNode,
    store: &Store<OpCli>,
    vault: &str,
    args: &ArgMatches,
    say: &Say,
) -> Result<String, String> {
    reviewed(node)?;
    let op = node_common::op_runner()?;
    let secret = credential(&op, &node.upstream_ref)?;
    let original = if node.role == "validator" {
        Some(original_signer(&op, node, vault, None)?)
    } else {
        None
    };
    let facts = facts(session)?;
    let vars = variables(node, Some(&facts), &intent()?, flag(args, "restore-keys"))?;
    let inventory = inventory(node, &vars);
    let built = bundle(&inventory)?;
    let mut body = request(node, "credential")?;
    for (key, variable) in [
        ("profile", "polygon_profile"),
        ("helpers", "polygon_helpers"),
        ("intent", "polygon_intent"),
    ] {
        body[key] = vars[variable].clone();
    }
    let phase = node.validator.as_ref().map(|value| value.phase.clone());
    let mut pending = None;
    let mut confirmed = None;
    deployment_steps(phase.as_deref(), flag(args, "restore-keys"), |step| {
        let play_name = match step {
            DeploymentStep::Init => Some("ansible/polygon/init.yml"),
            DeploymentStep::Prepare => Some("ansible/polygon/prepare.yml"),
            DeploymentStep::FinalizeValidator => Some("ansible/polygon/validator-finalize.yml"),
            _ => None,
        };
        if let Some(name) = play_name {
            return Ok(play(session, target, &built, name, say)?.as_str().into());
        }
        match step {
            DeploymentStep::RestoreOriginal => {
                let mut recovery = body.clone();
                recovery["action"] = json!("recover-original");
                control(session, &recovery)?;
            }
            DeploymentStep::PersistTarget => {
                *node = store
                    .update_polygon_node(node)
                    .map_err(|error| error.to_string())?;
            }
            DeploymentStep::AuthorizeActive => {
                let mut authorization = body.clone();
                authorization["action"] = json!("authorize-active");
                send_secret_action(session, &authorization, &secret)?;
            }
            DeploymentStep::ImportParent => send_credential(session, &body, &secret)?,
            DeploymentStep::ImportSigner => send_signer(
                session,
                &body,
                &original
                    .as_ref()
                    .ok_or("original Polygon signer is missing")?
                    .secret,
            )?,
            DeploymentStep::ApplyFirewall => {
                // Every original/credential read, download and native preparation
                // has completed before the bounded firewall transaction begins.
                pending = Some(play(
                    session,
                    target,
                    &built,
                    "ansible/polygon/firewall.yml",
                    say,
                )?);
            }
            DeploymentStep::ConfirmFirewall => {
                let run = pending
                    .as_ref()
                    .ok_or("no exact Polygon firewall candidate")?;
                let fresh = Session::open(target).map_err(|error| error.to_string())?;
                let mut confirmation = body.clone();
                confirmation["action"] = json!("confirm");
                confirmation["firewall"] = json!({"run":run.as_str(),"bundle":built.sha256});
                control(&fresh, &confirmation)?;
                confirmed = Some(bundle(&erpc_ops::firewall_inventory(
                    &inventory,
                    run,
                    &built.sha256,
                )?)?);
            }
            DeploymentStep::Activate => {
                return Ok(play(
                    session,
                    target,
                    confirmed
                        .as_ref()
                        .ok_or("Polygon firewall was not confirmed")?,
                    "ansible/polygon/activate.yml",
                    say,
                )?
                .as_str()
                .into());
            }
            _ => return Err("unsupported Polygon deployment step".into()),
        }
        Ok(String::new())
    })
}

fn emit_json(value: &Value, stdout: &mut impl FnMut(&str)) {
    stdout(&value.to_string());
}
fn emit_log(
    stream: erpc_ssh::Stream,
    line: &str,
    json_out: bool,
    stdout: &mut impl FnMut(&str),
    stderr: &mut impl FnMut(&str),
) {
    if json_out {
        emit_json(
            &json!({"journal":line,"stream":match stream {
            erpc_ssh::Stream::Stdout=>"stdout",erpc_ssh::Stream::Stderr=>"stderr"}}),
            stdout,
        );
    } else {
        stderr(line);
    }
}

fn logs(
    session: &Session,
    node: &PolygonNode,
    network: &str,
    args: &ArgMatches,
    json_out: bool,
) -> Result<Value, String> {
    let profile = Network::get(network)?;
    let contract = Contract::new(
        network,
        owner(node)?,
        &node.architecture,
        &profile.bor_genesis_hash,
        &profile.heimdall_genesis.sha256,
    )?;
    let contract = if node.role == "validator" {
        let validator = node
            .validator
            .as_ref()
            .ok_or("Polygon validator authority is missing")?;
        contract.validator(&validator.signer, &validator.stake_owner)?
    } else {
        contract
    };
    let command = Command::logs(
        &contract,
        one(args, "component").unwrap_or("all"),
        args.get_one::<u32>("lines").copied().unwrap_or(100),
        flag(args, "follow"),
    )?;
    let output = Say { quiet: false };
    session
        .stream(&RemoteCommand::Polygon(command), &mut |stream, line| {
            emit_log(
                stream,
                line,
                json_out,
                &mut crate::print_line,
                &mut |text| output.line(text),
            );
        })
        .map_err(|e| e.to_string())?;
    Ok(json!({"logs":"complete"}))
}

fn runtime_action(node: &PolygonNode, verb: &str) -> Result<&'static str, String> {
    if verb == "stop" {
        return Ok("stop-v2");
    }
    reviewed(node)?;
    match verb {
        "start" => Ok("start-v3"),
        "restart" => Ok("restart-v3"),
        _ => Err("unsupported Polygon runtime action".into()),
    }
}

fn change_target(
    node: &mut PolygonNode,
    verb: &str,
    network: &str,
    args: &ArgMatches,
) -> Result<(), String> {
    if verb == "update" {
        node.profile = serde_json::to_value(Network::get(network)?)
            .map_err(|_| "cannot encode reviewed target")?;
    }
    reviewed(node)?;
    if let Some(reference) = one(args, "l1-execution") {
        OpRef::parse(reference).map_err(|_| "invalid parent op reference")?;
        node.upstream_ref = reference.into();
    }
    if let Some(ip) = one(args, "advertise-ip") {
        node.advertise_ip = advertise(ip)?;
    }
    node.rpc_allow = access(args, "rpc-allow", &node.rpc_allow)?;
    node.management_allow = access(args, "management-allow", &node.management_allow)?;
    node.monitoring_allow = access(args, "monitoring-allow", &node.monitoring_allow)?;
    if let Some(authority) = node.validator.as_mut() {
        authority.sentries = validator_sentries(args, &authority.sentries)?;
        if flag(args, "activate-validator") {
            authority.phase = "active".into();
        }
    }
    Ok(())
}

fn plan(mut node: PolygonNode, network: &str, args: &ArgMatches) -> Result<Value, String> {
    if one(args, "change") == Some("update") {
        node.profile = serde_json::to_value(Network::get(network)?)
            .map_err(|_| "cannot encode reviewed Polygon update")?;
    }
    if let Some(authority) = node.validator.as_mut()
        && flag(args, "activate-validator")
    {
        authority.phase = "active".into();
    }
    let mut value = json!({"name":node.name,"network":network,"change":one(args,"change").unwrap_or("deploy"),
        "desired_profile":operation_profile(&node),"reviewed_profile":Network::get(network)?,
        "sync_order":["heimdall","bor"],"bootstrap":"authenticated migrated genesis; no community snapshot",
        "destroy_preserves_data":true,"live_acceptance":"deferred"});
    if let Some(authority) = node.validator {
        value["validator_authority"] = json!({"phase":authority.phase,"stake_owner":authority.stake_owner,
            "signer":authority.signer,"original_custody_ready":authority.original_ready,"sentries":authority.sentries});
        value["active_precondition"] = json!(
            "healthy original observer and current admission/owner; fresh authorization before stop"
        );
        value["external_only"] = json!(["owner registration", "staking", "approval", "funding"]);
    }
    Ok(value)
}

fn operation(
    role: &str,
    verb: &str,
    network: &str,
    args: &ArgMatches,
    say: &Say,
) -> Result<Value, String> {
    if verb == "init" {
        return init(role, network, args, say);
    }
    let (store, vault) = open(network, args)?;
    if verb == "list" {
        return Ok(json!({"nodes":store.polygon_nodes(role).map_err(|e|e.to_string())?}));
    }
    let mut node = find(&store, args, role)?;
    if verb == "plan" {
        return plan(node, network, args);
    }
    if flag(args, "restore-keys")
        && flag(args, "activate-validator")
        && node
            .validator
            .as_ref()
            .is_some_and(|value| value.phase == "observing")
    {
        return Err("restore and restart the original observer first, then request --activate-validator after it is healthy".into());
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if verb == "status" {
        return control(&session, &request(&node, "status")?);
    }
    if verb == "logs" {
        return logs(&session, &node, network, args, say.quiet);
    }
    if verb == "registration" {
        if role != "validator" {
            return Err("registration requires the validator role".into());
        }
        let mut body = request(&node, "registration")?;
        body["registration_action"] =
            json!(one(args, "action").ok_or("registration requires --action")?);
        return control(&session, &body);
    }
    node_common::go_ahead(flag(args, "yes"), "no Polygon host changed")
        .map_err(|e| e.to_string())?;
    match verb {
        "deploy" | "update" | "update-config" => {
            change_target(&mut node, verb, network, args)?;
            // Active phase is committed only after host admission succeeds,
            // and always before any new native preparation or credential grant.
            node.last_run = deploy(&session, &target, &mut node, &store, &vault, args, say)?;
            node.last_result = format!("{verb} complete; Heimdall synchronization precedes Bor");
            store
                .update_polygon_node(&node)
                .map_err(|e| e.to_string())?;
            Ok(
                json!({"name":node.name,"accepted":true,"synchronization":"inspect status; clients start asynchronously","run":node.last_run}),
            )
        }
        "start" | "stop" | "restart" => {
            // An old installed helper cannot acknowledge the new startup
            // protocol and silently start its pre-Karwar release pair.
            let action = runtime_action(&node, verb)?;
            let result = match control(&session, &request(&node, action)?) {
                Ok(value) => value,
                Err(_) if verb == "stop" => {
                    // An old or incomplete installed helper cannot enforce the
                    // current account protocol. A sealed carried stop never
                    // adopts accounts or publishes a replacement helper.
                    let vars = variables(&node, None, &intent()?, false)?;
                    node.last_run = play(
                        &session,
                        &target,
                        &bundle(&inventory(&node, &vars))?,
                        "ansible/polygon/stop.yml",
                        say,
                    )?
                    .as_str()
                    .into();
                    json!({"stopped":true,"data_retained":true})
                }
                Err(error) => return Err(error),
            };
            node.last_result = format!("{verb} complete");
            store
                .update_polygon_node(&node)
                .map_err(|e| e.to_string())?;
            Ok(result)
        }
        "destroy" => {
            // A carried guarded controller also retires an interrupted first preparation.
            let vars = variables(&node, None, &intent()?, false)?;
            node.last_run = play(
                &session,
                &target,
                &bundle(&inventory(&node, &vars))?,
                "ansible/polygon/destroy.yml",
                say,
            )?
            .as_str()
            .into();
            node.last_result =
                "retired; original encrypted identities and all history retained".into();
            store
                .update_polygon_node(&node)
                .map_err(|e| e.to_string())?;
            Ok(json!({"retired":true,"data_retained":true}))
        }
        _ => Err("unsupported Polygon RPC operation".into()),
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
    role: &str,
    verb: &str,
    args: &ArgMatches,
    network: Option<&str>,
    json_out: bool,
) -> Outcome {
    if !["fullnode", "validator"].contains(&role) {
        return Outcome::Usage("unsupported Polygon role".into());
    }
    let Some(network) = network.filter(|n| ["mainnet", "amoy"].contains(n)) else {
        return Outcome::Usage("Polygon requires explicit --network mainnet or amoy".into());
    };
    let say = Say { quiet: json_out };
    let result = operation(role, verb, network, args, &say);
    if verb == "status" {
        return report_status(result, json_out, &mut crate::print_line);
    }
    match result {
        Ok(value) => {
            let unhealthy = verb == "registration"
                && one(args, "action") == Some("validate")
                && value["eligible"] != true;
            if json_out {
                emit_json(&value, &mut crate::print_line);
            } else {
                say.line(&serde_json::to_string_pretty(&value).unwrap_or_default());
            }
            if unhealthy {
                Outcome::Failed(if value["observer_ready"] == true {
                    "Polygon observer is ready; external admission and explicit --activate-validator are still required".into()
                } else if verb == "registration" {
                    "Polygon original signer is not currently validated for both chain views and the separate owner".into()
                } else {
                    "Polygon is not ready; inspect separate Heimdall, Bor and parent progress"
                        .into()
                })
            } else {
                Outcome::Done(String::new())
            }
        }
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_deployment_orchestrator_finishes_all_custody_before_arming_ingress() {
        use DeploymentStep::{
            Activate, ApplyFirewall, AuthorizeActive, ConfirmFirewall, FinalizeValidator,
            ImportParent, ImportSigner, Init, PersistTarget, Prepare,
        };
        for (phase, expected) in [
            (
                None,
                vec![
                    Init,
                    PersistTarget,
                    Prepare,
                    ImportParent,
                    ApplyFirewall,
                    ConfirmFirewall,
                    Activate,
                ],
            ),
            (
                Some("observing"),
                vec![
                    Init,
                    PersistTarget,
                    Prepare,
                    ImportParent,
                    ImportSigner,
                    FinalizeValidator,
                    ApplyFirewall,
                    ConfirmFirewall,
                    Activate,
                ],
            ),
            (
                Some("active"),
                vec![
                    Init,
                    AuthorizeActive,
                    PersistTarget,
                    Prepare,
                    ImportParent,
                    ImportSigner,
                    FinalizeValidator,
                    ApplyFirewall,
                    ConfirmFirewall,
                    Activate,
                ],
            ),
        ] {
            let mut calls = Vec::new();
            let result = deployment_steps(phase, false, |step| {
                calls.push(step);
                Ok("inert run".into())
            })
            .unwrap();
            assert_eq!(result, "inert run");
            assert_eq!(calls, expected);
            for failure in &expected {
                let mut calls = Vec::new();
                assert!(
                    deployment_steps(phase, false, |step| {
                        calls.push(step);
                        if step == *failure {
                            Err("inert operation failure".into())
                        } else {
                            Ok(String::new())
                        }
                    })
                    .is_err()
                );
                assert_eq!(calls.last(), Some(failure));
                assert_eq!(
                    calls,
                    expected[..=expected.iter().position(|item| item == failure).unwrap()]
                );
            }
        }
        assert!(
            deployment_steps(Some("invented"), false, |_| panic!(
                "invalid phase must not reach any host step"
            ))
            .is_err()
        );
    }
    #[test]
    fn active_recovery_restores_before_authorization_and_observer_uses_prepare() {
        for phase in [None, Some("observing"), Some("active")] {
            let mut calls = Vec::new();
            deployment_steps(phase, true, |step| {
                calls.push(step);
                Ok(String::new())
            })
            .unwrap();
            if phase == Some("active") {
                assert_eq!(
                    calls[..4],
                    [
                        DeploymentStep::Init,
                        DeploymentStep::RestoreOriginal,
                        DeploymentStep::AuthorizeActive,
                        DeploymentStep::PersistTarget
                    ]
                );
            } else {
                assert!(!calls.contains(&DeploymentStep::RestoreOriginal));
            }
        }
    }
    #[test]
    fn actual_secret_encoder_binds_original_public_signer_without_mutating_public_request() {
        let (mut pending, secret) = pending_validator();
        pending.id = Some("i".repeat(26));
        let authority = pending.validator.as_mut().unwrap();
        authority.original_ready = true;
        authority.original_ref = "inert original reference".into();
        let public = request(&pending, "credential").unwrap();
        let input = signer_request(&public, &secret).unwrap();
        let decoded: Value = serde_json::from_str(input.expose_secret()).unwrap();
        assert_eq!(decoded["action"], "validator-key");
        assert_eq!(
            decoded["original_signer"].as_str(),
            Some(secret.expose_secret())
        );
        assert!(!public.to_string().contains(secret.expose_secret()));
        let mut foreign = public.clone();
        foreign["contract"]["signer"] = json!(format!("0x{}", "ab".repeat(20)));
        assert!(signer_request(&foreign, &secret).is_err());
        assert!(signer_request(&public, &SecretString::from("0".repeat(64))).is_err());
        assert!(
            signer_request(&public, &SecretString::from("inert\"injection".to_owned())).is_err()
        );
    }
    fn node(network: &str) -> PolygonNode {
        PolygonNode {
            id: Some("i".repeat(26)),
            name: "polygon-fixture".into(),
            network: network.into(),
            role: "fullnode".into(),
            architecture: "x86_64".into(),
            advertise_ip: "8.8.8.8".into(),
            profile: serde_json::to_value(Network::get(network).unwrap()).unwrap(),
            ..PolygonNode::default()
        }
    }

    #[test]
    fn explicit_karwar_update_preserves_both_roles_and_previews_the_actual_target() {
        use erpc_core::chain::{Chain, Role};
        for network in ["mainnet", "amoy"] {
            for architecture in ["x86_64", "aarch64"] {
                for role in [Role::Rpc, Role::Validator] {
                    let mut original = node(network);
                    original.architecture = architecture.into();
                    if role == Role::Validator {
                        original.role = "validator".into();
                        let (sample, _) = pending_validator();
                        original.validator = sample.validator;
                        original.validator.as_mut().unwrap().phase = "active".into();
                    }
                    original.profile = serde_json::from_str(if network == "mainnet" {
                        include_str!(
                            "../../erpc-chain-polygon/tests/fixtures/pre-karwar-mainnet.json"
                        )
                    } else {
                        include_str!("../../erpc-chain-polygon/tests/fixtures/pre-karwar-amoy.json")
                    })
                    .unwrap();
                    assert!(runtime_action(&original, "start").is_err());
                    assert!(runtime_action(&original, "restart").is_err());
                    assert_eq!(runtime_action(&original, "stop").unwrap(), "stop-v2");
                    let tree = crate::tree::command(role, Chain::Polygon);
                    let parsed = tree
                        .clone()
                        .try_get_matches_from([
                            role.as_str(),
                            "update",
                            "--network",
                            network,
                            "--name",
                            "polygon-fixture",
                        ])
                        .unwrap();
                    let mut changed = original.clone();
                    change_target(
                        &mut changed,
                        "update",
                        network,
                        parsed.subcommand_matches("update").unwrap(),
                    )
                    .unwrap();
                    assert_eq!(changed.profile["releases"]["heimdall"]["tag"], "v0.13.2");
                    assert_eq!(
                        changed.profile["releases"]["bor"],
                        original.profile["releases"]["bor"]
                    );
                    assert_eq!(changed.validator, original.validator);
                    let target_profile = changed.profile.clone();
                    changed.profile = original.profile.clone();
                    assert_eq!(changed, original);
                    changed.profile = target_profile;
                    assert_eq!(runtime_action(&changed, "start").unwrap(), "start-v3");
                    assert_eq!(runtime_action(&changed, "restart").unwrap(), "restart-v3");
                    let preview = tree
                        .try_get_matches_from([
                            role.as_str(),
                            "plan",
                            "--change",
                            "update",
                            "--network",
                            network,
                        ])
                        .unwrap();
                    let output = plan(
                        original,
                        network,
                        preview.subcommand_matches("plan").unwrap(),
                    )
                    .unwrap();
                    assert_eq!(
                        output["desired_profile"]["releases"]["heimdall"]["tag"],
                        "v0.13.2"
                    );
                    if role == Role::Validator {
                        assert_eq!(output["desired_profile"]["validator"]["phase"], "active");
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn compiled_karwar_init_hands_off_public_source_before_private_authorization() {
        use std::io::Write as _;
        for network in ["mainnet", "amoy"] {
            for architecture in ["x86_64", "aarch64"] {
                for role in ["fullnode", "validator"] {
                    let mut selected = node(network);
                    selected.architecture = architecture.into();
                    if role == "validator" {
                        let (sample, _) = pending_validator();
                        selected.role = role.into();
                        selected.validator = sample.validator;
                        let original = selected.validator.as_mut().unwrap();
                        original.original_ready = true;
                        original.original_ref =
                            format!("op://{}/{}/signer_secret", "a".repeat(26), "b".repeat(26));
                        original.phase = "active".into();
                    }
                    let values = variables(&selected, None, &"c".repeat(32), false).unwrap();
                    let built = bundle(&inventory(&selected, &values)).unwrap();
                    let python = std::env::var("ERPC_TEST_ANSIBLE_PYTHON")
                        .unwrap_or_else(|_| "python3".into());
                    let mut command = std::process::Command::new(python);
                    command.args(["-I", "-B"]).arg(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("tests/polygon_karwar_handoff.py"),
                    );
                    if std::env::var_os("ERPC_TEST_ANSIBLE_PYTHON").is_some() {
                        command.env("ERPC_REQUIRE_PINNED_ANSIBLE", "1");
                    }
                    let mut child = command
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .unwrap();
                    child.stdin.take().unwrap().write_all(&built.bytes).unwrap();
                    let result = child.wait_with_output().unwrap();
                    assert!(
                        result.status.success(),
                        "{}",
                        String::from_utf8_lossy(&result.stderr)
                    );
                }
            }
        }
    }
    #[derive(Default)]
    struct MemoryOp {
        items: std::cell::RefCell<Vec<Value>>,
        events: std::cell::RefCell<Vec<&'static str>>,
        fail_secret: std::cell::Cell<bool>,
    }
    impl MemoryOp {
        fn create(&self, input: &str) -> (bool, String) {
            let mut value: Value = serde_json::from_str(input).expect("inert template");
            let secret = value["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["type"] == "CONCEALED");
            if secret {
                let public = self.items.borrow();
                let node = public
                    .iter()
                    .flat_map(|item| item["fields"].as_array().unwrap())
                    .find(|field| field["id"] == "polygon_node")
                    .expect("public reservation before secret creation");
                let parsed: Value = serde_json::from_str(node["value"].as_str().unwrap()).unwrap();
                assert_eq!(parsed["validator"]["original_ready"], false);
                self.events.borrow_mut().push("secret-create");
                if self.fail_secret.get() {
                    return (false, "inert uncertain create failure".into());
                }
            } else {
                self.events.borrow_mut().push("public-create");
            }
            value["id"] = json!(format!("{:026}", self.items.borrow().len() + 1));
            value["version"] = json!(1);
            value["vault"] = json!({"id":"v".repeat(26)});
            self.items.borrow_mut().push(value.clone());
            (true, value.to_string())
        }
        fn get(&self, args: &[&str], input: Option<&str>) -> String {
            if args[2] == "-" {
                let listed: Vec<Value> = serde_json::from_str(input.unwrap()).unwrap();
                return listed
                    .iter()
                    .map(|item| {
                        self.items
                            .borrow()
                            .iter()
                            .find(|found| found["id"] == item["id"])
                            .unwrap()
                            .to_string()
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
            }
            let items = self.items.borrow();
            let item = items.iter().find(|item| item["id"] == args[2]).unwrap();
            if let Some(index) = args.iter().position(|value| *value == "--fields") {
                let labels: Vec<_> = args[index + 1]
                    .split(',')
                    .map(|label| label.strip_prefix("label=").unwrap())
                    .collect();
                if labels == ["signer_secret"] {
                    self.events.borrow_mut().push("secret-read");
                }
                let values: Vec<_> = item["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|field| labels.contains(&field["label"].as_str().unwrap()))
                    .cloned()
                    .collect();
                return if values.len() == 1 {
                    values[0].to_string()
                } else {
                    json!(values).to_string()
                };
            }
            self.events.borrow_mut().push("public-read");
            item.to_string()
        }
    }
    impl OpRunner for MemoryOp {
        fn run(
            &self,
            args: &[&str],
            input: Option<&str>,
        ) -> Result<erpc_auth::store::one_password::OpOutput, erpc_auth::store::StoreError>
        {
            let (success, stdout) = match args[1] {
                "create" => self.create(input.unwrap()),
                "get" => (true, self.get(args, input)),
                "list" => {
                    let tag = args[args.iter().position(|value| *value == "--tags").unwrap() + 1];
                    let items: Vec<_> = self
                        .items
                        .borrow()
                        .iter()
                        .filter(|item| item["tags"].as_array().unwrap().contains(&json!(tag)))
                        .cloned()
                        .collect();
                    (true, json!(items).to_string())
                }
                "edit" => {
                    assert!(self.events.borrow().contains(&"secret-read"));
                    self.events.borrow_mut().push("ready-write");
                    let mut items = self.items.borrow_mut();
                    let previous = items.iter_mut().find(|item| item["id"] == args[2]).unwrap();
                    let mut value: Value = serde_json::from_str(input.unwrap()).unwrap();
                    value["id"] = previous["id"].clone();
                    value["version"] = json!(previous["version"].as_u64().unwrap() + 1);
                    value["vault"] = previous["vault"].clone();
                    *previous = value.clone();
                    (true, value.to_string())
                }
                _ => panic!("unexpected custody operation"),
            };
            Ok(erpc_auth::store::one_password::OpOutput {
                success,
                stdout,
                stderr: String::new(),
            })
        }
    }
    impl OpRunner for &MemoryOp {
        fn run(
            &self,
            args: &[&str],
            input: Option<&str>,
        ) -> Result<erpc_auth::store::one_password::OpOutput, erpc_auth::store::StoreError>
        {
            (*self).run(args, input)
        }
    }
    fn pending_validator() -> (PolygonNode, SecretString) {
        let secret = SecretString::from("01".repeat(32));
        let signer = erpc_wallet::evm::EvmKey::from_hex(secret.expose_secret())
            .unwrap()
            .address()
            .to_string()
            .to_ascii_lowercase();
        let mut node = node("amoy");
        node.id = None;
        node.role = "validator".into();
        node.address = "192.0.2.1".into();
        node.upstream_ref = format!("op://{}/{}/l1", "a".repeat(26), "b".repeat(26));
        node.validator = Some(PolygonValidator {
            phase: "observing".into(),
            stake_owner: format!("0x{}", "cd".repeat(20)),
            signer,
            creation: "c".repeat(32),
            original_ref: String::new(),
            original_ready: false,
            sentries: vec![PolygonSentry {
                address: "192.0.2.2".into(),
                bor_node_id: "ab".repeat(64),
                heimdall_node_id: "cd".repeat(20),
            }],
        });
        (node, secret)
    }
    #[test]
    fn public_reservation_secret_readback_and_ready_binding_are_composed_before_host_authority() {
        let op = MemoryOp::default();
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(
            &op,
            "vault",
            erpc_chain::inventory::Scope {
                chain: "polygon".into(),
                network: "amoy".into(),
            },
            directory.path().join("custody.lock"),
        );
        let (pending, key) = pending_validator();
        assert!(contract(&pending).is_err());
        let ready = reserve_validator(&store, &op, "vault", pending, Some(&key)).unwrap();
        assert!(contract(&ready).is_ok());
        assert!(ready.validator.as_ref().unwrap().original_ready);
        let events = op.events.borrow();
        let index = |event| events.iter().position(|value| *value == event).unwrap();
        assert!(
            index("public-create") < index("public-read")
                && index("public-read") < index("secret-create")
        );
        assert!(index("secret-read") < index("ready-write"));
        drop(events);
        assert!(reserve_validator(&store, &op, "vault", ready.clone(), None).is_ok());
        assert!(reserve_validator(&store, &op, "vault", ready, Some(&key)).is_err());
        assert_eq!(
            op.events
                .borrow()
                .iter()
                .filter(|event| **event == "secret-create")
                .count(),
            1
        );
    }
    #[test]
    fn uncertain_original_creation_retains_pending_public_owner_and_never_recreates_on_retry() {
        let op = MemoryOp::default();
        op.fail_secret.set(true);
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(
            &op,
            "vault",
            erpc_chain::inventory::Scope {
                chain: "polygon".into(),
                network: "amoy".into(),
            },
            directory.path().join("custody.lock"),
        );
        let (pending, key) = pending_validator();
        assert!(reserve_validator(&store, &op, "vault", pending, Some(&key)).is_err());
        let pending = store.polygon_nodes("validator").unwrap().pop().unwrap();
        assert!(contract(&pending).is_err());
        assert!(pending.id.is_some());
        assert!(reserve_validator(&store, &op, "vault", pending, None).is_err());
        assert_eq!(
            op.events
                .borrow()
                .iter()
                .filter(|event| **event == "secret-create")
                .count(),
            1
        );
        assert!(!op.events.borrow().contains(&"ready-write"));
    }
    #[test]
    fn log_sink_and_completion_are_compact_stdout_ndjson_in_json_mode() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        for stream in [erpc_ssh::Stream::Stdout, erpc_ssh::Stream::Stderr] {
            emit_log(
                stream,
                "quoted \"line\"\nnext\titem",
                true,
                &mut |line| stdout.push(line.to_owned()),
                &mut |line| stderr.push(line.to_owned()),
            );
        }
        emit_json(&json!({"logs":"complete"}), &mut |line| {
            stdout.push(line.to_owned());
        });
        assert!(stderr.is_empty());
        assert_eq!(stdout.len(), 3);
        let values: Vec<Value> = stdout
            .iter()
            .map(|line| {
                assert!(!line.contains('\n'));
                serde_json::from_str(line).unwrap()
            })
            .collect();
        assert_eq!(values[0]["journal"], "quoted \"line\"\nnext\titem");
        assert_eq!(values[0]["stream"], "stdout");
        assert_eq!(values[1]["stream"], "stderr");
        assert_eq!(values[2], json!({"logs":"complete"}));
        stdout.clear();
        emit_log(
            erpc_ssh::Stream::Stderr,
            "human journal",
            false,
            &mut |line| stdout.push(line.to_owned()),
            &mut |line| stderr.push(line.to_owned()),
        );
        assert!(stdout.is_empty());
        assert_eq!(stderr, ["human journal"]);
    }

    #[test]
    fn secret_json_retains_nested_profile_and_never_enters_public_bundle() {
        let node = node("amoy");
        let secret=ExecutionCredential::parse(json!({"execution":{"url":"https://github.com/rpc?private=fixture","headers":{"Authorization":"Bearer private-fixture"}}}).to_string().into()).unwrap();
        let base = json!({"contract":contract(&node).unwrap(),"profile":node.profile,"action":"credential"});
        let encoded = secret_request(&base, &secret).unwrap();
        let parsed: Value = serde_json::from_str(encoded.expose_secret()).unwrap();
        assert_eq!(parsed["profile"], base["profile"]);
        assert_eq!(
            parsed["credential"]["execution"]["headers"]["Authorization"],
            "Bearer private-fixture"
        );
        let vars = variables(&node, None, &"a".repeat(32), false).unwrap();
        assert!(!vars.to_string().contains("private-fixture"));
        assert!(!vars.to_string().contains("private=fixture"));
        assert!(secret_request(&json!([]), &secret).is_err());
    }
    #[test]
    fn unique_inventory_owner_and_catalog_changes_cannot_be_silently_adopted() {
        let mut original = node("mainnet");
        let first = contract(&original).unwrap();
        original.id = Some("j".repeat(26));
        assert_ne!(contract(&original).unwrap(), first);
        original.id = None;
        assert!(contract(&original).is_err());
        let mut changed = node("amoy");
        changed.profile["releases"]["bor"]["tag"] = json!("v99.0.0");
        assert!(reviewed(&changed).is_err());
        // Stopping an owned newer release still uses the immutable chain contract.
        assert!(contract(&changed).is_ok());
        changed.role = "validator".into();
        assert!(contract(&changed).is_err());
    }
    #[test]
    fn firewall_uses_actual_remote_ssh_port_and_preserves_both_ip_families() {
        let mut node = node("amoy");
        node.ssh_port = 2222;
        node.rpc_allow = vec!["198.51.100.0/24".into(), "2001:db8::/32".into()];
        let facts = Facts {
            os: "ubuntu 24.04".into(),
            sudo: true,
            cpus: 16,
            mem_kb: 16_000_000,
            machine: "x86_64".into(),
            controller: "2001:db8::1".into(),
            ssh_port: 22,
            ..Facts::default()
        };
        let vars = variables(&node, Some(&facts), &"b".repeat(32), true).unwrap();
        assert_eq!(vars["polygon_ssh_port"], 22);
        assert_eq!(vars["polygon_management_v6"], json!(["2001:db8::1"]));
        assert_eq!(vars["polygon_rpc_v4"], json!(["198.51.100.0/24"]));
        assert_eq!(vars["polygon_rpc_v6"], json!(["2001:db8::/32"]));
        node.rpc_allow.push("::/0".into());
        assert!(variables(&node, Some(&facts), &"b".repeat(32), false).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn immutable_helper_digest_matches_the_native_publication_profile() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let scripts = root.join("erpc-chain-polygon/templates/scripts");
        let before = std::fs::read_dir(&scripts)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            !before.contains(std::ffi::OsStr::new("__pycache__")),
            "generated bytecode is not a template input"
        );
        let output=std::process::Command::new("python3").args(["-I", "-B", "-c"])
            .arg("import ast,hashlib,pathlib,shlex,sys; assert sys.dont_write_bytecode; root=pathlib.Path(sys.argv[1]); sys.path.insert(0,str(root/'erpc-chain-polygon/templates/scripts')); import install; argv=shlex.split(sys.argv[2]); program=ast.parse(argv[argv.index('-c')+1]); calls=[node for node in ast.walk(program) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='trusted_release']; assert len(calls)==1; profiles=ast.literal_eval(calls[0].args[1]); assert profiles[0]==list(install.SCRIPTS); digest=hashlib.sha256(); [(digest.update((root/'erpc-chain-rollup/templates/scripts/upstreams.py' if name=='upstreams.py' else root/'erpc-chain-polygon/templates/scripts'/name).read_bytes())) for name in install.SCRIPTS]; print(digest.hexdigest())")
            .arg(root).arg(RemoteCommand::Polygon(Command::request().unwrap()).line()).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            helpers().unwrap()
        );
        let after = std::fs::read_dir(&scripts)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            before, after,
            "digest verification changed distribution inputs"
        );
    }
}
