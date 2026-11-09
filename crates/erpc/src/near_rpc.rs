// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Dedicated NEAR follower lifecycle with persistent original identity.
use crate::{
    commands::Outcome,
    eth_rpc::Facts,
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{
    Store,
    near::{NearRpc, Validator},
};
use erpc_chain_near::network::{self, Network};
use erpc_ops::bundle::{Built, Bundle};
use erpc_ssh::{
    HostKey, Identity, RemoteCommand, Session, Target,
    near::{Action, Contract},
};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn registration(
    node: &NearRpc,
    network: Network,
) -> Result<erpc_chain_near::staking::Registration, String> {
    let value = node
        .validator
        .as_ref()
        .ok_or("validator reservation is missing")?;
    let registration = erpc_chain_near::staking::Registration {
        network: network.name.into(),
        validator_account: value.account_id.clone(),
        owner_account: value.owner_account.clone(),
        staking_public_key: value.public_key.clone(),
        commission_basis_points: value.commission_basis_points,
    };
    registration.validate()?;
    Ok(registration)
}
fn contract(node: &NearRpc, network: Network) -> Result<Contract, String> {
    let mut value = json!({"owner":owner(node)?,"network":network.name,"role":"rpc","genesis_hash":network.genesis_hash});
    if node.validator.is_some() {
        let reservation = registration(node, network)?;
        value["role"] = json!("validator");
        value["validator_account"] = json!(reservation.validator_account);
        value["owner_account"] = json!(reservation.owner_account);
        value["staking_public_key"] = json!(reservation.staking_public_key);
        value["commission_basis_points"] = json!(reservation.commission_basis_points);
    }
    Contract::new(&serde_json::to_vec(&value).map_err(|_| "cannot encode NEAR owner")?)
}

fn control(
    session: &Session,
    node: &NearRpc,
    network: Network,
    action: Action,
) -> Result<Value, String> {
    let request = json!({"policy_sha256":policy(node)?}).to_string();
    let output = session
        .run(
            &RemoteCommand::NearControl {
                action,
                contract: contract(node, network)?,
            },
            Some(request.as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    if output.stdout.is_empty() {
        return Ok(json!({"operation":"complete"}));
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid NEAR control response".into())
}
fn host_check(facts: &Facts, network: Network, validator: bool) -> Result<(), String> {
    let ubuntu = facts
        .os
        .strip_prefix("ubuntu ")
        .and_then(|v| v.split_once('.'))
        .and_then(|(a, b)| Some((a.parse::<u32>().ok()?, b.parse::<u32>().ok()?)))
        .is_some_and(|v| v >= (24, 4));
    let minimum = if validator {
        60_000_000
    } else if network.name == "mainnet" {
        30_000_000
    } else {
        15_000_000
    };
    if !ubuntu || !facts.sudo || facts.mem_kb < minimum || facts.cpus < 16 {
        return Err("NEAR requires Ubuntu 24.04+, passwordless sudo, 16 CPU cores and 64 GB validator / 32 GB mainnet RPC / 16 GB testnet RPC RAM".into());
    }
    network.platform(&facts.machine)
}
fn open(network: Network, args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        network.name,
        one(args, "vault"),
        "erpc r --chain near init --network <network> --vault <vault>",
    )?;
    Ok((
        node_common::store(&node_common::op_runner()?, &vault, "near", network.name)?,
        vault,
    ))
}
fn find(store: &Store<OpCli>, args: &ArgMatches, validator: bool) -> Result<NearRpc, String> {
    let name = one(args, "name").ok_or("NEAR operation requires --name")?;
    store
        .near_nodes(validator)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name)
        .ok_or_else(|| "NEAR node is not initialized in this network".into())
}
fn ranges(args: &ArgMatches, name: &str, old: &[String]) -> Result<Vec<String>, String> {
    let clear = match name {
        "rpc-allow" => "clear-rpc-allow",
        "metrics-allow" => "clear-metrics-allow",
        _ => "unused",
    };
    if args
        .try_get_one::<bool>(clear)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
    {
        if args.try_get_many::<String>(name).ok().flatten().is_some() {
            return Err("cannot set and clear the same ingress range".into());
        }
        return Ok(Vec::new());
    }
    let values = args
        .try_get_many::<String>(name)
        .ok()
        .flatten()
        .map_or_else(|| old.to_vec(), |v| v.cloned().collect());
    crate::arc_rpc::allow_list(name, &values, false)
}
fn policy(node: &NearRpc) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        &node.management_allow,
        &node.rpc_allow,
        &node.metrics_allow,
        node.ssh_port,
    ))
    .map_err(|_| "invalid NEAR policy")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn variables(node: &NearRpc, network: Network, facts: &Facts) -> Result<Value, String> {
    host_check(facts, network, node.validator.is_some())?;
    if facts.ssh_port == 0 {
        return Err("cannot establish the host SSH listener port".into());
    }
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| "cannot create a unique deployment intent")?;
    let intent = erpc_ssh::sui::Confirmation::new(random);
    if node.platform != facts.machine {
        return Err("NEAR host architecture changed".into());
    }
    let mut v4 = crate::arc_rpc::allow_list("management", &node.management_allow, false)?;
    let mut v6 = Vec::new();
    match facts.controller_ip()? {
        std::net::IpAddr::V4(ip) => {
            if !v4.contains(&ip.to_string()) {
                v4.push(ip.to_string());
            }
        }
        std::net::IpAddr::V6(ip) => v6.push(ip.to_string()),
    }
    let rpc = crate::arc_rpc::allow_list("RPC", &node.rpc_allow, false)?;
    let metrics = crate::arc_rpc::allow_list("metrics", &node.metrics_allow, false)?;
    let (config, genesis) = erpc_core::endpoints::near_artifacts(network.name, network.commit)
        .ok_or("unsupported NEAR artifact network")?;
    Ok(
        json!({"ansible_connection":"local","near_contract":contract(node,network)?.encoded(),"near_network":network.name,"near_validator":node.validator.is_some(),"near_systemd_control":erpc_ssh::python::systemd_command("/usr/local/lib/erpc/near/control.py")?,
        "near_management_v4":v4,"near_management_v6":v6,"near_ssh_port":facts.ssh_port,"near_rpc_allow":rpc,"near_metrics_allow":metrics,
        "near_prepare":{"intent":intent.text(),"config_url":config,"genesis_url":genesis,"bootstrap_url":erpc_core::endpoints::near_bootstrap(network.name).ok_or("unsupported bootstrap network")?,"rpc_public":!node.rpc_allow.is_empty(),"metrics_public":!node.metrics_allow.is_empty(),"policy_sha256":policy(node)?,"allow_pending_upgrade":false}}),
    )
}
fn bundle(inventory: &str) -> Result<Built, String> {
    let mut bundle = Bundle::new();
    add_templates(&erpc_chain_near::TEMPLATES, &mut bundle)?;
    bundle
        .add("inventory.yml", inventory.as_bytes().to_vec())
        .map_err(|e| e.to_string())?;
    bundle
        .add("rpc-firewall.py", erpc_ops::RPC_FIREWALL.to_vec())
        .map_err(|e| e.to_string())?;
    bundle.finish().map_err(|e| e.to_string())
}

fn preparation_variables(
    node: &NearRpc,
    network: Network,
    facts: &Facts,
    verb: &str,
) -> Result<Value, String> {
    let mut vars = variables(node, network, facts)?;
    vars["near_prepare"]["allow_pending_upgrade"] = json!(verb == "update");
    Ok(vars)
}
fn deploy(
    session: &Session,
    target: &Target,
    node: &NearRpc,
    network: Network,
    inventory: &str,
    say: &Say,
    args: &ArgMatches,
) -> Result<String, String> {
    // Artifact download and native identity initialization precede the short
    // firewall confirmation window. The host remains durably fenced meanwhile.
    play(session, target, inventory, "node/prepare.yml", say)?;
    if node.validator.is_some() {
        let vars: Value =
            serde_json::from_str(inventory).map_err(|_| "invalid public deployment variables")?;
        let intent = vars["all"]["hosts"][&node.name]["near_prepare"]["intent"]
            .as_str()
            .ok_or("missing deployment intent")?;
        import_validator(session, node, network, args, intent, false)?;
    }
    let prepared = bundle(inventory)?;
    let run =
        erpc_ops::run::start(session, &prepared, "node/firewall.yml").map_err(|e| e.to_string())?;
    let result = node_common::follow(target, &run, "Retry NEAR firewall preparation", say)?;
    if !result.ok() {
        return Err("NEAR firewall preparation failed; node remains fenced".into());
    }
    let fresh = Session::open(target).map_err(|e| e.to_string())?;
    control(&fresh, node, network, Action::Status)?;
    fresh
        .run(
            &RemoteCommand::NearFirewallConfirm {
                token: erpc_ssh::firewall::FirewallToken::new(run.clone(), &prepared.sha256)?,
            },
            None,
        )
        .map_err(|_| "NEAR firewall confirmation failed; wait for rollback before retrying")?;
    let confirmed = erpc_ops::firewall_inventory(inventory, &run, &prepared.sha256)?;
    play(session, target, &confirmed, "node/activate.yml", say)
}
fn import_validator(
    session: &Session,
    node: &NearRpc,
    network: Network,
    args: &ArgMatches,
    intent: &str,
    restore: bool,
) -> Result<Value, String> {
    #[derive(serde::Serialize)]
    struct Import<'a> {
        key_file: &'a str,
        keys_unhosted: bool,
        restore: bool,
        intent: &'a str,
        policy_sha256: String,
    }
    let reservation = registration(node, network)?;
    let validator = node
        .validator
        .as_ref()
        .ok_or("validator metadata is missing")?;
    let reference = erpc_secret::OpRef::parse(&validator.key_ref)
        .map_err(|_| "invalid consensus key reference")?;
    let secret = crate::rollup_credentials::read_concealed(&node_common::op_runner()?, &reference)?;
    erpc_chain_near::validator::validate_key(
        &secret,
        &reservation.validator_account,
        &reservation.staking_public_key,
    )?;
    let request = Zeroizing::new(
        serde_json::to_string(&Import {
            key_file: secret.expose_secret(),
            keys_unhosted: args
                .try_get_one::<bool>("keys-unhosted")
                .ok()
                .flatten()
                .copied()
                .unwrap_or(false),
            restore,
            intent,
            policy_sha256: policy(node)?,
        })
        .map_err(|_| "cannot encode consensus import")?,
    );
    let output = session
        .run(
            &RemoteCommand::NearControl {
                action: Action::ImportValidator,
                contract: contract(node, network)?,
            },
            Some(request.as_bytes()),
        )
        .map_err(|_| "consensus import refused; original custody and deployment fences remain")?;
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "invalid public consensus import response".into())
}

fn registration_action(
    session: &Session,
    node: &NearRpc,
    network: Network,
    args: &ArgMatches,
) -> Result<Value, String> {
    let reservation = registration(node, network)?;
    match one(args, "action") {
        Some("restore-key") => {
            node_common::go_ahead(yes(args), "validator key was not restored")
                .map_err(|e| e.to_string())?;
            import_validator(session, node, network, args, "", true)
        }
        Some("status") => control(session, node, network, Action::Registration),
        Some("validate") => control(session, node, network, Action::ValidateRegistration),
        Some("prepare") => {
            let observed = control(session, node, network, Action::ValidateRegistration)?;
            let step = one(args, "step").ok_or("prepare requires an explicit --step")?;
            reservation.prepare_observed(step, one(args, "amount-yocto"), &observed)
        }
        _ => Err("unsupported read-only registration or explicit restoration action".into()),
    }
}

fn init(network: Network, args: &ArgMatches, say: &Say, validator: bool) -> Result<Value, String> {
    let (store, vault) = open(network, args)?;
    let name = one(args, "name").ok_or("init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    let existing = store
        .near_nodes(validator)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name);
    let mut node = if let Some(node) = existing {
        if one(args, "host").is_some_and(|v| v != node.address) {
            return Err("init cannot retarget an owned NEAR host".into());
        }
        node
    } else {
        let host = one(args, "host").ok_or("new node requires --host")?;
        let port = args.get_one::<u16>("port").copied().unwrap_or(22);
        let key = node_common::host_key(host, port, None, one(args, "fingerprint"), say)?;
        NearRpc {
            name: name.into(),
            address: host.into(),
            ssh_user: one(args, "user").unwrap_or("ubuntu").into(),
            ssh_port: port,
            host_key: key.to_openssh(),
            version: network.version.into(),
            commit: network.commit.into(),
            platform: "x86_64".into(),
            management_allow: ranges(args, "management-allow", &[])?,
            rpc_allow: ranges(args, "rpc-allow", &[])?,
            metrics_allow: ranges(args, "metrics-allow", &[])?,
            validator: if validator {
                Some(Validator {
                    account_id: one(args, "validator-account")
                        .ok_or("validator init requires --validator-account")?
                        .into(),
                    owner_account: one(args, "owner-account")
                        .ok_or("validator init requires --owner-account")?
                        .into(),
                    public_key: one(args, "staking-public-key")
                        .ok_or("validator init requires --staking-public-key")?
                        .into(),
                    key_ref: one(args, "validator-key")
                        .ok_or("validator init requires --validator-key op:// reference")?
                        .into(),
                    commission_basis_points: *args
                        .get_one::<u16>("commission-bps")
                        .ok_or("validator init requires explicit --commission-bps")?,
                })
            } else {
                None
            },
            ..NearRpc::default()
        }
    };
    if node.validator.is_some() {
        registration(&node, network)?;
        if !node.rpc_allow.is_empty() {
            return Err("dedicated validators keep RPC on loopback".into());
        }
        erpc_secret::OpRef::parse(&node.validator.as_ref().ok_or("missing validator")?.key_ref)
            .map_err(|_| "validator key requires an identifier-only 1Password reference")?;
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let facts = crate::eth_rpc::facts(&session)?;
    host_check(&facts, network, validator)?;
    node_common::go_ahead(yes(args), "no NEAR host changed").map_err(|e| e.to_string())?;
    if node.id.is_none() {
        node = store.add_near_rpc(&node).map_err(|e| e.to_string())?;
    }
    let inventory =
        json!({"all":{"hosts":{node.name.clone():variables(&node,network,&facts)?}}}).to_string();
    node.last_run = play(&session, &target, &inventory, "node/init.yml", say)?;
    node.last_result = "prepared; deploy required".into();
    store.update_near_rpc(&node).map_err(|e| e.to_string())?;
    node_common::save_vault(network.name, &vault)?;
    Ok(json!({"name":node.name,"network":network.name,"phase":"prepared"}))
}
fn runtime_qualified(network: Network, observed: &Value) -> bool {
    let installed = &observed["installed"];
    installed["version"] == network.version
        && installed["commit"] == network.commit
        && installed["image"] == network.image
}

fn observed_status(network: Network, mut observed: Value) -> Result<Value, String> {
    let qualified = runtime_qualified(network, &observed);
    let fields = observed
        .as_object_mut()
        .ok_or("invalid original NEAR status structure")?;
    fields.insert("release_qualified".into(), json!(qualified));
    fields.insert("qualified_version".into(), json!(network.version));
    if !qualified {
        fields.insert("ready".into(), json!(false));
        if fields.contains_key("producer_eligible") {
            fields.insert("producer_eligible".into(), json!(false));
        }
    }
    Ok(observed)
}

fn operation(
    verb: &str,
    network: Network,
    args: &ArgMatches,
    say: &Say,
    validator: bool,
) -> Result<Value, String> {
    if verb == "init" {
        return init(network, args, say, validator);
    }
    let (store, _) = open(network, args)?;
    if verb == "list" {
        return Ok(json!({"nodes":store.near_nodes(validator).map_err(|e|e.to_string())?}));
    }
    let mut node = find(&store, args, validator)?;
    if verb == "plan" {
        return Ok(
            json!({"name":node.name,"network":network.name,"current_version":node.version,"qualified_version":network.version,"source_commit":network.commit,
            "image":network.image,"role":if validator {"validator"} else {"RPC follower"},"retention":"five epochs, all shards","rpc":"loopback unless trusted ranges selected","identity":"encrypted host credential; retained on destroy","live_acceptance":"deferred"}),
        );
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if verb == "registration" {
        return registration_action(&session, &node, network, args);
    }
    let before = control(&session, &node, network, Action::Status)?;
    if verb == "status" {
        return observed_status(network, before);
    }
    if verb == "logs" {
        session
            .stream(
                &RemoteCommand::NearLogs {
                    lines: args.get_one::<u32>("lines").copied().unwrap_or(100),
                    follow: args.get_flag("follow"),
                },
                &mut |_, line| {
                    journal(line, say.quiet, crate::print_line, |value| say.line(value));
                },
            )
            .map_err(|e| e.to_string())?;
        return Ok(json!({"logs":"complete"}));
    }
    if before["phase"] == "installing" && !["deploy", "update", "stop", "destroy"].contains(&verb) {
        return Err("resume the same NEAR deploy before another mutation".into());
    }
    if matches!(verb, "start" | "restart") && !runtime_qualified(network, &before) {
        return Err("the installed NEAR source/image is outside this CLI's network qualification; use a CLI qualified for it or explicitly upgrade the original node, never downgrade its database".into());
    }
    node_common::go_ahead(yes(args), "no NEAR host changed").map_err(|e| e.to_string())?;
    match verb {
        "deploy" | "update" | "update-config" => {
            if verb == "update" {
                if one(args, "version") != Some(network.version) {
                    return Err("select this network's reviewed NEAR release; update the CLI catalog for other versions".into());
                }
                node.version = network.version.into();
                node.commit = network.commit.into();
            }
            if node.version != network.version || node.commit != network.commit {
                return Err(
                    "stored release differs from this CLI's qualified target; use update --version"
                        .into(),
                );
            }
            node.management_allow = ranges(args, "management-allow", &node.management_allow)?;
            node.rpc_allow = ranges(args, "rpc-allow", &node.rpc_allow)?;
            node.metrics_allow = ranges(args, "metrics-allow", &node.metrics_allow)?;
            let facts = crate::eth_rpc::facts(&session)?;
            let vars = preparation_variables(&node, network, &facts, verb)?;
            node = store.update_near_rpc(&node).map_err(|e| e.to_string())?;
            let inventory = json!({"all":{"hosts":{node.name.clone():vars}}}).to_string();
            node.last_run = deploy(&session, &target, &node, network, &inventory, say, args)?;
            node.last_result = format!("{verb} complete; synchronization observed separately");
            store.update_near_rpc(&node).map_err(|e| e.to_string())?;
            control(&session, &node, network, Action::Status)
        }
        "start" | "stop" | "restart" | "destroy" => {
            let action = match verb {
                "start" => Action::Start,
                "restart" => Action::Restart,
                "destroy" => Action::Retire,
                _ => Action::Stop,
            };
            let result = control(&session, &node, network, action)?;
            node.last_result = format!("{verb} complete; data and identity retained");
            store.update_near_rpc(&node).map_err(|e| e.to_string())?;
            Ok(result)
        }
        _ => Err("unsupported NEAR operation".into()),
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
    if verb == "registration"
        && let Err(error) = crate::near_tree::validate_registration_inputs(args)
    {
        return Outcome::Usage(error);
    }
    let Some(network) = network.and_then(network::get) else {
        return Outcome::Usage("NEAR requires mainnet or testnet explicitly".into());
    };
    let say = Say { quiet: json_out };
    let result = operation(verb, network, args, &say, validator);
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
fn owner(node: &NearRpc) -> Result<&str, String> {
    node.id
        .as_deref()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 80
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        .ok_or_else(|| "invalid NEAR inventory owner".into())
}
fn target(node: &NearRpc, args: &ArgMatches) -> Result<Target, String> {
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
fn add_templates(dir: &include_dir::Dir<'_>, bundle: &mut Bundle) -> Result<(), String> {
    for file in dir.files() {
        bundle
            .add(
                file.path().to_str().ok_or("invalid carried path")?,
                file.contents().to_vec(),
            )
            .map_err(|e| e.to_string())?;
    }
    for child in dir.dirs() {
        add_templates(child, bundle)?;
    }
    Ok(())
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
        "Resume NEAR deployment using its stored owner and release",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "NEAR play failed; data and ownership retained (run {})",
            run.as_str()
        ));
    }
    Ok(run.as_str().into())
}

fn journal(line: &str, json: bool, mut stdout: impl FnMut(&str), mut stderr: impl FnMut(&str)) {
    if json {
        stdout(&json!({"journal":line}).to_string());
    } else {
        stderr(line);
    }
}

#[cfg(test)]
mod journal_tests {
    #[test]
    fn original_status_requires_the_exact_current_network_release_without_erasing_its_receipt() {
        for name in ["mainnet", "testnet"] {
            let network = erpc_chain_near::network::get(name).unwrap();
            let original = serde_json::json!({"ready":true,"producer_eligible":true,"installed":{
                "version":network.version,"commit":network.commit,"image":network.image}});
            assert!(super::runtime_qualified(network, &original));
            assert_eq!(
                super::observed_status(network, original.clone()).unwrap()["ready"],
                true
            );
            for field in ["version", "commit", "image"] {
                let mut old = original.clone();
                old["installed"][field] = serde_json::json!("original-older-value");
                assert!(!super::runtime_qualified(network, &old));
                let report = super::observed_status(network, old.clone()).unwrap();
                assert_eq!(report["installed"], old["installed"]);
                assert_eq!(report["release_qualified"], false);
                assert_eq!(report["ready"], false);
                assert_eq!(report["producer_eligible"], false);
            }
            for malformed in [
                serde_json::Value::Null,
                serde_json::json!([]),
                serde_json::json!(true),
            ] {
                assert!(super::observed_status(network, malformed).is_err());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn parsed_update_reaches_the_carried_forward_recovery_with_original_data() {
        use std::io::Write as _;
        let network = erpc_chain_near::network::get("mainnet").unwrap();
        let node = erpc_chain::inventory::near::NearRpc {
            id: Some("fixtureowner".into()),
            name: "fixture".into(),
            version: network.version.into(),
            commit: network.commit.into(),
            platform: "x86_64".into(),
            ssh_port: 22,
            ..Default::default()
        };
        let facts = crate::eth_rpc::Facts::parse(
            "os=ubuntu 24.04\nmachine=x86_64\nmem_kb=131072000\ncpus=16\nsudo=yes\ncontroller=192.0.2.1\nssh_port=22\n",
        );
        for verb in ["deploy", "update", "update-config"] {
            let mut arguments = vec!["rpc", "--chain", "near", "--network", "mainnet", verb];
            if verb == "update" {
                arguments.extend(["--version", network.version]);
            }
            let parsed =
                crate::tree::command(erpc_core::chain::Role::Rpc, erpc_core::chain::Chain::Near)
                    .try_get_matches_from(arguments)
                    .unwrap();
            let (selected, _) = parsed.subcommand().unwrap();
            let vars = super::preparation_variables(&node, network, &facts, selected).unwrap();
            assert_eq!(
                vars["near_prepare"]["allow_pending_upgrade"],
                verb == "update"
            );
            if verb != "update" {
                continue;
            }
            let inventory = serde_json::json!({"all":{"hosts":{"fixture":vars}}}).to_string();
            let built = super::bundle(&inventory).unwrap();
            let python =
                std::env::var("ERPC_TEST_ANSIBLE_PYTHON").unwrap_or_else(|_| "python3".into());
            let mut child = std::process::Command::new(python)
                .args(["-I", "-B"])
                .arg(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/near_forward_play.py"),
                )
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
            let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(result["version"], "2.14.0");
            assert_eq!(result["original_data_preserved"], true);
            if std::env::var_os("ERPC_TEST_ANSIBLE_PYTHON").is_some() {
                assert_eq!(result["templated"], true);
            }
        }
    }

    #[test]
    fn firewall_uses_host_listener_across_port_translation_and_refuses_unknown_ports() {
        let network = erpc_chain_near::network::get("testnet").unwrap();
        let node = erpc_chain::inventory::near::NearRpc {
            id: Some("fixtureowner".into()),
            version: network.version.into(),
            commit: network.commit.into(),
            platform: "x86_64".into(),
            ssh_port: 2222,
            ..Default::default()
        };
        let observed = "os=ubuntu 24.04\nmachine=x86_64\nmem_kb=32000000\ncpus=16\nsudo=yes\ncontroller=192.0.2.1\n";
        for port in [22, 2222] {
            let facts = crate::eth_rpc::Facts::parse(&format!("{observed}ssh_port={port}\n"));
            let vars = super::variables(&node, network, &facts).unwrap();
            assert_eq!(vars["near_ssh_port"], port);
            assert_eq!(node.ssh_port, 2222);
        }
        for value in ["", "0", "invalid", "65536"] {
            let facts = crate::eth_rpc::Facts::parse(&format!("{observed}ssh_port={value}\n"));
            assert!(
                super::variables(&node, network, &facts)
                    .unwrap_err()
                    .contains("SSH listener")
            );
        }
        assert!(super::variables(&node, network, &crate::eth_rpc::Facts::parse(observed)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rendered_startup_authenticates_paths_before_interpreting_helper_bytes() {
        use std::io::Write;
        let built = super::bundle("all: {hosts: {fixture: {ansible_connection: local}}}").unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-near/tests/entrypoints.py");
        let mut child = std::process::Command::new("python3")
            .arg("-I")
            .arg("-B")
            .arg(script)
            .arg(erpc_ssh::python::systemd_command("/usr/local/lib/erpc/near/control.py").unwrap())
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
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["rendered_entries"], 4);
        assert_eq!(report["inert_execution_scenarios"], 28);
    }

    #[test]
    fn json_journal_records_never_emit_unencoded_lines_on_either_stream() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        for line in ["node started", "quoted \"value\" and\nnewline"] {
            super::journal(
                line,
                true,
                |s| out.push(s.to_owned()),
                |s| err.push(s.to_owned()),
            );
        }
        assert!(err.is_empty());
        assert_eq!(out.len(), 2);
        for record in out {
            assert_eq!(record.lines().count(), 1);
            assert!(
                serde_json::from_str::<serde_json::Value>(&record).expect("NDJSON")["journal"]
                    .is_string()
            );
        }
        super::journal(
            "plain",
            false,
            |_| panic!("human logs stay on stderr"),
            |s| err.push(s.to_owned()),
        );
        assert_eq!(err, ["plain"]);
    }
}
