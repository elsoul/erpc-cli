// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated Arbitrum/Robinhood followers, with concealed parent-chain transport.

use crate::{
    commands::Outcome,
    eth_rpc::Facts,
    node_common::{self, Say},
};
use clap::ArgMatches;
use erpc_auth::store::one_password::{OpCli, OpRunner};
use erpc_chain::inventory::{Store, nitro::NitroRpc};
use erpc_chain_nitro::{
    network::{Network, robinhood_genesis},
    release::{self, Platform},
};
use erpc_chain_rollup::upstreams::Credential;
use erpc_ops::bundle::{Built, Bundle};
use erpc_secret::OpRef;
use erpc_ssh::{HostKey, Identity, RemoteCommand, Session, Target};
use secrecy::{ExposeSecret, SecretString};
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
fn owner(node: &NitroRpc) -> Result<&str, String> {
    node.id
        .as_deref()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 80
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        .ok_or_else(|| "invalid Nitro inventory owner".into())
}
fn request(node: &NitroRpc, network: Network, action: &str) -> Result<Value, String> {
    let qualified = release::get(&node.version)?;
    if node.commit != qualified.commit || Platform::parse(&node.platform).is_none() {
        return Err("stored Nitro pin is not in the reviewed catalog".into());
    }
    let identity =
        serde_json::to_vec(&(&node.upstreams_ref, &node.management_allow, node.ssh_port))
            .map_err(|_| "cannot encode configuration identity")?;
    let config_id = format!("{:x}", Sha256::digest(identity));
    Ok(
        json!({"owner":owner(node)?,"family":network.family(),"network":network.name(),"version":node.version,"commit":node.commit,"platform":node.platform,"action":action,"config_id":config_id}),
    )
}
fn control(
    session: &Session,
    node: &NitroRpc,
    network: Network,
    action: &str,
) -> Result<Value, String> {
    let body = request(node, network, action)?.to_string();
    let output = session
        .run(&RemoteCommand::NitroControl, Some(body.as_bytes()))
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid Nitro controller response".into())
}
fn credential<R: OpRunner>(runner: &R, reference: &str) -> Result<Credential, String> {
    let reference = OpRef::parse(reference)
        .map_err(|_| "L1 upstreams require an identifier-only op reference")?;
    crate::rollup_credentials::read(runner, &reference)
}
fn send_credential(
    session: &Session,
    node: &NitroRpc,
    network: Network,
    secret: &Credential,
    action: &str,
) -> Result<(), String> {
    let encoded = secret_request(node, network, secret, action)?;
    session
        .run(
            &RemoteCommand::NitroControl,
            Some(encoded.expose_secret().as_bytes()),
        )
        .map_err(|_| "L1 credential installation or parent identity verification failed")?;
    Ok(())
}
fn secret_request(
    node: &NitroRpc,
    network: Network,
    secret: &Credential,
    action: &str,
) -> Result<SecretString, String> {
    let quoted = SecretString::from(
        serde_json::to_string(secret.secret().expose_secret())
            .map_err(|_| "cannot encode L1 credential")?,
    );
    let base = request(node, network, action)?.to_string();
    let encoded = SecretString::from(format!(
        "{},\"secret\":{}}}",
        base.trim_end_matches('}'),
        quoted.expose_secret()
    ));
    Ok(encoded)
}

fn target(node: &NitroRpc, args: &ArgMatches) -> Result<Target, String> {
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
fn host_check(facts: &Facts) -> Result<Platform, String> {
    let ubuntu = facts
        .os
        .strip_prefix("ubuntu ")
        .and_then(|v| v.split_once('.'))
        .and_then(|(a, b)| Some((a.parse::<u32>().ok()?, b.parse::<u32>().ok()?)))
        .is_some_and(|v| v >= (24, 4));
    if !ubuntu || !facts.sudo || facts.mem_kb < 60_000_000 || facts.cpus < 8 {
        return Err(
            "Nitro hosts require Ubuntu 24.04+, passwordless sudo, 64 GB RAM and eight CPU cores"
                .into(),
        );
    }
    Platform::parse(&facts.machine)
        .ok_or_else(|| "Nitro images support Linux x86-64 or ARM64".into())
}
fn open(network: Network, args: &ArgMatches) -> Result<(Store<OpCli>, String), String> {
    let vault = node_common::vault_for(
        network.name(),
        one(args, "vault"),
        "erpc r --chain <arbitrum|robinhood> init --network <network> --vault <vault>",
    )?;
    Ok((
        node_common::store(
            &node_common::op_runner()?,
            &vault,
            network.family(),
            network.name(),
        )?,
        vault,
    ))
}
fn find(store: &Store<OpCli>, args: &ArgMatches) -> Result<NitroRpc, String> {
    let name = one(args, "name").ok_or("Nitro operation requires --name")?;
    store
        .nitro_rpcs()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name)
        .ok_or_else(|| "Nitro node is not initialized in this network".into())
}
fn management(args: &ArgMatches, old: &[String]) -> Result<Vec<String>, String> {
    let values = args
        .try_get_many::<String>("management-allow")
        .ok()
        .flatten()
        .map_or_else(|| old.to_vec(), |v| v.cloned().collect());
    crate::arc_rpc::allow_list("management", &values, false)
}
fn variables(node: &NitroRpc, network: Network, facts: &Facts) -> Result<Value, String> {
    let platform = host_check(facts)?;
    if Some(platform) != Platform::parse(&node.platform) {
        return Err("host platform differs from its immutable inventory".into());
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
    let (url, sha) = network.chain_info()?;
    let genesis = robinhood_genesis()?;
    Ok(
        json!({"ansible_connection":"local","nitro_request":request(node,network,"prepare")?,"nitro_prepare_action":"prepare","nitro_family":network.family(),"nitro_parent":network.parent(),"nitro_image":release::get(&node.version)?.image(platform),"nitro_info_url":url,"nitro_info_sha":sha,"nitro_custom_genesis":network.custom_genesis(),"nitro_genesis_url":genesis.0,"nitro_genesis_sha":genesis.1,"nitro_management_v4":v4,"nitro_management_v6":v6,"nitro_ssh_port":node.ssh_port}),
    )
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
fn bundle(inventory: &str) -> Result<Built, String> {
    let mut bundle = Bundle::new();
    add_templates(&erpc_chain_nitro::TEMPLATES, &mut bundle)?;
    bundle
        .add("inventory.yml", inventory.as_bytes().to_vec())
        .map_err(|e| e.to_string())?;
    bundle
        .add(
            "node/upstreams.py",
            erpc_chain_rollup::UPSTREAM_PROXY.as_bytes().to_vec(),
        )
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
        "Resume Nitro deployment using its stored owner and release",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "Nitro play failed; data and ownership retained (run {})",
            run.as_str()
        ));
    }
    Ok(run.as_str().into())
}
fn deploy(
    session: &Session,
    target: &Target,
    node: &NitroRpc,
    network: Network,
    inventory: &str,
    say: &Say,
) -> Result<String, String> {
    // Short policy application completes before confirmation. No slow image/snapshot
    // work holds the run lock while its rollback timer is awaiting confirmation.
    let preparation = bundle(inventory)?;
    let prepared = erpc_ops::run::start(session, &preparation, "node/firewall.yml")
        .map_err(|e| e.to_string())?;
    let result = node_common::follow(target, &prepared, "Retry Nitro firewall preparation", say)?;
    if !result.ok() {
        return Err("Nitro firewall preparation failed; deployment did not start".into());
    }
    let fresh = Session::open(target).map_err(|e| e.to_string())?;
    // A new connection also verifies that the same immutable node owns this host.
    control(&fresh, node, network, "status")?;
    fresh
        .run(
            &RemoteCommand::NitroFirewallConfirm {
                robinhood: network.family() == "robinhood",
                token: erpc_ssh::firewall::FirewallToken::new(
                    prepared.clone(),
                    &preparation.sha256,
                )?,
            },
            None,
        )
        .map_err(|_| "Nitro firewall confirmation failed; await rollback before retrying")?;
    let confirmed = erpc_ops::firewall_inventory(inventory, &prepared, &preparation.sha256)?;
    play(session, target, &confirmed, "node/deploy.yml", say)
}

fn init(network: Network, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let (store, vault) = open(network, args)?;
    let name = one(args, "name").ok_or("init requires --name")?;
    erpc_chain::inventory::check_name(name).map_err(|e| e.to_string())?;
    let existing = store
        .nitro_rpcs()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name);
    let mut node = if let Some(node) = existing {
        if one(args, "host").is_some_and(|v| v != node.address)
            || one(args, "l1-upstreams").is_some_and(|v| v != node.upstreams_ref)
            || one(args, "version").is_some_and(|v| v != node.version)
        {
            return Err(
                "init cannot retarget an owned node; use update-config for upstream rotation"
                    .into(),
            );
        }
        node
    } else {
        let qualified = release::get(one(args, "version").unwrap_or(release::VERSION))?;
        let host = one(args, "host").ok_or("new node requires --host")?;
        let port = args.get_one::<u16>("port").copied().unwrap_or(22);
        let host_key = node_common::host_key(host, port, None, one(args, "fingerprint"), say)?;
        NitroRpc {
            name: name.into(),
            address: host.into(),
            ssh_user: one(args, "user").unwrap_or("ubuntu").into(),
            ssh_port: port,
            host_key: host_key.to_openssh(),
            version: qualified.version.into(),
            commit: qualified.commit.into(),
            upstreams_ref: one(args, "l1-upstreams")
                .ok_or("new node requires --l1-upstreams with an op reference")?
                .into(),
            management_allow: management(args, &[])?,
            ..NitroRpc::default()
        }
    };
    release::qualify(&node.version)?;
    let secret = credential(&node_common::op_runner()?, &node.upstreams_ref)?;
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let facts = crate::eth_rpc::facts(&session)?;
    let platform = host_check(&facts)?;
    if node.id.is_some() && Platform::parse(&node.platform) != Some(platform) {
        return Err("stored Nitro platform differs from host".into());
    }
    node.platform = platform.name().into();
    node_common::go_ahead(yes(args), "no Nitro host changed").map_err(|e| e.to_string())?;
    if node.id.is_none() {
        node = store.add_nitro_rpc(&node).map_err(|e| e.to_string())?;
    }
    let vars = variables(&node, network, &facts)?;
    let inventory = json!({"all":{"hosts":{node.name.clone():vars}}}).to_string();
    node.last_run = play(&session, &target, &inventory, "node/prepare.yml", say)?;
    // Init retry must not mutate a running owner's credentials; deploy/update-config
    // performs a fenced refresh. A prepared host has no listener to interrupt.
    let status = control(&session, &node, network, "status")?;
    if status["phase"] == "prepared" {
        send_credential(&session, &node, network, &secret, "install-upstreams")?;
    }
    node.last_result = "prepared; deploy required".into();
    store.update_nitro_rpc(&node).map_err(|e| e.to_string())?;
    node_common::save_vault(network.name(), &vault)?;
    Ok(
        json!({"name":node.name,"family":network.family(),"network":network.name(),"state":status["phase"]}),
    )
}
fn operation(verb: &str, network: Network, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    if verb == "init" {
        return init(network, args, say);
    }
    let (store, _) = open(network, args)?;
    if verb == "list" {
        return Ok(json!({"nodes":store.nitro_rpcs().map_err(|e|e.to_string())?}));
    }
    let mut node = find(&store, args)?;
    if verb == "plan" {
        let wanted = one(args, "version").unwrap_or(&node.version);
        release::qualify(wanted)?;
        return Ok(
            json!({"name":node.name,"family":network.family(),"network":network.name(),"change":one(args,"change").unwrap_or("deploy"),"current_version":node.version,"version":wanted,"storage":"PathDB full follower with online pruning","rpc":"loopback HTTP/WS","validator":false,"destroy_preserves_data":true,"financial_transactions":"external tools only"}),
        );
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let before = control(&session, &node, network, "status")?;
    if verb == "status" {
        return Ok(before);
    }
    if verb == "logs" {
        let output = Say { quiet: false };
        session
            .stream(
                &RemoteCommand::NitroLogs {
                    robinhood: network.family() == "robinhood",
                    lines: args.get_one::<u32>("lines").copied().unwrap_or(100),
                    follow: args.get_flag("follow"),
                },
                &mut |_, line| output.line(line),
            )
            .map_err(|e| e.to_string())?;
        return Ok(json!({"logs":"complete"}));
    }
    if before["phase"] == "installing" && verb != "deploy" {
        return Err("resume deploy at the stored target before another operation".into());
    }
    let facts = crate::eth_rpc::facts(&session)?;
    host_check(&facts)?;
    node_common::go_ahead(yes(args), "no Nitro host changed").map_err(|e| e.to_string())?;
    match verb {
        "deploy" | "update" | "update-config" => {
            let existing = node.clone();
            if verb == "update" {
                let wanted = release::update(
                    &node.version,
                    one(args, "version").ok_or("update requires --version")?,
                )?;
                node.version = wanted.version.into();
                node.commit = wanted.commit.into();
            }
            if let Some(reference) = one(args, "l1-upstreams") {
                OpRef::parse(reference).map_err(|_| "invalid L1 upstream op reference")?;
                node.upstreams_ref = reference.into();
            }
            node.management_allow = management(args, &node.management_allow)?;
            let secret = credential(&node_common::op_runner()?, &node.upstreams_ref)?;
            send_credential(&session, &existing, network, &secret, "validate-upstreams")?;
            // Keep the desired reference before remote mutation so an interrupted
            // encrypted credential rotation resumes exactly that intended source.
            node = store.update_nitro_rpc(&node).map_err(|e| e.to_string())?;
            let mut vars = variables(&node, network, &facts)?;
            vars["nitro_prepare_action"] = json!("begin-install");
            let inventory = json!({"all":{"hosts":{node.name.clone():vars}}}).to_string();
            // The carried controller understands this CLI's release catalog. It
            // fences/stops the old owner before replacing the installed helper.
            play(&session, &target, &inventory, "node/prepare.yml", say)?;
            send_credential(&session, &node, network, &secret, "install-upstreams")?;
            node.last_run = deploy(&session, &target, &node, network, &inventory, say)?;
            node.last_result = format!("{verb} complete; synchronization observed separately");
            store.update_nitro_rpc(&node).map_err(|e| e.to_string())?;
            control(&session, &node, network, "status")
        }
        "start" | "stop" | "restart" | "destroy" => {
            let result = control(&session, &node, network, verb)?;
            node.last_result = format!("{verb} complete; data retained");
            store.update_nitro_rpc(&node).map_err(|e| e.to_string())?;
            Ok(result)
        }
        _ => Err("unsupported Nitro operation".into()),
    }
}
pub(crate) fn run(
    verb: &str,
    family: &str,
    args: &ArgMatches,
    network: Option<&str>,
    json_out: bool,
) -> Outcome {
    let Some(network) = network.and_then(|n| Network::parse(family, n)) else {
        return Outcome::Usage(
            "Nitro requires an explicit supported network for its chain family".into(),
        );
    };
    let say = Say { quiet: json_out };
    match operation(verb, network, args, &say) {
        Ok(value) => {
            let unhealthy = verb == "status" && value["ready"] != true;
            if json_out {
                crate::print_json(&value);
            } else {
                say.line(&serde_json::to_string_pretty(&value).unwrap_or_default());
            }
            if unhealthy {
                Outcome::Failed(
                    "Nitro follower is not ready; inspect sync and parent-chain connectivity"
                        .into(),
                )
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
    use erpc_auth::store::{StoreError, one_password::OpOutput};
    use std::cell::Cell;
    struct FakeOp {
        called: Cell<bool>,
        success: bool,
        body: String,
    }
    impl OpRunner for FakeOp {
        fn run(&self, args: &[&str], input: Option<&str>) -> Result<OpOutput, StoreError> {
            self.called.set(true);
            assert_eq!(&args[..2], &["item", "get"]);
            assert_eq!(args[2], "b".repeat(26));
            assert!(input.is_none());
            Ok(OpOutput {
                success: self.success,
                stdout: self.body.clone(),
                stderr: "concealed fixture must not leak".into(),
            })
        }
    }
    fn reference() -> String {
        format!("op://{}/{}/l1", "a".repeat(26), "b".repeat(26))
    }
    fn node() -> NitroRpc {
        NitroRpc {
            id: Some("ownerfixture".into()),
            version: release::VERSION.into(),
            commit: release::COMMIT.into(),
            platform: "amd64".into(),
            upstreams_ref: reference(),
            ..NitroRpc::default()
        }
    }
    #[test]
    fn secret_store_failures_and_reference_errors_never_echo_provider_data() {
        let fake = FakeOp {
            called: Cell::new(false),
            success: false,
            body: "concealed fixture".into(),
        };
        assert!(credential(&fake, "op://by-name/item/field").is_err());
        assert!(!fake.called.get());
        let error = credential(&fake, &reference()).err().expect("failed op");
        assert!(!error.contains("concealed fixture"));
        assert!(fake.called.get());
    }
    #[test]
    fn concealed_payload_is_valid_json_on_stdin_and_public_request_has_only_identity() {
        let endpoint = json!({"url":"https://github.com/rpc?fixture=concealed","headers":{"Authorization":"Bearer fixture-only"}});
        let raw = json!({"execution":endpoint,"beacon":endpoint}).to_string();
        let fake = FakeOp {
            called: Cell::new(false),
            success: true,
            body: json!({"id":"l1","label":"l1","type":"CONCEALED","value":raw}).to_string(),
        };
        let secret = credential(&fake, &reference()).expect("concealed schema");
        let encoded = secret_request(&node(), Network::Sepolia, &secret, "validate-upstreams")
            .expect("stdin encoding");
        let decoded: Value = serde_json::from_str(encoded.expose_secret()).expect("valid JSON");
        assert_eq!(decoded["secret"], raw);
        assert_eq!(decoded["action"], "validate-upstreams");
        let public = request(&node(), Network::Sepolia, "status").expect("metadata");
        assert!(!public.to_string().contains("concealed"));
        let mut changed = node();
        changed.upstreams_ref = format!("op://{}/{}/l1", "a".repeat(26), "c".repeat(26));
        assert_ne!(
            public["config_id"],
            request(&changed, Network::Sepolia, "status").expect("changed source")["config_id"]
        );
    }
}
