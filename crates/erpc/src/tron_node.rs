// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! TRON lifecycle with immutable ownership and external owner signing.
use crate::{
    commands::Outcome,
    error::CliError,
    eth_rpc::{Facts, Login},
    node_common::{self, Say},
};
use erpc_chain::inventory::tron::TronNode;
use erpc_chain_tron::{
    network::{self, Network},
    witness::{self, Witness},
};
use erpc_ops::bundle::Bundle;
use erpc_ssh::{
    HostKey, Identity, RemoteCommand, Session, Target,
    firewall::FirewallToken,
    sui::Confirmation,
    tron::{Action, Command, Contract},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // Independent CLI switches.
pub(crate) struct Args {
    pub validator: bool,
    pub network: String,
    pub name: String,
    pub host: Option<String>,
    pub user: String,
    pub port: u16,
    pub fingerprint: Option<String>,
    pub vault: Option<String>,
    pub login: Login,
    pub yes: bool,
    pub rpc_allow: Option<Vec<String>>,
    pub management_allow: Option<Vec<String>>,
    pub monitoring_allow: Option<Vec<String>>,
    pub owner: Option<String>,
    pub signer: Option<String>,
    pub candidate_url: Option<String>,
    pub references: [Option<String>; 2],
    pub keys_unhosted: bool,
    pub restore_keys: bool,
    pub registration: Option<String>,
    pub lines: u32,
    pub follow: bool,
}

fn metadata(node: &TronNode) -> Result<Witness, String> {
    let value = Witness {
        owner: node.owner.clone(),
        signer: node.signer.clone(),
        url: node.candidate_url.clone(),
    };
    value.validate()?;
    Ok(value)
}

fn ownership(node: &TronNode, net: Network) -> Result<Contract, String> {
    if node.role == "validator" {
        metadata(node)?;
    }
    Contract::new(
        net.name,
        &node.role,
        net.genesis,
        &node.architecture,
        &node.owner,
        &node.signer,
        node.id
            .as_deref()
            .ok_or("TRON requires a persisted inventory owner before host operations")?,
    )
}

fn contract(node: &TronNode, net: Network) -> Value {
    json!({"network":net.name,"role":node.role,"genesis":net.genesis,"architecture":node.architecture,"owner":node.owner,"signer":node.signer,"inventory_owner":node.id})
}

fn initialize_identity(node: &mut TronNode, existing: bool, args: &Args) -> Result<(), String> {
    if existing {
        metadata(node)?;
        if [&args.owner, &args.signer, &args.candidate_url]
            .iter()
            .zip([&node.owner, &node.signer, &node.candidate_url])
            .any(|(supplied, old)| supplied.as_ref().is_some_and(|value| value != old))
            || args
                .references
                .iter()
                .zip(&node.credential_references)
                .any(|(new, old)| new.as_ref().is_some_and(|value| value != old))
        {
            return Err("TRON owner, signer and credential references are immutable; no implicit signer migration".into());
        }
        return Ok(());
    }
    if !args.keys_unhosted {
        return Err(
            "new SR imports require --keys-unhosted; live signer migration is refused".into(),
        );
    }
    node.owner = args
        .owner
        .clone()
        .ok_or("new SR nodes require --owner-address")?;
    node.signer = args
        .signer
        .clone()
        .ok_or("new SR nodes require a separate --witness-address")?;
    node.candidate_url = args
        .candidate_url
        .clone()
        .ok_or("new SR nodes require --candidate-url")?;
    metadata(node)?;
    for (value, stored) in args.references.iter().zip(&mut node.credential_references) {
        let reference = value
            .as_deref()
            .ok_or("new SR nodes require --keystore-ref and --password-ref")?;
        witness::reference(reference)?;
        reference.clone_into(stored);
    }
    Ok(())
}

fn target(node: &TronNode, login: &Login) -> Result<Target, String> {
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
    let output = session
        .run(&RemoteCommand::Tron(Command::Facts), None)
        .map_err(|e| e.to_string())?;
    Ok(Facts::parse(&String::from_utf8_lossy(&output.stdout)))
}

fn preflight(value: &Facts, fresh: bool, validator: bool) -> Result<(), String> {
    if value.os != "ubuntu 24.04"
        || !value.sudo
        || value.mem_kb < if validator { 60_000_000 } else { 30_000_000 }
        || value.cpus < if validator { 32 } else { 16 }
    {
        return Err("TRON requires Ubuntu 24.04, passwordless sudo, 32 GB/16 CPUs for a query node or 64 GB/32 CPUs for an SR".into());
    }
    if fresh && value.data_free_kb.unwrap_or(value.root_free_kb) < 3_500_000_000 {
        return Err("TRON requires at least 3.5 TB free for chain data; prepare SSD storage before init, which never formats disks".into());
    }
    value.controller_ip()?;
    Ok(())
}

fn allow_lists(node: &mut TronNode, args: &Args) -> Result<(), String> {
    for (input, output, flag) in [
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
        if let Some(values) = input {
            *output = crate::arc_rpc::allow_list(flag, values, false)?;
        }
    }
    if node.role == "validator" && !node.rpc_allow.is_empty() {
        return Err("SR APIs must remain private".into());
    }
    Ok(())
}

fn pin(node: &mut TronNode, net: Network) -> Result<(), String> {
    net.tag.clone_into(&mut node.version);
    net.commit.clone_into(&mut node.commit);
    net.artifact(&node.architecture)?
        .sha256
        .clone_into(&mut node.archive_sha256);
    Ok(())
}

fn release_target(node: &TronNode, net: Network) -> Value {
    json!({"network":net.name,"architecture":node.architecture,"genesis":net.genesis,"version":net.version,
        "tag":node.version,"commit":node.commit,"jar_sha256":node.archive_sha256,"config_sha256":net.config_sha256})
}

fn variables(
    node: &TronNode,
    net: Network,
    facts: &Facts,
    intent: Confirmation,
) -> Result<String, String> {
    net.validate(
        &node.architecture,
        &node.version,
        &node.commit,
        &node.archive_sha256,
    )?;
    ownership(node, net)?;
    if node.role == "fullnode"
        && (!node.candidate_url.is_empty()
            || node.credential_references.iter().any(|s| !s.is_empty()))
    {
        return Err("query-only nodes cannot contain signer references".into());
    }
    for (name, list) in [
        ("stored API ranges", &node.rpc_allow),
        ("stored management ranges", &node.management_allow),
        ("stored metrics ranges", &node.monitoring_allow),
    ] {
        crate::arc_rpc::allow_list(name, list, false)?;
    }
    if node.role == "validator" && !node.rpc_allow.is_empty() {
        return Err("SR APIs must remain private".into());
    }
    let mut management = node.management_allow.clone();
    management.push(facts.controller_ip()?.to_string());
    management.sort();
    management.dedup();
    let artifact = net.artifact(&node.architecture)?;
    Ok(json!({"all":{"hosts":{node.name.clone():{
        "ansible_connection":"local", "tron_network":net.name,"tron_role":node.role,"tron_architecture":node.architecture,
        "tron_genesis":net.genesis,"tron_contract":contract(node,net),"tron_intent":intent.text(),"tron_release_target":release_target(node,net),
        "tron_owner":node.owner,"tron_signer":node.signer,"tron_inventory_owner":node.id,"tron_tag":net.tag,"tron_client_version":net.version,
        "tron_jar_url":artifact.url,"tron_jar_sha256":artifact.sha256,"tron_signature_url":artifact.signature_url,
        "tron_signature_sha256":artifact.signature_sha256,"tron_config_url":net.config_url(),"tron_config_sha256":net.config_sha256,
        "tron_primary_fingerprint":net.primary_fingerprint,"tron_signing_fingerprint":net.signing_fingerprint,
        "tron_java":artifact.java,"tron_javac":artifact.javac,"tron_java_major":artifact.java_major,"tron_java_package":artifact.java_package,
        "tron_database":artifact.database,"tron_ssh_port":node.ssh_port,"tron_management_allow":management,
        "tron_rpc_allow":node.rpc_allow,"tron_monitoring_allow":node.monitoring_allow
    }}}}).to_string())
}

fn play(
    session: &Session,
    target: &Target,
    inventory: &str,
    phase: &str,
    say: &Say,
) -> Result<(erpc_ssh::RunId, String), String> {
    let mut bundle = Bundle::new();
    for file in erpc_chain_tron::files() {
        bundle
            .add(
                file,
                erpc_chain_tron::file(file)
                    .ok_or("missing TRON template")?
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
    let run = erpc_ops::run::start(session, &built, &format!("ansible/tron/{phase}.yml"))
        .map_err(|e| e.to_string())?;
    say.line(&format!("run        {} ({phase})", run.as_str()));
    let result = node_common::follow(
        target,
        &run,
        "Inspect this run before retrying; ownership and original identity are retained",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "TRON {phase} failed in run {}; startup remains guarded",
            run.as_str()
        ));
    }
    Ok((run, built.sha256))
}

#[derive(Serialize)]
struct Payload<'a> {
    keystore: &'a str,
    password: &'a str,
}

fn credential(
    runner: &impl erpc_auth::store::one_password::OpRunner,
    raw: &str,
    maximum: usize,
) -> Result<SecretString, String> {
    let reference = erpc_secret::OpRef::parse(raw)
        .map_err(|_| "invalid identifier-only TRON credential reference")?;
    let value = crate::rollup_credentials::read_concealed(runner, &reference)?;
    if value.expose_secret().len() > maximum {
        return Err("TRON concealed credential exceeds its size limit".into());
    }
    Ok(value)
}

fn import_identity(
    session: &Session,
    node: &TronNode,
    net: Network,
    intent: Confirmation,
    restore: bool,
) -> Result<(), String> {
    let expected = ownership(node, net)?;
    if !restore
        && session
            .run(
                &RemoteCommand::Tron(Command::Operation(Action::CheckKeys, expected.clone())),
                None,
            )
            .is_ok()
    {
        return Ok(());
    }
    let runner = node_common::op_runner()?;
    let encrypted = credential(&runner, &node.credential_references[0], 16384)?;
    // Inspect only the encrypted document's declared public address before
    // reading its password or transferring anything to the host.
    let public: Value = serde_json::from_str(encrypted.expose_secret())
        .map_err(|_| "expected a native encrypted TRON keystore")?;
    if public["address"] != node.signer || public["version"] != 3 {
        return Err("the encrypted keystore does not declare the reserved witness address".into());
    }
    let password = credential(&runner, &node.credential_references[1], 1024)?;
    let payload = SecretString::from(
        serde_json::to_string(&Payload {
            keystore: encrypted.expose_secret(),
            password: password.expose_secret(),
        })
        .map_err(|_| "could not encode the private credential transport")?,
    );
    session.run(&RemoteCommand::Tron(Command::Import {contract:expected, intent, restore}), Some(payload.expose_secret().as_bytes()))
        .map_err(|_| "TRON identity import was not verified; original credentials and data were retained")?;
    Ok(())
}

fn public(node: &TronNode, net: Network) -> Value {
    json!({"name":node.name,"network":net.name,"role":node.role,"version":node.version,"commit":node.commit,
        "archive_sha256":node.archive_sha256,"genesis":net.genesis,"owner":node.owner,"witness_signer":node.signer,
        "last_run":node.last_run,"last_result":node.last_result})
}

fn observation(
    session: &Session,
    action: Action,
    node: &TronNode,
    net: Network,
) -> Result<Value, String> {
    let output = session
        .run(
            &RemoteCommand::Tron(Command::Operation(action, ownership(node, net)?)),
            None,
        )
        .map_err(|_| "TRON host/network observation could not be verified")?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid TRON observation response".into())
}

#[allow(clippy::too_many_lines)]
fn execute(verb: &str, args: &Args, say: &Say) -> Result<Value, CliError> {
    let net = network::get(&args.network)
        .ok_or("TRON supports Mainnet and Nile; Shasta is closed to independent nodes")?;
    let vault = node_common::vault_for(
        &args.network,
        args.vault.as_deref(),
        "erpc r/v --chain tron init --vault <vault ID>",
    )?;
    let store = node_common::store(&node_common::op_runner()?, &vault, "tron", net.name)?;
    let role = if args.validator {
        "validator"
    } else {
        "fullnode"
    };
    let nodes = store.tron_nodes(role).map_err(|e| e.to_string())?;
    if verb == "list" {
        return Ok(json!({"nodes":nodes.iter().map(|n|public(n,net)).collect::<Vec<_>>()}));
    }
    erpc_chain::inventory::check_name(&args.name).map_err(|e| e.to_string())?;
    let existing = nodes.iter().find(|n| n.name == args.name);
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| "could not create a unique deployment intent")?;
    let intent = Confirmation::new(random);
    if verb == "init" {
        let mut node = existing.cloned().unwrap_or_else(|| TronNode {
            name: args.name.clone(),
            address: args.host.clone().unwrap_or_default(),
            role: role.into(),
            ssh_user: args.user.clone(),
            ssh_port: args.port,
            ..TronNode::default()
        });
        if node.address.is_empty() {
            return Err("new TRON nodes require --host".into());
        }
        if existing.is_some()
            && args
                .host
                .as_ref()
                .is_some_and(|value| value != &node.address)
        {
            return Err("stored host is immutable".into());
        }
        if args.validator {
            initialize_identity(&mut node, existing.is_some(), args)?;
        }
        allow_lists(&mut node, args)?;
        node.host_key = node_common::host_key(
            &node.address,
            node.ssh_port,
            existing.map(|n| n.host_key.as_str()),
            args.fingerprint.as_deref(),
            say,
        )?
        .to_openssh();
        let target = target(&node, &args.login)?;
        let session = Session::open(&target).map_err(|e| e.to_string())?;
        let facts = facts(&session)?;
        preflight(&facts, existing.is_none(), args.validator)?;
        if existing.is_some() && node.architecture != facts.machine {
            return Err("host architecture changed".into());
        }
        node.architecture.clone_from(&facts.machine);
        if existing.is_none() {
            pin(&mut node, net)?;
        }
        net.validate(
            &node.architecture,
            &node.version,
            &node.commit,
            &node.archive_sha256,
        )?;
        say.line("plan       prepare Ubuntu/JDK and immutable ownership; no disk formatting or node signing");
        node_common::go_ahead(args.yes, "TRON init was not started")?;
        node = if existing.is_none() {
            store.add_tron_node(&node)
        } else {
            store.update_tron_node(&node)
        }
        .map_err(|e| e.to_string())?;
        // Reserve the unique inventory item before constructing any remote ownership.
        let inventory = variables(&node, net, &facts, intent)?;
        node_common::save_vault(net.name, &vault)?;
        node.last_run = play(&session, &target, &inventory, "init", say)?
            .0
            .as_str()
            .into();
        node.last_result = "init ok".into();
        return Ok(public(
            &store.update_tron_node(&node).map_err(|e| e.to_string())?,
            net,
        ));
    }
    let mut node = existing
        .cloned()
        .ok_or("no stored TRON node; run init first")?;
    if verb == "plan" {
        return Ok(
            json!({"node":public(&node,net),"phases":["fence and gracefully stop","authenticate exact client/config and native key binding","confirm short firewall preparation","activate only matching receipt"],"bootstrap":"genesis replay; no unauthenticated database snapshot is imported","acceptance":"real-host tests deferred"}),
        );
    }
    if verb == "registration" && args.registration.as_deref() == Some("prepare") {
        return Ok(metadata(&node)?.preparation(net.name));
    }
    let target = target(&node, &args.login)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if verb == "status" {
        return observation(&session, Action::Status, &node, net).map_err(Into::into);
    }
    if verb == "registration" {
        let action = if args.registration.as_deref() == Some("validate") {
            Action::ValidateRegistration
        } else {
            Action::Registration
        };
        return observation(&session, action, &node, net).map_err(Into::into);
    }
    if verb == "logs" {
        session
            .stream(
                &RemoteCommand::Tron(Command::Logs {
                    contract: ownership(&node, net)?,
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
        return Ok(json!({"journal":"complete"}));
    }
    if node.last_result.is_empty() {
        return Err("init has not completed; retry init first".into());
    }
    node_common::go_ahead(args.yes, "TRON operation was not started")?;
    if ["start", "stop", "restart"].contains(&verb) {
        let action = match verb {
            "start" => Action::Start,
            "stop" => Action::Stop,
            _ => Action::Restart,
        };
        return observation(&session, action, &node, net).map_err(Into::into);
    }
    if !["deploy", "update", "update-config", "destroy"].contains(&verb) {
        return Err("unsupported TRON operation".into());
    }
    let facts = facts(&session)?;
    preflight(&facts, false, args.validator)?;
    if facts.machine != node.architecture {
        return Err("stored host architecture changed; no cross-platform adoption".into());
    }
    if verb == "update" {
        pin(&mut node, net)?;
    }
    if verb == "update-config" {
        allow_lists(&mut node, args)?;
    }
    let inventory = variables(&node, net, &facts, intent)?;
    let run = if verb == "destroy" {
        play(&session, &target, &inventory, "destroy", say)?.0
    } else {
        play(&session, &target, &inventory, "prepare", say)?;
        if args.validator {
            import_identity(&session, &node, net, intent, args.restore_keys)?;
        }
        let (prepared, digest) = play(&session, &target, &inventory, "firewall", say)?;
        Session::open(&target).map_err(|e|e.to_string())?.run(&RemoteCommand::Tron(Command::Confirm{
            contract:ownership(&node,net)?,intent,token:FirewallToken::new(prepared.clone(),&digest)?}),None)
            .map_err(|_|"fresh firewall confirmation failed; this deployment was rolled back or superseded")?;
        let activated = erpc_ops::firewall_inventory(&inventory, &prepared, &digest)?;
        play(&session, &target, &activated, "activate", say)?.0
    };
    node.last_run = run.as_str().into();
    node.last_result = format!("{verb} ok");
    let saved = store.update_tron_node(&node).map_err(
        |_| "host operation finished but inventory update failed; inspect the run before retrying",
    )?;
    Ok(
        json!({"node":public(&saved,net),"readiness":"use status for sync/election; deployment success does not imply block production"}),
    )
}

fn report(verb: &str, result: &Value, json_out: bool) -> Outcome {
    let text = if json_out {
        crate::print_json(result);
        String::new()
    } else {
        serde_json::to_string_pretty(result).unwrap_or_default()
    };
    if verb == "status" && result["ready"] != true {
        Outcome::Problems(text)
    } else {
        Outcome::Done(text)
    }
}

pub(crate) fn run(verb: &str, args: &Args, json_out: bool) -> Outcome {
    match execute(verb, args, &Say { quiet: json_out }) {
        Ok(result) => report(verb, &result, json_out),
        Err(error) => Outcome::from(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_auth::store::{
        StoreError,
        one_password::{OpOutput, OpRunner},
    };
    struct Fake {
        kind: &'static str,
        value: String,
    }
    impl OpRunner for Fake {
        fn run(&self, args: &[&str], _: Option<&str>) -> Result<OpOutput, StoreError> {
            assert_eq!(&args[..2], &["item", "get"]);
            assert!(
                args.windows(2)
                    .any(|pair| pair == ["--fields", "label=witness"])
            );
            assert!(!args.join(" ").contains(&self.value));
            Ok(OpOutput {
                success: true,
                stdout:
                    json!({"id":"witness","label":"witness","type":self.kind,"value":self.value})
                        .to_string(),
                stderr: String::new(),
            })
        }
    }
    #[test]
    fn status_reports_problems_until_readiness_is_explicitly_true() {
        for result in [json!({"ready":false}), json!({}), json!({"ready":"true"})] {
            assert!(matches!(
                report("status", &result, false),
                Outcome::Problems(_)
            ));
        }
        assert!(matches!(
            report("status", &json!({"ready":true}), false),
            Outcome::Done(_)
        ));
        assert!(matches!(
            report("registration", &json!({"membership":"candidate"}), false),
            Outcome::Done(_)
        ));
    }

    #[test]
    fn witness_fields_are_selected_concealed_bounded_and_never_in_arguments() {
        let reference = format!("op://{}/{}/witness", "a".repeat(26), "b".repeat(26));
        let op = Fake {
            kind: "CONCEALED",
            value: "fixture passphrase".into(),
        };
        assert_eq!(
            credential(&op, &reference, 1024)
                .expect("concealed")
                .expose_secret(),
            "fixture passphrase"
        );
        assert!(credential(&op, &reference, 4).is_err());
        assert!(
            credential(
                &Fake {
                    kind: "STRING",
                    value: op.value
                },
                &reference,
                1024
            )
            .is_err()
        );
    }
    #[test]
    fn public_inventory_bundle_contains_no_credential_references_or_password_fields() {
        let net = network::get("nile").unwrap();
        let mut node = TronNode {
            name: "tron1".into(),
            id: Some("i".repeat(26)),
            architecture: "x86_64".into(),
            role: "fullnode".into(),
            ssh_port: 22,
            ..TronNode::default()
        };
        pin(&mut node, net).unwrap();
        let mut facts = Facts::parse("");
        facts.controller = "192.0.2.1".into();
        let inventory = variables(&node, net, &facts, Confirmation::new([3; 16])).unwrap();
        let parsed: Value = serde_json::from_str(&inventory).unwrap();
        let host = &parsed["all"]["hosts"]["tron1"];
        assert_eq!(host["tron_genesis"], net.genesis);
        assert_eq!(host["tron_inventory_owner"], "i".repeat(26));
        assert_eq!(host["tron_contract"]["inventory_owner"], "i".repeat(26));
        assert_eq!(host["tron_database"], "LEVELDB");
        assert_eq!(host["tron_java_major"], 8);
        assert!(!inventory.contains("password"));
        assert!(!inventory.contains("op://"));
        node.credential_references[0] = "forbidden reference".into();
        assert!(variables(&node, net, &facts, Confirmation::new([3; 16])).is_err());
    }
}
