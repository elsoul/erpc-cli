// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Separate AQA host lifecycle. External approval stays with the selected master.
use crate::{
    commands::Outcome,
    hyperliquid_ops as shared,
    node_common::{self, Say},
};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use erpc_chain::inventory::hyperliquid_aqa::Publisher;
use erpc_chain_hyperliquid::{
    Network,
    aqa::{self, AgentMaterial, Contract},
};
use erpc_core::chain::{COMMON_VERBS, Chain, Source, guard_mainnet};
use erpc_secret::OpRef;
use erpc_ssh::{
    HostKey, Identity, RemoteCommand, Session, Target,
    hyperliquid_aqa::{Command as HostCommand, Owner},
};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;
use zeroize::Zeroizing;

fn common_command(verb: &erpc_core::chain::Verb) -> Command {
    let mut sub = Command::new(verb.name)
        .about(verb.about)
        .arg(Arg::new("vault").long("vault"));
    if !verb.read_only {
        sub = sub.arg(
            Arg::new("yes")
                .long("yes")
                .short('y')
                .action(ArgAction::SetTrue),
        );
    }
    if !["list", "plan"].contains(&verb.name) {
        for name in ["ssh-key", "ssh-agent"] {
            sub = sub.arg(
                Arg::new(name)
                    .long(name)
                    .value_parser(value_parser!(PathBuf)),
            );
        }
    }
    sub
}

pub(crate) fn command() -> Command {
    let mut tree =
        Command::new("aqa").about("Manage a separate AQA publisher host and dedicated API agent");
    for verb in COMMON_VERBS {
        let mut sub = common_command(verb);
        if verb.name == "init" {
            for name in [
                "host",
                "user",
                "fingerprint",
                "validator-address",
                "consensus-signer",
                "agent-master",
                "agent-name",
                "agent-key-ref",
            ] {
                sub = sub.arg(Arg::new(name).long(name));
            }
            sub=sub.arg(Arg::new("port").long("port").value_parser(value_parser!(u16)))
                .arg(Arg::new("agent-exclusive").long("agent-exclusive").action(ArgAction::SetTrue)
                     .help("Attest this fresh dedicated agent is not used by another signing process and has never been deregistered"));
        }
        if ["init", "update-config"].contains(&verb.name) {
            sub = sub.arg(
                Arg::new("management-allow")
                    .long("management-allow")
                    .value_delimiter(',')
                    .action(ArgAction::Append),
            );
        }
        if verb.name == "update" {
            sub = sub.arg(Arg::new("version").long("version"));
        }
        if verb.name == "update-config" {
            sub = sub.arg(
                Arg::new("restore-key")
                    .long("restore-key")
                    .action(ArgAction::SetTrue)
                    .conflicts_with("management-allow")
                    .help("Stop and restore only the original concealed agent; do not restart"),
            );
        }
        if ["deploy", "update", "update-config"].contains(&verb.name) {
            sub = sub.arg(
                Arg::new("recover-preparation")
                    .long("recover-preparation")
                    .action(ArgAction::SetTrue)
                    .help(
                        "Fence and abandon an unfinished preparation, retaining original custody",
                    ),
            );
            if verb.name == "update-config" {
                sub = sub.mut_arg("recover-preparation", |arg| {
                    arg.conflicts_with("restore-key")
                });
            }
        }
        if verb.name == "logs" {
            sub = sub
                .arg(
                    Arg::new("lines")
                        .long("lines")
                        .default_value("100")
                        .value_parser(value_parser!(u32)),
                )
                .arg(
                    Arg::new("follow")
                        .long("follow")
                        .short('f')
                        .action(ArgAction::SetTrue),
                );
        }
        if verb.name == "plan" {
            sub = sub.arg(
                Arg::new("step")
                    .long("step")
                    .value_parser(["deploy", "approve-agent", "revoke-agent"])
                    .default_value("deploy"),
            );
        }
        tree = tree.subcommand(sub);
    }
    tree
}

fn required<'a>(args: &'a ArgMatches, name: &str) -> Result<&'a str, String> {
    shared::one(args, name).ok_or_else(|| format!("pass --{name}"))
}
fn target(node: &Publisher, args: &ArgMatches) -> Result<Target, String> {
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
fn settings(node: &mut Publisher, args: &ArgMatches) -> Result<(), String> {
    if let Some(values) = args
        .try_get_many::<String>("management-allow")
        .ok()
        .flatten()
    {
        node.management_allow = values.cloned().collect();
    }
    node.management_allow = aqa::management(&node.management_allow).map_err(str::to_owned)?;
    Ok(())
}
fn request(node: &Publisher, action: &str, intent: Option<&str>) -> Result<Value, String> {
    let catalog = aqa::catalog()?;
    let pin = &catalog["artifact"];
    let policy = json!({"management_allow":node.management_allow});
    let mut helper = Sha256::new();
    for name in erpc_ssh::hyperliquid_aqa::RUNTIME_FILES {
        helper.update(
            erpc_chain_hyperliquid::file(&format!("aqa/{name}"))
                .ok_or("compiled publisher helper missing")?,
        );
    }
    let mut value = json!({"action":action,"contract":node.contract,"policy":policy,"target":{
        "id":format!("aqa-{}",catalog["version"].as_str().ok_or("invalid publisher version")?),
        "sha256":pin["sha256"],"signed_at":pin["signed_at"],"helper_sha":format!("{:x}",helper.finalize()),
        "config_id":format!("{:x}",Sha256::digest(policy.to_string().as_bytes()))}});
    if let Some(intent) = intent {
        value["intent"] = json!(intent);
    }
    Ok(value)
}
fn control(session: &Session, value: &Value) -> Result<Value, String> {
    let response = session
        .run(
            &RemoteCommand::HyperliquidAqa(HostCommand::Control),
            Some(value.to_string().as_bytes()),
        )
        .map_err(|_| "AQA control refused; original authority and custody remain retained")?;
    serde_json::from_slice(&response.stdout).map_err(|_| "invalid public publisher response".into())
}
fn facts(session: &Session) -> Result<crate::eth_rpc::Facts, String> {
    let value = crate::eth_rpc::facts(session)?;
    if value.os != "ubuntu 24.04"
        || value.machine != "x86_64"
        || !value.sudo
        || value.cpus < 2
        || value.mem_kb < 1_536_000
        || value.ssh_port == 0
    {
        return Err("AQA requires Ubuntu24.04 x86-64, two CPUs, nominal2GiB RAM, passwordless sudo and the observed SSH listener".into());
    }
    Ok(value)
}
fn inventory(
    node: &Publisher,
    facts: &crate::eth_rpc::Facts,
    value: &Value,
) -> Result<String, String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for entry in &node.management_allow {
        if entry.contains(':') {
            v6.push(entry.clone());
        } else {
            v4.push(entry.clone());
        }
    }
    match facts.controller_ip()? {
        std::net::IpAddr::V4(ip) => v4.push(ip.to_string()),
        std::net::IpAddr::V6(ip) => v6.push(ip.to_string()),
    }
    if facts.ssh_port == 0 {
        return Err("actual SSH server listener is unavailable".into());
    }
    Ok(json!({"all":{"hosts":{node.name.clone():{"ansible_connection":"local","aqa_request":value,
        "aqa_loader":aqa::carried_loader(),"aqa_management_v4":v4,"aqa_management_v6":v6,"aqa_ssh_port":facts.ssh_port}}}}).to_string())
}
fn play(
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
        "recovery",
        "control",
    ]
    .contains(&phase)
    {
        return Err("unknown AQA phase".into());
    }
    let mut bundle = erpc_ops::bundle::Bundle::new();
    for name in erpc_chain_hyperliquid::files()
        .into_iter()
        .filter(|name| name.starts_with("aqa/") || name.starts_with("ansible/aqa/"))
    {
        bundle
            .add(
                name,
                erpc_chain_hyperliquid::file(name)
                    .ok_or("compiled AQA resource missing")?
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
    let archive = bundle.finish().map_err(|e| e.to_string())?;
    let run = erpc_ops::run::start(session, &archive, &format!("ansible/aqa/{phase}.yml"))
        .map_err(|e| e.to_string())?;
    let result = node_common::follow(
        target,
        &run,
        "Repair the original host condition and retry the same publisher target; custody is retained",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "AQA {phase} failed in {}; original custody is retained",
            run.as_str()
        ));
    }
    Ok((run, archive.sha256))
}

fn material(reference: &str) -> Result<AgentMaterial, String> {
    let reference = OpRef::parse(reference)
        .map_err(|_| "identifier-only concealed agent reference required")?;
    AgentMaterial::parse(crate::rollup_credentials::read_concealed(
        &node_common::op_runner()?,
        &reference,
    )?)
    .map_err(str::to_owned)
}
#[derive(Serialize)]
struct PrivateImport<'a> {
    action: &'static str,
    contract: &'a Contract,
    original: &'a str,
    restore: bool,
    unhosted: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyResult {
    custody: String,
    restored: bool,
    #[serde(default)]
    journal_recorded: Option<bool>,
}
fn import_agent(
    session: &Session,
    node: &Publisher,
    key: &AgentMaterial,
    restore: bool,
    exclusive: bool,
) -> Result<Value, String> {
    let expected = &node.contract.identity;
    if key
        .identity(
            &expected.validator,
            &expected.consensus_signer,
            &expected.agent_master,
            &expected.agent_name,
        )
        .map_err(str::to_owned)?
        != *expected
    {
        return Err("concealed agent differs from the immutable original public identity".into());
    }
    let value = PrivateImport {
        action: "import-agent",
        contract: &node.contract,
        original: key.original().expose_secret(),
        restore,
        unhosted: exclusive,
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(8192));
    serde_json::to_writer(&mut *bytes, &value)
        .map_err(|_| "cannot encode concealed original agent transport")?;
    let response = session
        .run(
            &RemoteCommand::HyperliquidAqa(HostCommand::Control),
            Some(bytes.as_slice()),
        )
        .map_err(|_| "original AQA custody import refused; inspect retained host state")?;
    let stdout = Zeroizing::new(response.stdout);
    let _stderr = Zeroizing::new(response.stderr);
    let result: CustodyResult =
        serde_json::from_slice(&stdout).map_err(|_| "invalid public original-agent receipt")?;
    if result.custody != "original" || result.restored != restore {
        return Err("unexpected original-agent import outcome".into());
    }
    Ok(
        json!({"custody":"original","restored":result.restored,"started":false,"journal_recorded":result.journal_recorded.unwrap_or(true)}),
    )
}

fn public(node: &Publisher) -> Value {
    json!({"name":node.name,"network":node.contract.network.name(),"profile":"hyperliquid-aqa","host":node.address,
        "identity":node.contract.identity,"version":node.version,"archive_sha256":node.archive_sha256,
        "management_allow":node.management_allow,"last_run":node.last_run,"last_result":node.last_result})
}

fn initial_record(
    network: Network,
    args: &ArgMatches,
    name: &str,
    previous: Option<&Publisher>,
    key: &AgentMaterial,
    reference: &str,
) -> Result<Publisher, String> {
    let catalog = aqa::catalog()?;
    let pin = &catalog["artifact"];
    let node = if let Some(old) = previous {
        for (flag, stored) in [
            ("host", old.address.as_str()),
            ("user", old.ssh_user.as_str()),
            ("agent-key-ref", old.agent_key_ref.as_str()),
            (
                "validator-address",
                old.contract.identity.validator.as_str(),
            ),
            (
                "consensus-signer",
                old.contract.identity.consensus_signer.as_str(),
            ),
            ("agent-master", old.contract.identity.agent_master.as_str()),
            ("agent-name", old.contract.identity.agent_name.as_str()),
        ] {
            if shared::one(args, flag).is_some_and(|value| value != stored) {
                return Err("original publisher host and agent authority cannot change".into());
            }
        }
        if args
            .get_one::<u16>("port")
            .is_some_and(|port| *port != old.ssh_port)
        {
            return Err("original publisher SSH port cannot change".into());
        }
        old.clone()
    } else {
        Publisher {
            id: None,
            item_version: 0,
            name: name.into(),
            address: required(args, "host")?.into(),
            ssh_user: shared::one(args, "user").unwrap_or("ubuntu").into(),
            ssh_port: args.get_one::<u16>("port").copied().unwrap_or(22),
            host_key: String::new(),
            contract: Contract {
                schema: 1,
                profile: "hyperliquid-aqa".into(),
                owner: shared::nonce()?,
                network,
                host_binding: String::new(),
                identity: key
                    .identity(
                        required(args, "validator-address")?,
                        required(args, "consensus-signer")?,
                        required(args, "agent-master")?,
                        required(args, "agent-name")?,
                    )
                    .map_err(str::to_owned)?,
            },
            agent_key_ref: reference.into(),
            version: catalog["version"]
                .as_str()
                .ok_or("invalid publisher version")?
                .into(),
            archive_sha256: pin["sha256"]
                .as_str()
                .ok_or("invalid publisher archive")?
                .into(),
            signed_at: pin["signed_at"]
                .as_u64()
                .ok_or("invalid publisher signature time")?,
            management_allow: vec![],
            last_run: String::new(),
            last_result: String::new(),
        }
    };
    Ok(node)
}

fn init(network: Network, args: &ArgMatches, say: &Say) -> Result<Value, String> {
    let name = required(args, "name")?;
    let (store, vault) = shared::open(network, args)?;
    let previous = store
        .hyperliquid_publishers()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|n| n.name == name);
    if previous.is_none() && !shared::flag(args, "agent-exclusive") {
        return Err(
            "initial AQA custody requires --agent-exclusive for a fresh dedicated agent".into(),
        );
    }
    let reference = previous.as_ref().map_or_else(
        || required(args, "agent-key-ref"),
        |n| Ok(n.agent_key_ref.as_str()),
    )?;
    let key = material(reference)?;
    let mut node = initial_record(network, args, name, previous.as_ref(), &key, reference)?;
    let identity = &node.contract.identity;
    if key
        .identity(
            &identity.validator,
            &identity.consensus_signer,
            &identity.agent_master,
            &identity.agent_name,
        )
        .map_err(str::to_owned)?
        != *identity
    {
        return Err("selected agent field no longer holds the original key".into());
    }
    settings(&mut node, args)?;
    erpc_ssh::config::check_host(&node.address).map_err(|e| e.to_string())?;
    node.host_key = node_common::host_key(
        &node.address,
        node.ssh_port,
        previous.as_ref().map(|n| n.host_key.as_str()),
        shared::one(args, "fingerprint"),
        say,
    )?
    .to_openssh();
    let binding = aqa::host_binding(&node.address, &node.ssh_user, node.ssh_port, &node.host_key);
    if previous.is_some() && binding != node.contract.host_binding {
        return Err("original pinned publisher connection changed".into());
    }
    node.contract.host_binding = binding;
    node.contract.validate()?;
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    let facts = facts(&session)?;
    node_common::go_ahead(shared::flag(args, "yes"), "AQA host unchanged")
        .map_err(|e| e.to_string())?;
    let vars = inventory(&node, &facts, &request(&node, "preflight", None)?)?;
    play(&session, &target, &vars, "preflight", say)?;
    node = if previous.is_some() {
        store.update_hyperliquid_publisher(&node)
    } else {
        store.add_hyperliquid_publisher(&node)
    }
    .map_err(|e| e.to_string())?;
    let (run, _) = play(&session, &target, &vars, "initialize", say)?;
    let imported = import_agent(&session, &node, &key, false, true)?;
    node.last_run = run.as_str().into();
    node.last_result = "initialized; original agent encrypted; publishing not started".into();
    store
        .update_hyperliquid_publisher(&node)
        .map_err(|e| e.to_string())?;
    node_common::save_vault(network.name(), &vault)?;
    Ok(json!({"publisher":public(&node),"custody":imported,"started":false,"approval":"external"}))
}

fn plan(node: Option<&Publisher>, args: &ArgMatches) -> Result<Value, String> {
    let catalog = aqa::catalog()?;
    let mut value = json!({"profile":"hyperliquid-aqa","version":catalog["version"],"source_commit":catalog["source_commit"],
        "archive_sha256":catalog["artifact"]["sha256"],"signed_at":catalog["artifact"]["signed_at"],
        "approval_and_revocation":"external wallet or official SDK","agent_authority":"general API-agent trading authority; not vote scoped",
        "vote_eligibility":"not established by agent approval","accepted_vote":null,"signed":false,"submitted":false});
    if let Some(node) = node {
        value["publisher"] = public(node);
        match shared::one(args, "step").unwrap_or("deploy") {
            "approve-agent" => {
                value["external_approval"] = json!({"master":node.contract.identity.agent_master,
                "action_fields":{"type":"approveAgent","hyperliquidChain":if node.contract.network==Network::Mainnet{"Mainnet"}else{"Testnet"},
                                 "agentAddress":node.contract.identity.agent,"agentName":node.contract.identity.agent_name},
                "operator_supplies":"fresh nonce, signing-chain domain and signature using the external master; this is not a broadcastable transaction"});
            }
            "revoke-agent" => {
                value["external_revocation"] = json!({"master":node.contract.identity.agent_master,"agent":node.contract.identity.agent,
                "name":node.contract.identity.agent_name,"instructions":"Stop this publisher, then revoke or replace the named approval using the official external wallet or SDK. Do not reapprove a pruned agent key."});
            }
            _ => {}
        }
    }
    Ok(value)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicEvent {
    sequence: u64,
    time: u64,
    action: String,
    ok: bool,
}
fn logs(
    session: &Session,
    node: &Publisher,
    args: &ArgMatches,
    json_out: bool,
    say: &Say,
) -> Result<Value, String> {
    let mut invalid = false;
    session
        .stream(
            &RemoteCommand::HyperliquidAqa(HostCommand::Logs {
                owner: Owner::new(&node.contract.owner)?,
                lines: args.get_one::<u32>("lines").copied().unwrap_or(100),
                follow: shared::flag(args, "follow"),
            }),
            &mut |stream, line| {
                if !matches!(stream, erpc_ssh::Stream::Stdout) {
                    return;
                }
                let parsed = serde_json::from_str::<PublicEvent>(line);
                if let Ok(event) = parsed {
                    if event.sequence == 0
                        || ![
                            "initialize",
                            "import-agent",
                            "authorize",
                            "prepare",
                            "configure",
                            "activate",
                            "start",
                            "stop",
                            "restart",
                            "destroy",
                            "recover-preparation",
                            "observe",
                            "firewall-apply",
                            "firewall-confirm",
                        ]
                        .contains(&event.action.as_str())
                    {
                        invalid = true;
                        return;
                    }
                    if let Ok(text) = serde_json::to_string(&event) {
                        if json_out {
                            crate::print_line(&text);
                        } else {
                            say.line(&text);
                        }
                    }
                } else {
                    invalid = true;
                }
            },
        )
        .map_err(|_| "publisher lifecycle journal could not be read")?;
    if invalid {
        return Err("publisher returned an invalid public lifecycle event".into());
    }
    Ok(json!({"journal":"complete","native_diagnostics_forwarded":false}))
}

fn stop_with_carried_fallback(
    session: &Session,
    target: &Target,
    node: &Publisher,
    verb: &str,
    say: &Say,
) -> Result<Value, String> {
    let request = json!({"action":verb,"contract":node.contract});
    if let Ok(value) = control(session, &request) {
        return Ok(value);
    }
    // The sealed recovery bundle contains public scope only, never an agent key.
    let vars=json!({"all":{"hosts":{node.name.clone():{"ansible_connection":"local","aqa_loader":aqa::carried_loader(),"aqa_request":request}}}}).to_string();
    play(session, target, &vars, "control", say)?;
    Ok(
        json!({"publisher_stopped":true,"retired":verb=="destroy","custody_preserved":true,"carried_recovery":true}),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeployStage {
    Recover,
    Authorize,
    Prepare,
    Firewall,
    Confirm,
    Activate,
}
fn deployment_sequence(
    mut step: impl FnMut(DeployStage) -> Result<(), String>,
    recover: bool,
) -> Result<(), String> {
    if recover {
        step(DeployStage::Recover)?;
    }
    for stage in [
        DeployStage::Authorize,
        DeployStage::Prepare,
        DeployStage::Firewall,
        DeployStage::Confirm,
        DeployStage::Activate,
    ] {
        step(stage)?;
    }
    Ok(())
}
fn remote_deploy(
    node: &Publisher,
    session: &Session,
    target: &Target,
    recover: bool,
    say: &Say,
) -> Result<erpc_ssh::RunId, String> {
    let facts = facts(session)?;
    let intent = shared::nonce()?;
    let vars = inventory(node, &facts, &request(node, "prepare", Some(&intent))?)?;
    let mut confirmation = None;
    let mut fresh = None;
    let mut completed = None;
    deployment_sequence(
        |stage| {
            match stage {
                DeployStage::Recover => {
                    let recovery = inventory(
                        node,
                        &facts,
                        &json!({"action":"recover-preparation","contract":node.contract}),
                    )?;
                    play(session, target, &recovery, "recovery", say)?;
                }
                DeployStage::Authorize => {
                    control(session, &request(node, "authorize", Some(&intent))?)?;
                }
                DeployStage::Prepare => {
                    play(session, target, &vars, "prepare", say)?;
                }
                DeployStage::Firewall => {
                    confirmation = Some(play(session, target, &vars, "firewall", say)?);
                }
                DeployStage::Confirm => {
                    let (run, sha) = confirmation
                        .as_ref()
                        .ok_or("publisher firewall receipt missing")?;
                    let connection = Session::open(target).map_err(
                        |_| "fresh publisher SSH confirmation failed; rollback remains armed",
                    )?;
                    control(
                        &connection,
                        &json!({"action":"firewall-confirm","contract":node.contract,"intent":intent,"run":run.as_str(),"bundle":sha}),
                    )?;
                    fresh = Some(connection);
                }
                DeployStage::Activate => {
                    let (run, sha) = confirmation
                        .as_ref()
                        .ok_or("publisher firewall receipt missing")?;
                    let confirmed = erpc_ops::firewall_inventory(&vars, run, sha)?;
                    completed = Some(
                        play(
                            fresh
                                .as_ref()
                                .ok_or("fresh publisher confirmation missing")?,
                            target,
                            &confirmed,
                            "activate",
                            say,
                        )?
                        .0,
                    );
                }
            }
            Ok(())
        },
        recover,
    )?;
    completed.ok_or_else(|| "publisher activation did not complete".into())
}

fn deploy(
    node: &mut Publisher,
    session: &Session,
    target: &Target,
    verb: &str,
    args: &ArgMatches,
    say: &Say,
) -> Result<Value, String> {
    let catalog = aqa::catalog()?;
    let version = catalog["version"]
        .as_str()
        .ok_or("invalid publisher version")?;
    let sha = catalog["artifact"]["sha256"]
        .as_str()
        .ok_or("invalid publisher archive")?;
    let signed_at = catalog["artifact"]["signed_at"]
        .as_u64()
        .ok_or("invalid publisher signature time")?;
    if signed_at < node.signed_at || (node.version == version && node.archive_sha256 != sha) {
        return Err("publisher rollback or same-version substitution is refused".into());
    }
    if verb == "update" {
        if required(args, "version")? != version {
            return Err("version is not qualified by this CLI".into());
        }
    } else if node.version != version || node.archive_sha256 != sha {
        return Err(
            "publisher qualification changed; inspect plan and select update explicitly".into(),
        );
    }
    let run = remote_deploy(
        node,
        session,
        target,
        shared::flag(args, "recover-preparation"),
        say,
    )?;
    node.version = version.into();
    node.archive_sha256 = sha.into();
    node.signed_at = signed_at;
    node.last_run = run.as_str().into();
    node.last_result = "publisher started; external vote acceptance not established".into();
    Ok(
        json!({"publisher":public(node),"publisher_started":true,"accepted_vote":null,"vote_eligibility":"not established by agent approval"}),
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
    if verb == "plan" && shared::one(args, "name").is_none() {
        return plan(None, args);
    }
    let (store, _) = shared::open(network, args)?;
    let nodes = store.hyperliquid_publishers().map_err(|e| e.to_string())?;
    if verb == "list" {
        return Ok(json!({"publishers":nodes.iter().map(public).collect::<Vec<_>>()}));
    }
    let name = required(args, "name")?;
    let mut node = nodes
        .into_iter()
        .find(|n| n.name == name)
        .ok_or("AQA publisher is not initialized in this network")?;
    node.contract.validate()?;
    settings(&mut node, args)?;
    if verb == "plan" {
        return plan(Some(&node), args);
    }
    let target = target(&node, args)?;
    let session = Session::open(&target).map_err(|e| e.to_string())?;
    if verb == "logs" {
        return logs(&session, &node, args, json_out, &say);
    }
    if verb == "status" {
        return control(
            &session,
            &json!({"action":"status","contract":node.contract}),
        );
    }
    node_common::go_ahead(shared::flag(args, "yes"), "AQA publisher unchanged")
        .map_err(|e| e.to_string())?;
    if ["start", "stop", "restart", "destroy"].contains(&verb) {
        let result = if ["stop", "destroy"].contains(&verb) {
            stop_with_carried_fallback(&session, &target, &node, verb, &say)?
        } else {
            control(&session, &json!({"action":verb,"contract":node.contract}))?
        };
        node.last_result = format!("{verb} complete; original agent retained");
        store
            .update_hyperliquid_publisher(&node)
            .map_err(|e| e.to_string())?;
        return Ok(result);
    }
    if verb == "update-config" && shared::flag(args, "restore-key") {
        let key = material(&node.agent_key_ref)?;
        let result = import_agent(&session, &node, &key, true, false)?;
        node.last_result = "original agent restored; publisher remains stopped".into();
        store
            .update_hyperliquid_publisher(&node)
            .map_err(|e| e.to_string())?;
        return Ok(result);
    }
    if !["deploy", "update", "update-config"].contains(&verb) {
        return Err("unsupported publisher operation".into());
    }
    let result = deploy(&mut node, &session, &target, verb, args, &say)?;
    store
        .update_hyperliquid_publisher(&node)
        .map_err(|e| e.to_string())?;
    Ok(result)
}

pub(crate) fn run(matches: &ArgMatches, source: Source, json_out: bool) -> Outcome {
    let Some((name, args)) = matches.subcommand() else {
        return Outcome::Usage("AQA needs a lifecycle verb; inspect aqa --help".into());
    };
    let Some(verb) = COMMON_VERBS.iter().find(|verb| verb.name == name) else {
        return Outcome::Usage("unsupported AQA lifecycle verb".into());
    };
    let Some(network) = shared::one(args, "network").and_then(Network::parse) else {
        return Outcome::Usage("AQA requires --network mainnet or testnet".into());
    };
    if let Err(error) = guard_mainnet(verb, Chain::Hyperliquid, source, Some(network.name())) {
        return Outcome::Usage(error);
    }
    if !["list", "plan"].contains(&name) && shared::one(args, "name").is_none() {
        return Outcome::Usage("pass --name <original publisher>".into());
    }
    report_operation(
        name,
        operation(name, network, args, json_out),
        json_out,
        &mut |report| {
            if json_out || name == "status" {
                crate::print_line(report);
            } else {
                Say { quiet: false }.line(report);
            }
        },
    )
}

pub(crate) fn report_status(
    result: Result<Value, String>,
    json_out: bool,
    output: &mut dyn FnMut(&str),
) -> Outcome {
    crate::node_report::status(result, "/publisher_service_ready", json_out, output)
}

fn report_operation(
    name: &str,
    result: Result<Value, String>,
    json_out: bool,
    output: &mut dyn FnMut(&str),
) -> Outcome {
    if name == "status" {
        return report_status(result, json_out, output);
    }
    match result {
        Ok(value) => {
            output(&if json_out {
                value.to_string()
            } else {
                serde_json::to_string_pretty(&value).unwrap_or_default()
            });
            Outcome::Done(String::new())
        }
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_core::chain::Role;
    #[test]
    fn observed_status_is_one_report_while_non_status_and_acquisition_errors_keep_their_contract() {
        use std::process::ExitCode;
        for json_out in [false, true] {
            for value in [
                json!({"publisher_service_ready":true}),
                json!({"publisher_service_ready":false}),
                json!({"publisher_service_ready":null}),
                json!({"publisher_service_ready":"true"}),
                json!({}),
                Value::Null,
            ] {
                for name in ["status", "deploy", "stop"] {
                    let mut reports = Vec::new();
                    let outcome =
                        report_operation(name, Ok(value.clone()), json_out, &mut |line| {
                            reports.push(line.to_owned());
                        });
                    let expected = if name == "status" && value["publisher_service_ready"] != true {
                        5
                    } else {
                        0
                    };
                    assert!(
                        matches!(&outcome, Outcome::Done(message) | Outcome::Problems(message) if message.is_empty())
                    );
                    assert_eq!(crate::finish(outcome), ExitCode::from(expected));
                    assert_eq!(reports.len(), 1);
                    assert_eq!(serde_json::from_str::<Value>(&reports[0]).unwrap(), value);
                    if json_out {
                        assert_eq!(reports[0].lines().count(), 1);
                    }
                }
            }
            for name in ["status", "deploy"] {
                let mut reports = Vec::new();
                let outcome = report_operation(
                    name,
                    Err("inert acquisition failure".into()),
                    json_out,
                    &mut |line| reports.push(line.to_owned()),
                );
                assert!(reports.is_empty());
                assert!(
                    matches!(&outcome, Outcome::Failed(message) if message == "inert acquisition failure")
                );
                assert_eq!(crate::finish(outcome), ExitCode::from(1));
            }
        }
    }

    fn parse(verb: &str, extra: &[&str]) -> ArgMatches {
        let mut args = vec!["v", "--network", "testnet", "aqa", verb];
        args.extend(extra);
        crate::tree::command(Role::Validator, Chain::Hyperliquid)
            .try_get_matches_from(args)
            .unwrap()
    }
    fn fixture() -> Publisher {
        let key =
            AgentMaterial::parse(format!("{{\"key\":\"{}\"}}", "02".repeat(32)).into()).unwrap();
        let args = parse(
            "init",
            &[
                "--host",
                "192.0.2.46",
                "--validator-address",
                &format!("0x{}", "ab".repeat(20)),
                "--consensus-signer",
                &format!("0x{}", "cd".repeat(20)),
                "--agent-master",
                &format!("0x{}", "ef".repeat(20)),
                "--agent-name",
                "original-agent",
            ],
        );
        let mut node = initial_record(
            Network::Testnet,
            args.subcommand_matches("aqa")
                .unwrap()
                .subcommand_matches("init")
                .unwrap(),
            "publisher",
            None,
            &key,
            &format!("op://{}/{}/agent", "a".repeat(26), "b".repeat(26)),
        )
        .unwrap();
        node.host_key = "inert-host-key".into();
        node.contract.host_binding =
            aqa::host_binding(&node.address, &node.ssh_user, node.ssh_port, &node.host_key);
        node
    }
    #[test]
    fn all_twelve_nested_verbs_and_custody_flags_are_closed_and_early_guarded() {
        for verb in COMMON_VERBS {
            let parsed = parse(verb.name, &[]);
            let nested = parsed.subcommand_matches("aqa").unwrap();
            if !["list", "plan"].contains(&verb.name) {
                assert!(matches!(
                    run(nested, Source::Flag, false),
                    Outcome::Usage(_)
                ));
            }
            for (flag, allowed) in [
                ("--restore-key", verb.name == "update-config"),
                ("--agent-exclusive", verb.name == "init"),
                (
                    "--recover-preparation",
                    ["deploy", "update", "update-config"].contains(&verb.name),
                ),
            ] {
                assert_eq!(
                    crate::tree::command(Role::Validator, Chain::Hyperliquid)
                        .try_get_matches_from(["v", "aqa", verb.name, flag])
                        .is_ok(),
                    allowed
                );
            }
            let missing = crate::tree::command(Role::Validator, Chain::Hyperliquid)
                .try_get_matches_from(["v", "aqa", verb.name])
                .unwrap();
            assert!(matches!(
                run(
                    missing.subcommand_matches("aqa").unwrap(),
                    Source::Flag,
                    false
                ),
                Outcome::Usage(_)
            ));
            if !verb.read_only {
                let main = crate::tree::command(Role::Validator, Chain::Hyperliquid)
                    .try_get_matches_from([
                        "v",
                        "--network",
                        "mainnet",
                        "aqa",
                        verb.name,
                        "--name",
                        "publisher",
                    ])
                    .unwrap();
                assert!(matches!(
                    run(main.subcommand_matches("aqa").unwrap(), Source::Env, false),
                    Outcome::Usage(_)
                ));
            }
        }
        assert!(
            crate::tree::command(Role::Validator, Chain::Hyperliquid)
                .try_get_matches_from([
                    "v",
                    "aqa",
                    "update-config",
                    "--restore-key",
                    "--recover-preparation"
                ])
                .is_err()
        );
        assert!(
            crate::tree::command(Role::Rpc, Chain::Hyperliquid)
                .try_get_matches_from(["rpc", "aqa", "plan"])
                .is_err()
        );
    }
    #[test]
    fn public_plans_never_claim_approval_proves_vote_eligibility_or_expose_custody_reference() {
        let node = fixture();
        for step in ["deploy", "approve-agent", "revoke-agent"] {
            let args = parse("plan", &["--step", step]);
            let args = args
                .subcommand_matches("aqa")
                .unwrap()
                .subcommand_matches("plan")
                .unwrap();
            let value = plan(Some(&node), args).unwrap();
            assert_eq!(value["signed"], false);
            assert_eq!(value["submitted"], false);
            assert!(value["accepted_vote"].is_null());
            assert!(!value.to_string().contains(&node.agent_key_ref));
            assert_eq!(
                value["vote_eligibility"],
                "not established by agent approval"
            );
            if step == "approve-agent" {
                assert_eq!(
                    value["external_approval"]["master"],
                    node.contract.identity.agent_master
                );
            }
        }
    }
    #[test]
    fn observed_server_port_and_exact_policy_and_helper_digest_are_carried() {
        let node = fixture();
        let request = request(&node, "prepare", Some(&"a".repeat(32))).unwrap();
        let mut facts = crate::eth_rpc::Facts {
            os: "ubuntu 24.04".into(),
            machine: "x86_64".into(),
            cpus: 2,
            mem_kb: 2_000_000,
            sudo: true,
            controller: "192.0.2.10".into(),
            ssh_port: 2200,
            ..crate::eth_rpc::Facts::default()
        };
        let vars: Value =
            serde_json::from_str(&inventory(&node, &facts, &request).unwrap()).unwrap();
        assert_eq!(vars["all"]["hosts"][&node.name]["aqa_ssh_port"], 2200);
        assert_eq!(
            request["target"]["config_id"],
            format!(
                "{:x}",
                Sha256::digest(request["policy"].to_string().as_bytes())
            )
        );
        assert!(!vars.to_string().contains(&node.agent_key_ref));
        facts.ssh_port = 0;
        assert!(inventory(&node, &facts, &request).is_err());
    }
    #[test]
    fn production_deployment_sequence_never_reaches_activation_after_any_failed_boundary() {
        for recover in [true, false] {
            let mut full = vec![];
            deployment_sequence(
                |stage| {
                    full.push(stage);
                    Ok(())
                },
                recover,
            )
            .unwrap();
            assert_eq!(full.last(), Some(&DeployStage::Activate));
            assert_eq!(
                full.iter().filter(|s| **s == DeployStage::Recover).count(),
                usize::from(recover)
            );
            for failed in &full {
                let mut observed = vec![];
                assert!(
                    deployment_sequence(
                        |stage| {
                            observed.push(stage);
                            if stage == *failed {
                                Err("inert failed boundary".into())
                            } else {
                                Ok(())
                            }
                        },
                        recover
                    )
                    .is_err()
                );
                assert_eq!(observed.last(), Some(failed));
                assert_eq!(observed, full[..observed.len()]);
            }
            assert!(
                full.iter().position(|s| *s == DeployStage::Confirm)
                    < full.iter().position(|s| *s == DeployStage::Activate)
            );
        }
    }
}
