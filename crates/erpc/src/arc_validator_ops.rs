// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Live caller wiring for dedicated Arc preparation; no production signing activation.
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::Store;
use erpc_chain::inventory::arc_validator::ArcValidatorNode;
use erpc_chain_arc::{
    key,
    validator::{self, GovernanceIntent, GovernanceStep},
};
use erpc_ssh::{Session, Target};
use serde_json::{Value, json};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::commands::Outcome;
use crate::node_common::{Say, op_runner, store, vault_for};
use crate::{arc_rpc, arc_validator_host as host};

pub(crate) const HISTORY_REQUIRED: &str = "Production Arc activation remains unavailable: the official Remote signing protocol receives opaque proposal hashes without public evidence of durable same-height/round anti-equivocation. Obtain Circle's qualified signing-history/recovery contract; PublicKey TLS verification or institutional approval alone does not authorize signing";

pub(crate) fn string<'a>(sub: &'a ArgMatches, field: &str) -> Option<&'a str> {
    sub.try_get_one::<String>(field)
        .ok()
        .flatten()
        .map(String::as_str)
}
pub(crate) fn flag(sub: &ArgMatches, field: &str) -> bool {
    sub.try_get_one::<bool>(field)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}
pub(crate) fn path(sub: &ArgMatches, field: &str) -> Option<PathBuf> {
    sub.try_get_one::<PathBuf>(field).ok().flatten().cloned()
}
pub(crate) fn list(sub: &ArgMatches, field: &str) -> Option<Vec<String>> {
    sub.try_get_many::<String>(field)
        .ok()
        .flatten()
        .map(|values| values.cloned().collect())
}
pub(crate) fn public_file(path: &Path, maximum: u64) -> Result<String, String> {
    let before = std::fs::symlink_metadata(path)
        .map_err(|_| "could not inspect the supplied public Arc input")?;
    if !before.file_type().is_file() || before.len() > maximum {
        return Err("Arc public input must be a bounded regular file".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "could not read the supplied public Arc input")?;
    let opened = file
        .metadata()
        .map_err(|_| "could not inspect opened Arc public input")?;
    if !opened.is_file() || opened.len() > maximum {
        return Err("Arc public input must be a bounded regular file".into());
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read bounded Arc public input")?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err("Arc public input exceeds its bound".into());
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| "Arc public input must be UTF-8".into())
}

pub(crate) struct Opened {
    pub(crate) runner: OpCli,
    pub(crate) store: Store<OpCli>,
    pub(crate) vault: String,
    pub(crate) nodes: Vec<ArcValidatorNode>,
}
pub(crate) fn open(network: &str, vault: Option<&str>, say: &Say) -> Result<Opened, String> {
    erpc_chain_arc::network::get(network).ok_or("unsupported Arc network")?;
    let vault = vault_for(
        network,
        vault,
        "erpc v --chain arc init --network <network> --vault <vault id>",
    )?;
    let runner = op_runner()?;
    let store = store(&runner, &vault, "arc", network)?;
    say.line("inventory  reading dedicated public Arc validator metadata");
    let nodes = store.arc_validators().map_err(|error| error.to_string())?;
    Ok(Opened {
        runner,
        store,
        vault,
        nodes,
    })
}
pub(crate) fn login(sub: &ArgMatches) -> arc_rpc::Login {
    arc_rpc::Login {
        ssh_key: path(sub, "ssh-key"),
        ssh_agent: path(sub, "ssh-agent"),
    }
}
fn find(opened: &Opened, name: &str) -> Result<ArcValidatorNode, String> {
    opened
        .nodes
        .iter()
        .find(|node| node.name == name)
        .cloned()
        .ok_or("no original Arc validator reservation with that name".into())
}
fn result(value: &Value, json_out: bool, problem: bool) -> Outcome {
    if json_out {
        crate::print_json(value);
    }
    let text = if json_out {
        String::new()
    } else {
        value.to_string()
    };
    if problem {
        Outcome::Problems(text)
    } else {
        Outcome::Done(text)
    }
}

pub(crate) fn run(verb: &str, sub: &ArgMatches, network: Option<&str>, json_out: bool) -> Outcome {
    if verb == "activate" {
        return Outcome::Failed(HISTORY_REQUIRED.into());
    }
    if verb == "plan" && string(sub, "name").is_none() {
        return result(
            &json!({"chain":"arc","role":"validator","preparation_available":true,
            "production_activation_available":false,"validator_ready":false,"reason":HISTORY_REQUIRED,
            "qualified_source":{"version":erpc_chain_arc::authority::VERSION,"commit":validator::SOURCE},
            "runtime":"dedicated-observer","remote_signer":"externally-prepared-official-service",
            "required_public_inputs":["endpoint/server-CA/public-key","tested-image/PCR0/PCR1/PCR2/PCR4",
                                      "external-controller/fee-recipient","approved-native-peers"],
            "aws_resources_created":false,"private_consensus_key_imported":false}),
            json_out,
            true,
        );
    }
    let Some(network) = network else {
        return Outcome::Usage("Arc validator operations need --network".into());
    };
    if verb != "list" && string(sub, "name").is_none() {
        return Outcome::Usage("Arc validator operations need --name".into());
    }
    if let Err(error) = validate_cli(verb, sub) {
        return Outcome::Usage(error);
    }
    let say = Say { quiet: json_out };
    let operation = if verb == "init" {
        crate::arc_validator_init::run(sub, network, &say)
    } else {
        operate(verb, sub, network, &say)
    };
    match operation {
        Ok(value) => {
            let unhealthy = ["status", "health", "plan"].contains(&verb)
                && value.get("ready") != Some(&Value::Bool(true));
            result(&value, json_out, unhealthy)
        }
        Err(error) => Outcome::Failed(error),
    }
}

fn original_intent(sub: &ArgMatches) -> Result<&str, String> {
    let intent = string(sub, "original-intent").ok_or("--original-intent is required")?;
    if intent.len() != 32
        || !intent
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("original bootstrap intent must be 128-bit lowercase hexadecimal".into());
    }
    Ok(intent)
}

fn validate_cli(verb: &str, sub: &ArgMatches) -> Result<(), String> {
    if verb == "init" && path(sub, "signer-ca").is_none() {
        return Err("--signer-ca is required on initial or resumed init".into());
    }
    if verb == "reset-bootstrap" {
        original_intent(sub)?;
    }
    if ["prepare-registration", "validate-registration"].contains(&verb) {
        governance(sub)?;
        if !validator::address(string(sub, "from").ok_or("--from is required")?) {
            return Err("--from requires a canonical nonzero external governance address".into());
        }
        if verb == "validate-registration" && path(sub, "registration-file").is_none() {
            return Err("--registration-file is required".into());
        }
    }
    Ok(())
}

fn governance(sub: &ArgMatches) -> Result<GovernanceStep, String> {
    let number = |name: &str| {
        sub.try_get_one::<u64>(name)
            .ok()
            .flatten()
            .copied()
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("--{name} requires a positive integer"))
    };
    let step = string(sub, "step").ok_or("--step is required")?;
    let expected: &[&str] = match step {
        "configure-controller" => &["registration-id", "voting-power-limit"],
        "voting-power" => &["voting-power"],
        _ => &[],
    };
    for field in ["registration-id", "voting-power-limit", "voting-power"] {
        if sub.try_get_one::<u64>(field).ok().flatten().is_some() && !expected.contains(&field) {
            return Err(format!("--{field} does not apply to this governance step"));
        }
    }
    Ok(match string(sub, "step").ok_or("--step is required")? {
        "register" => GovernanceStep::Register,
        "configure-controller" => GovernanceStep::ConfigureController {
            registration_id: number("registration-id")?,
            voting_power_limit: number("voting-power-limit")?,
        },
        "activate" => GovernanceStep::Activate,
        "voting-power" => GovernanceStep::VotingPower {
            voting_power: number("voting-power")?,
        },
        "remove" => GovernanceStep::Remove,
        _ => return Err("unsupported public governance step".into()),
    })
}

fn public_node(node: &ArcValidatorNode) -> Value {
    json!({"name":node.name,"address":node.address,"ssh_user":node.ssh_user,"ssh_port":node.ssh_port,
           "version":node.version,"commit":node.commit,"mode":node.participation,
           "controller":node.controller,"fee_recipient":node.fee_recipient,
           "peer_public_key":node.consensus_public_key,"consensus_public_key":node.signing_public_key,
           "last_run":node.last_run,"last_result":node.last_result,"production_activation_available":false})
}

fn list_nodes(network: &str, say: &Say) -> Result<Value, String> {
    let config = crate::keyless::load(&crate::keyless::path()?)?;
    let nodes = if config.networks.contains_key(network) {
        open(network, None, say)?.nodes
    } else {
        Vec::new()
    };
    Ok(
        json!({"chain":"arc","role":"validator","network":network,"nodes":nodes.iter().map(public_node).collect::<Vec<_>>()}),
    )
}

fn operate(verb: &str, sub: &ArgMatches, network: &str, say: &Say) -> Result<Value, String> {
    if verb == "list" {
        return list_nodes(network, say);
    }
    let opened = open(network, None, say)?;
    let name = string(sub, "name").ok_or("--name is required")?;
    let mut node = find(&opened, name)?;
    let original = host::contract(&node, network)?;
    if verb == "plan" {
        return Ok(
            json!({"contract":original,"source":{"version":node.version,"commit":node.commit},
            "preparation_available":true,"validator_ready":false,"ready":false,"reason":HISTORY_REQUIRED,
            "remote_signer":host::remote(&node)?,"private_consensus_key_on_host":false}),
        );
    }
    let intended = if ["prepare-registration", "validate-registration"].contains(&verb) {
        Some(validator::prepare_governance(
            &original,
            &governance(sub)?,
            string(sub, "from").ok_or("--from is required")?,
        )?)
    } else {
        None
    };
    if verb == "prepare-registration" {
        return serde_json::to_value(intended)
            .map_err(|_| "invalid public governance intent".into());
    }
    if ![
        "status",
        "health",
        "logs",
        "remote-public-key",
        "validate-registration",
    ]
    .contains(&verb)
    {
        crate::node_common::go_ahead(flag(sub, "yes"), "no Arc validator host change was made")
            .map_err(|error| error.to_string())?;
    }
    let target = arc_rpc::target(&node.host, &login(sub))?;
    let session =
        Session::open(&target).map_err(|_| "could not open the original pinned Arc host")?;
    match verb {
        "status" | "health" => host::invoke(&session, &node, network, "status", json!({})),
        "remote-public-key" => host::invoke(
            &session,
            &node,
            network,
            "remote-public-key",
            json!({"remote_signer":host::remote(&node)?}),
        ),
        "validate-registration" => {
            validate_registration(sub, &session, &node, network, intended.as_ref())
        }
        "stop" | "destroy" => {
            host::invoke(&session, &node, network, verb, json!({})).or_else(|_| {
                say.line("recovery   retrying original shutdown through a freshly sealed helper");
                host::carried_shutdown(&session, &target, &node, network, verb, say)
            })
        }
        "start" => host::invoke(&session, &node, network, "start", json!({})),
        "restart" => {
            host::invoke(&session, &node, network, "stop", json!({}))?;
            host::invoke(&session, &node, network, "start", json!({}))
        }
        "reset-bootstrap" | "restore-peer-key" => {
            recover(verb, sub, network, &opened, &session, &node)
        }
        "deploy" | "update" | "update-config" => {
            let facts = arc_rpc::facts(&session)?;
            if !facts.refusals().is_empty() {
                return Err(format!(
                    "Arc host preflight refused: {}",
                    facts.refusals().join("; ")
                ));
            }
            if verb == "update-config" {
                update_policy(&mut node, sub)?;
            }
            if verb == "update" {
                pin(&mut node, sub, &facts)?;
            }
            host::policy(&node, &facts)?;
            if node.participation != "observer" {
                return Err(HISTORY_REQUIRED.into());
            }
            node = opened
                .store
                .update_arc_validator(&node)
                .map_err(|error| error.to_string())?;
            deploy(&opened, &session, &target, &node, network, &facts, say)
        }
        "logs" => {
            host::invoke(&session, &node, network, "status", json!({}))?;
            logs(&session, sub, say.quiet)
        }
        _ => Err("unsupported dedicated Arc preparation operation".into()),
    }
}

fn validate_registration(
    sub: &ArgMatches,
    session: &Session,
    node: &ArcValidatorNode,
    network: &str,
    intended: Option<&GovernanceIntent>,
) -> Result<Value, String> {
    let file = path(sub, "registration-file").ok_or("--registration-file is required")?;
    let value: GovernanceIntent = serde_json::from_str(&public_file(&file, 16384)?)
        .map_err(|_| "invalid bounded public governance intent")?;
    if Some(&value) != intended {
        return Err(
            "public governance intent differs from the original exact requested action".into(),
        );
    }
    host::invoke(
        session,
        node,
        network,
        "validate-registration",
        json!({"registration":value}),
    )
}

fn recover(
    verb: &str,
    sub: &ArgMatches,
    network: &str,
    opened: &Opened,
    session: &Session,
    node: &ArcValidatorNode,
) -> Result<Value, String> {
    match verb {
        "reset-bootstrap" => {
            let intent = original_intent(sub)?;
            host::invoke(session, node, network, "stop", json!({}))?;
            host::invoke(
                session,
                node,
                network,
                "reset-bootstrap",
                json!({"bootstrap_intent":intent}),
            )
        }
        "restore-peer-key" => {
            host::invoke(session, node, network, "stop", json!({}))?;
            deliver(opened, session, node, network, true)?;
            Ok(json!({"peer_custody":"restored","started":false,"consensus_key_imported":false}))
        }
        _ => Err("unsupported Arc recovery operation".into()),
    }
}

pub(crate) fn update_policy(node: &mut ArcValidatorNode, sub: &ArgMatches) -> Result<(), String> {
    if let Some(value) = string(sub, "fee-recipient") {
        if !validator::address(value) {
            return Err("invalid external fee recipient".into());
        }
        node.fee_recipient = value.into();
    }
    if flag(sub, "admission-approved") {
        node.admission_approved = true;
    }
    if let Some(values) = list(sub, "execution-peer") {
        node.host.trusted_peers = values;
    }
    if let Some(values) = list(sub, "sentry-peer") {
        node.host.sentry_peers = values;
    }
    if let Some(values) = list(sub, "management-allow") {
        node.host.management_allow = arc_rpc::allow_list("--management-allow", &values, false)?;
    }
    if let Some(values) = list(sub, "monitoring-allow") {
        node.host.monitoring_allow = arc_rpc::allow_list("--monitoring-allow", &values, false)?;
    }
    Ok(())
}
pub(crate) fn pin(
    node: &mut ArcValidatorNode,
    sub: &ArgMatches,
    facts: &arc_rpc::Facts,
) -> Result<(), String> {
    let snapshot = erpc_chain_arc::releases::snapshot();
    let release = erpc_chain_arc::releases::choose(
        &snapshot.releases,
        Some(string(sub, "version").unwrap_or(erpc_chain_arc::authority::VERSION)),
        facts.platform()?,
    )
    .map_err(|e| e.to_string())?;
    node.host.version.clone_from(&release.tag);
    node.host.commit.clone_from(&release.commit);
    node.host.archive_sha256 = release
        .digest(facts.platform()?)
        .ok_or("qualified native platform is absent")?
        .into();
    erpc_chain_arc::authority::qualify_source(
        &node.version,
        &node.commit,
        &node.archive_sha256,
        facts.platform()?,
    )?;
    Ok(())
}
fn deliver(
    opened: &Opened,
    session: &Session,
    node: &ArcValidatorNode,
    network: &str,
    restore: bool,
) -> Result<(), String> {
    if !restore
        && host::invoke(session, node, network, "custody-status", json!({}))?["present"] == true
    {
        return Ok(());
    }
    let stored = key::StoredKey {
        public_key: node.consensus_public_key.clone(),
        reference: opened
            .store
            .arc_validator_key_reference(node)
            .map_err(|e| e.to_string())?
            .ok_or("original peer key binding is incomplete; resume init")?
            .to_string(),
    };
    let owner = key::validator::Owner {
        vault: &opened.vault,
        network,
        name: &node.name,
        item: node.id.as_deref().ok_or("original inventory missing")?,
    };
    let key = key::validator::read(&opened.runner, &owner, &stored)
        .map_err(|_| "original local peer custody qualification failed")?;
    host::import_peer_key(session, node, network, &key, restore)
}
fn deploy(
    opened: &Opened,
    session: &Session,
    target: &Target,
    node: &ArcValidatorNode,
    network: &str,
    facts: &arc_rpc::Facts,
    say: &Say,
) -> Result<Value, String> {
    deliver(opened, session, node, network, false)?;
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "could not reserve a fresh Arc operation")?;
    let intent = nonce
        .iter()
        .fold(String::with_capacity(32), |mut text, value| {
            use std::fmt::Write as _;
            let _ = write!(text, "{value:02x}");
            text
        });
    host::invoke(
        session,
        node,
        network,
        "authorize",
        json!({"intent":intent,"target":crate::arc_authority::source(&node.host,facts)?,"policy":host::policy(node,facts)?}),
    )?;
    let extra = serde_json::Map::from_iter([("arc_validator_intent".into(), json!(intent))]);
    let inventory = host::inventory(node, network, facts, extra)?;
    let preparation = host::bundle(&inventory)?;
    let prepared = host::run_play(session, target, &inventory, validator::plays::FIREWALL, say)?;
    let fresh =
        Session::open(target).map_err(|_| "fresh original SSH firewall confirmation failed")?;
    host::invoke(
        &fresh,
        node,
        network,
        "confirm-firewall",
        json!({"intent":intent,"firewall_run":prepared,"firewall_bundle":preparation.sha256}),
    )?;
    let run = erpc_ssh::RunId::new(&prepared).map_err(|e| e.to_string())?;
    let inventory = erpc_ops::firewall_inventory(&inventory, &run, &preparation.sha256)?;
    let run = host::run_play(session, target, &inventory, validator::plays::DEPLOY, say)?;
    let mut saved = node.clone();
    saved.host.last_run.clone_from(&run);
    saved.host.last_result = "observer-start-requested".into();
    if opened.store.update_arc_validator(&saved).is_err() {
        say.line("inventory  host operation completed; public run-result update must be retried");
    }
    Ok(
        json!({"run":run,"observer_start_requested":true,"validator_ready":false,"production_activation_available":false,"reason":HISTORY_REQUIRED}),
    )
}
fn logs(session: &Session, sub: &ArgMatches, json_out: bool) -> Result<Value, String> {
    let layer = match string(sub, "layer").unwrap_or("both") {
        "execution" => erpc_ssh::arc::Layer::Execution,
        "consensus" => erpc_ssh::arc::Layer::Consensus,
        _ => erpc_ssh::arc::Layer::Both,
    };
    let lines = sub.get_one::<u32>("lines").copied().unwrap_or(100);
    session
        .stream(
            &erpc_ssh::RemoteCommand::ArcValidatorLogs {
                layer,
                lines,
                follow: flag(sub, "follow"),
            },
            &mut |stream, line| {
                if json_out {
                    crate::print_line(&json!({"kind":"journal","line":line}).to_string());
                } else {
                    match stream {
                        erpc_ssh::Stream::Stdout => crate::print_line(line),
                        erpc_ssh::Stream::Stderr => crate::interrupt::say(line),
                    }
                }
            },
        )
        .map_err(|_| "Arc validator journal operation failed")?;
    Ok(json!({"kind":"complete","operation":"logs"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_input_is_bounded_before_parsing_and_does_not_read_directories() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("public.json");
        std::fs::write(&file, b"{}").unwrap();
        assert_eq!(public_file(&file, 2).unwrap(), "{}");
        assert!(public_file(&file, 1).is_err());
        assert!(public_file(root.path(), 65536).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn public_input_refuses_links_and_fifos_before_any_blocking_read() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        std::fs::write(&original, b"{}").unwrap();
        let link = root.path().join("linked");
        std::os::unix::fs::symlink(&original, &link).unwrap();
        assert!(public_file(&link, 65536).is_err());
        let fifo = root.path().join("pipe");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(public_file(&fifo, 65536).is_err());
    }

    #[test]
    fn public_list_shape_cannot_serialize_a_reference_or_external_private_field() {
        let node = ArcValidatorNode {
            host: erpc_chain::inventory::RpcNode {
                name: "inert".into(),
                consensus_key_ref: "inert must not escape".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let value = public_node(&node);
        assert!(!value.to_string().contains("reference"));
        assert!(!value.to_string().contains("must not escape"));
        assert_eq!(value["production_activation_available"], false);
    }
}
