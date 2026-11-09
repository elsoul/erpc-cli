// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated Arc preparation requests, sealed resources and original peer-key delivery.
use erpc_chain::inventory::arc_validator::ArcValidatorNode;
use erpc_chain_arc::validator::{self, Contract, Phase, Policy, RemoteSigner};
use erpc_ops::bundle::{Built, Bundle};
use erpc_ssh::{Session, Target};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::arc_rpc::Facts;
use crate::node_common::Say;

pub(crate) fn contract(node: &ArcValidatorNode, network: &str) -> Result<Contract, String> {
    let native = erpc_chain_arc::network::get(network).ok_or("unsupported Arc network")?;
    if node.host_key.is_empty()
        || node.rpc_type != "validator-minimal"
        || !node.rpc_allow.is_empty()
        || node.debug_api
    {
        return Err("Arc validator requires its dedicated host profile without public RPC".into());
    }
    let value = Contract {
        owner: node
            .id
            .clone()
            .ok_or("original Arc validator inventory reservation is absent")?,
        network: network.into(),
        chain_id: native.chain_id,
        genesis_hash: native.genesis_hash,
        public_key: node.signing_public_key.clone(),
        peer_public_key: node.consensus_public_key.clone(),
        controller: node.controller.clone(),
        host_binding: format!("{:x}", Sha256::digest(node.host_key.as_bytes())),
    };
    value.validate()?;
    Ok(value)
}

pub(crate) fn policy(node: &ArcValidatorNode, facts: &Facts) -> Result<Policy, String> {
    let value = Policy {
        approved: node.admission_approved,
        fee_recipient: node.fee_recipient.clone(),
        execution_peers: node.trusted_peers.clone(),
        sentry_peers: node.sentry_peers.clone(),
        phase: match node.participation.as_str() {
            "observer" => Phase::Observer,
            "validator" => Phase::Validator,
            _ => return Err("unsupported Arc validator participation mode".into()),
        },
        ssh_port: facts.ssh_port,
        management_allow: node.management_allow.clone(),
        monitoring_allow: node.monitoring_allow.clone(),
    };
    value.validate()?;
    Ok(value)
}

pub(crate) fn remote(node: &ArcValidatorNode) -> Result<RemoteSigner, String> {
    let profile: RemoteSigner = serde_json::from_str(&node.remote_signer)
        .map_err(|_| "invalid original Arc remote signer public profile")?;
    profile.validate()?;
    Ok(profile)
}

pub(crate) fn request(
    node: &ArcValidatorNode,
    network: &str,
    action: &str,
    fields: Value,
) -> Result<Value, String> {
    let mut value = json!({"action":action,"contract":contract(node, network)?});
    let Value::Object(additional) = fields else {
        return Err("invalid Arc validator request fields".into());
    };
    for (name, field) in additional {
        if ["action", "contract", "key"].contains(&name.as_str()) {
            return Err(
                "public Arc request cannot replace original authority or carry a key".into(),
            );
        }
        value[&name] = field;
    }
    Ok(value)
}

fn command() -> Result<erpc_ssh::RemoteCommand, String> {
    let names = validator::helper_profile()?;
    let profile: Vec<&str> = names.iter().map(String::as_str).collect();
    Ok(erpc_ssh::RemoteCommand::ArcControl(
        erpc_ssh::arc::Control::validator(&profile)?,
    ))
}

pub(crate) fn invoke(
    session: &Session,
    node: &ArcValidatorNode,
    network: &str,
    action: &str,
    fields: Value,
) -> Result<Value, String> {
    let body = request(node, network, action, fields)?.to_string();
    let result = session.run(&command()?, Some(body.as_bytes())).map_err(
        |_| "Arc validator original host operation was refused; original data and custody retained",
    )?;
    let raw = zeroize::Zeroizing::new(result.stdout);
    let _diagnostics = zeroize::Zeroizing::new(result.stderr);
    if raw.len() > 65536 {
        return Err("Arc validator public reply exceeds its bound".into());
    }
    serde_json::from_slice(&raw).map_err(|_| "invalid Arc validator public response".into())
}

pub(crate) fn import_peer_key(
    session: &Session,
    node: &ArcValidatorNode,
    network: &str,
    key: &erpc_chain_arc::key::ConsensusKey,
    restore: bool,
) -> Result<(), String> {
    if key.public_key() != node.consensus_public_key || key.public_key() == node.signing_public_key
    {
        return Err("supplied local peer key differs from its original dedicated identity".into());
    }
    let mut body = zeroize::Zeroizing::new(
        request(
            node,
            network,
            if restore {
                "restore-peer-key"
            } else {
                "import-peer-key"
            },
            json!({}),
        )?
        .to_string(),
    );
    body.pop();
    body.push_str(",\"key\":");
    let private = key.node_json();
    let quoted = zeroize::Zeroizing::new(
        serde_json::to_string(private.as_str())
            .map_err(|_| "could not encode the original peer-key envelope")?,
    );
    body.push_str(&quoted);
    body.push('}');
    let result = session
        .run(&command()?, Some(body.as_bytes()))
        .map_err(|_| "original Arc peer-key delivery was refused")?;
    let raw = zeroize::Zeroizing::new(result.stdout);
    let _diagnostics = zeroize::Zeroizing::new(result.stderr);
    if raw.len() > 4096 {
        return Err("invalid Arc peer-key acknowledgement".into());
    }
    let ack: Value =
        serde_json::from_slice(&raw).map_err(|_| "invalid Arc peer-key acknowledgement")?;
    if ack["public_key"] != node.consensus_public_key
        || ack["custody"] != if restore { "restored" } else { "original" }
    {
        return Err("Arc did not acknowledge the original dedicated peer identity".into());
    }
    Ok(())
}

pub(crate) fn inventory(
    node: &ArcValidatorNode,
    network: &str,
    facts: &Facts,
    extra: Map<String, Value>,
) -> Result<String, String> {
    let policy = policy(node, facts)?;
    let mut values = json!({
        "ansible_connection":"local", "arc_validator_loader":validator::carried_loader()?,
        "arc_validator_contract":contract(node,network)?, "arc_validator_helpers":validator::helper_hash()?,
        "arc_validator_remote":remote(node)?,
        "arc_validator_archive_url":erpc_chain_arc::releases::archive_url(&node.version, facts.platform()?),
        "arc_validator_archive_sha256":node.archive_sha256,
        "arc_validator_firewall":validator::firewall(&policy, facts.controller_ip()?)?
    });
    for (name, value) in extra {
        if values.get(&name).is_some() {
            return Err("Arc run cannot overwrite its qualified original variables".into());
        }
        values[&name] = value;
    }
    Ok(json!({"all":{"hosts":{node.name.clone():values}}}).to_string())
}

pub(crate) fn bundle(inventory: &str) -> Result<Built, String> {
    let mut bundle = Bundle::new();
    for (path, bytes) in validator::carried_files()? {
        bundle.add(&path, bytes).map_err(|e| e.to_string())?;
    }
    bundle
        .add("inventory.yml", inventory.as_bytes())
        .map_err(|e| e.to_string())?;
    bundle
        .add("rpc-firewall.py", erpc_ops::RPC_FIREWALL)
        .map_err(|e| e.to_string())?;
    bundle.finish().map_err(|e| e.to_string())
}

pub(crate) fn run_play(
    session: &Session,
    target: &Target,
    inventory: &str,
    play: &str,
    say: &Say,
) -> Result<String, String> {
    if ![
        validator::plays::PREFLIGHT,
        validator::plays::INIT,
        validator::plays::FIREWALL,
        validator::plays::DEPLOY,
        validator::plays::DESTROY,
        validator::plays::CONTROL,
    ]
    .contains(&play)
    {
        return Err("unsupported Arc validator play".into());
    }
    let built = bundle(inventory)?;
    let run = erpc_ops::run::start(session, &built, play).map_err(|e| e.to_string())?;
    let result = crate::node_common::follow(
        target,
        &run,
        "Resume the original Arc validator operation",
        say,
    )?;
    if !result.ok() {
        return Err(format!(
            "Arc validator preparation run {} failed; original data retained",
            run.as_str()
        ));
    }
    Ok(run.as_str().into())
}

pub(crate) fn carried_shutdown(
    session: &Session,
    target: &Target,
    node: &ArcValidatorNode,
    network: &str,
    action: &str,
    say: &Say,
) -> Result<Value, String> {
    let (value, play) = shutdown_inventory(node, network, action)?;
    let run = run_play(session, target, &value, play, say)?;
    Ok(json!({"stopped":true,"retired":action=="destroy","data_retained":true,"run":run}))
}

fn shutdown_inventory(
    node: &ArcValidatorNode,
    network: &str,
    action: &str,
) -> Result<(String, &'static str), String> {
    let play = match action {
        "stop" => validator::plays::CONTROL,
        "destroy" => validator::plays::DESTROY,
        _ => return Err("only original stop/retirement may use carried shutdown".into()),
    };
    let value=json!({"all":{"hosts":{node.name.clone():{"ansible_connection":"local",
        "arc_validator_loader":validator::carried_loader()?,"arc_validator_contract":contract(node,network)?,
        "arc_validator_request":request(node,network,action,json!({}))?}}}}).to_string();
    Ok((value, play))
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_chain::inventory::RpcNode;

    pub(super) fn fixture() -> (ArcValidatorNode, Facts) {
        let release = erpc_chain_arc::releases::snapshot()
            .releases
            .into_iter()
            .find(|release| release.tag == erpc_chain_arc::authority::VERSION)
            .unwrap();
        let node = ArcValidatorNode {
            host: RpcNode {
                id: Some("a".repeat(26)),
                item_version: 1,
                name: "inert-validator".into(),
                address: "192.0.2.9".into(),
                ssh_user: "ubuntu".into(),
                ssh_port: 2222,
                host_key: "inert original host key metadata".into(),
                version: release.tag.clone(),
                commit: release.commit.clone(),
                archive_sha256: release
                    .digest(erpc_chain_arc::releases::Platform::X86_64)
                    .unwrap()
                    .into(),
                rpc_type: "validator-minimal".into(),
                consensus_public_key: "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=".into(),
                ..RpcNode::default()
            },
            controller: format!("0x{}", "b".repeat(40)),
            fee_recipient: format!("0x{}", "c".repeat(40)),
            participation: "observer".into(),
            admission_approved: false,
            signing_public_key: "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".into(),
            remote_signer:
                json!({"endpoint":"https://127.0.0.1:10340/","server_ca_sha256":"d".repeat(64),
            "image_sha256":"e".repeat(64),"pcr0":"f".repeat(96),"pcr1":"f".repeat(96),
            "pcr2":"f".repeat(96),"pcr4":"f".repeat(96)})
                .to_string(),
        };
        (
            node,
            Facts {
                machine: "x86_64".into(),
                controller: "192.0.2.10".into(),
                ssh_port: 2223,
                ..Facts::default()
            },
        )
    }

    #[test]
    fn actual_run_inventory_preserves_original_role_network_key_and_observed_port() {
        let (node, facts) = fixture();
        for network in ["mainnet", "testnet"] {
            let value: Value =
                serde_json::from_str(&inventory(&node, network, &facts, Map::new()).unwrap())
                    .unwrap();
            let variables = &value["all"]["hosts"][&node.name];
            assert_eq!(variables["arc_validator_contract"]["network"], network);
            assert_eq!(
                variables["arc_validator_contract"]["peer_public_key"],
                node.consensus_public_key
            );
            assert_eq!(
                variables["arc_validator_contract"]["public_key"],
                node.signing_public_key
            );
            assert_eq!(
                variables["arc_validator_helpers"],
                validator::helper_hash().unwrap()
            );
            let firewall = variables["arc_validator_firewall"].as_str().unwrap();
            assert!(firewall.contains("tcp dport 2223 "));
            assert!(!firewall.contains("tcp dport 2222 "));
            assert!(!variables.to_string().contains("private_key"));
        }
        let mut changed = node.clone();
        changed.host.rpc_type = "full".into();
        assert!(contract(&changed, "testnet").is_err());
        changed = node.clone();
        changed
            .signing_public_key
            .clone_from(&node.consensus_public_key);
        assert!(contract(&changed, "testnet").is_err());
        let mut changed = facts.clone();
        changed.ssh_port = 0;
        assert!(inventory(&node, "testnet", &changed, Map::new()).is_err());
        assert!(
            inventory(
                &node,
                "testnet",
                &facts,
                Map::from_iter([("arc_validator_contract".into(), json!({}))])
            )
            .is_err()
        );
        assert!(request(&node, "testnet", "stop", json!({"key":"not-public"})).is_err());
    }

    #[test]
    fn emergency_carried_request_uses_only_original_scope_without_runtime_facts_or_custody() {
        let (node, _) = fixture();
        for (action, play) in [
            ("stop", validator::plays::CONTROL),
            ("destroy", validator::plays::DESTROY),
        ] {
            let (raw, selected) = shutdown_inventory(&node, "testnet", action).unwrap();
            assert_eq!(selected, play);
            let value: Value = serde_json::from_str(&raw).unwrap();
            let variables = &value["all"]["hosts"][&node.name];
            assert_eq!(
                variables["arc_validator_request"],
                request(&node, "testnet", action, json!({})).unwrap()
            );
            assert_eq!(
                variables["arc_validator_contract"],
                serde_json::to_value(contract(&node, "testnet").unwrap()).unwrap()
            );
            for irrelevant in [
                "arc_validator_ca",
                "arc_validator_firewall",
                "arc_validator_archive_url",
            ] {
                assert!(variables.get(irrelevant).is_none());
            }
        }
        assert!(shutdown_inventory(&node, "testnet", "start").is_err());
        let mut foreign = node;
        foreign.host.rpc_type = "full".into();
        assert!(shutdown_inventory(&foreign, "testnet", "destroy").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn actual_compiled_profile_bundle_and_external_entrypoints_are_executed_inertly() {
        use std::io::Write as _;
        let (node, facts) = fixture();
        let inventory = inventory(&node, "testnet", &facts, Map::new()).unwrap();
        let built = bundle(&inventory).unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../erpc-chain-arc/tests/validator_bundle.py");
        let python = std::env::var_os("ERPC_TEST_ARC_PYTHON").unwrap_or_else(|| "python3".into());
        let mut child = std::process::Command::new(python)
            .arg("-B")
            .arg(script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let original = contract(&node, "testnet").unwrap();
        let governance = [
            validator::GovernanceStep::Register,
            validator::GovernanceStep::ConfigureController {
                registration_id: 3,
                voting_power_limit: 10,
            },
            validator::GovernanceStep::Activate,
            validator::GovernanceStep::VotingPower { voting_power: 10 },
            validator::GovernanceStep::Remove,
        ]
        .iter()
        .map(|step| validator::prepare_governance(&original, step, &node.controller).unwrap())
        .collect::<Vec<_>>();
        let document = json!({"governance":governance,"bundle":built.bytes,"ssh":command().unwrap().line(),
            "source":crate::arc_authority::source(&node.host,&facts).unwrap(),"policy":policy(&node,&facts).unwrap()}).to_string();
        if let Some(path) = std::env::var_os("ERPC_TEST_ARC_CAPTURE") {
            std::fs::write(path, &document).unwrap();
        }
        child
            .stdin
            .take()
            .unwrap()
            .write_all(document.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
