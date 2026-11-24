// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Original public reservation precedes concealed peer-key custody and host setup.
use clap::ArgMatches;
use erpc_chain::inventory::RpcNode;
use erpc_chain::inventory::arc_validator::ArcValidatorNode;
use erpc_chain_arc::{key, validator};
use erpc_ssh::{Identity, Session, Target};
use serde_json::{Value, json};

use crate::node_common::{Say, agent_socket, check_ubuntu, go_ahead, host_key, save_vault};
use crate::{arc_rpc, arc_validator_host as host, arc_validator_ops as ops};

fn public_profile(
    sub: &ArgMatches,
    existing: Option<&ArcValidatorNode>,
) -> Result<ArcValidatorNode, String> {
    let mut node = existing.cloned().unwrap_or_else(|| ArcValidatorNode {
        host: RpcNode {
            rpc_type: "validator-minimal".into(),
            ..RpcNode::default()
        },
        participation: "observer".into(),
        ..ArcValidatorNode::default()
    });
    if let Some(value) = ops::string(sub, "controller") {
        if existing.is_some_and(|old| old.controller != value) {
            return Err("original external governance controller cannot change".into());
        }
        node.controller = value.into();
    }
    if let Some(value) = ops::string(sub, "consensus-public-key") {
        if existing.is_some_and(|old| old.signing_public_key != value) {
            return Err("original external consensus public key cannot change".into());
        }
        node.signing_public_key = value.into();
    }
    if let Some(path) = ops::path(sub, "remote-signer-profile") {
        let value = ops::public_file(&path, 4096)?;
        let profile: validator::RemoteSigner = serde_json::from_str(&value)
            .map_err(|_| "invalid bounded public remote signer profile")?;
        profile.validate()?;
        let encoded =
            serde_json::to_string(&profile).map_err(|_| "invalid public remote signer profile")?;
        if existing.is_some_and(|old| host::remote(old).ok().as_ref() != Some(&profile)) {
            return Err("original remote signer qualification cannot be replaced".into());
        }
        node.remote_signer = encoded;
    }
    if !validator::address(&node.controller)
        || !erpc_chain_arc::authority::public_identity(&node.signing_public_key)
    {
        return Err("--controller and canonical --consensus-public-key are required for a new original reservation".into());
    }
    ops::update_policy(&mut node, sub)?;
    if !validator::address(&node.fee_recipient) {
        return Err("--fee-recipient is required for a new original reservation".into());
    }
    host::remote(&node)?;
    Ok(node)
}

fn inputs(
    sub: &ArgMatches,
    existing: Option<&ArcValidatorNode>,
) -> Result<(ArcValidatorNode, String), String> {
    let node = public_profile(sub, existing)?;
    let profile = host::remote(&node)?;
    let ca_path =
        ops::path(sub, "signer-ca").ok_or("--signer-ca is required on initial or resumed init")?;
    let ca = ops::public_file(&ca_path, 65536)?;
    validator::qualify_ca(&profile, &ca)?;
    Ok((node, ca))
}

struct Reached {
    session: Session,
    target: Target,
    facts: arc_rpc::Facts,
}
fn reach(
    sub: &ArgMatches,
    existing: Option<&ArcValidatorNode>,
    opened: &ops::Opened,
    name: &str,
    say: &Say,
) -> Result<Reached, String> {
    let address = existing
        .map(|node| node.address.clone())
        .or_else(|| ops::string(sub, "host").map(str::to_owned))
        .ok_or("--host is required for a new host")?;
    if ops::string(sub, "host").is_some_and(|value| value != address) {
        return Err("original Arc validator host cannot be replaced".into());
    }
    if opened
        .nodes
        .iter()
        .any(|other| other.name != name && other.address == address)
        || opened
            .store
            .rpc_nodes()
            .map_err(|error| error.to_string())?
            .iter()
            .any(|other| other.address == address)
    {
        return Err(
            "dedicated Arc validator host collides with an existing original inventory".into(),
        );
    }
    erpc_ssh::config::check_host(&address).map_err(|error| error.to_string())?;
    let port = existing.map_or_else(
        || sub.get_one::<u16>("port").copied().unwrap_or(22),
        |node| node.ssh_port,
    );
    if port == 0 {
        return Err("SSH port must be nonzero".into());
    }
    let user = existing.map_or_else(
        || ops::string(sub, "user").unwrap_or("ubuntu").to_owned(),
        |node| node.ssh_user.clone(),
    );
    let offered = host_key(
        &address,
        port,
        existing.map(|node| node.host_key.as_str()),
        ops::string(sub, "fingerprint"),
        say,
    )?;
    let login = ops::login(sub);
    let target = Target {
        host: address.clone(),
        port,
        user: user.clone(),
        host_key: offered.clone(),
        identity: Identity::Agent {
            socket: agent_socket(login.ssh_agent.as_deref())?,
            public_key: login
                .ssh_key
                .ok_or("--ssh-key must name the login identity's public key")?,
        },
    };
    let session =
        Session::open(&target).map_err(|_| "could not open the original pinned Arc host")?;
    check_ubuntu(&session)?;
    let facts = arc_rpc::facts(&session)?;
    if !facts.refusals().is_empty() {
        return Err(format!(
            "Arc preparation preflight refused: {}",
            facts.refusals().join("; ")
        ));
    }
    Ok(Reached {
        session,
        target,
        facts,
    })
}

pub(crate) fn run(sub: &ArgMatches, network: &str, say: &Say) -> Result<Value, String> {
    let name = ops::string(sub, "name").ok_or("--name is required")?;
    erpc_chain::inventory::check_name(name).map_err(|error| error.to_string())?;
    let opened = ops::open(network, ops::string(sub, "vault"), say)?;
    let existing = opened.nodes.iter().find(|node| node.name == name);
    let (mut node, ca) = inputs(sub, existing)?;
    let Reached {
        session,
        target,
        facts,
    } = reach(sub, existing, &opened, name, say)?;
    node.host.name = name.into();
    node.host.address.clone_from(&target.host);
    node.host.ssh_user.clone_from(&target.user);
    node.host.ssh_port = target.port;
    node.host.host_key = target.host_key.to_openssh();
    if existing.is_none() {
        ops::pin(&mut node, sub, &facts)?;
    } else if ops::string(sub, "version").is_some_and(|version| version != node.version) {
        return Err("use explicit update for another native release".into());
    }
    host::policy(&node, &facts)?;
    if node.participation != "observer" {
        return Err(ops::HISTORY_REQUIRED.into());
    }
    go_ahead(
        ops::flag(sub, "yes"),
        "no inventory, peer key or host setup was created",
    )
    .map_err(|error| error.to_string())?;
    preflight(&session, &target, existing, network, name, say)?;
    let mut node = crate::arc_validator_custody::provision(
        &opened.store,
        &opened.runner,
        &opened.vault,
        network,
        node,
        existing,
        key::ConsensusKey::generate,
    )?;
    save_vault(network, &opened.vault)?;
    let extra = serde_json::Map::from_iter([("arc_validator_ca".into(), json!(ca))]);
    let inventory = host::inventory(&node, network, &facts, extra)?;
    let run = host::run_play(&session, &target, &inventory, validator::plays::INIT, say)?;
    node.host.last_run.clone_from(&run);
    node.host.last_result = "prepared".into();
    opened
        .store
        .update_arc_validator(&node)
        .map_err(|error| error.to_string())?;
    Ok(
        json!({"chain":"arc","role":"validator","network":network,"name":name,"run":run,
              "prepared":true,"validator_ready":false,"production_activation_available":false,
              "peer_public_key":node.consensus_public_key,"consensus_public_key":node.signing_public_key}),
    )
}

fn preflight(
    session: &Session,
    target: &Target,
    existing: Option<&ArcValidatorNode>,
    network: &str,
    name: &str,
    say: &Say,
) -> Result<(), String> {
    let request = existing.map_or_else(
        || Ok(json!({"action":"preflight"})),
        |node| host::request(node, network, "preflight", json!({})),
    )?;
    let inventory = json!({"all":{"hosts":{name:{"ansible_connection":"local",
        "arc_validator_loader":validator::carried_loader()?,"arc_validator_request":request}}}})
    .to_string();
    host::run_play(
        session,
        target,
        &inventory,
        validator::plays::PREFLIGHT,
        say,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use erpc_core::chain::{Chain, Role};

    #[test]
    fn actual_parsed_initial_profile_is_the_typed_minimal_role_before_key_creation() {
        let directory = tempfile::tempdir().unwrap();
        let profile = directory.path().join("signer.json");
        let value = json!({"endpoint":"https://127.0.0.1:10340/","server_ca_sha256":"a".repeat(64),
            "image_sha256":"b".repeat(64),"pcr0":"c".repeat(96),"pcr1":"c".repeat(96),"pcr2":"c".repeat(96),"pcr4":"c".repeat(96)});
        std::fs::write(&profile, value.to_string()).unwrap();
        let owner = format!("0x{}", "a".repeat(40));
        let recipient = format!("0x{}", "b".repeat(40));
        let matches = crate::tree::command(Role::Validator, Chain::Arc)
            .try_get_matches_from([
                "v",
                "--chain",
                "arc",
                "--network",
                "testnet",
                "--name",
                "inert",
                "init",
                "--controller",
                &owner,
                "--consensus-public-key",
                "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
                "--remote-signer-profile",
                profile.to_str().unwrap(),
                "--fee-recipient",
                &recipient,
            ])
            .unwrap();
        let node = public_profile(matches.subcommand().unwrap().1, None).unwrap();
        assert_eq!(node.rpc_type, "validator-minimal");
        assert_eq!(node.participation, "observer");
        assert!(node.rpc_allow.is_empty());
        assert!(node.consensus_key_ref.is_empty());
        assert!(node.consensus_public_key.is_empty());
        assert!(node.id.is_none());
        assert!(!node.admission_approved);
        let mut other = node.clone();
        other.controller = format!("0x{}", "c".repeat(40));
        assert!(public_profile(matches.subcommand().unwrap().1, Some(&other)).is_err());
    }
}
