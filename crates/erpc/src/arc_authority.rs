// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Arc public original-host requests; private seed transport is a separate boundary.

use erpc_chain::inventory::RpcNode;
use erpc_chain_arc::network::Network;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub(crate) fn contract(node: &RpcNode, network: &Network) -> Result<Value, String> {
    let owner = node
        .id
        .as_deref()
        .ok_or("Arc original inventory item is missing")?;
    if owner.len() != 26
        || !owner
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || node.host_key.is_empty()
        || !["full", "archive", "provider"].contains(&node.rpc_type.as_str())
    {
        return Err("invalid original Arc host contract".into());
    }
    if !erpc_chain_arc::authority::public_identity(&node.consensus_public_key) {
        return Err("invalid original Arc public identity".into());
    }
    let name = network
        .chain
        .strip_prefix("arc-")
        .ok_or("unknown Arc network")?;
    let qualified = erpc_chain_arc::network::get(name).ok_or("unknown Arc network")?;
    if &qualified != network {
        return Err("Arc network differs from its carried original profile".into());
    }
    Ok(json!({
        "owner":owner,"network":name,"chain_id":network.chain_id,"genesis_hash":network.genesis_hash,
        "public_key":node.consensus_public_key,"rpc_type":node.rpc_type,
        "host_key_sha256":format!("{:x}",Sha256::digest(node.host_key.as_bytes()))
    }))
}

pub(crate) fn prepare(node: &RpcNode, network: &Network) -> Result<Value, String> {
    Ok(json!({
        "schema":erpc_chain_arc::authority::SCHEMA,"action":"prepare",
        "contract":contract(node,network)?,"helpers":erpc_chain_arc::authority::helper_hash()?
    }))
}

pub(crate) fn request(
    node: &RpcNode,
    network: &Network,
    action: &str,
    extra: Value,
) -> Result<Value, String> {
    let mut value = json!({"schema":erpc_chain_arc::authority::SCHEMA,"action":action,"contract":contract(node,network)?});
    let target = value.as_object_mut().ok_or("invalid Arc request")?;
    let Value::Object(extra) = extra else {
        return Err("invalid Arc request fields".into());
    };
    for (key, field) in extra {
        if target.contains_key(&key) {
            return Err("Arc request cannot replace its original contract".into());
        }
        target.insert(key, field);
    }
    Ok(value)
}

pub(crate) fn invoke(
    session: &erpc_ssh::Session,
    node: &RpcNode,
    network: &Network,
    action: &str,
    extra: Value,
) -> Result<Value, String> {
    let body = request(node, network, action, extra)?.to_string();
    let command = erpc_ssh::RemoteCommand::ArcControl(erpc_ssh::arc::Control::new(
        &erpc_chain_arc::authority::profile(),
    )?);
    let output = session.run(&command, Some(body.as_bytes())).map_err(
        |_| "Arc original host operation was refused; original custody and data were retained",
    )?;
    let bytes = zeroize::Zeroizing::new(output.stdout);
    let _stderr = zeroize::Zeroizing::new(output.stderr);
    if bytes.len() > 65_536 {
        return Err("Arc public reply exceeds its bound".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid public Arc authority reply".into())
}

pub(crate) fn import_key(
    session: &erpc_ssh::Session,
    node: &RpcNode,
    network: &Network,
    key: &erpc_chain_arc::key::ConsensusKey,
    restore: bool,
) -> Result<(), String> {
    use secrecy::ExposeSecret as _;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ack {
        credential: secrecy::SecretString,
        public_key: secrecy::SecretString,
    }
    let mut body = zeroize::Zeroizing::new(
        request(
            node,
            network,
            if restore {
                "credential-restore"
            } else {
                "credential-import"
            },
            json!({}),
        )?
        .to_string(),
    );
    body.pop();
    body.push_str(",\"key\":");
    body.push_str(&key.node_json());
    body.push('}');
    let command = erpc_ssh::RemoteCommand::ArcControl(erpc_ssh::arc::Control::new(
        &erpc_chain_arc::authority::profile(),
    )?);
    let output = session
        .run(&command, Some(body.as_bytes()))
        .map_err(|_| "original Arc key delivery was refused")?;
    let stdout = zeroize::Zeroizing::new(output.stdout);
    let _stderr = zeroize::Zeroizing::new(output.stderr);
    if stdout.len() > 4096 {
        return Err("invalid Arc custody acknowledgement".into());
    }
    let ack: Ack =
        serde_json::from_slice(&stdout).map_err(|_| "invalid Arc custody acknowledgement")?;
    if ack.credential.expose_secret() != "original"
        || ack.public_key.expose_secret() != node.consensus_public_key
    {
        return Err("Arc did not acknowledge the same original encrypted identity".into());
    }
    Ok(())
}

pub(crate) fn source(node: &RpcNode, facts: &crate::arc_rpc::Facts) -> Result<Value, String> {
    let version =
        erpc_chain_arc::releases::read(&node.version).ok_or("invalid Arc source version")?;
    if version.pre.is_some()
        || version
            < erpc_chain_arc::releases::read(erpc_chain_arc::releases::FLOOR)
                .ok_or("invalid Arc source floor")?
        || node.commit.len() != 40
        || !node.commit.bytes().all(|b| b.is_ascii_hexdigit())
        || node.archive_sha256.len() != 64
        || !node.archive_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("Arc requires a stable complete source-qualified release".into());
    }
    Ok(
        json!({"version":node.version,"commit":node.commit,"archive_sha256":node.archive_sha256,
              "platform":facts.platform()?.target()}),
    )
}

pub(crate) fn policy(node: &RpcNode, facts: &crate::arc_rpc::Facts) -> Result<Value, String> {
    if facts.ssh_port == 0 {
        return Err("observed SSH destination port is missing".into());
    }
    Ok(
        json!({"rpc_allow":node.rpc_allow,"monitoring_allow":node.monitoring_allow,
              "management_allow":node.management_allow,"ssh_port":facts.ssh_port,"debug_api":node.debug_api,
              "trusted_peers":node.trusted_peers,"sentry_peers":node.sentry_peers}),
    )
}

pub(crate) fn preflight(
    session: &erpc_ssh::Session,
    target: &erpc_ssh::Target,
    existing: Option<&RpcNode>,
    network: &Network,
    say: &crate::node_common::Say,
) -> Result<(), String> {
    let mut request = json!({"schema":erpc_chain_arc::authority::SCHEMA,"action":"preflight"});
    if let Some(node) = existing {
        request["contract"] = contract(node, network)?;
    }
    let inventory=json!({"all":{"hosts":{"original_arc_preflight":{
        "ansible_connection":"local","arc_authority_loader":erpc_chain_arc::authority::carried_loader()?,
        "arc_preflight_request":request
    }}}}).to_string();
    let bundle = crate::arc_rpc::bundle(&inventory)?;
    let run = erpc_ops::run::start(session, &bundle, "ansible/arc-rpc/preflight.yml")
        .map_err(|e| e.to_string())?;
    let result = crate::node_common::follow(
        target,
        &run,
        "Repeat init to requalify the original Arc host",
        say,
    )?;
    if result.ok() {
        Ok(())
    } else {
        Err("Arc host preflight refused; no new key or inventory reservation was created".into())
    }
}

pub(crate) fn directory(node: &RpcNode, platform: &str) -> Option<String> {
    if !["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"].contains(&platform) {
        return None;
    }
    let source = std::collections::BTreeMap::from([
        ("archive_sha256", node.archive_sha256.as_str()),
        ("commit", node.commit.as_str()),
        ("platform", platform),
        ("version", node.version.as_str()),
    ]);
    serde_json::to_vec(&source)
        .ok()
        .map(|raw| format!("/opt/arc/releases/{:x}", Sha256::digest(raw)))
}
