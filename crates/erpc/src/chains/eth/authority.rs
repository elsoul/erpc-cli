// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Original Ethereum RPC host contract and authenticated controller requests.
use erpc_chain::inventory::EthRpc;
use erpc_chain_eth::authority::{Contract, host_binding};
use erpc_ssh::{RemoteCommand, Session};
use serde_json::{Value, json};
use std::fmt::Write as _;

pub(crate) fn contract(node: &EthRpc, network: &str) -> Result<Contract, String> {
    let value = Contract {
        schema: 1,
        role: "rpc".to_owned(),
        owner: node
            .id
            .clone()
            .ok_or("original Ethereum inventory identity is missing")?,
        network: network.to_owned(),
        kind: node.rpc_type.clone(),
        host_binding: host_binding(&node.address, &node.ssh_user, node.ssh_port, &node.host_key),
    };
    value.validate().map_err(str::to_owned)?;
    Ok(value)
}

pub(crate) fn request(
    node: &EthRpc,
    network: &str,
    action: &str,
    fields: Value,
) -> Result<Value, String> {
    if !matches!(
        action,
        "reserve"
            | "upgrade-volume"
            | "migrate"
            | "prepare"
            | "deployment"
            | "public-status"
            | "engine-init"
            | "begin"
            | "install"
            | "bootstrap"
            | "activate"
            | "start"
            | "stop"
            | "restart"
            | "destroy"
            | "recover"
            | "reserve-deploy"
            | "check-deploy"
            | "qualify"
            | "extract"
            | "firewall-apply"
            | "firewall-confirm"
            | "firewall-require"
    ) {
        return Err("unsupported original Ethereum authority operation".into());
    }
    let Value::Object(mut value) = fields else {
        return Err("public Ethereum request must be an object".into());
    };
    if value.contains_key("action") || value.contains_key("contract") {
        return Err("public operation fields cannot replace original host authority".into());
    }
    value.insert("action".into(), json!(action));
    value.insert("contract".into(), json!(contract(node, network)?));
    Ok(Value::Object(value))
}

pub(crate) fn source(node: &EthRpc) -> Result<Value, String> {
    let profile = std::str::from_utf8(
        erpc_chain_eth::file("authority/network.yml").ok_or("missing fixed network profile")?,
    )
    .map_err(|_| "invalid fixed network profile")?;
    let checkpoint = profile
        .lines()
        .find_map(|line| line.strip_prefix("eth_checkpoint_sync_url: "))
        .ok_or("missing fixed checkpoint")?;
    Ok(
        json!({"pair":format!("reth-{}--lighthouse-{}",node.reth_version,node.lighthouse_version),
        "reth_commit":node.reth_commit,"lighthouse_commit":node.lighthouse_commit,
        "reth_archive":node.reth_sha256,"lighthouse_archive":node.lighthouse_sha256,
        "rpc_bind":if node.rpc_allow.is_empty(){"127.0.0.1"}else{"0.0.0.0"},
        "metrics_bind":if node.monitoring_allow.is_empty(){"127.0.0.1"}else{"0.0.0.0"},"checkpoint":checkpoint}),
    )
}

pub(crate) fn deployment_intent(
    observed: &Value,
    source: &Value,
    operation: &str,
) -> Result<String, String> {
    if !observed["recovery"].is_null() {
        return Err("complete the original Ethereum recovery before deployment".into());
    }
    let pending = &observed["pending"];
    if !pending.is_null() {
        if observed["pending_current"] != true
            || pending["target"] != *source
            || pending["action"] != operation
        {
            return Err("pending Ethereum request differs or was canceled; explicitly recover its original intent before a new deployment".into());
        }
        let value = pending["intent"]
            .as_str()
            .ok_or("missing original deployment intent")?;
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("invalid original deployment intent".into());
        }
        return Ok(value.into());
    }
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| "cannot create an original Ethereum deployment intent")?;
    let mut value = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    Ok(value)
}

pub(crate) fn invoke(
    session: &Session,
    node: &EthRpc,
    network: &str,
    action: &str,
    fields: Value,
) -> Result<Value, String> {
    let encoded =
        serde_json::to_vec(&request(node, network, action, fields)?).map_err(|e| e.to_string())?;
    if encoded.len() > 131_072 {
        return Err("public Ethereum request exceeds its bound".into());
    }
    let result = session
        .run(&RemoteCommand::EthAuthority, Some(&encoded))
        .map_err(|e| e.to_string())?;
    if result.stdout.len() > 1024 * 1024 {
        return Err("public Ethereum response exceeds its bound".into());
    }
    serde_json::from_slice(&result.stdout)
        .map_err(|_| "invalid original Ethereum authority response".into())
}
