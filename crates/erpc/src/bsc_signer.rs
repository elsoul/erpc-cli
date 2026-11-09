// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! BSC public identity binding and concealed backup/recovery orchestration.

use crate::{
    bsc_owned::{self, Node},
    bsc_rpc, node_common,
};
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::Store;
use erpc_chain_bsc::{Network, validator};
use erpc_secret::OpRef;
use erpc_ssh::{RemoteCommand, Session};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct Recovery<'a> {
    #[serde(flatten)]
    public: Value,
    backup: &'a str,
}

fn bind(node: &mut Node, network: Network, status: &Value) -> Result<Value, String> {
    let Node::Validator(signer) = node else {
        return Err("expected a BSC validator".into());
    };
    let fields = &status["identities"];
    let value = |key| {
        fields[key]
            .as_str()
            .ok_or("owned signer has not published its identities")
    };
    let reviewed = validator::registration(
        network,
        &signer.operator,
        value("consensus")?,
        value("vote")?,
        value("proof")?,
    )?;
    let consensus = value("consensus")?;
    let vote = value("vote")?;
    let proof = value("proof")?;
    if !["unprovisioned", "owned"].contains(&signer.custody.as_str())
        || (!signer.consensus.is_empty()
            && (signer.consensus != consensus || signer.vote != vote || signer.proof != proof))
    {
        return Err("reserved BSC identities differ from the host; ownership retained".into());
    }
    signer.consensus = consensus.into();
    signer.vote = vote.into();
    signer.proof = proof.into();
    signer.custody = "owned".into();
    Ok(reviewed)
}

fn export(session: &Session, node: &Node, network: Network) -> Result<SecretString, String> {
    let request = bsc_rpc::request(node, network, "export-custody")?.to_string();
    let output = session
        .run(
            &RemoteCommand::BscControl(erpc_ssh::bsc::Control::new()?),
            Some(request.as_bytes()),
        )
        .map_err(|_| "cannot export this host's custody backup")?;
    let raw = zeroize::Zeroizing::new(output.stdout);
    let _stderr = zeroize::Zeroizing::new(output.stderr);
    if raw.len() > 65537 {
        return Err("custody backup exceeds the concealed-field bound".into());
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| "invalid custody backup encoding")?
        .trim_end_matches('\n');
    if text.is_empty() {
        return Err("custody backup is empty".into());
    }
    Ok(SecretString::from(text.to_owned()))
}

pub(crate) fn finish(
    session: &Session,
    node: &mut Node,
    network: Network,
    store: &Store<OpCli>,
    vault: &str,
) -> Result<Value, String> {
    let status = bsc_rpc::control(session, node, network, "status")?;
    if !node.is_validator() {
        return Ok(status);
    }
    bind(node, network, &status)?;
    bsc_owned::save(store, node).map_err(|e| e.to_string())?;
    let backup = export(session, node, network)?;
    let op = node_common::op_runner()?;
    let reference = crate::bsc_backup::ensure(
        &op,
        vault,
        network.name(),
        node.id.as_deref().ok_or("missing validator owner")?,
        &backup,
    )?;
    let Node::Validator(signer) = node else {
        return Err("expected validator".into());
    };
    if !signer.backup_ref.is_empty() && signer.backup_ref != reference.to_string() {
        return Err("custody backup reference changed; inspect before acknowledgement".into());
    }
    signer.backup_ref = reference.to_string();
    bsc_owned::save(store, node).map_err(|e| e.to_string())?;
    let mut request = bsc_rpc::request(node, network, "confirm-backup")?;
    request["backup_digest"] = json!(format!(
        "{:x}",
        Sha256::digest(backup.expose_secret().as_bytes())
    ));
    bsc_rpc::control_request(session, &request)?;
    bsc_rpc::control(session, node, network, "status")
}

pub(crate) fn registration(
    session: &Session,
    node: &Node,
    network: Network,
) -> Result<Value, String> {
    let status = bsc_rpc::control(session, node, network, "status")?;
    if status["backup_confirmed"] != true {
        return Err(
            "verify the concealed custody backup through deploy before registration".into(),
        );
    }
    if status["node_ready"] != true || status["clock_synchronized"] != true {
        return Err("finish node and clock synchronization before registration preparation".into());
    }
    if status["registration"]["identity_conflict"] == true {
        return Err("operator is already registered with other identities; inspect the official registration tools".into());
    }
    let mut observed = node.clone();
    bind(&mut observed, network, &status)
}

pub(crate) fn restore(session: &Session, node: &Node, network: Network) -> Result<Value, String> {
    let Node::Validator(signer) = node else {
        return Err("custody recovery is only available for validators".into());
    };
    let reference = OpRef::parse(&signer.backup_ref)
        .map_err(|_| "this owner has no valid concealed backup reference")?;
    let backup = crate::rollup_credentials::read_concealed(&node_common::op_runner()?, &reference)?;
    let input = SecretString::from(
        serde_json::to_string(&Recovery {
            public: bsc_rpc::request(node, network, "restore-custody")?,
            backup: backup.expose_secret(),
        })
        .map_err(|_| "cannot encode custody recovery")?,
    );
    let output = session
        .run(
            &RemoteCommand::BscControl(erpc_ssh::bsc::Control::new()?),
            Some(input.expose_secret().as_bytes()),
        )
        .map_err(|_| "same-owner custody recovery failed; signing remains fenced")?;
    serde_json::from_slice(&output.stdout).map_err(|_| "invalid custody recovery response".into())
}
