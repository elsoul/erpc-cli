// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Original core-cell identity, concealed backup and same-host recovery.
use crate::{
    kaia_owned::{self, Node},
    kaia_rpc, node_common,
};
use clap::ArgMatches;
use erpc_auth::store::one_password::OpCli;
use erpc_chain::inventory::{Store, kaia::KaiaRpc, kaia_corecell::KaiaCoreCell};
use erpc_chain_kaia::{Network, corecell, custody::Capsule};
use erpc_secret::OpRef;
use erpc_ssh::{RemoteCommand, Session};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::{Value, json};

fn one<'a>(args: &'a ArgMatches, key: &str) -> Option<&'a str> {
    args.try_get_one::<String>(key)
        .ok()
        .flatten()
        .map(String::as_str)
}
pub(crate) fn fresh(node: KaiaRpc, args: &ArgMatches) -> Result<KaiaCoreCell, String> {
    let kind = one(args, "node-kind")
        .and_then(corecell::Kind::parse)
        .ok_or("new core cell requires --node-kind cn|pn")?;
    if kind == corecell::Kind::Consensus && node.storage != "full" {
        return Err(
            "the qualified CN profile uses full retention; live pruning is not recommended for CNs"
                .into(),
        );
    }
    let advertise = one(args, "advertise-ip")
        .ok_or("pass --advertise-ip with this core-cell's numeric IPv4 route")?;
    let address: std::net::Ipv4Addr = advertise
        .parse()
        .map_err(|_| "invalid numeric IPv4 advertisement")?;
    if address.octets()[0] == 0
        || address.octets()[0] >= 224
        || address.is_loopback()
        || address.is_link_local()
    {
        return Err("unsupported core-cell advertisement".into());
    }
    let peers = args
        .try_get_many::<String>("peer")
        .ok()
        .flatten()
        .map(|v| v.cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let peers = if peers.is_empty() {
        peers
    } else {
        corecell::peers(&peers, None)?
            .iter()
            .map(corecell::Peer::uri)
            .collect()
    };
    let cell = KaiaCoreCell {
        node,
        node_kind: kind.name().into(),
        advertise: address.to_string(),
        peers,
        reward_address: one(args, "reward-address")
            .unwrap_or("")
            .to_ascii_lowercase(),
        manager_address: one(args, "manager-address")
            .unwrap_or("")
            .to_ascii_lowercase(),
        staking_address: one(args, "staking-address")
            .unwrap_or("")
            .to_ascii_lowercase(),
        gc_id: one(args, "gc-id").unwrap_or("0").into(),
        ..KaiaCoreCell::default()
    };
    if kind == corecell::Kind::Consensus
        && (cell.reward_address.is_empty() || cell.manager_address.is_empty())
    {
        return Err(
            "CN requires externally controlled --reward-address and --manager-address".into(),
        );
    }
    Ok(cell)
}
pub(crate) fn check_init(node: &Node, args: &ArgMatches) -> Result<(), String> {
    if let Node::Validator(cell) = node {
        for (key, old) in [
            ("node-kind", &cell.node_kind),
            ("advertise-ip", &cell.advertise),
            ("reward-address", &cell.reward_address),
            ("manager-address", &cell.manager_address),
            ("staking-address", &cell.staking_address),
            ("gc-id", &cell.gc_id),
        ] {
            if one(args, key).is_some_and(|value| value.to_ascii_lowercase() != *old) {
                return Err("init cannot change an existing core-cell reservation".into());
            }
        }
        if let Some(peers) = args.try_get_many::<String>("peer").ok().flatten() {
            let supplied = peers.cloned().collect::<Vec<_>>();
            if corecell::peers(&supplied, None)?
                .iter()
                .map(corecell::Peer::uri)
                .collect::<Vec<_>>()
                != cell.peers
            {
                return Err("init cannot change approved core-cell peers".into());
            }
        }
    }
    Ok(())
}
fn private_request(session: &Session, input: &SecretString) -> Result<SecretString, String> {
    let output = session
        .run(
            &RemoteCommand::KaiaControl(erpc_ssh::kaia::Control::custody()?),
            Some(input.expose_secret().as_bytes()),
        )
        .map_err(|_| "concealed core-cell operation failed; original ownership retained")?;
    let raw = zeroize::Zeroizing::new(output.stdout);
    let _stderr = zeroize::Zeroizing::new(output.stderr);
    if raw.len() > 16384 {
        return Err("concealed core-cell response exceeds its bound".into());
    }
    Ok(SecretString::from(
        std::str::from_utf8(&raw)
            .map_err(|_| "invalid concealed core-cell encoding")?
            .to_owned(),
    ))
}
fn bind(node: &mut Node, capsule: &Capsule) -> Result<(), String> {
    let Node::Validator(cell) = node else {
        return Err("core-cell custody requires validator role".into());
    };
    let identity = capsule.public();
    if !cell.node_address.is_empty()
        && (
            &cell.node_address,
            &cell.peer_key,
            &cell.bls_key,
            &cell.bls_pop,
        ) != (
            &identity.address,
            &identity.peer_key,
            &identity.bls_key,
            &identity.bls_pop,
        )
    {
        return Err("original core-cell identity differs; reservation retained".into());
    }
    if identity.address == cell.reward_address || identity.address == cell.manager_address {
        return Err("financial authorities cannot use the dedicated consensus identity".into());
    }
    if !cell.peers.is_empty() {
        corecell::peers(&cell.peers, Some(&identity.peer_key))?;
    }
    cell.node_address.clone_from(&identity.address);
    cell.peer_key.clone_from(&identity.peer_key);
    cell.bls_key.clone_from(&identity.bls_key);
    cell.bls_pop.clone_from(&identity.bls_pop);
    Ok(())
}
pub(crate) fn finish(
    session: &Session,
    node: &mut Node,
    network: Network,
    store: &Store<OpCli>,
    vault: &str,
) -> Result<Value, String> {
    let Node::Validator(cell) = node else {
        return Err("core-cell custody requires validator role".into());
    };
    let kind = cell.node_kind.clone();
    let request =
        SecretString::from(kaia_rpc::request(node, network, "custody-create")?.to_string());
    let capsule = Capsule::parse(
        private_request(session, &request)?,
        kaia_rpc::owner(node)?,
        network.name(),
        &kind,
    )?;
    bind(node, &capsule)?;
    kaia_owned::save(store, node).map_err(|e| e.to_string())?;
    let reference = crate::kaia_backup::ensure(
        &node_common::op_runner()?,
        vault,
        network.name(),
        kaia_rpc::owner(node)?,
        capsule.secret(),
    )?;
    let Node::Validator(cell) = node else {
        return Err("core-cell role differs".into());
    };
    if !cell.backup_ref.is_empty() && cell.backup_ref != reference.to_string() {
        return Err("original concealed backup reference differs".into());
    }
    cell.backup_ref = reference.to_string();
    kaia_owned::save(store, node).map_err(|e| e.to_string())?;
    let mut request = kaia_rpc::request(node, network, "custody-confirm")?;
    request["backup_digest"] = json!(capsule.digest());
    request["public"] =
        serde_json::to_value(capsule.public()).map_err(|_| "cannot encode public identity")?;
    let raw = private_request(session, &SecretString::from(request.to_string()))?;
    serde_json::from_str(raw.expose_secret()).map_err(|_| "invalid backup confirmation".into())
}
#[derive(Serialize)]
struct Recovery<'a> {
    #[serde(flatten)]
    public: Value,
    material: &'a str,
}
pub(crate) fn restore(session: &Session, node: &Node, network: Network) -> Result<Value, String> {
    let Node::Validator(cell) = node else {
        return Err("core-cell recovery requires validator role".into());
    };
    let reference =
        OpRef::parse(&cell.backup_ref).map_err(|_| "original concealed backup is unavailable")?;
    let raw = crate::rollup_credentials::read_concealed(&node_common::op_runner()?, &reference)?;
    let capsule = Capsule::parse(raw, kaia_rpc::owner(node)?, network.name(), &cell.node_kind)?;
    let mut checked = node.clone();
    bind(&mut checked, &capsule)?;
    let input = SecretString::from(
        serde_json::to_string(&Recovery {
            public: kaia_rpc::request(node, network, "custody-restore")?,
            material: capsule.secret().expose_secret(),
        })
        .map_err(|_| "cannot encode concealed recovery")?,
    );
    let raw = private_request(session, &input)?;
    serde_json::from_str(raw.expose_secret()).map_err(|_| "invalid recovery response".into())
}

pub(crate) fn configure(node: &mut Node, args: &ArgMatches) -> Result<(), String> {
    let Node::Validator(cell) = node else {
        return Ok(());
    };
    if let Some(values) = args.try_get_many::<String>("peer").ok().flatten() {
        let values = values.cloned().collect::<Vec<_>>();
        cell.peers = corecell::peers(
            &values,
            (!cell.peer_key.is_empty()).then_some(cell.peer_key.as_str()),
        )?
        .iter()
        .map(corecell::Peer::uri)
        .collect();
    }
    for (key, value) in [
        ("reward-address", &mut cell.reward_address),
        ("manager-address", &mut cell.manager_address),
        ("staking-address", &mut cell.staking_address),
        ("gc-id", &mut cell.gc_id),
    ] {
        if let Some(input) = one(args, key) {
            *value = input.to_ascii_lowercase();
        }
    }
    if !cell.node_address.is_empty()
        && (cell.node_address == cell.reward_address || cell.node_address == cell.manager_address)
    {
        return Err(
            "financial authorities must remain separate from the dedicated consensus identity"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn registration(node: &Node) -> Value {
    let Node::Validator(cell) = node else {
        return Value::Null;
    };
    json!({"node_kind":cell.node_kind,"node_uri":if cell.peer_key.is_empty(){String::new()}else{format!("kni://{}@{}:32323?discport=0&ntype={}",cell.peer_key,cell.advertise,cell.node_kind)},"approved_peer_count":cell.peers.len(),"node_address":cell.node_address,"bls_public_key":cell.bls_key,"bls_proof_of_possession":cell.bls_pop,
        "manager_address":cell.manager_address,"reward_address":cell.reward_address,"staking_address":cell.staking_address,"gc_id":cell.gc_id,
        "backup_verified":!cell.backup_ref.is_empty(),"financial_submission":false,"gasless_disabled":true,"auction_disabled":true,
        "admission":"Kaia Team approval and assigned GC ID remain external; verify running-node identity and qualified status before onboarding",
        "portal_funding":if cell.node_kind=="cn" {"Official onboarding currently requires the Consensus Node ID to hold at least 10 KAIA; funding is external and no exemption is assumed"} else {"N/A: proxy nodes do not register as consensus validators"},
        "preparation":"Public identity derived from original sealed keys; use status for owned live-node registration observations"})
}
