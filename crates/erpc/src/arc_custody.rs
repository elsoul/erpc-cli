// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Persist public ownership before creating its one original concealed key.
use erpc_auth::store::one_password::OpRunner;
use erpc_chain::inventory::{RpcNode, Store};
use erpc_chain_arc::key::{self, ConsensusKey, KeyError};
use erpc_secret::OpRef;

/// Carry the saved public version through original-key delivery and host configuration.
pub(crate) fn configure<R: OpRunner, T>(
    store: &Store<R>,
    original: &RpcNode,
    next: &RpcNode,
    deliver: impl FnOnce(&RpcNode) -> Result<(), String>,
    apply: impl FnOnce(&RpcNode) -> Result<T, String>,
) -> Result<(RpcNode, T), String> {
    let node = if next == original {
        original.clone()
    } else {
        store.update_rpc_node(next).map_err(|e| e.to_string())?
    };
    deliver(&node).map_err(|_|"original-key delivery was refused after configuration qualification; public configuration may already be saved; reload the current inventory before retrying".to_owned())?;
    let result = apply(&node)?;
    Ok((node, result))
}

pub(crate) fn provision<R: OpRunner>(
    store: &Store<R>,
    runner: &R,
    vault: &str,
    network: &str,
    mut wanted: RpcNode,
    existing: Option<&RpcNode>,
    generate: impl FnOnce() -> Result<ConsensusKey, KeyError>,
) -> Result<RpcNode, String> {
    let mut original = None;
    let mut node = if let Some(previous) = existing {
        wanted.id.clone_from(&previous.id);
        wanted.item_version = previous.item_version;
        wanted.last_run.clone_from(&previous.last_run);
        wanted.last_result.clone_from(&previous.last_result);
        if wanted == *previous {
            wanted
        } else {
            store.update_rpc_node(&wanted).map_err(|e| e.to_string())?
        }
    } else {
        let key = generate().map_err(|e| e.to_string())?;
        wanted.consensus_public_key = key.public_key();
        // A lost public-create acknowledgement is not permission to create
        // private material or to regenerate on the next init.
        let reserved = store.add_rpc_node(&wanted).map_err(|e| e.to_string())?;
        original = Some(key);
        reserved
    };
    let owner = key::Owner {
        vault,
        network,
        name: &node.name,
        item: node
            .id
            .as_deref()
            .ok_or("original Arc reservation is missing")?,
    };
    if let Some(reference) = store.arc_key_reference(&node).map_err(|e| e.to_string())? {
        let stored = key::StoredKey {
            public_key: node.consensus_public_key.clone(),
            reference: reference.to_string(),
        };
        key::verify(runner, &owner, &stored).map_err(|e| e.to_string())?;
        return Ok(node);
    }
    let stored = if let Some(key) = original {
        key::store_reserved(runner, &owner, &key).map_err(|e| e.to_string())?
    } else {
        let found=key::find_original(runner,&owner,&node.consensus_public_key).map_err(|e|e.to_string())?
            .ok_or("original Arc reservation has no confirmed key item; do not regenerate or replace it; inspect the original ambiguous creation")?;
        // A recovered public item alone is insufficient to bind custody.
        let _original = key::read(runner, &owner, &found).map_err(|e| e.to_string())?;
        found
    };
    let reference =
        OpRef::parse(&stored.reference).map_err(|_| "invalid original Arc key reference")?;
    node = store
        .bind_arc_key(&node, &reference)
        .map_err(|e| e.to_string())?;
    Ok(node)
}

#[cfg(test)]
#[path = "arc_custody_tests.rs"]
mod tests;
