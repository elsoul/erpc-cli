// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Original local peer custody, adapted from the reviewed Arc public-reservation flow.
//! The separate external consensus signer is never generated or imported here.
use erpc_auth::store::one_password::OpRunner;
use erpc_chain::inventory::Store;
use erpc_chain::inventory::arc_validator::ArcValidatorNode;
use erpc_chain_arc::key::{self, ConsensusKey, KeyError};
use erpc_secret::OpRef;

pub(crate) fn provision<R: OpRunner>(
    store: &Store<R>,
    runner: &R,
    vault: &str,
    network: &str,
    mut wanted: ArcValidatorNode,
    existing: Option<&ArcValidatorNode>,
    generate: impl FnOnce() -> Result<ConsensusKey, KeyError>,
) -> Result<ArcValidatorNode, String> {
    let mut original = None;
    let mut node = if let Some(previous) = existing {
        wanted.host.id.clone_from(&previous.id);
        wanted.item_version = previous.item_version;
        wanted.host.last_run.clone_from(&previous.last_run);
        wanted.host.last_result.clone_from(&previous.last_result);
        if wanted == *previous {
            wanted
        } else {
            store
                .update_arc_validator(&wanted)
                .map_err(|e| e.to_string())?
        }
    } else {
        let key = generate().map_err(|e| e.to_string())?;
        wanted.consensus_public_key = key.public_key();
        if wanted.consensus_public_key == wanted.signing_public_key {
            return Err(
                "local peer identity must be distinct from the external consensus signer".into(),
            );
        }
        // A lost public-create acknowledgement is not permission to create
        // private material or to regenerate on the next init.
        let reserved = store
            .add_arc_validator(&wanted)
            .map_err(|e| e.to_string())?;
        original = Some(key);
        reserved
    };
    let owner = key::validator::Owner {
        vault,
        network,
        name: &node.name,
        item: node
            .id
            .as_deref()
            .ok_or("original Arc reservation is missing")?,
    };
    if let Some(reference) = store
        .arc_validator_key_reference(&node)
        .map_err(|e| e.to_string())?
    {
        let stored = key::StoredKey {
            public_key: node.consensus_public_key.clone(),
            reference: reference.to_string(),
        };
        key::validator::verify(runner, &owner, &stored).map_err(|e| e.to_string())?;
        return Ok(node);
    }
    let stored = if let Some(key) = original {
        key::validator::store_reserved(runner, &owner, &key).map_err(|e| e.to_string())?
    } else {
        let found=key::validator::find_original(runner,&owner,&node.consensus_public_key).map_err(|e|e.to_string())?
            .ok_or("original Arc reservation has no confirmed key item; do not regenerate or replace it; inspect the original ambiguous creation")?;
        // A recovered public item alone is insufficient to bind custody.
        let _original = key::validator::read(runner, &owner, &found).map_err(|e| e.to_string())?;
        found
    };
    let reference =
        OpRef::parse(&stored.reference).map_err(|_| "invalid original Arc key reference")?;
    node = store
        .bind_arc_validator_key(&node, &reference)
        .map_err(|e| e.to_string())?;
    Ok(node)
}

#[cfg(test)]
#[path = "arc_validator_custody_tests.rs"]
mod tests;
