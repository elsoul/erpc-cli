// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Role-explicit BSC inventory dispatch shared by the two host lifecycles.

use erpc_auth::store::one_password::OpRunner;
use erpc_chain::inventory::{InventoryError, Store, bsc::BscRpc, bsc_validator::BscValidator};

#[derive(Clone)]
pub(crate) enum Node {
    Rpc(BscRpc),
    Validator(BscValidator),
}
impl std::ops::Deref for Node {
    type Target = BscRpc;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Rpc(node) => node,
            Self::Validator(node) => &node.node,
        }
    }
}
impl std::ops::DerefMut for Node {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Rpc(node) => node,
            Self::Validator(node) => &mut node.node,
        }
    }
}
impl Node {
    pub(crate) const fn is_validator(&self) -> bool {
        matches!(self, Self::Validator(_))
    }
    pub(crate) fn operator(&self) -> Option<&str> {
        match self {
            Self::Rpc(_) => None,
            Self::Validator(node) => Some(&node.operator),
        }
    }
    pub(crate) fn public(&self) -> Result<serde_json::Value, String> {
        match self {
            Self::Rpc(node) => serde_json::to_value(node),
            Self::Validator(node) => serde_json::to_value(node),
        }
        .map_err(|_| "cannot encode public BSC inventory".into())
    }
}
pub(crate) fn list<R: OpRunner>(
    store: &Store<R>,
    validator: bool,
) -> Result<Vec<Node>, InventoryError> {
    if validator {
        store
            .bsc_validators()
            .map(|items| items.into_iter().map(Node::Validator).collect())
    } else {
        store
            .bsc_rpcs()
            .map(|items| items.into_iter().map(Node::Rpc).collect())
    }
}
pub(crate) fn add<R: OpRunner>(store: &Store<R>, node: &Node) -> Result<Node, InventoryError> {
    match node {
        Node::Rpc(value) => store.add_bsc_rpc(value).map(Node::Rpc),
        Node::Validator(value) => store.add_bsc_validator(value).map(Node::Validator),
    }
}
pub(crate) fn save<R: OpRunner>(store: &Store<R>, node: &mut Node) -> Result<(), InventoryError> {
    let updated = match node {
        Node::Rpc(value) => store.update_bsc_rpc(value).map(Node::Rpc),
        Node::Validator(value) => store.update_bsc_validator(value).map(Node::Validator),
    }?;
    // Every later write uses the returned optimistic version, including the
    // public-identity reservation followed by the concealed-backup reference.
    *node = updated;
    Ok(())
}
