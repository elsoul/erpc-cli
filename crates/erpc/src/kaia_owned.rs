// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Role-explicit Kaia inventory dispatch shared by the two host lifecycles.

use erpc_auth::store::one_password::OpRunner;
use erpc_chain::inventory::{InventoryError, Store, kaia::KaiaRpc, kaia_corecell::KaiaCoreCell};

#[derive(Clone)]
pub(crate) enum Node {
    Rpc(Box<KaiaRpc>),
    Validator(Box<KaiaCoreCell>),
}
impl std::ops::Deref for Node {
    type Target = KaiaRpc;
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
    pub(crate) fn rpc(node: KaiaRpc) -> Self {
        Self::Rpc(Box::new(node))
    }
    pub(crate) fn validator(node: KaiaCoreCell) -> Self {
        Self::Validator(Box::new(node))
    }
    pub(crate) const fn is_validator(&self) -> bool {
        matches!(self, Self::Validator(_))
    }
    pub(crate) fn public(&self) -> Result<serde_json::Value, String> {
        match self {
            Self::Rpc(node) => serde_json::to_value(node),
            Self::Validator(node) => serde_json::to_value(node),
        }
        .map_err(|_| "cannot encode public Kaia inventory".into())
    }
}
pub(crate) fn list<R: OpRunner>(
    store: &Store<R>,
    validator: bool,
) -> Result<Vec<Node>, InventoryError> {
    if validator {
        store
            .kaia_corecells()
            .map(|items| items.into_iter().map(Node::validator).collect())
    } else {
        store
            .kaia_rpcs()
            .map(|items| items.into_iter().map(Node::rpc).collect())
    }
}
pub(crate) fn add<R: OpRunner>(store: &Store<R>, node: &Node) -> Result<Node, InventoryError> {
    match node {
        Node::Rpc(value) => store.add_kaia_rpc(value).map(Node::rpc),
        Node::Validator(value) => store.add_kaia_corecell(value).map(Node::validator),
    }
}
pub(crate) fn save<R: OpRunner>(store: &Store<R>, node: &mut Node) -> Result<(), InventoryError> {
    let updated = match node {
        Node::Rpc(value) => store.update_kaia_rpc(value).map(Node::rpc),
        Node::Validator(value) => store.update_kaia_corecell(value).map(Node::validator),
    }?;
    // Every later write uses the returned optimistic version, including the
    // public-identity reservation followed by the concealed-backup reference.
    *node = updated;
    Ok(())
}
