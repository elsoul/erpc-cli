// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Monad inventory contains public ownership and a concealed-field reference only.
use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked};
use erpc_chain_monad::contract::Contract;
use serde::{Deserialize, Serialize};

/// A dedicated native host. Device, consensus keys and financial authorities never change in place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonadNode {
    /// Secret-store item identifier.
    #[serde(skip)]
    pub id: Option<String>,
    /// Optimistic concurrency version.
    #[serde(skip)]
    pub item_version: u64,
    /// Inventory name.
    pub name: String,
    /// SSH address.
    pub address: String,
    /// SSH login user.
    pub ssh_user: String,
    /// SSH port.
    pub ssh_port: u16,
    /// Pinned OpenSSH host key.
    pub host_key: String,
    /// Immutable native ownership.
    pub contract: Contract,
    /// Identifier-only reference to both original native keystores in one concealed field.
    pub keys_ref: String,
    /// Selected canonical package version.
    pub version: String,
    /// Source-qualified consensus commit.
    pub consensus_commit: String,
    /// Exact execution submodule of the consensus release.
    pub execution_commit: String,
    /// RPC gateway ranges; empty means deny all.
    pub rpc_allow: Vec<String>,
    /// Additional SSH controller ranges.
    pub management_allow: Vec<String>,
    /// Metrics gateway ranges.
    pub monitoring_allow: Vec<String>,
    /// Last completed remote operation.
    pub last_run: String,
    /// Last completed state transition.
    pub last_result: String,
}
fn validate(n: &MonadNode) -> Result<(), InventoryError> {
    check_name(&n.name)?;
    n.contract
        .validate()
        .map_err(|_| InventoryError::Unreadable("Monad ownership"))?;
    erpc_secret::OpRef::parse(&n.keys_ref)
        .map_err(|_| InventoryError::Unreadable("Monad concealed reference"))?;
    if n.ssh_port == 0
        || n.version.len() > 20
        || n.version.split('.').count() != 3
        || n.version.split('.').any(|p| p.parse::<u16>().is_err())
    {
        return Err(InventoryError::Unreadable("Monad connection/release"));
    }
    for commit in [&n.consensus_commit, &n.execution_commit] {
        erpc_chain_monad::contract::hex_bytes(commit, 20)
            .map_err(|_| InventoryError::Unreadable("Monad source commit"))?;
    }
    Ok(())
}
fn kind(role: &str) -> Result<Kind, InventoryError> {
    match role {
        "rpc" => Ok(Kind::Rpc),
        "validator" => Ok(Kind::Validator),
        _ => Err(InventoryError::Unreadable("Monad role")),
    }
}
fn read(item: &OpItem) -> Result<MonadNode, InventoryError> {
    let f = checked(item)?;
    let mut n: MonadNode = serde_json::from_str(
        f.get("monad_record")
            .ok_or(InventoryError::Unreadable("Monad record"))?,
    )
    .map_err(|_| InventoryError::Unreadable("Monad record"))?;
    validate(&n)?;
    n.id = Some(item.id.clone());
    n.item_version = item.version;
    Ok(n)
}
fn fields(n: &MonadNode) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(n)?;
    Ok(vec![
        ("erpc_format", super::FORMAT.into()),
        (
            "monad_record",
            serde_json::to_string(n).map_err(|_| InventoryError::Unreadable("Monad record"))?,
        ),
    ])
}
impl<R: OpRunner> Store<R> {
    /// List public records in one exact role/network scope.
    /// # Errors
    /// Refuses mismatched scope and malformed stored fields.
    pub fn monad_nodes(&self, role: &str) -> Result<Vec<MonadNode>, InventoryError> {
        if self.scope.chain != "monad" {
            return Err(InventoryError::Refused("expected Monad scope".into()));
        }
        let nodes = self
            .items(kind(role)?)?
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        if nodes
            .iter()
            .any(|n| n.contract.role != role || n.contract.network != self.scope.network)
        {
            return Err(InventoryError::Unreadable("Monad role/network scope"));
        }
        Ok(nodes)
    }
    /// Reserve a host, partition and dedicated consensus identity once.
    /// # Errors
    /// Refuses duplicate hosts, names and public identities across both roles.
    pub fn add_monad_node(&self, node: &MonadNode) -> Result<MonadNode, InventoryError> {
        validate(node)?;
        if self.scope.chain != "monad" || node.contract.network != self.scope.network {
            return Err(InventoryError::Refused(
                "Monad inventory scope differs from native contract".into(),
            ));
        }
        let _lock = self.lock()?;
        for role in ["rpc", "validator"] {
            if self.monad_nodes(role)?.iter().any(|n| {
                n.name == node.name
                    || n.address == node.address
                    || n.contract.owner == node.contract.owner
                    || n.contract.secp == node.contract.secp
                    || n.contract.bls == node.contract.bls
            }) {
                return Err(InventoryError::Refused(
                    "Monad host/name or consensus identity already reserved".into(),
                ));
            }
        }
        read(&self.create(kind(&node.contract.role)?, &node.name, &fields(node)?, None)?)
    }
    /// Update release/results/ACLs, preserving native, SSH and credential ownership.
    /// # Errors
    /// Refuses stale writes and ownership/secret-source changes.
    pub fn update_monad_node(&self, node: &MonadNode) -> Result<MonadNode, InventoryError> {
        validate(node)?;
        if self.scope.chain != "monad" || node.contract.network != self.scope.network {
            return Err(InventoryError::Refused(
                "Monad inventory scope differs from native contract".into(),
            ));
        }
        let _lock = self.lock()?;
        let id = node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("Monad item"))?;
        let old = read(&self.get(id)?)?;
        if old.name != node.name
            || old.address != node.address
            || old.ssh_user != node.ssh_user
            || old.ssh_port != node.ssh_port
            || old.host_key != node.host_key
            || old.contract != node.contract
            || old.keys_ref != node.keys_ref
        {
            return Err(InventoryError::Refused(
                "Monad host/device/identity contract is immutable".into(),
            ));
        }
        read(&self.update(
            kind(&node.contract.role)?,
            (Some(id), node.item_version),
            &node.name,
            &fields(node)?,
            None,
        )?)
    }
}
