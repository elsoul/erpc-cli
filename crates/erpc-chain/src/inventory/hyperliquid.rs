// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0
//! Public RPC ownership only. No funded native signer belongs in this record.
use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked};
use erpc_chain_hyperliquid::contract::Contract;
use serde::{Deserialize, Serialize};

/// Dedicated non-validator host and observed deployment result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HyperliquidNode {
    /// Store identifier, never serialized into the public record.
    #[serde(skip)]
    pub id: Option<String>,
    /// Optimistic concurrency version.
    #[serde(skip)]
    pub item_version: u64,
    /// Operator inventory name.
    pub name: String,
    /// SSH destination.
    pub address: String,
    /// SSH login user.
    pub ssh_user: String,
    /// SSH port.
    pub ssh_port: u16,
    /// Pinned OpenSSH host key.
    pub host_key: String,
    /// Immutable owner, network, RPC role and public peer address.
    pub contract: Contract,
    /// Pinned supervisor identity; not a child release version.
    pub supervisor_sha256: String,
    /// Signed supervisor publication timestamp.
    pub signed_at: u64,
    /// Public gateway access ranges, default deny.
    pub rpc_allow: Vec<String>,
    /// Additional management access ranges.
    pub management_allow: Vec<String>,
    /// Last remote operation identifier.
    pub last_run: String,
    /// Last completed operation outcome.
    pub last_result: String,
}
fn validate(node: &HyperliquidNode) -> Result<(), InventoryError> {
    validate_for(node, "rpc")
}
pub(super) fn validate_for(node: &HyperliquidNode, role: &str) -> Result<(), InventoryError> {
    check_name(&node.name)?;
    node.contract
        .validate()
        .map_err(|_| InventoryError::Unreadable("Hyperliquid ownership"))?;
    if node.contract.role != role
        || node.ssh_port == 0
        || node.supervisor_sha256.len() != 64
        || !node
            .supervisor_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !(1..4_102_444_800).contains(&node.signed_at)
    {
        return Err(InventoryError::Unreadable("Hyperliquid public deployment"));
    }
    Ok(())
}
fn read(item: &OpItem) -> Result<HyperliquidNode, InventoryError> {
    let fields = checked(item)?;
    let mut node: HyperliquidNode = serde_json::from_str(
        fields
            .get("hyperliquid_record")
            .ok_or(InventoryError::Unreadable("Hyperliquid record"))?,
    )
    .map_err(|_| InventoryError::Unreadable("Hyperliquid record"))?;
    validate(&node)?;
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}
fn fields(node: &HyperliquidNode) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(node)?;
    Ok(vec![
        ("erpc_format", super::FORMAT.into()),
        (
            "hyperliquid_record",
            serde_json::to_string(node)
                .map_err(|_| InventoryError::Unreadable("Hyperliquid record"))?,
        ),
    ])
}
impl<R: OpRunner> Store<R> {
    /// Read one exact RPC/network inventory scope.
    /// # Errors
    /// Refuses malformed or mismatched ownership records.
    pub fn hyperliquid_nodes(&self) -> Result<Vec<HyperliquidNode>, InventoryError> {
        if self.scope.chain != "hyperliquid" {
            return Err(InventoryError::Refused("expected Hyperliquid scope".into()));
        }
        let nodes = self
            .items(Kind::Rpc)?
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        if nodes
            .iter()
            .any(|n| n.contract.network.name() != self.scope.network)
        {
            return Err(InventoryError::Unreadable("Hyperliquid network scope"));
        }
        Ok(nodes)
    }
    /// Reserve a unique host and public ownership nonce.
    /// # Errors
    /// Refuses duplicate records and mismatched network scope.
    pub fn add_hyperliquid_node(
        &self,
        node: &HyperliquidNode,
    ) -> Result<HyperliquidNode, InventoryError> {
        validate(node)?;
        if self.scope.chain != "hyperliquid" || node.contract.network.name() != self.scope.network {
            return Err(InventoryError::Refused("Hyperliquid scope differs".into()));
        }
        let _lock = self.lock()?;
        if self.hyperliquid_nodes()?.iter().any(|n| {
            n.name == node.name
                || n.address == node.address
                || n.contract.owner == node.contract.owner
                || n.contract.public_ip == node.contract.public_ip
        }) || self.hyperliquid_validators()?.iter().any(|other| {
            let n = &other.host;
            n.name == node.name
                || n.address == node.address
                || n.host_key == node.host_key
                || n.contract.owner == node.contract.owner
                || n.contract.public_ip == node.contract.public_ip
        }) || self.hyperliquid_publishers()?.iter().any(|other| {
            other.name == node.name
                || other.address == node.address
                || other.host_key == node.host_key
                || other.contract.owner == node.contract.owner
        }) {
            return Err(InventoryError::Refused(
                "Hyperliquid host, name or peer address is already reserved".into(),
            ));
        }
        read(&self.create(Kind::Rpc, &node.name, &fields(node)?, None)?)
    }
    /// Update supervisor/results/ACLs while preserving original host ownership.
    /// # Errors
    /// Refuses stale writes or changes to immutable connection/contract fields.
    pub fn update_hyperliquid_node(
        &self,
        node: &HyperliquidNode,
    ) -> Result<HyperliquidNode, InventoryError> {
        validate(node)?;
        if self.scope.chain != "hyperliquid" || node.contract.network.name() != self.scope.network {
            return Err(InventoryError::Refused("Hyperliquid scope differs".into()));
        }
        let _lock = self.lock()?;
        let id = node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("Hyperliquid item"))?;
        let previous = read(&self.get(id)?)?;
        if previous.name != node.name
            || previous.address != node.address
            || previous.ssh_user != node.ssh_user
            || previous.ssh_port != node.ssh_port
            || previous.host_key != node.host_key
            || previous.contract != node.contract
        {
            return Err(InventoryError::Refused(
                "Hyperliquid original host and network are immutable".into(),
            ));
        }
        read(&self.update(
            Kind::Rpc,
            (Some(id), node.item_version),
            &node.name,
            &fields(node)?,
            None,
        )?)
    }
}
