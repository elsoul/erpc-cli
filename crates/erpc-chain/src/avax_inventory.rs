// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Avalanche inventory. Node identities are not Solana keypairs or vote accounts.
use super::{FORMAT, InventoryError, Kind, Store, check_name};
use erpc_auth::store::one_password::OpRunner;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::json;

#[path = "avax_inventory/projection.rs"]
mod projection;
#[path = "avax_inventory/write.rs"]
mod write;

/// One physical `AvalancheGo` node; its role and network are immutable after init.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AvaxNode {
    /// Item locator, assigned by storage.
    #[serde(skip)]
    pub id: Option<String>,
    /// Optimistic concurrency version.
    #[serde(skip)]
    pub item_version: u64,
    /// Inventory name.
    pub name: String,
    /// Pinned host address.
    pub address: String,
    /// SSH login user.
    pub ssh_user: String,
    /// SSH port.
    pub ssh_port: u16,
    /// Pinned SSH host key.
    pub host_key: String,
    /// Canonical network, duplicated to reject cross-scope imports.
    pub network: String,
    /// Explicit validator intent; RPC remains a follower until on-chain registration.
    pub validator: bool,
    /// `full` or `archive`; immutable history policy.
    pub rpc_type: String,
    /// Release tag.
    pub version: String,
    /// Resolved release commit.
    pub commit: String,
    /// Archive SHA-256, from authenticated release metadata.
    pub archive_sha256: String,
    /// Linux release architecture.
    pub arch: String,
    /// Stable public `NodeID`; empty before first deploy.
    pub node_id: String,
    /// Public BLS proof response (no signing key).
    pub node_pop: serde_json::Value,
    /// SHA-256 digests of each staking identity file.
    pub identity_hashes: serde_json::Value,
    /// Addresses permitted to use the restricted API gateway.
    pub rpc_allow: Vec<String>,
    /// Addresses permitted to SSH, plus the current controller.
    pub management_allow: Vec<String>,
    /// Addresses permitted to scrape metrics through the gateway.
    pub monitoring_allow: Vec<String>,
    /// Last completed remote run.
    pub last_run: String,
    /// Last run result.
    pub last_result: String,
}
impl<R: OpRunner> Store<R> {
    fn avax_scope(&self) -> Result<(), InventoryError> {
        if self.scope.chain != "avax" || !["mainnet", "fuji"].contains(&self.scope.network.as_str())
        {
            return Err(InventoryError::Refused(
                "not an Avalanche network scope".into(),
            ));
        }
        Ok(())
    }
    /// Read nodes without reading identity backup material into listings.
    /// # Errors
    /// Rejects malformed/cross-network items and storage errors.
    pub fn avax_nodes(&self) -> Result<Vec<AvaxNode>, InventoryError> {
        self.avax_scope()?;
        let before = self.avax_listing()?;
        let nodes = before
            .iter()
            .map(|item| self.avax_public(item))
            .collect::<Result<Vec<_>, _>>()?;
        if before != self.avax_listing()? {
            return Err(projection::invalid());
        }
        Ok(nodes)
    }
    /// Persist an immutable node identity/host contract.
    /// # Errors
    /// Rejects collisions, malformed scope and storage errors.
    pub fn add_avax_node(&self, node: &AvaxNode) -> Result<AvaxNode, InventoryError> {
        self.avax_scope()?;
        check_name(&node.name)?;
        let _lock = self.lock()?;
        if node.network != self.scope.network
            || self
                .avax_nodes()?
                .iter()
                .any(|n| n.name == node.name || n.address == node.address)
        {
            return Err(InventoryError::Refused(
                "Avalanche network/name/host collision".into(),
            ));
        }
        if node.id.is_some() || node.item_version != 0 {
            return Err(projection::invalid());
        }
        self.avax_create(node)
    }
    /// Update mutable release/API state; retain any concealed identity backup.
    /// # Errors
    /// Rejects stale writers and changes of host, role, history policy or public identity.
    pub fn update_avax_node(&self, node: &AvaxNode) -> Result<AvaxNode, InventoryError> {
        self.avax_scope()?;
        let _lock = self.lock()?;
        let selected = self.avax_selected(node)?;
        let old = self.avax_public(&selected)?;
        if old.item_version != node.item_version {
            return Err(InventoryError::Changed(node.name.clone()));
        }
        if old.name != node.name
            || old.address != node.address
            || old.host_key != node.host_key
            || old.network != node.network
            || old.validator != node.validator
            || old.rpc_type != node.rpc_type
            || (!old.node_id.is_empty()
                && (old.node_id != node.node_id
                    || old.identity_hashes != node.identity_hashes
                    || old.node_pop != node.node_pop))
        {
            return Err(InventoryError::Refused(
                "Avalanche host, role, history and established identity are immutable".into(),
            ));
        }
        let previous = self.avax_snapshot(selected)?;
        if previous.node != old {
            return Err(projection::invalid());
        }
        self.avax_write(node, &previous, None)
    }
    /// Save a concealed identity bundle only after public identity is pinned.
    /// # Errors
    /// Refuses missing identity, stale writers and storage errors.
    pub fn backup_avax_identity(
        &self,
        node: &AvaxNode,
        backup: &SecretString,
    ) -> Result<AvaxNode, InventoryError> {
        self.avax_scope()?;
        let _lock = self.lock()?;
        let selected = self.avax_selected(node)?;
        let old = self.avax_public(&selected)?;
        if node.node_id.is_empty() || old != *node || backup.expose_secret().is_empty() {
            return Err(InventoryError::Refused(
                "pin the node identity before backup".into(),
            ));
        }
        let previous = self.avax_snapshot(selected)?;
        if previous.node != old {
            return Err(projection::invalid());
        }
        self.avax_write(node, &previous, Some(backup))
    }
    /// Read the concealed bundle for same-host disaster recovery.
    /// # Errors
    /// Rejects missing backup or a stale inventory read.
    pub fn avax_identity_backup(&self, node: &AvaxNode) -> Result<SecretString, InventoryError> {
        self.avax_scope()?;
        let selected = self.avax_selected(node)?;
        if self.avax_public(&selected)? != *node {
            return Err(projection::invalid());
        }
        let mut fields = self.avax_fields(&selected, "label=staking_backup", true)?;
        if fields.len() != 1 {
            return Err(projection::invalid());
        }
        let field = fields.pop().ok_or_else(projection::invalid)?;
        if field.label != "staking_backup"
            || field.kind != "CONCEALED"
            || field.id.is_empty()
            || field.section.is_some()
        {
            return Err(projection::invalid());
        }
        let secret = field
            .value
            .filter(|v| !v.expose_secret().is_empty())
            .ok_or(InventoryError::Unreadable("identity backup"))?;
        if self.avax_selected(node)? != selected {
            return Err(projection::invalid());
        }
        Ok(secret)
    }
}

#[cfg(test)]
#[path = "avax_inventory/tests.rs"]
mod tests;
