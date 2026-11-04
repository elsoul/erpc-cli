// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Avalanche inventory. Node identities are not Solana keypairs or vote accounts.
use super::{FORMAT, InventoryError, Kind, OpItem, Store, check_name, checked, field};
use erpc_auth::store::one_password::OpRunner;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;

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
fn fields(node: &AvaxNode) -> Result<Vec<(&'static str, String)>, InventoryError> {
    Ok(vec![
        ("erpc_format", FORMAT.into()),
        (
            "avax_node",
            serde_json::to_string(node)
                .map_err(|_| InventoryError::Unreadable("Avalanche node"))?,
        ),
    ])
}
fn read(item: &OpItem) -> Result<AvaxNode, InventoryError> {
    let f = checked(item)?;
    let mut node: AvaxNode = serde_json::from_str(&field(&f, "avax_node"))
        .map_err(|_| InventoryError::Unreadable("Avalanche node"))?;
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
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
        self.items(Kind::Rpc)?
            .iter()
            .map(|item| {
                let node = read(item)?;
                if node.network != self.scope.network {
                    return Err(InventoryError::Refused(
                        "Avalanche inventory network mismatch".into(),
                    ));
                }
                Ok(node)
            })
            .collect()
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
        read(&self.create(Kind::Rpc, &node.name, &fields(node)?, None)?)
    }
    /// Update mutable release/API state; retain any concealed identity backup.
    /// # Errors
    /// Rejects stale writers and changes of host, role, history policy or public identity.
    pub fn update_avax_node(&self, node: &AvaxNode) -> Result<AvaxNode, InventoryError> {
        self.avax_scope()?;
        let _lock = self.lock()?;
        let id = node
            .id
            .as_deref()
            .ok_or_else(|| InventoryError::Refused("node has no item".into()))?;
        let previous = self.get(id)?;
        let old = read(&previous)?;
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
        self.avax_write(node, &previous, None)
    }
    fn avax_write(
        &self,
        node: &AvaxNode,
        previous: &OpItem,
        backup: Option<&SecretString>,
    ) -> Result<AvaxNode, InventoryError> {
        let mut document: serde_json::Value =
            serde_json::from_str(&self.template(Kind::Rpc, &node.name, &fields(node)?, None))
                .map_err(|_| InventoryError::Unreadable("Avalanche template"))?;
        let retained = previous
            .fields
            .iter()
            .find(|f| f.label == "staking_backup")
            .and_then(|f| f.value.as_deref());
        if let Some(secret) = backup.map(ExposeSecret::expose_secret).or(retained) {
            document["fields"].as_array_mut().ok_or(InventoryError::Unreadable("fields"))?.push(json!({"id":"staking_backup","label":"staking_backup","type":"CONCEALED","value":secret}));
        }
        let template = SecretString::from(document.to_string());
        let id = node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("item id"))?;
        let out = self
            .runner
            .run(
                &["item", "edit", id, "--vault", &self.vault],
                Some(template.expose_secret()),
            )
            .map_err(|_| InventoryError::Unreadable("Avalanche write"))?;
        if !out.success {
            return Err(InventoryError::Unreadable("Avalanche write"));
        }
        let back = self.get(id)?;
        super::verify(&back, &fields(node)?, &node.name)?;
        if let Some(wanted) = backup {
            let got = back
                .fields
                .iter()
                .find(|f| f.label == "staking_backup")
                .and_then(|f| f.value.as_deref());
            if got != Some(wanted.expose_secret()) {
                return Err(InventoryError::Unreadable("identity backup readback"));
            }
        }
        read(&back)
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
        let previous = self.get(
            node.id
                .as_deref()
                .ok_or(InventoryError::Unreadable("item id"))?,
        )?;
        if previous.version != node.item_version {
            return Err(InventoryError::Changed(node.name.clone()));
        }
        if node.node_id.is_empty() || read(&previous)? != *node {
            return Err(InventoryError::Refused(
                "pin the node identity before backup".into(),
            ));
        }
        self.avax_write(node, &previous, Some(backup))
    }
    /// Read the concealed bundle for same-host disaster recovery.
    /// # Errors
    /// Rejects missing backup or a stale inventory read.
    pub fn avax_identity_backup(&self, node: &AvaxNode) -> Result<SecretString, InventoryError> {
        self.avax_scope()?;
        let item = self.get(
            node.id
                .as_deref()
                .ok_or(InventoryError::Unreadable("item id"))?,
        )?;
        if item.version != node.item_version {
            return Err(InventoryError::Changed(node.name.clone()));
        }
        item.fields
            .into_iter()
            .find(|f| f.label == "staking_backup" && f.kind == "CONCEALED")
            .and_then(|f| f.value)
            .map(SecretString::from)
            .ok_or(InventoryError::Unreadable("identity backup"))
    }
}
