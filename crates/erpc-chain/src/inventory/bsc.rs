// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! BSC RPC ownership and immutable platform metadata.

use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked};
use serde::{Deserialize, Serialize};

/// Dedicated BSC follower host, stored as an RPC item in its network vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BscRpc {
    /// Item identity, assigned by the secret store.
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
    /// Canonical stable version.
    pub version: String,
    /// Resolved source commit.
    pub commit: String,
    /// Linux binary architecture.
    pub platform: String,
    /// Immutable full/pruned block-history contract.
    pub storage: String,
    /// Immutable official snapshot identity for initial bootstrap.
    pub snapshot: String,
    /// Additional canonical management IPv4 ranges.
    pub management_allow: Vec<String>,
    /// Last remote run identifier.
    pub last_run: String,
    /// Last completed controller operation.
    pub last_result: String,
}

fn validate(node: &BscRpc) -> Result<(), InventoryError> {
    if !["full", "pruned"].contains(&node.storage.as_str())
        || node.snapshot.is_empty()
        || node.snapshot.len() > 100
        || !node
            .snapshot
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !["amd64", "arm64"].contains(&node.platform.as_str())
        || node.commit.len() != 40
        || !node
            .commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || node.version.len() > 24
        || node.version.split('.').count() != 3
        || node
            .version
            .split('.')
            .any(|part| part.parse::<u16>().is_err())
    {
        return Err(InventoryError::Unreadable("BSC release metadata"));
    }
    Ok(())
}

pub(super) fn fields(node: &BscRpc) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(node)?;
    let record =
        serde_json::to_string(node).map_err(|_| InventoryError::Unreadable("BSC record"))?;
    Ok(vec![
        ("erpc_format", super::FORMAT.to_owned()),
        ("bsc_record", record),
    ])
}
pub(super) fn read(item: &OpItem) -> Result<BscRpc, InventoryError> {
    let fields = checked(item)?;
    let mut node: BscRpc = serde_json::from_str(
        fields
            .get("bsc_record")
            .ok_or(InventoryError::Unreadable("BSC record"))?,
    )
    .map_err(|_| InventoryError::Unreadable("BSC record"))?;
    validate(&node)?;
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}
impl<R: OpRunner> Store<R> {
    /// List BSC RPC items in this exact scope.
    /// # Errors
    /// Wrong chain or malformed records are refused.
    pub fn bsc_rpcs(&self) -> Result<Vec<BscRpc>, InventoryError> {
        if self.scope.chain != "bsc" {
            return Err(InventoryError::Refused("expected BSC scope".into()));
        }
        self.items(Kind::Rpc)?.iter().map(read).collect()
    }
    /// Reserve a host without changing its remote data.
    /// # Errors
    /// Duplicate name/address or a store failure prevents reservation.
    pub fn add_bsc_rpc(&self, node: &BscRpc) -> Result<BscRpc, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        if self
            .bsc_rpcs()?
            .iter()
            .any(|old| old.name == node.name || old.address == node.address)
            || self
                .bsc_validators()?
                .iter()
                .any(|old| old.node.address == node.address)
        {
            return Err(InventoryError::Refused(
                "BSC host is already reserved".into(),
            ));
        }
        read(&self.create(Kind::Rpc, &node.name, &fields(node)?, None)?)
    }
    /// Update pins/run results while preserving host and platform ownership.
    /// # Errors
    /// Ownership changes and stale writes are refused.
    pub fn update_bsc_rpc(&self, node: &BscRpc) -> Result<BscRpc, InventoryError> {
        let _lock = self.lock()?;
        let id = node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("BSC owner"))?;
        let old = read(&self.get(id)?)?;
        if (
            old.address,
            old.host_key,
            old.platform,
            old.storage,
            old.snapshot,
        ) != (
            node.address.clone(),
            node.host_key.clone(),
            node.platform.clone(),
            node.storage.clone(),
            node.snapshot.clone(),
        ) {
            return Err(InventoryError::Refused(
                "BSC host/platform/retention/snapshot contract are immutable".into(),
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
