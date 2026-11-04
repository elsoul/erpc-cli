// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin RPC ownership and immutable retention metadata.

use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked};
use serde::{Deserialize, Serialize};

/// Dedicated Bitcoin Core host, stored as an RPC item in its network vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinRpc {
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
    /// Archive digest from the authenticated manifest.
    pub sha256: String,
    /// Linux machine architecture.
    pub platform: String,
    /// Full or pruned, immutable for this owner/datadir.
    pub storage: String,
    /// Prune target MiB, zero for full.
    pub prune_mib: u64,
    /// Last remote run identifier.
    pub last_run: String,
    /// Last completed controller operation.
    pub last_result: String,
}

fn fields(node: &BitcoinRpc) -> Result<Vec<(&'static str, String)>, InventoryError> {
    let record =
        serde_json::to_string(node).map_err(|_| InventoryError::Unreadable("Bitcoin record"))?;
    Ok(vec![
        ("erpc_format", super::FORMAT.to_owned()),
        ("bitcoin_record", record),
    ])
}
fn read(item: &OpItem) -> Result<BitcoinRpc, InventoryError> {
    let fields = checked(item)?;
    let mut node: BitcoinRpc = serde_json::from_str(
        fields
            .get("bitcoin_record")
            .ok_or(InventoryError::Unreadable("Bitcoin record"))?,
    )
    .map_err(|_| InventoryError::Unreadable("Bitcoin record"))?;
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}
impl<R: OpRunner> Store<R> {
    /// List Bitcoin RPC items in this exact scope.
    /// # Errors
    /// Wrong chain or malformed records are refused.
    pub fn bitcoin_rpcs(&self) -> Result<Vec<BitcoinRpc>, InventoryError> {
        if self.scope.chain != "bitcoin" {
            return Err(InventoryError::Refused("expected Bitcoin scope".into()));
        }
        self.items(Kind::Rpc)?.iter().map(read).collect()
    }
    /// Reserve a host without changing its remote data.
    /// # Errors
    /// Duplicate name/address or a store failure prevents reservation.
    pub fn add_bitcoin_rpc(&self, node: &BitcoinRpc) -> Result<BitcoinRpc, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        if self
            .bitcoin_rpcs()?
            .iter()
            .any(|old| old.name == node.name || old.address == node.address)
        {
            return Err(InventoryError::Refused(
                "Bitcoin host is already reserved".into(),
            ));
        }
        read(&self.create(Kind::Rpc, &node.name, &fields(node)?, None)?)
    }
    /// Update pins/run results while preserving host and retention ownership.
    /// # Errors
    /// Ownership changes and stale writes are refused.
    pub fn update_bitcoin_rpc(&self, node: &BitcoinRpc) -> Result<BitcoinRpc, InventoryError> {
        let _lock = self.lock()?;
        let id = node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("Bitcoin owner"))?;
        let old = read(&self.get(id)?)?;
        if (old.address, old.host_key, old.storage, old.prune_mib)
            != (
                node.address.clone(),
                node.host_key.clone(),
                node.storage.clone(),
                node.prune_mib,
            )
        {
            return Err(InventoryError::Refused(
                "Bitcoin host and retention contract are immutable".into(),
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
