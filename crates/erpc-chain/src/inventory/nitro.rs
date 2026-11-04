// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Nitro RPC ownership and immutable platform metadata.

use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked};
use serde::{Deserialize, Serialize};

/// Dedicated Nitro follower host, stored as an RPC item in its network vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NitroRpc {
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
    /// Linux OCI architecture.
    pub platform: String,
    /// Identifier-only reference to a concealed L1 configuration field.
    pub upstreams_ref: String,
    /// Additional canonical management IPv4 ranges.
    pub management_allow: Vec<String>,
    /// Last remote run identifier.
    pub last_run: String,
    /// Last completed controller operation.
    pub last_result: String,
}

fn validate(node: &NitroRpc) -> Result<(), InventoryError> {
    erpc_secret::OpRef::parse(&node.upstreams_ref)
        .map_err(|_| InventoryError::Unreadable("Nitro upstream reference"))?;
    if !["amd64", "arm64"].contains(&node.platform.as_str())
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
        return Err(InventoryError::Unreadable("Nitro release metadata"));
    }
    Ok(())
}

fn fields(node: &NitroRpc) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(node)?;
    let record =
        serde_json::to_string(node).map_err(|_| InventoryError::Unreadable("Nitro record"))?;
    Ok(vec![
        ("erpc_format", super::FORMAT.to_owned()),
        ("nitro_record", record),
    ])
}
fn read(item: &OpItem) -> Result<NitroRpc, InventoryError> {
    let fields = checked(item)?;
    let mut node: NitroRpc = serde_json::from_str(
        fields
            .get("nitro_record")
            .ok_or(InventoryError::Unreadable("Nitro record"))?,
    )
    .map_err(|_| InventoryError::Unreadable("Nitro record"))?;
    validate(&node)?;
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}
impl<R: OpRunner> Store<R> {
    /// List Nitro RPC items in this exact scope.
    /// # Errors
    /// Wrong chain or malformed records are refused.
    pub fn nitro_rpcs(&self) -> Result<Vec<NitroRpc>, InventoryError> {
        if !["arbitrum", "robinhood"].contains(&self.scope.chain.as_str()) {
            return Err(InventoryError::Refused("expected Nitro scope".into()));
        }
        self.items(Kind::Rpc)?.iter().map(read).collect()
    }
    /// Reserve a host without changing its remote data.
    /// # Errors
    /// Duplicate name/address or a store failure prevents reservation.
    pub fn add_nitro_rpc(&self, node: &NitroRpc) -> Result<NitroRpc, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        if self
            .nitro_rpcs()?
            .iter()
            .any(|old| old.name == node.name || old.address == node.address)
        {
            return Err(InventoryError::Refused(
                "Nitro host is already reserved".into(),
            ));
        }
        read(&self.create(Kind::Rpc, &node.name, &fields(node)?, None)?)
    }
    /// Update pins/run results while preserving host and platform ownership.
    /// # Errors
    /// Ownership changes and stale writes are refused.
    pub fn update_nitro_rpc(&self, node: &NitroRpc) -> Result<NitroRpc, InventoryError> {
        let _lock = self.lock()?;
        let id = node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("Nitro owner"))?;
        let old = read(&self.get(id)?)?;
        if (old.address, old.host_key, old.platform)
            != (
                node.address.clone(),
                node.host_key.clone(),
                node.platform.clone(),
            )
        {
            return Err(InventoryError::Refused(
                "Nitro host and platform contract are immutable".into(),
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
