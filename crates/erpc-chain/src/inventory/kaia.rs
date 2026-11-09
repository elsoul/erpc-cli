// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Kaia RPC ownership and immutable platform metadata.

use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked};
use serde::{Deserialize, Serialize};

/// Dedicated Kaia follower host, stored as an RPC item in its network vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KaiaRpc {
    /// Item identity, assigned by the secret store.
    #[serde(skip)]
    pub id: Option<String>,
    /// Optimistic concurrency version.
    #[serde(skip)]
    pub item_version: u64,
    /// Inventory name.
    pub name: String,
    /// Immutable public network scope.
    pub network: String,
    /// Immutable native genesis identity.
    pub genesis: String,
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
    /// Exact reviewed OCI platform manifest, never a mutable tag.
    pub image: String,
    /// Linux OCI architecture.
    pub platform: String,
    /// Immutable full/pruned state-retention choice.
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

pub(super) fn validate(node: &KaiaRpc) -> Result<(), InventoryError> {
    let hex = |value: &str, size: usize| {
        value.len() == size
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    };
    let prefix = format!("kaia-{}-pruning-chaindata-", node.network);
    let selected = node
        .snapshot
        .strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix(".tar.zst"));
    let bootstrap = match node.storage.as_str() {
        "full" => node.snapshot == "genesis",
        "pruned" => selected
            .is_some_and(|date| date.len() == 14 && date.bytes().all(|b| b.is_ascii_digit())),
        _ => false,
    };
    if !bootstrap
        || !["mainnet", "kairos"].contains(&node.network.as_str())
        || !node.genesis.strip_prefix("0x").is_some_and(|v| hex(v, 64))
        || !node
            .image
            .strip_prefix("docker.io/kaiachain/kaia@sha256:")
            .is_some_and(|v| hex(v, 64))
        || !["full", "pruned"].contains(&node.storage.as_str())
        || node.snapshot.is_empty()
        || node.snapshot.len() > 100
        || !node
            .snapshot
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b))
        || node.platform != "amd64"
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
        return Err(InventoryError::Unreadable("Kaia release metadata"));
    }
    Ok(())
}

fn fields(node: &KaiaRpc) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(node)?;
    let record =
        serde_json::to_string(node).map_err(|_| InventoryError::Unreadable("Kaia record"))?;
    Ok(vec![
        ("erpc_format", super::FORMAT.to_owned()),
        ("kaia_record", record),
    ])
}
fn read(item: &OpItem) -> Result<KaiaRpc, InventoryError> {
    let fields = checked(item)?;
    let mut node: KaiaRpc = serde_json::from_str(
        fields
            .get("kaia_record")
            .ok_or(InventoryError::Unreadable("Kaia record"))?,
    )
    .map_err(|_| InventoryError::Unreadable("Kaia record"))?;
    validate(&node)?;
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}
impl<R: OpRunner> Store<R> {
    /// List Kaia RPC items in this exact scope.
    /// # Errors
    /// Wrong chain or malformed records are refused.
    pub fn kaia_rpcs(&self) -> Result<Vec<KaiaRpc>, InventoryError> {
        if self.scope.chain != "kaia" {
            return Err(InventoryError::Refused("expected Kaia scope".into()));
        }
        let nodes = self
            .items(Kind::Rpc)?
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        if nodes.iter().any(|node| node.network != self.scope.network) {
            return Err(InventoryError::Unreadable("Kaia network scope"));
        }
        Ok(nodes)
    }
    /// Reserve a host without changing its remote data.
    /// # Errors
    /// Duplicate name/address or a store failure prevents reservation.
    pub fn add_kaia_rpc(&self, node: &KaiaRpc) -> Result<KaiaRpc, InventoryError> {
        check_name(&node.name)?;
        if node.network != self.scope.network {
            return Err(InventoryError::Unreadable("Kaia network scope"));
        }
        let _lock = self.lock()?;
        if self
            .kaia_rpcs()?
            .iter()
            .any(|old| old.name == node.name || old.address == node.address)
            || self
                .kaia_corecells()?
                .iter()
                .any(|old| old.node.name == node.name || old.node.address == node.address)
        {
            return Err(InventoryError::Refused(
                "Kaia host is already reserved".into(),
            ));
        }
        read(&self.create(Kind::Rpc, &node.name, &fields(node)?, None)?)
    }
    /// Update pins/run results while preserving host and platform ownership.
    /// # Errors
    /// Ownership changes and stale writes are refused.
    pub fn update_kaia_rpc(&self, node: &KaiaRpc) -> Result<KaiaRpc, InventoryError> {
        let _lock = self.lock()?;
        let id = node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("Kaia owner"))?;
        let old = read(&self.get(id)?)?;
        if old.name != node.name
            || old.network != node.network
            || old.genesis != node.genesis
            || old.address != node.address
            || old.ssh_user != node.ssh_user
            || old.ssh_port != node.ssh_port
            || old.host_key != node.host_key
            || old.platform != node.platform
            || old.storage != node.storage
            || old.snapshot != node.snapshot
        {
            return Err(InventoryError::Refused(
                "Kaia host/platform/retention/snapshot contract are immutable".into(),
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
