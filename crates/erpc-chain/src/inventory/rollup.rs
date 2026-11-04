// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! OP-family follower inventory. Provider credentials are never stored here.

use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked};
use serde::{Deserialize, Serialize};

/// One owned follower host. Network and family are also encoded in store scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupRpc {
    /// 1Password item identity.
    #[serde(skip)]
    pub id: Option<String>,
    /// Optimistic concurrency revision.
    #[serde(skip)]
    pub item_version: u64,
    /// Operator inventory name.
    pub name: String,
    /// SSH target.
    pub address: String,
    /// SSH login account.
    pub ssh_user: String,
    /// SSH port.
    pub ssh_port: u16,
    /// Pinned OpenSSH server key.
    pub host_key: String,
    /// Chain family, checked against the store scope.
    pub family: String,
    /// Network, checked against the store scope.
    pub network: String,
    /// Immutable full/archive retention.
    pub history: String,
    /// Public numeric address for consensus peer advertisement.
    pub advertise_ip: String,
    /// Reference to a concealed execution/beacon upstream JSON field.
    pub upstream_ref: String,
    /// Allowed HTTP/WebSocket clients; empty keeps the gateway on loopback.
    pub rpc_allow: Vec<String>,
    /// SSH management ranges.
    pub management_allow: Vec<String>,
    /// Metrics clients; empty keeps metrics on loopback.
    pub monitoring_allow: Vec<String>,
    /// Exact source/artifact pair, never a mutable tag or arbitrary URL.
    pub pair: serde_json::Value,
    /// Bootstrap metadata identity and content hashes.
    pub bootstrap: serde_json::Value,
    /// Last operation identifier.
    pub last_run: String,
    /// Last successfully recorded lifecycle result.
    pub last_result: String,
}

fn read(item: &OpItem) -> Result<RollupRpc, InventoryError> {
    let fields = checked(item)?;
    let mut node: RollupRpc = serde_json::from_str(
        fields
            .get("rollup_record")
            .ok_or(InventoryError::Unreadable("follower record"))?,
    )
    .map_err(|_| InventoryError::Unreadable("follower record"))?;
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}

fn fields(node: &RollupRpc) -> Result<Vec<(&'static str, String)>, InventoryError> {
    Ok(vec![
        ("erpc_format", super::FORMAT.to_owned()),
        (
            "rollup_record",
            serde_json::to_string(node)
                .map_err(|_| InventoryError::Unreadable("follower record"))?,
        ),
    ])
}

impl<R: OpRunner> Store<R> {
    fn rollup_scope(&self) -> Result<(), InventoryError> {
        if !["optimism", "base", "soneium"].contains(&self.scope.chain.as_str()) {
            return Err(InventoryError::Refused(
                "expected OP-family follower scope".into(),
            ));
        }
        Ok(())
    }

    fn rollup_matches(&self, node: &RollupRpc) -> Result<(), InventoryError> {
        self.rollup_scope()?;
        erpc_secret::OpRef::parse(&node.upstream_ref).map_err(|_| {
            InventoryError::Refused(
                "upstream credentials require an identifier-only secret reference".into(),
            )
        })?;
        if !["full", "archive"].contains(&node.history.as_str()) {
            return Err(InventoryError::Refused(
                "invalid follower history policy".into(),
            ));
        }
        if node.family != self.scope.chain || node.network != self.scope.network {
            return Err(InventoryError::Refused(
                "follower chain/network scope mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Read only records in this exact chain/network scope.
    /// # Errors
    /// Malformed or wrongly scoped records are refused.
    pub fn rollup_rpcs(&self) -> Result<Vec<RollupRpc>, InventoryError> {
        self.rollup_scope()?;
        self.items(Kind::Rpc)?
            .iter()
            .map(|item| {
                let node = read(item)?;
                self.rollup_matches(&node)?;
                Ok(node)
            })
            .collect()
    }

    /// Reserve a unique host after the caller has checked the remote contract.
    /// # Errors
    /// Duplicate host/name, wrong scope and storage failures are refused.
    pub fn add_rollup_rpc(&self, node: &RollupRpc) -> Result<RollupRpc, InventoryError> {
        self.rollup_matches(node)?;
        check_name(&node.name)?;
        let _lock = self.lock()?;
        if self
            .rollup_rpcs()?
            .iter()
            .any(|old| old.name == node.name || old.address == node.address)
        {
            return Err(InventoryError::Refused(
                "follower host is already reserved".into(),
            ));
        }
        read(&self.create(Kind::Rpc, &node.name, &fields(node)?, None)?)
    }

    /// Update settings/pins while preserving immutable host, chain and retention.
    /// # Errors
    /// Wrong scope, stale revision or an attempted ownership change fails closed.
    pub fn update_rollup_rpc(&self, node: &RollupRpc) -> Result<RollupRpc, InventoryError> {
        self.rollup_matches(node)?;
        let _lock = self.lock()?;
        let id = node
            .id
            .as_deref()
            .ok_or(InventoryError::Unreadable("follower owner"))?;
        let old = read(&self.get(id)?)?;
        self.rollup_matches(&old)?;
        if (
            old.name.as_str(),
            old.address.as_str(),
            old.host_key.as_str(),
            old.ssh_user.as_str(),
            old.ssh_port,
            old.history.as_str(),
        ) != (
            node.name.as_str(),
            node.address.as_str(),
            node.host_key.as_str(),
            node.ssh_user.as_str(),
            node.ssh_port,
            node.history.as_str(),
        ) {
            return Err(InventoryError::Refused(
                "follower host and retention ownership are immutable".into(),
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
