// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Tron inventory: public configuration only; node keys never enter listing JSON.
use super::{FORMAT, InventoryError, Kind, OpItem, OpRunner, Store, check_name};
use serde::{Deserialize, Serialize};

/// A single network/role bound Tron host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TronNode {
    /// 1Password item identifier.
    #[serde(skip)]
    pub id: Option<String>,
    /// Optimistic update version.
    #[serde(skip)]
    pub item_version: u64,
    /// Unique node name.
    pub name: String,
    /// SSH host address.
    pub address: String,
    /// Login user.
    pub ssh_user: String,
    /// SSH port.
    pub ssh_port: u16,
    /// Pinned OpenSSH host public key.
    pub host_key: String,
    /// `fullnode` or `validator`; immutable on a host.
    pub role: String,
    /// `uname -m` platform.
    pub architecture: String,
    /// Reviewed release tag.
    pub version: String,
    /// Resolved source commit.
    pub commit: String,
    /// Release archive digest.
    pub archive_sha256: String,
    /// Trusted API gateway/client IP ranges; never an unrestricted public listener.
    pub rpc_allow: Vec<String>,
    /// Extra SSH access ranges.
    pub management_allow: Vec<String>,
    /// Metrics scraper ranges.
    pub monitoring_allow: Vec<String>,
    /// Public candidate account; empty for query-only nodes.
    #[serde(default)]
    pub owner: String,
    /// Dedicated block-signing address; never the owner key.
    #[serde(default)]
    pub signer: String,
    /// Public candidate URL for external registration preparation.
    #[serde(default)]
    pub candidate_url: String,
    /// Native keystore and password field references, never their values.
    #[serde(default)]
    pub credential_references: [String; 2],
    /// Last completed remote run.
    pub last_run: String,
    /// Last completed operation.
    pub last_result: String,
}

fn read(item: &OpItem) -> Result<TronNode, InventoryError> {
    let fields = item.plain();
    if fields.get("erpc_format") != Some(&FORMAT) {
        return Err(InventoryError::Unreadable("Tron inventory format"));
    }
    let raw = fields
        .get("tron_node")
        .ok_or(InventoryError::Unreadable("Tron node"))?;
    let mut node: TronNode =
        serde_json::from_str(raw).map_err(|_| InventoryError::Unreadable("Tron node"))?;
    check_name(&node.name)?;
    if !["fullnode", "validator"].contains(&node.role.as_str()) {
        return Err(InventoryError::Unreadable("Tron node role"));
    }
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}
fn fields(node: &TronNode) -> Result<Vec<(&'static str, String)>, InventoryError> {
    Ok(vec![
        ("erpc_format", FORMAT.to_owned()),
        (
            "tron_node",
            serde_json::to_string(node).map_err(|_| InventoryError::Unreadable("Tron node"))?,
        ),
    ])
}
fn kind(role: &str) -> Result<Kind, InventoryError> {
    match role {
        "fullnode" => Ok(Kind::Rpc),
        "validator" => Ok(Kind::Validator),
        _ => Err(InventoryError::Refused("unknown Tron role".to_owned())),
    }
}
impl<R: OpRunner> Store<R> {
    /// List the requested Tron role without reading any concealed keys.
    /// # Errors
    /// Refuses a different chain scope or malformed inventory.
    pub fn tron_nodes(&self, role: &str) -> Result<Vec<TronNode>, InventoryError> {
        if self.scope.chain != "tron" {
            return Err(InventoryError::Refused(
                "Tron inventory requires a Tron scope".to_owned(),
            ));
        }
        let nodes = self
            .items(kind(role)?)?
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        if nodes.iter().any(|n| n.role != role) {
            return Err(InventoryError::Unreadable("Tron role tag"));
        }
        Ok(nodes)
    }
    /// Reserve a host, refusing reuse across RPC and validator roles.
    /// # Errors
    /// Refuses duplicate names/addresses or malformed inventory.
    pub fn add_tron_node(&self, node: &TronNode) -> Result<TronNode, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        for role in ["fullnode", "validator"] {
            if self.tron_nodes(role)?.iter().any(|n| {
                n.name == node.name
                    || n.address == node.address
                    || (!node.owner.is_empty()
                        && (n.owner == node.owner || n.signer == node.signer))
            }) {
                return Err(InventoryError::Refused("Tron name or host is already reserved; role changes and migration require a separate host workflow".to_owned()));
            }
        }
        read(&self.create(kind(&node.role)?, &node.name, &fields(node)?, None)?)
    }
    /// Update a node using the inventory's optimistic concurrency guard.
    /// # Errors
    /// Refuses stale versions; host and role cannot be changed by this method.
    pub fn update_tron_node(&self, node: &TronNode) -> Result<TronNode, InventoryError> {
        let _lock = self.lock()?;
        let old = self
            .tron_nodes(&node.role)?
            .into_iter()
            .find(|n| n.id == node.id)
            .ok_or_else(|| InventoryError::Refused("Tron node is not stored".to_owned()))?;
        if old.name != node.name
            || old.address != node.address
            || old.ssh_user != node.ssh_user
            || old.ssh_port != node.ssh_port
            || old.host_key != node.host_key
            || old.architecture != node.architecture
            || old.owner != node.owner
            || old.signer != node.signer
            || old.candidate_url != node.candidate_url
            || old.credential_references != node.credential_references
        {
            return Err(InventoryError::Refused(
                "Tron host identity is immutable".to_owned(),
            ));
        }
        read(&self.update(
            kind(&node.role)?,
            (node.id.as_deref(), node.item_version),
            &node.name,
            &fields(node)?,
            None,
        )?)
    }
}
