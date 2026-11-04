// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Sui inventory: public configuration only; node keys never enter listing JSON.
use super::{FORMAT, InventoryError, Kind, OpItem, OpRunner, Store, check_name};
use serde::{Deserialize, Serialize};

/// A single network/role bound Sui host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiNode {
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
    /// Trusted gRPC gateway/client IP ranges; never an unrestricted public listener.
    pub rpc_allow: Vec<String>,
    /// Extra SSH access ranges.
    pub management_allow: Vec<String>,
    /// Metrics scraper ranges.
    pub monitoring_allow: Vec<String>,
    /// Public official validator metadata, absent for an RPC node.
    #[serde(default)]
    pub validator_metadata: Option<serde_json::Value>,
    /// 1Password references in protocol/network/worker order, never key values.
    #[serde(default)]
    pub key_references: [String; 3],
    /// Last completed remote run.
    pub last_run: String,
    /// Last completed operation.
    pub last_result: String,
}

fn read(item: &OpItem) -> Result<SuiNode, InventoryError> {
    let fields = item.plain();
    if fields.get("erpc_format") != Some(&FORMAT) {
        return Err(InventoryError::Unreadable("Sui inventory format"));
    }
    let raw = fields
        .get("sui_node")
        .ok_or(InventoryError::Unreadable("Sui node"))?;
    let mut node: SuiNode =
        serde_json::from_str(raw).map_err(|_| InventoryError::Unreadable("Sui node"))?;
    check_name(&node.name)?;
    if !["fullnode", "validator"].contains(&node.role.as_str()) {
        return Err(InventoryError::Unreadable("Sui node role"));
    }
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}
fn fields(node: &SuiNode) -> Result<Vec<(&'static str, String)>, InventoryError> {
    Ok(vec![
        ("erpc_format", FORMAT.to_owned()),
        (
            "sui_node",
            serde_json::to_string(node).map_err(|_| InventoryError::Unreadable("Sui node"))?,
        ),
    ])
}
fn kind(role: &str) -> Result<Kind, InventoryError> {
    match role {
        "fullnode" => Ok(Kind::Rpc),
        "validator" => Ok(Kind::Validator),
        _ => Err(InventoryError::Refused("unknown Sui role".to_owned())),
    }
}
impl<R: OpRunner> Store<R> {
    /// List the requested Sui role without reading any concealed keys.
    /// # Errors
    /// Refuses a different chain scope or malformed inventory.
    pub fn sui_nodes(&self, role: &str) -> Result<Vec<SuiNode>, InventoryError> {
        if self.scope.chain != "sui" {
            return Err(InventoryError::Refused(
                "Sui inventory requires a Sui scope".to_owned(),
            ));
        }
        let nodes = self
            .items(kind(role)?)?
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        if nodes.iter().any(|n| n.role != role) {
            return Err(InventoryError::Unreadable("Sui role tag"));
        }
        Ok(nodes)
    }
    /// Reserve a host, refusing reuse across RPC and validator roles.
    /// # Errors
    /// Refuses duplicate names/addresses or malformed inventory.
    pub fn add_sui_node(&self, node: &SuiNode) -> Result<SuiNode, InventoryError> {
        check_name(&node.name)?;
        let _lock = self.lock()?;
        for role in ["fullnode", "validator"] {
            if self.sui_nodes(role)?.iter().any(|n| {
                n.name == node.name
                    || n.address == node.address
                    || [
                        "account-address",
                        "protocol-key",
                        "network-key",
                        "worker-key",
                    ]
                    .iter()
                    .any(|field| {
                        let new = node
                            .validator_metadata
                            .as_ref()
                            .and_then(|m| m.get("info")?.get(field)?.as_str());
                        let old = n
                            .validator_metadata
                            .as_ref()
                            .and_then(|m| m.get("info")?.get(field)?.as_str());
                        new.zip(old).is_some_and(|(a, b)| {
                            if *field == "account-address" {
                                a.eq_ignore_ascii_case(b)
                            } else {
                                a == b
                            }
                        })
                    })
            }) {
                return Err(InventoryError::Refused("Sui name, host or validator identity is already reserved; do not duplicate a signer".to_owned()));
            }
        }
        read(&self.create(kind(&node.role)?, &node.name, &fields(node)?, None)?)
    }
    /// Update a node using the inventory's optimistic concurrency guard.
    /// # Errors
    /// Refuses stale versions; host and role cannot be changed by this method.
    pub fn update_sui_node(&self, node: &SuiNode) -> Result<SuiNode, InventoryError> {
        let _lock = self.lock()?;
        let old = self
            .sui_nodes(&node.role)?
            .into_iter()
            .find(|n| n.id == node.id)
            .ok_or_else(|| InventoryError::Refused("Sui node is not stored".to_owned()))?;
        if old.name != node.name
            || old.address != node.address
            || old.host_key != node.host_key
            || old.architecture != node.architecture
            || old.validator_metadata != node.validator_metadata
            || old.key_references != node.key_references
        {
            return Err(InventoryError::Refused(
                "Sui host identity is immutable".to_owned(),
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
