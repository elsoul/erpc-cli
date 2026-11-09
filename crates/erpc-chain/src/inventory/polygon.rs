// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Polygon inventory binds a unique host owner to an immutable network and role.
use super::{InventoryError, Kind, OpItem, OpRunner, Store, check_name, checked};
use serde::{Deserialize, Serialize};

/// One explicitly selected public sentry peer for both native clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolygonSentry {
    /// Numeric public P2P address; native verification applies the IANA policy.
    pub address: String,
    /// Uncompressed Bor enode public key, without its 04 prefix.
    pub bor_node_id: String,
    /// Heimdall's `CometBFT` node ID.
    pub heimdall_node_id: String,
}

/// Immutable financial identity and public sentry policy for a fresh validator.
/// The actual hot key lives only in a separate concealed original 1Password item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolygonValidator {
    /// Separate external stake-owner address; its private key is never imported.
    pub stake_owner: String,
    /// Public address of the newly generated dedicated hot signer.
    pub signer: String,
    /// Durable original-key creation intent, published before the secret write.
    pub creation: String,
    /// Original concealed field reference, empty until verified read-back.
    pub original_ref: String,
    /// Whether the original key read back exactly after creation.
    pub original_ready: bool,
    /// Desired native mode; first deployment remains a non-signing observer.
    #[serde(default = "observing")]
    pub phase: String,
    /// Explicit P2P peer identities; can change only through stopped configuration.
    pub sentries: Vec<PolygonSentry>,
}

fn observing() -> String {
    "observing".into()
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn public_address(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|v| hex(v, 40) && v.bytes().any(|b| b != b'0'))
}
impl PolygonValidator {
    fn validate(&self) -> Result<(), InventoryError> {
        if !matches!(self.phase.as_str(), "observing" | "active")
            || !public_address(&self.signer)
            || !public_address(&self.stake_owner)
            || self.signer == self.stake_owner
            || !hex(&self.creation, 32)
            || self.sentries.is_empty()
            || self.sentries.len() > 8
            || self.original_ready == self.original_ref.is_empty()
        {
            return Err(InventoryError::Unreadable("Polygon validator authority"));
        }
        if !self.original_ref.is_empty() {
            erpc_secret::OpRef::parse(&self.original_ref)
                .map_err(|_| InventoryError::Unreadable("Polygon original signer reference"))?;
        }
        let mut peers = std::collections::BTreeSet::new();
        for peer in &self.sentries {
            if peer.address.parse::<std::net::IpAddr>().is_err()
                || !hex(&peer.bor_node_id, 128)
                || !hex(&peer.heimdall_node_id, 40)
                || !peers.insert(&peer.address)
            {
                return Err(InventoryError::Unreadable("Polygon sentry identity"));
            }
        }
        Ok(())
    }
    fn same_original(&self, other: &Self) -> bool {
        (self.phase != "active" || other.phase == "active")
            && self.stake_owner == other.stake_owner
            && self.signer == other.signer
            && self.creation == other.creation
            && (!self.original_ready
                || other.original_ready && self.original_ref == other.original_ref)
    }
}

/// Public configuration of one Bor/Heimdall RPC host. Credentials stay concealed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolygonNode {
    /// Stable 1Password item identity, reserved before rendering a host contract.
    #[serde(skip)]
    pub id: Option<String>,
    /// Optimistic inventory revision.
    #[serde(skip)]
    pub item_version: u64,
    /// Inventory name.
    pub name: String,
    /// SSH address.
    pub address: String,
    /// SSH login user.
    pub ssh_user: String,
    /// SSH listener port.
    pub ssh_port: u16,
    /// Pinned host public key.
    pub host_key: String,
    /// Mainnet or Amoy; also encoded in store scope.
    pub network: String,
    /// RPC role is `fullnode`; validator admission uses a separate lifecycle.
    pub role: String,
    /// Dedicated validator authority; absent for RPC/sentry inventory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<PolygonValidator>,
    /// Native Debian artifact architecture.
    pub architecture: String,
    /// Public P2P advertisement, never a provider URL.
    pub advertise_ip: String,
    /// Identifier-only reference to a concealed execution-parent field.
    pub upstream_ref: String,
    /// Exact desired reviewed network-qualified release profile.
    pub profile: serde_json::Value,
    /// Trusted HTTP and WebSocket clients.
    pub rpc_allow: Vec<String>,
    /// Additional SSH management ranges.
    pub management_allow: Vec<String>,
    /// Trusted native metrics scrapers.
    pub monitoring_allow: Vec<String>,
    /// Last remote operation.
    pub last_run: String,
    /// Last completed lifecycle result.
    pub last_result: String,
}

fn validate(node: &PolygonNode) -> Result<(), InventoryError> {
    check_name(&node.name)?;
    match (&*node.role, &node.validator) {
        ("fullnode", None) => {}
        ("validator", Some(value)) => value.validate()?,
        _ => return Err(InventoryError::Unreadable("Polygon role authority")),
    }
    erpc_secret::OpRef::parse(&node.upstream_ref)
        .map_err(|_| InventoryError::Unreadable("Polygon parent reference"))?;
    if !["mainnet", "amoy"].contains(&node.network.as_str())
        || !["fullnode", "validator"].contains(&node.role.as_str())
        || !["x86_64", "aarch64"].contains(&node.architecture.as_str())
        || node.advertise_ip.parse::<std::net::IpAddr>().is_err()
        || node
            .profile
            .get("network")
            .and_then(serde_json::Value::as_str)
            != Some(&node.network)
    {
        return Err(InventoryError::Unreadable("Polygon ownership profile"));
    }
    Ok(())
}
fn kind(role: &str) -> Result<Kind, InventoryError> {
    match role {
        "fullnode" => Ok(Kind::Rpc),
        "validator" => Ok(Kind::Validator),
        _ => Err(InventoryError::Unreadable("Polygon role")),
    }
}
fn read(item: &OpItem) -> Result<PolygonNode, InventoryError> {
    let fields = checked(item)?;
    let mut node: PolygonNode = serde_json::from_str(
        fields
            .get("polygon_node")
            .ok_or(InventoryError::Unreadable("Polygon node"))?,
    )
    .map_err(|_| InventoryError::Unreadable("Polygon node"))?;
    validate(&node)?;
    node.id = Some(item.id.clone());
    node.item_version = item.version;
    Ok(node)
}
fn fields(node: &PolygonNode) -> Result<Vec<(&'static str, String)>, InventoryError> {
    validate(node)?;
    Ok(vec![
        ("erpc_format", super::FORMAT.to_owned()),
        (
            "polygon_node",
            serde_json::to_string(node).map_err(|_| InventoryError::Unreadable("Polygon node"))?,
        ),
    ])
}
impl<R: OpRunner> Store<R> {
    /// Read only this network/role's public Polygon inventory.
    /// # Errors
    /// Refuses another scope or inconsistent role/network tags.
    pub fn polygon_nodes(&self, role: &str) -> Result<Vec<PolygonNode>, InventoryError> {
        if self.scope.chain != "polygon" {
            return Err(InventoryError::Refused(
                "Polygon inventory requires its own scope".into(),
            ));
        }
        let nodes = self
            .items(kind(role)?)?
            .iter()
            .map(read)
            .collect::<Result<Vec<_>, _>>()?;
        if nodes
            .iter()
            .any(|node| node.role != role || node.network != self.scope.network)
        {
            return Err(InventoryError::Unreadable("Polygon scope tags"));
        }
        Ok(nodes)
    }
    /// Reserve a stable unique owner before host mutation; never adopt a host.
    /// # Errors
    /// Refuses duplicate names/hosts across roles or invalid public metadata.
    pub fn add_polygon_node(&self, node: &PolygonNode) -> Result<PolygonNode, InventoryError> {
        validate(node)?;
        if node.network != self.scope.network {
            return Err(InventoryError::Unreadable("Polygon network scope"));
        }
        let _lock = self.lock()?;
        for role in ["fullnode", "validator"] {
            if self
                .polygon_nodes(role)?
                .iter()
                .any(|old| old.name == node.name || old.address == node.address)
            {
                return Err(InventoryError::Refused(
                    "Polygon name or host is already reserved; role/host migration is not implicit"
                        .into(),
                ));
            }
        }
        read(&self.create(kind(&node.role)?, &node.name, &fields(node)?, None)?)
    }
    /// Update mutable policy/target metadata without changing host ownership.
    /// # Errors
    /// Refuses stale revisions and host, network, role or architecture changes.
    pub fn update_polygon_node(&self, node: &PolygonNode) -> Result<PolygonNode, InventoryError> {
        validate(node)?;
        let _lock = self.lock()?;
        let old = self
            .polygon_nodes(&node.role)?
            .into_iter()
            .find(|old| old.id == node.id)
            .ok_or_else(|| InventoryError::Refused("Polygon node is not reserved".into()))?;
        if old.name != node.name
            || old.address != node.address
            || old.ssh_user != node.ssh_user
            || old.ssh_port != node.ssh_port
            || old.host_key != node.host_key
            || old.network != node.network
            || old.role != node.role
            || old.architecture != node.architecture
            || match (&old.validator, &node.validator) {
                (None, None) => false,
                (Some(before), Some(after)) => !before.same_original(after),
                _ => true,
            }
        {
            return Err(InventoryError::Refused(
                "Polygon inventory ownership is immutable".into(),
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
